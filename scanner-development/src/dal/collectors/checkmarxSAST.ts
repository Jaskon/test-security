import memoryDB from "@oxappsec/ox-memory-db";
import axios from "axios";
import crypto from "crypto";
import * as fs from "fs";
import { ApplicationManager } from "../../appmgr/AppManager";
import { SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import { SimpleSecurityEventBuilder } from "../../helper/tools/securityEventBuilderHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
const { XMLParser } = require("fast-xml-parser");

const logger = loggerImport.getDebugLogger();
let duplicate = 0;
let ignored = 0;
let token: string | undefined;
let url;

interface checkMarxSastScan {
  id: string;
  project: string;
  reportId: string;
  scanId: string;
  scannedAt: string;
  reportUri?: string;
}

type ProjectID = string;

namespace CheckMarxSAST {
  export interface ScanResult {
    id: number;
    project: Project;
    dateAndTime: DateAndTime;
  }

  export interface ScanReport {
    link: Link;
    contentType: string;
    status: Status;
  }

  export interface ScanReportRequest {
    reportId: number;
    links: Links;
  }

  export interface Links {
    report: Report;
    status: Report;
  }

  export interface Report {
    rel: string;
    uri: string;
  }

  export interface Link {
    rel: string;
    uri: string;
  }

  export interface Status {
    id: number;
    value: string;
  }

  export interface DateAndTime {
    startedOn: string;
    finishedOn: string;
    engineStartedOn: string;
    engineFinishedOn: string;
  }

  export interface Project {
    id: number;
    name: string;
    link: Link;
  }
}

const getCacheKey = (projectId: string, projectName: string, scanId: string): string => {
  return `CXSAST_CACHE_KEY_${projectId}_${projectName}_${scanId}`;
};

const fifteenMinutesInMs = 1000 * 60 * 15;
const fortyEightHoursInSec = 60 * 60 * 48;

interface CheckMarxSASTRequest {
  url: string;
  token: string;
}

const fetchDataWithTimeout = async (req: CheckMarxSASTRequest, timeout: number = fifteenMinutesInMs): Promise<string> => {
  const randomSleep = async () => {
    // sleep for 5-30 seconds
    await new Promise(resolve => setTimeout(resolve, (Math.floor(Math.random() * 31) + 5) * 1000));
  };

  return new Promise(async (resolve, reject) => {
    const timer = setTimeout(() => {
      reject("Operation timed out.");
    }, timeout);

    try {
      while (true) {
        await randomSleep();
        const response = await axios.get(req.url, {
          timeout: 90000,
          headers: {
            "Content-Type": `application/json`,
            Authorization: `Bearer ${req.token}`,
          },
        });

        if (response.status === 200) {
          clearTimeout(timer);
          resolve(response.data);
          return;
        } else if (response.status === 204) {
          await randomSleep();
          continue; // Will try again as response is 204.
        } else {
          clearTimeout(timer);
          reject(`Failed to get the report. Status code: ${response.status}`);
          return;
        }
      }
    } catch (error) {
      clearTimeout(timer);
      reject(error);
    }
  });
};

export const CXSast = (username: string, password: string, urlInfo: string) => {
  const projectsMap: Map<string, string> = new Map();
  const projectsGitToProjectName = {};

  const scanResultsEx: Map<ProjectID, checkMarxSastScan> = new Map();

  const scanResultsByProject: Set<string> = new Set();

  async function sleep() {
    const delay = (ms: number) => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 5);
  }

  return {
    login: async (): Promise<any> => {
      try {
        logger.info(`CheckMarx SAST: logging in...`);
        url = urlInfo;

        StatesHelper.Instance.isCheckMarxEnable = true;

        const params = new URLSearchParams();
        params.append("username", username);
        params.append("password", password);
        params.append("grant_type", "password");
        params.append("scope", "sast_rest_api");
        params.append("client_id", "resource_owner_client");
        params.append("client_secret", "014DF517-39D1-4453-B7B3-9930C563627C");

        // Assuming url is: https://888holdings.checkmarx.net/CxRestAPI or similar
        logger.info(
          `CheckMarx SAST: trying to login with: URL:${url}/CxRestAPI/auth/identity/connect/token, username:${username} and password:${crypto
            .createHash("sha256")
            .update(password)
            .digest("hex")}`,
        );
        const res: any = await axios.post(`${url}/CxRestAPI/auth/identity/connect/token`, params, {
          headers: {
            "Content-Type": "application/x-www-form-urlencoded",
          },
          timeout: 10000,
        });
        if (res.status !== 200) {
          logger.error(`CheckMarx SAST: Failed to login to CheckMarx. Status code: ${res.status}`);
          return;
        }

        token = res.data.access_token;
        logger.info(`CheckMarx SAST: login successful`);
      } catch (error) {
        logger.info(`CheckMarx SAST: Error logging into CheckMarx Sast: ${error}`);
      }

      return token;
    },

    getAllProjects: async (): Promise<any> => {
      logger.info(`CheckMarx SAST: getting all projects...`);

      try {
        const res = await axios.get(`${url}/CxRestAPI/projects`, {
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
          timeout: 30000,
        });
        if (res.status !== 200) {
          logger.error(`CheckMarx SAST: Failed to login to CheckMarx. Status code: ${res.status}`);
          return null;
        }

        logger.info(`CheckMarx SAST: get all projects successful`);

        const projects: any = res.data;

        for (const project of projects) {
          // We are interested in id, name, and links (specifically latest scan)
          logger.info(`CheckMarx SAST: project found: ${project.name}. Id: ${project.id}`);

          projectsMap.set(`${project.id}:${project.name}`, JSON.stringify(project));
        }
      } catch (error) {
        logger.info(`CheckMarx SAST: Error getting all projects: ${error}`);
        StatesHelper.Instance.globalApisFails.add("check-marx-sast");
      }

      return projectsMap;
    },

    getScanResultsEx: async (): Promise<void> => {
      logger.info(`CheckMarx SAST: getting scan results...`);

      try {
        for (let [project, projectData] of projectsMap) {
          const projectId = project.split(":")[0];

          try {
            const res = await axios.get(`${url}/CxRestAPI/sast/scans?projectId=${projectId}&last=1&scanStatus=Finished`, {
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
              },
              timeout: 10000,
            });
            if (res.status !== 200) {
              logger.error(`CheckMarx SAST: Failed to retrieve 1 data for project: ${project}. Status code: ${res.status}`);
              continue;
            }

            const scanArray: CheckMarxSAST.ScanResult[] = res.data;
            for (const singleScan of scanArray) {
              const cachedResult = (await memoryDB.get.execute(
                getCacheKey(projectId, project.split(":")[1], singleScan.id.toString()),
              )) as string;

              if (cachedResult) {
                logger.info(`CheckMarx SAST: Scan results for project: ${project} found in cache`);
                const cachedDateJson = JSON.parse(cachedResult) as checkMarxSastScan;
                const cachedDate = new Date(cachedDateJson.scannedAt);
                const scanDate = new Date(singleScan.dateAndTime.finishedOn);

                if (cachedDate.getTime() === scanDate.getTime()) {
                  logger.info(`CheckMarx SAST: Scan results for project: ${project} did not change, no need to generate again`);
                  scanResultsEx.set(projectId, cachedDateJson);

                  continue;
                } else {
                  logger.info(
                    `CheckMarx SAST: Scan results for project: ${project} changed, need to generate again. New scan date: ${scanDate}`,
                  );
                }
              }

              // We should enter here only once
              scanResultsEx.set(projectId, {
                id: projectId,
                project: project.split(":")[1],
                reportId: "", // We will get this one later
                scanId: singleScan.id.toString(),
                scannedAt: singleScan.dateAndTime.finishedOn,
              });
            }
          } catch (error) {
            logger.info(`CheckMarx SAST: Error getting scan results: ${error} for project: ${project} (last scan)`);
          }
        }
      } catch (error) {
        logger.info(`CheckMarx SAST: Error getting scan results for all projects: ${error} (projects: ${projectsMap})`);
        StatesHelper.Instance.globalApisFails.add("check-marx-sast");
      }
    },

    getAllScanReportEx: async (): Promise<any> => {
      logger.info(`CheckMarx SAST: getting latest scan report per project`);

      try {
        const reportRequests: Map<ProjectID, CheckMarxSAST.ScanReportRequest> = new Map();

        for (let [projectId, projectSastScan] of scanResultsEx) {
          try {
            if (projectSastScan.reportId !== "") {
              logger.info(`CheckMarx SAST: Scan report meta data for ${projectId} already created: ${JSON.stringify(projectSastScan)}`);

              // Check if we already have the report
              const cachedReportUri = projectSastScan.reportUri;
              if (cachedReportUri) {
                try {
                  const reportBlob: any = await axios.get(`${url}/CxRestAPI${cachedReportUri}`, {
                    headers: {
                      Accept: `application/json`,
                      Authorization: `Bearer ${token}`,
                    },
                    timeout: 10000,
                  });

                  if (reportBlob.status !== 200) {
                    if (reportBlob.status === 204) {
                      logger.info(`CheckMarx SAST: Scan report for ${projectId} (${projectSastScan.project}) is not ready yet`);
                      reportRequests.set(projectId, {
                        reportId: parseInt(projectSastScan.reportId),
                        links: {
                          report: {
                            rel: "report",
                            uri: cachedReportUri,
                          },
                          status: {
                            rel: "status",
                            uri: `${cachedReportUri}/status`,
                          },
                        },
                      });
                      continue;
                    } else {
                      logger.info(
                        `CheckMarx SAST: Failed to retrieve data Status code: ${reportBlob.status} for ${projectId} (${projectSastScan.project}, generating again`,
                      );
                    }
                  } else {
                    logger.info(`CheckMarx SAST: Old scan report for ${projectId} (${projectSastScan.project}) retrieved`);
                    scanResultsByProject.add(JSON.stringify(reportBlob.data));
                    continue;
                  }
                } catch (error) {
                  logger.error(`CheckMarx SAST: Failed to retrieve old report for project: ${projectId} (${projectSastScan.project})`);
                  StatesHelper.Instance.globalApisFails.add("check-marx-sast");
                }
              } else {
                logger.error(`CheckMarx SAST: Scan report meta data for ${projectId} (${projectSastScan.project}) is missing report uri`);
              }
            }

            logger.info(
              `CheckMarx SAST: getting scan report for project: ${projectId} (${projectSastScan.project}) with scan id: ${projectSastScan.id}`,
            );

            const res: any = await axios.post(
              `${url}/CxRestAPI/reports/sastScan`,
              {
                reportType: "XML", // No JSON support
                scanId: projectSastScan.scanId,
              },
              {
                headers: {
                  "Content-Type": "application/json",
                  Authorization: `Bearer ${token}`,
                },
                timeout: 10000,
              },
            );

            // We should get 202 here, which means the report is being generated
            if (res.status === 202) {
              logger.info(`CheckMarx SAST: Scan report meta data for ${projectId} retrieved: ${JSON.stringify(res.data)}`);
              reportRequests.set(projectId, res.data);
            } else if (res.status !== 200) {
              logger.error(
                `CheckMarx SAST: Failed to retrieve generate report data for project: ${projectId} (${projectSastScan.project}). Status code: ${res.status}`,
              );
            }
          } catch (error) {
            logger.error(
              `CheckMarx SAST: Error generating new scan report: ${error} for project: ${projectId} (${projectSastScan.project})`,
            );
          }
        }

        const cacheReportId = async (projectId: string, reportId: string, reportUri: string) => {
          try {
            // Save the report uri
            const projectSastScan = scanResultsEx.get(projectId);
            if (projectSastScan) {
              projectSastScan.reportUri = reportUri;
              projectSastScan.reportId = reportId;
              await memoryDB.set.execute(
                getCacheKey(projectId, projectSastScan.project, projectSastScan.scanId),
                fortyEightHoursInSec,
                JSON.stringify(projectSastScan),
              );
            }
          } catch (e) {
            logger.error(`CheckMarx SAST: Failed to cache report id for project: ${projectId} (${reportUri})`);
          }
        };

        const reportsRequestsPromises: Promise<string>[] = [];
        // After we got all the report requests, we need to wait for them to finish
        try {
          for (const [projectId, reportRequest] of reportRequests) {
            await cacheReportId(projectId, reportRequest.reportId.toString(), reportRequest.links.report.uri);

            reportsRequestsPromises.push(
              fetchDataWithTimeout({
                url: `${url}/CxRestAPI${reportRequest.links.report.uri}`,
                token: token,
              }),
            );
          }

          logger.info(
            `CheckMarx SAST: Waiting for ${reportsRequestsPromises.length} reports to finish... (this might take a while, up to 15 minutes)`,
          );
          await Promise.all(reportsRequestsPromises.map(p => p.catch(e => e))).then(results => {
            results.forEach((result, index) => {
              if (result instanceof Error) {
                logger.error(`Promise ${index} failed with`, result);
              } else {
                // Promise succeeded.

                if (result.startsWith("Operation timed out.")) {
                  logger.error(`CheckMarx SAST: Report timed out for ${index}`);
                  return;
                }
                logger.info(`Got report for ${index}`);
                scanResultsByProject.add(JSON.stringify(result));
              }
            });
          });
        } catch (error) {
          logger.info(`CheckMarx SAST: Error getting scan reports with status: ${error}`);
          StatesHelper.Instance.globalApisFails.add("check-marx-sast");
        }
      } catch (error) {
        logger.error(`CheckMarx SAST: Error getting latest scan report level 1 err: ${error}`);
      }

      return scanResultsByProject;
    },
  };
};

const replaceAll = (str, find, replace) => {
  return str.replace(new RegExp(find, "g"), replace);
};

export const CXSastAnalyzer = () => {
  const uniqueEvents: Set<string> = new Set();

  const getProjectsGitInfo = async (projectName, ProjectId, s): Promise<any> => {
    try {
      if (token == undefined) {
        return;
      }

      //Get git info by project i
      const gitInfo3 = await axios.get(`${url}/CxRestAPI/projects/${ProjectId}/sourceCode/remoteSettings/${s}`, {
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${token}`,
        },
      });
      if (gitInfo3.status !== 200) {
        logger.error(
          `CheckMarx SAST: failed get project name: ${projectName} , ProjectId: ${ProjectId}, git info. Status code: ${gitInfo3.status}`,
        );
      } else {
        logger.info(`git info: ${JSON.stringify(gitInfo3.data)}`);
        logger.info(`git Jnfo: ${gitInfo3.data}`);
      }
    } catch (error) {
      logger.error(`CheckMarx SAST: failed get project name: ${projectName} git info, url: ${url}, err: ${error}`);
    }
  };

  const alreadyAdded = (securityEvent: SecurityEvent) => {
    const unique = `${securityEvent.startLineNumber}_${securityEvent.fileName}_${securityEvent.lineContent}_${securityEvent.ruleId}`;

    if (uniqueEvents.has(unique)) {
      duplicate++;
      return true;
    }
    uniqueEvents.add(unique);
    return false;
  };

  const ignoreAlert = (result: any) => {
    if (result.__FalsePositive.toLowerCase() === "true") {
      return true;
    }
    //https://checkmarx.atlassian.net/wiki/spaces/AST/pages/6275104806/results+show
    //0 - TO_VERIFY, 1 - NOT_EXPLOITABLE, 2 - PROPOSED_NOT_EXPLOITABLE, 3 - CONFIRMED, 4 - URGENT, 5 - IGNORED, 6 - NOT_IGNORED

    if (result.__state === "1" || result.__state === "2" || result.__state === "5" || result.__state === "6") {
      ignored++;
      return true;
    }
    if (result.__state === "1") {
      ignored++;
      return true;
    }
    if (result.__Status.toLowerCase() === "fixed") {
      ignored++;
      return true;
    }
    if (result.__state === "3" || result.__state === "4") {
      ignored++;
      return true;
    }
    return false;
  };

  const checkIfHaveAdditionalResaults = result => {
    if (result.Path == undefined) {
      return false;
    }
    if (result.Path.PathNode == undefined) {
      return false;
    }
    const res = Array.isArray(result.Path.PathNode);
    if (!res) {
      return false;
    }
    return true;
  };

  return {
    analyzeScanResults: async (scanResult: string) => {
      try {
        const options = {
          ignoreAttributes: false,
          attributeNamePrefix: "__",
          allowBooleanAttributes: true,
        };
        const parser = new XMLParser(options);
        const scanResultJson = parser.parse(scanResult);

        const timeHelper: TimeHelper = new TimeHelper("");
        const diffInDays = timeHelper.getTimeIntervalFronNowInDays(scanResultJson.CxXMLResults.__ReportCreationTime);
        if (diffInDays > 180) {
          logger.info(
            `CheckMarx SAST: project report name: ${scanResultJson.CxXMLResults.__ProjectName} are ${diffInDays} days old, ignoring results`,
          );
          return [];
        }

        const securityEvents: SecurityEvent[] = [];

        const projectName = scanResultJson.CxXMLResults.__ProjectName;
        const scanStart = scanResultJson.CxXMLResults.__ScanStart;
        const projectResults = scanResultJson.CxXMLResults.Query;

        if (projectResults == undefined) {
          return [];
        }

        if (Array.isArray(projectResults)) {
          for (const projectResult of projectResults) {
            try {
              const category = replaceAll(projectResult.__name, "_", " ");
              const severity = projectResult.__Severity;
              const ruleId = projectResult.__name;
              const results = projectResult.Result;

              if (Array.isArray(results)) {
                for (const result of results) {
                  try {
                    if (ignoreAlert(result)) {
                      continue;
                    }

                    const fileName = result.__FileName;
                    const line = result.__Line;
                    const deepLink = result.__DeepLink;

                    const isArr = checkIfHaveAdditionalResaults(result);
                    if (!isArr) {
                      let lineContent = result.Path.PathNode.Snippet.Line.Code;
                      const securityEvent = new SimpleSecurityEventBuilder();
                      securityEvent.setSecurityProvider("CxSAST");
                      securityEvent.setSecurityAlertType(SecurityAlertType.sast);
                      securityEvent.setStatus(true);
                      securityEvent.setLink(`${fileName}L${line}`);
                      securityEvent.setCreationTime(result.__DetectionDate === "Not available" ? scanStart : result.__DetectionDate);
                      securityEvent.setClosureTime("");
                      securityEvent.setTitle(category);
                      securityEvent.setFileName(fileName);
                      securityEvent.setSeverity(severity);
                      securityEvent.setStartLine(line);
                      securityEvent.setLineContent(lineContent);
                      securityEvent.setRuleId(`${ruleId}`);
                      securityEvent.setMoreInfoLink(deepLink);
                      securityEvent.setViolationInfo(category);
                      securityEvent.setRepoFullName(projectName);

                      const secEvent: SecurityEvent = securityEvent.generateSecurityEvent();
                      secEvent.tools = ["check-marx-sast"];
                      secEvent.realMatch = lineContent.substring(0, 300);

                      if (!alreadyAdded(secEvent)) {
                        securityEvents.push(secEvent);
                      }
                    } else {
                      for (const node of result.Path.PathNode) {
                        try {
                          const securityEvent = new SimpleSecurityEventBuilder();
                          securityEvent.setSecurityProvider("CxSAST");
                          securityEvent.setSecurityAlertType(SecurityAlertType.sast);
                          securityEvent.setStatus(true);
                          securityEvent.setLink(`${node.FileName}L${node.Snippet.Line.Number}`);
                          securityEvent.setCreationTime(node.__DetectionDate === "Not available" ? scanStart : node.__DetectionDate);
                          securityEvent.setClosureTime("");
                          securityEvent.setTitle(category);
                          securityEvent.setFileName(node.FileName);
                          securityEvent.setSeverity(severity);
                          securityEvent.setStartLine(node.Snippet.Line.Number);
                          securityEvent.setLineContent(node.Snippet.Line.Code);
                          securityEvent.setRuleId(`${ruleId}`);
                          securityEvent.setMoreInfoLink(deepLink);
                          securityEvent.setViolationInfo(category);
                          securityEvent.setRepoFullName(projectName);

                          const secEvent: SecurityEvent = securityEvent.generateSecurityEvent();
                          secEvent.realMatch = node.Snippet.Line.Code.substring(0, 300);
                          secEvent.tools = ["check-marx-sast"];

                          if (!alreadyAdded(secEvent)) {
                            securityEvents.push(secEvent);
                          }
                        } catch (err) {
                          logger.error(`Failed to add CheckMarx SAST event, level 0, err: ${err}`);
                        }
                      }
                    }
                  } catch (err) {
                    logger.error(`Failed to add CheckMarx SAST event, level 1, err: ${err}`);
                  }
                }
              } else {
                try {
                  if (ignoreAlert(results)) {
                    continue;
                  }

                  const fileName = results.__FileName;
                  const line = results.__Line;
                  const deepLink = results.__DeepLink;

                  const isArr = checkIfHaveAdditionalResaults(results);
                  if (!isArr) {
                    let lineContent = results.Path.PathNode.Snippet.Line.Code;

                    const securityEvent = new SimpleSecurityEventBuilder();
                    securityEvent.setSecurityProvider("CxSAST");
                    securityEvent.setSecurityAlertType(SecurityAlertType.sast);
                    securityEvent.setStatus(true);
                    securityEvent.setLink(`${fileName}L${line}`);
                    securityEvent.setCreationTime(results.__DetectionDate === "Not available" ? scanStart : results.__DetectionDate);
                    securityEvent.setClosureTime("");
                    securityEvent.setTitle(category);
                    securityEvent.setFileName(fileName);
                    securityEvent.setSeverity(severity);
                    securityEvent.setStartLine(line);
                    securityEvent.setLineContent(lineContent);
                    securityEvent.setRuleId(`${ruleId}`);
                    securityEvent.setMoreInfoLink(deepLink);
                    securityEvent.setViolationInfo(category);
                    securityEvent.setRepoFullName(projectName);

                    const secEvent = securityEvent.generateSecurityEvent();
                    secEvent.realMatch = lineContent.substring(0, 300);

                    if (!alreadyAdded(secEvent)) {
                      securityEvents.push(secEvent);
                    }
                  } else {
                    for (const node of results.Path.PathNode) {
                      try {
                        const securityEvent = new SimpleSecurityEventBuilder();
                        securityEvent.setSecurityProvider("CxSAST");
                        securityEvent.setSecurityAlertType(SecurityAlertType.sast);
                        securityEvent.setStatus(true);
                        securityEvent.setLink(`${node.FileName}L${node.Snippet.Line.Number}`);
                        securityEvent.setCreationTime(node.__DetectionDate === "Not available" ? scanStart : node.__DetectionDate);
                        securityEvent.setClosureTime("");
                        securityEvent.setTitle(category);
                        securityEvent.setFileName(node.FileName);
                        securityEvent.setSeverity(severity);
                        securityEvent.setStartLine(node.Snippet.Line.Number);
                        securityEvent.setLineContent(node.Snippet.Line.Code);
                        securityEvent.setRuleId(`${ruleId}`);
                        securityEvent.setMoreInfoLink(deepLink);
                        securityEvent.setViolationInfo(category);
                        securityEvent.setRepoFullName(projectName);

                        const secEvent = securityEvent.generateSecurityEvent();
                        secEvent.realMatch = node.Snippet.Line.Code.substring(0, 300);

                        if (!alreadyAdded(secEvent)) {
                          securityEvents.push(secEvent);
                        }
                      } catch (err) {
                        logger.error(`Failed to add CheckMarx SAST event, level 2, err: ${err}`);
                      }
                    }
                  }
                } catch (err) {
                  logger.error(`Failed to add CheckMarx SAST event, level 3, err: ${err}`);
                }
              }
            } catch (err) {
              logger.error(`Failed to add CheckMarx SAST event, level 4, err: ${err}`);
            }
          }
        } else {
          try {
            const categories = projectResults.__categories;
            const severity = projectResults.__Severity;
            const ruleId = projectResults.__name;
            const results = projectResults.Result;

            if (Array.isArray(results)) {
              for (const result of results) {
                const fileName = result.__FileName;
                const line = result.__Line;
                const deepLink = result.__DeepLink;

                if (ignoreAlert(result)) {
                  continue;
                }

                const securityEvent = new SimpleSecurityEventBuilder();
                securityEvent.setSecurityProvider("CxSAST");
                securityEvent.setSecurityAlertType(SecurityAlertType.sast);
                securityEvent.setStatus(true);
                securityEvent.setLink(`${fileName}L${line}`);
                securityEvent.setCreationTime(result.__DetectionDate === "Not available" ? scanStart : result.__DetectionDate);
                securityEvent.setClosureTime("");
                securityEvent.setTitle(categories);
                securityEvent.setFileName(fileName);
                securityEvent.setSeverity(severity);
                securityEvent.setStartLine(line);
                securityEvent.setLineContent(``);
                securityEvent.setRuleId(`${ruleId}`);
                securityEvent.setMoreInfoLink(deepLink);
                securityEvent.setViolationInfo(categories);
                securityEvent.setRepoFullName(projectName);

                const secEvent = securityEvent.generateSecurityEvent();
                secEvent.realMatch = "";

                if (!alreadyAdded(secEvent)) {
                  securityEvents.push(secEvent);
                }
              }
            } else {
              try {
                const fileName = results.__FileName;
                const line = results.__Line;
                const deepLink = results.__DeepLink;

                if (ignoreAlert(results)) {
                  return [];
                }

                const isArr = checkIfHaveAdditionalResaults(results);
                if (!isArr) {
                  let lineContent = results.Path.PathNode.Snippet.Line.Code;
                  const securityEvent = new SimpleSecurityEventBuilder();
                  securityEvent.setSecurityProvider("CxSAST");
                  securityEvent.setSecurityAlertType(SecurityAlertType.sast);
                  securityEvent.setStatus(true);
                  securityEvent.setLink(`${fileName}L${line}`);
                  securityEvent.setCreationTime(results.__DetectionDate === "Not available" ? scanStart : results.__DetectionDate);
                  securityEvent.setClosureTime("");
                  securityEvent.setTitle(categories);
                  securityEvent.setFileName(fileName);
                  securityEvent.setSeverity(severity);
                  securityEvent.setStartLine(line);
                  securityEvent.setLineContent(lineContent);
                  securityEvent.setRuleId(`${ruleId}`);
                  securityEvent.setMoreInfoLink(deepLink);
                  securityEvent.setViolationInfo(categories);
                  securityEvent.setRepoFullName(projectName);

                  const secEvent = securityEvent.generateSecurityEvent();
                  secEvent.realMatch = lineContent.substring(0, 300);

                  if (!alreadyAdded(secEvent)) {
                    securityEvents.push(secEvent);
                  }
                } else {
                  for (const node of results.Path.PathNode) {
                    try {
                      const securityEvent = new SimpleSecurityEventBuilder();
                      securityEvent.setSecurityProvider("CxSAST");
                      securityEvent.setSecurityAlertType(SecurityAlertType.sast);
                      securityEvent.setStatus(true);
                      securityEvent.setLink(`${node.FileName}L${node.Snippet.Line.Number}`);
                      securityEvent.setCreationTime(node.__DetectionDate === "Not available" ? scanStart : node.__DetectionDate);
                      securityEvent.setClosureTime("");
                      securityEvent.setTitle(categories);
                      securityEvent.setFileName(node.FileName);
                      securityEvent.setSeverity(severity);
                      securityEvent.setStartLine(node.Snippet.Line.Number);
                      securityEvent.setLineContent(node.Snippet.Line.Code);
                      securityEvent.setRuleId(`${ruleId}`);
                      securityEvent.setMoreInfoLink(deepLink);
                      securityEvent.setViolationInfo(categories);
                      securityEvent.setRepoFullName(projectName);

                      const secEvent = securityEvent.generateSecurityEvent();
                      secEvent.realMatch = node.Snippet.Line.Code.substring(0, 300);

                      if (!alreadyAdded(secEvent)) {
                        securityEvents.push(secEvent);
                      }
                    } catch (err) {
                      logger.error(`Failed to add CheckMarx SAST event, level 5, err: ${err}`);
                    }
                  }
                }
              } catch (err) {
                logger.error(`Failed to add CheckMarx SAST event, level 6, err: ${err}`);
              }
            }
          } catch (err) {
            logger.error(`Failed to add CheckMarx SAST event, level 7, err: ${err}`);
          }
        }
        return securityEvents;
      } catch (error) {
        logger.info(`CheckMarx SAST: Error analyzing scan results: ${error}`);
      }
      return [];
    },
  };
};

class checkmarxSAST extends ExternalSecurityProviderBase {
  host: string;
  private_token: string;
  appMgr: ApplicationManager;
  cxsast: ReturnType<typeof CXSast>;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.host = token.host;
    this.private_token = token.password;
    this.appMgr = new ApplicationManager(this.uuid);

    logger.info(`CheckMarx SAST: ${this.token.type} Ctx`);
    try {
      this.cxsast = CXSast(this.token.userName, this.token.password, this.token.host);
    } catch (err) {
      logger.error(`Failed to initialize CheckMarx SAST: ${this.token.type}, err: ${err}`);
    }
  }

  async initLib() {
    logger.info(`CheckMarx SAST: InitLib called`);
    try {
      // Perform login operation
      await this.cxsast.login();
    } catch (err) {
      logger.error(`Failed to initialize CheckMarx SAST: ${this.token.type}, err: ${err}`);
    }
  }

  async securityEvents() {
    logger.info(`CheckMarx SAST: try collect Security events`);

    try {
      let dumpedResults: any = new Set();

      if (process.env.DEBUG123) {
        const path = process.cwd() + "/tests/src/CXSAST/reports.json";
        const reports = fs.readFileSync(path, "utf8");
        dumpedResults = new Set<string>(JSON.parse(reports));
      } else {
        // Fetching all data
        const allProjects: any = await this.cxsast.getAllProjects();
        const allScanResults: any = await this.cxsast.getScanResultsEx();
        dumpedResults = await this.cxsast.getAllScanReportEx();
      }

      logger.info(`CheckMarx SAST: try analyze`);

      this.copyToolResults({
        toolName: "checkmarxSAST",
        data: JSON.stringify(dumpedResults, null, 2),
      });
      // Creating security events
      const analyzer = CXSastAnalyzer();
      const accumulatedSecurityEvents: SecurityEvent[] = [];
      for (const report of dumpedResults) {
        try {
          const currentReport = JSON.parse(report);
          const securityData = await analyzer.analyzeScanResults(currentReport);

          accumulatedSecurityEvents.push(...securityData);
        } catch (error) {
          logger.info(`CheckMarx SAST: Error parsing report: ${error}`);
        }
      }

      const stats = {};
      accumulatedSecurityEvents.forEach(i => {
        if (stats[i.repoFullName] == undefined) {
          stats[i.repoFullName] = 0;
        } else {
          stats[i.repoFullName] = stats[i.repoFullName] + 1;
        }
      });

      logger.info(
        `CheckMarx SAST: finish collect Security events, count: ${
          accumulatedSecurityEvents.length
        }, ignored: ${ignored}, duplicate: ${duplicate}, stats: ${JSON.stringify(stats)}`,
      );

      return accumulatedSecurityEvents;
    } catch (err) {
      logger.error(`Failed to get scan results for CheckMarx SCA: ${this.token.type}, err: ${err}`);
    }

    return [];
  }
}

export default checkmarxSAST;
