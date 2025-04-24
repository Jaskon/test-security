import xml2js from "xml2js";
import zlib from "zlib";
import { Token } from "../../entitis/collectorEntitisTypes";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import loggerImport from "../../logger";
import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";
import { AlertSeverity, SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import PromisePool from "@supercharge/promise-pool";
import { isDevelopment, isLocalDevelopment } from "../../helper/envUtils";
import StatesHelper from "../../helper/statesHelper";

const logger = loggerImport.getDebugLogger();
const concurrent_pool_call = 5;

enum CoverityIssueStatus {
  New = "New",
  Triaged = "Triaged",
  Dismissed = "Dismissed",
  Fixed = "Fixed",
  AbsentDismissed = "Absent_Dismissed",
}

enum CoverityIssueClassification {
  Unclassified = "Unclassified",
  Pending = "Pending",
  FalsePositive = "False Positive",
  Intentional = "Intentional",
  Bug = "Bug",
  Various = "Various",
}

enum CoverityIssueAction {
  Undecided = "Undecided",
  FixRequired = "Fix Required",
  FixSubmitted = "Fix Submitted",
  ModelingRequired = "Modeling Required",
  Ignore = "Ignore",
  Various = "Various",
}

class Coverity extends ExternalSecurityProviderBase {
  private axiosInstance: AxiosInstance = null;
  private cacheFileContent = {};
  private cacheIssueDescriptions = {};
  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);
  }

  async initLib() {
    try {
      logger.info(`try init lib for: ${this.token.name}, url: ${this.token.host}`);
      this.axiosInstance = axios.create({
        baseURL: this.token.host,
        auth: {
          username: this.token.userName,
          password: this.token.password,
        },
      });

      logger.info(`finish init lib for: ${this.token.name}, url: ${this.token.host}`);
    } catch (err) {
      logger.info(`failed init lib for: ${this.token.name}, url: ${this.token.host}`);
    }
  }

  async getAllUsersView() {
    const allUsersView = [];
    try {
      const getAllUsersViewUrl = "api/v2/views/user";
      const params = {
        offset: 0,
        rowCount: 200,
      };
      let page = 1;
      do {
        const { data }: any = await this.axiosInstance.get(getAllUsersViewUrl, { params });
        if (!data?.views?.length) {
          break;
        }
        allUsersView.push(...data.views);
        if (data.views.length < params.rowCount) {
          break;
        }
        params.offset = page * params.rowCount;
        ++page;
      } while (true);
    } catch (err) {
      logger.error(`${this.token.name} Failed to getAllUsersView, err: ${err}`);
    }
    return allUsersView;
  }

  async getAllProjects() {
    const allProjects = [];
    try {
      logger.info(`${this.token.name} - Getting All Projects ** Begin **`);

      const getAllProjectsUrl = "api/v2/projects";
      const params: any = {
        offset: 0,
        rowCount: 200,
        includeStreams: true,
      };
      if (StatesHelper.Instance.orgName === "org_3d57dOeJjhEkPYly" || StatesHelper.Instance.orgName === "org_4K6xdKcYduw2BVQy") {
        params.namePattern = "nick1987*";
      }
      let page = 1;
      do {
        const { data }: any = await this.axiosInstance.get(getAllProjectsUrl, { params });
        if (!data?.projects?.length) {
          break;
        }
        allProjects.push(...data.projects);
        //org_5oofWgKaxOMv27OD test org for coverity
        if (StatesHelper.Instance.orgName === "org_5oofWgKaxOMv27OD") {
          break;
        }
        if (data.projects.length < params.rowCount) {
          break;
        }
        params.offset = page * params.rowCount;
        ++page;
      } while (true);
      logger.info(`${this.token.name} - Getting All Projects , Found total projects count : ${allProjects.length}`);
    } catch (err) {
      logger.error(`${this.token.name} Failed to getAllProjects, err: ${err}`);
    }

    logger.info(`${this.token.name} - Getting All Projects ** Completed **`);

    return allProjects;
  }

  async getIssueColumns() {
    let columns: Array<any> = [];
    try {
      logger.info(`${this.token.name} - Getting Issue Columns ** Begin **`);

      const issueColumnsUrl = "api/v2/issues/columns";

      const { data }: any = await this.axiosInstance.get(issueColumnsUrl);
      columns = data.map(item => item.columnKey);

      const default_columns = ["action", "classification", "status"];
      for (const column of default_columns) {
        if (columns.includes(column) === false) {
          columns.push(column);
        }
      }
    } catch (err) {
      logger.error(`${this.token.name} Failed to getIssueColumns, err: ${err}`);
    }

    logger.info(`${this.token.name} - Getting Issue Columns ** Completed ** Total columns count:- ${columns.length}`);
    return columns;
  }

  async getAllIssues(project, columns, allIssues) {
    try {
      logger.info(
        `${this.token.name} - Getting Issue For ProjectName ${project.name}, projectDetails: ${JSON.stringify(project)} ** Begin **`,
      ); // remove project from logs

      const projectIssues = [];
      const params = {
        offset: 0,
        rowCount: 200,
      };

      // api/v2/views/viewContents/${viewId}?projectId=${project.projectKey}`;
      const issueSearchUrl = `api/v2/issues/search?includeColumnLabels=false&offset={offset}&rowCount=${params.rowCount}`;
      const issueRequestData = {
        columns: columns,
        filters: [
          {
            columnKey: "project",
            matchMode: "oneOrMoreMatch",
            matchers: [
              {
                class: "Project",
                name: project.name,
                type: "nameMatcher",
              },
            ],
          },
          {
            columnKey: "status",
            matchMode: "oneOrMoreMatch",
            matchers: [
              {
                key: CoverityIssueStatus.New,
                type: "keyMatcher",
              },
              {
                key: CoverityIssueStatus.Triaged,
                type: "keyMatcher",
              },
            ],
          },
        ],
        snapshotScope: {
          show: {
            scope: "last()",
            includeOutdatedSnapshots: false,
          },
        },
      };

      let page = 1;
      do {
        const { data }: any = await this.axiosInstance.post(issueSearchUrl.replace(`{offset}`, `${params.offset}`), issueRequestData);
        if (!data?.rows?.length) {
          break;
        }
        projectIssues.push(...data.rows);
        if (data.rows.length < params.rowCount) {
          break;
        }
        params.offset = page * params.rowCount;
        ++page;
      } while (true);

      logger.info(`${this.token.name} Getting Issue For Project ${project.name}, Found total Issue count: ${projectIssues.length}`);

      // Return if no issue found
      if (!projectIssues.length) {
        return;
      }
      const formattedIssues = await this.formatData(project, projectIssues);
      allIssues.push(...formattedIssues);

      logger.info(
        `${this.token.name} - Getting Issue For Project ${project.name}, formattedIssues: ${formattedIssues.length} ** Completed **`,
      );
    } catch (err) {
      logger.error(`${this.token.name} Failed to getAllIssues for, project: ${project.name}, err: ${err}`);
    }
  }

  async getAllSecurityIssue() {
    const allIssues = [];
    try {
      if (
        StatesHelper.Instance.orgName.toLowerCase() === "org_SWpml3xso7Sm86ZL".toLowerCase() ||
        StatesHelper.Instance.orgName.toLowerCase() === "org_qM5zv16cCZb2qNsc".toLowerCase()
      ) {
        try {
          const allViews = await this.getAllUsersView();
          logger.info(`${this.token.name} Found total user views ${JSON.stringify(allViews)}`);
        } catch (err) {}
      }

      const columns = await this.getIssueColumns();
      const projects = await this.getAllProjects();

      logger.info(`${this.token.name} Found total projects count: ${projects.length}`);
      await PromisePool.for(projects)
        .withConcurrency(concurrent_pool_call)
        .process(async project => {
          await this.getAllIssues(project, columns, allIssues);
        });
    } catch (err) {
      logger.error(`${this.token.name} Failed to getAllSecurityIssue, err: ${err}`);
    }
    return allIssues;
  }

  async formatData(project, allIssues) {
    const securityEventList = [];
    try {
      logger.info(`${this.token.name}, Before format issues count: ${allIssues.length} for project: ${project.name}`);
      const formattedCoverityIssues = this.formatCoverityIssueObj(allIssues);
      logger.info(`${this.token.name}, After format issues count: ${formattedCoverityIssues.length} for project: ${project.name}`);
      const commonFilePath = this.getCommonFilePath(formattedCoverityIssues);
      const projectStreamName = this.getProjectStreamName(project);
      await this.getMoreAlertInfo(formattedCoverityIssues, projectStreamName);
      for (const issueObj of formattedCoverityIssues) {
        try {
          if (issueObj.status == CoverityIssueStatus.Triaged) {
            // Ignore the issue with classification : FalsePositive , Intentional
            if ([CoverityIssueClassification.FalsePositive, CoverityIssueClassification.Intentional].includes(issueObj.classification)) {
              logger.info(
                `${this.token.name} - Prepare Issue - Ignore the issue with classification ${issueObj.classification} , Issue CID : ${issueObj.cid}`,
              );
              continue;
            }

            // Ignore the issue with action : FixSubmitted , Ignore
            if ([CoverityIssueAction.FixSubmitted, CoverityIssueAction.Ignore].includes(issueObj.action)) {
              logger.info(
                `${this.token.name} - Prepare Issue - Ignore the issue with action ${issueObj.action} , Issue CID : ${issueObj.cid}`,
              );
              continue;
            }
          }

          let repoFullName = project.name;
          const splittedValues = project.name.split("-");
          if (splittedValues.length > 1) {
            repoFullName = splittedValues.slice(1).join("-");
          }

          const fullPath = issueObj?.displayFile?.replace(commonFilePath, "");
          const fileName = issueObj?.displayFile?.replace(commonFilePath, "");
          const startLineNumber = !isNaN(issueObj.lineNumber) ? Number(issueObj.lineNumber) : 0;
          const ruleId = issueObj.checker;
          const endLineNumber = -1;
          const lineContent = "";
          let recommendation = "";
          if (issueObj?.fixTarget !== "Untargeted") {
            recommendation = issueObj.fixTarget;
          }

          const securityEvent = new SecurityEvent(
            "Coverity",
            true,
            "",
            issueObj.firstDetected,
            "",
            "",
            "",
            issueObj.displayType,
            issueObj.displayType,
            fileName,
            "high",
            issueObj.firstSnapshotDescription || "",
            startLineNumber,
            AlertSeverity[AlertSeverity.High],
            SecurityAlertType.sast,
            recommendation,
            lineContent,
            "",
            endLineNumber,
            false,
            false,
            "",
            "",
            "",
            "",
            ruleId,
            "",
            "",
            repoFullName,
            "",
            fullPath,
            "coverity",
          );

          securityEvent.realMatch = issueObj.cid;
          securityEvent.blame.language = issueObj.fileLanguage;

          const codeSnippet = this.getLineContent(issueObj.displayFile, startLineNumber);
          securityEvent.lineContent = codeSnippet.lineContent;
          securityEvent.snippetContent = codeSnippet.snippetContent;

          if (this.cacheIssueDescriptions[issueObj.cid]) {
            securityEvent.title = this.cacheIssueDescriptions[issueObj.cid].longDefectDescription || "";
            securityEvent.recommendation = this.cacheIssueDescriptions[issueObj.cid].remediationDescription || "";
            const defectInstanceId = this.cacheIssueDescriptions[issueObj.cid].defectInstanceId || "";
            securityEvent.linkToExternalProduct = `${this.token.host}/reports.htm#v59456/p${project.projectKey}/defectInstanceId=${defectInstanceId}&mergedDefectId=${issueObj.cid}`;
          }

          securityEventList.push(securityEvent);
        } catch (err) {
          logger.error(
            `failed to format single issue data for ${this.token.name}, with application: ${project?.name}, issueObj: ${JSON.stringify(
              issueObj,
            )}, err: ${err}`,
          );
        }
      }
    } catch (err) {
      logger.error(`failed to format all data for ${this.token.name}, with application: ${project?.name}, err: ${err}`);
    }
    return securityEventList;
  }

  getProjectStreamName(project) {
    try {
      const streams = project.streams;
      const allStreamNames = new Set();
      streams.forEach(stream => allStreamNames.add(stream.name));
      logger.info(
        `${this.token.name} Unique streams count: ${allStreamNames.size}, allStreamNames: ${Array.from(allStreamNames).join(",")}`,
      );
      const validStream = streams?.filter(stream => !stream.outdated)[0];
      if (!validStream) {
        logger.info(`${this.token.name} No stream found for project: ${project.name}`);
      }
      return validStream.name;
    } catch (err) {
      logger.error(`${this.token.name} Failed to getProjectStreamName for project: ${project.name}, err: ${err}`);
    }
  }

  getLineContent(filePath, lineNumber) {
    const content = { lineContent: "", snippetContent: "" };
    const file = this.cacheFileContent[filePath];
    if (!file) {
      logger.info(`${this.token.name} File not found in cached path: ${filePath}`);
      return content;
    }
    // file array index start from the 0 instead 1
    lineNumber = lineNumber > 0 ? lineNumber - 1 : lineNumber;
    try {
      const start = lineNumber < 2 ? 0 : lineNumber - 2;
      const end = lineNumber <= file.length - 3 ? lineNumber + 2 : file.length - 1;
      content.lineContent = file[lineNumber];

      const snippetContentLines = file.slice(start, end);
      content.snippetContent = snippetContentLines.join("\r\n");
    } catch (err) {
      logger.error(`${this.token.name} Failed to getLineContent, err: ${err}`);
    }
    return content;
  }

  /**
   * Here we are getting all other required issue such as fileContent, description and remediation details and cached locally
   */
  async getMoreAlertInfo(issues, projectStreamName) {
    try {
      const allIssues = [...issues];
      while (allIssues.length) {
        // We can get only 100 defects at time
        const cids = allIssues.splice(0, 100).map(issue => issue.cid);
        logger.info(`Starting getDefectInfo api calls for projectStreamName: ${projectStreamName}, cid count :- ${cids.length}`);
        const defectsData = await this.getDefectInfo(cids, projectStreamName);
        logger.info(`Data fetched from getDefectInfo for projectStreamName: ${projectStreamName}, cid count :- ${cids.length}`);
        if (!defectsData.length) {
          return;
        }

        for (const { mainEvent, remediationEvent, cid, defectInstanceId } of defectsData) {
          let longDefectDescription = "";
          let remediationDescription = "";
          if (mainEvent?.eventDescription?.length) {
            longDefectDescription = mainEvent?.eventDescription[0];
          }
          if (remediationEvent?.eventDescription?.length) {
            remediationDescription = remediationEvent?.eventDescription[0];
          }
          // cache descriptions
          this.cacheIssueDescriptions[cid] = {
            longDefectDescription,
            remediationDescription,
            defectInstanceId,
          };

          // Take file mdf and path
          let fileContentMD5 = "";
          let filePath = "";
          if (mainEvent?.fileId?.length) {
            fileContentMD5 = mainEvent?.fileId[0]?.contentsMD5?.[0];
            filePath = mainEvent?.fileId[0]?.filePathname?.[0];
          }
          if (!fileContentMD5 || !filePath) {
            logger.info(
              `${this.token.name} no fileContentMD5 and filePath found for cid:- ${cid}, mainEvent: ${JSON.stringify(
                mainEvent,
              )}, remediationEvent: ${JSON.stringify(remediationEvent)}`,
            );
            return;
          }
          // Call api if file is not cached
          if (!this.cacheFileContent[filePath]) {
            await this.getFileContent(fileContentMD5, filePath, projectStreamName);
          }
        }
      }
    } catch (err) {
      logger.error(`${this.token.name} Failed to getMoreAlertInfo, err: ${err}`);
    }
  }

  /**
   * This method is to get more info related to issue. we can pass max 100 cid in below soap api.
   * return only required data like main event, remediation event from received data
   */
  async getDefectInfo(cids: string[], projectStreamName: string) {
    const defectData = [];
    try {
      const cidTemplate = cids.reduce((str, cid) => {
        str += `<mergedDefectIdDataObjs>
                  <cid>${cid}</cid>
                </mergedDefectIdDataObjs>`;
        return str;
      }, "");
      const soapRequestObj = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:v9="http://ws.coverity.com/v9">
      <soapenv:Header>
          <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
              <wsse:UsernameToken wsu:Id="XWSSGID-1349973313023-787497544" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                  <wsse:Username>${this.token.userName}</wsse:Username>
                  <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${this.token.password}</wsse:Password>
              </wsse:UsernameToken>
          </wsse:Security>
      </soapenv:Header>
      <soapenv:Body>
          <v9:getStreamDefects>
              <!--Zero or more repetitions:-->
                ${cidTemplate}
              <!--Optional:-->
              <filterSpec>
                  <includeDefectInstances>true</includeDefectInstances>
                  <includeHistory>false</includeHistory>
                  <includeTotalDefectInstanceCount>0</includeTotalDefectInstanceCount>
                  <maxDefectInstances>0</maxDefectInstances>
                  <streamIdList>
                    <name>${projectStreamName}</name>
                  </streamIdList>
              </filterSpec>
          </v9:getStreamDefects>
      </soapenv:Body>
  </soapenv:Envelope>`;

      const config: AxiosRequestConfig = {
        method: "post",
        url: `${this.token.host}/ws/v9/defectservice`,
        headers: {
          SOAPAction: '"#POST"',
          "Content-Type": "text/xml",
        },
        data: soapRequestObj,
      };
      const { data } = await axios(config);

      // Parse XML response to JSON
      const jsonResponse = await xml2js.parseStringPromise(data);
      if (jsonResponse?.["S:Envelope"]?.["S:Body"]?.[0]?.["ns2:getStreamDefectsResponse"]?.[0]?.return?.length) {
        logger.info(
          `${this.token.name}, Received getDefectInfo data for projectStreamName: ${projectStreamName}, cids count: ${cids.length}, response count: ${jsonResponse?.["S:Envelope"]?.["S:Body"]?.[0]?.["ns2:getStreamDefectsResponse"]?.[0]?.return?.length}`,
        );
        for (const defect of jsonResponse?.["S:Envelope"]?.["S:Body"]?.[0]?.["ns2:getStreamDefectsResponse"]?.[0]?.return) {
          if (defect?.defectInstances?.length && defect?.defectInstances[0]?.events?.length) {
            const defectInstanceData = defect?.defectInstances[0];
            const events = defectInstanceData.events;
            const mainEvent = events.filter(event => event?.main?.[0] == "true")[0];
            const remediationEvent = events.filter(event => event?.eventTag?.[0] == "remediation")[0];
            defectData.push({
              cid: defect.cid[0],
              mainEvent,
              remediationEvent,
              defectInstanceId: defectInstanceData?.id?.[0]?.id?.[0] || "",
            });
          }
        }
      } else {
        logger.info(`${this.token.name}, Empty response received for getDefectInfo from coverity projectStreamName: ${projectStreamName}`);
      }
    } catch (err) {
      logger.error(
        `${this.token.name} Failed to getDefectInfo for projectStreamName: ${projectStreamName}, cids:- ${JSON.stringify(
          cids,
        )}, err: ${err}`,
      );
    }
    return defectData;
  }

  /**
   * Here we are getting file content from api and store locally to avoid api calls for same file
   * File content we received from coverity is in compressed form
   */
  async getFileContent(fileContentMD5: string, filePath: string, projectStreamName: string) {
    try {
      const soapRequestObj = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:v9="http://ws.coverity.com/v9">
      <soapenv:Header>
          <wsse:Security xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
              <wsse:UsernameToken wsu:Id="XWSSGID-1349973313023-787497544" xmlns:wsu="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd">
                  <wsse:Username>${this.token.userName}</wsse:Username>
                  <wsse:Password Type="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#PasswordText">${this.token.password}</wsse:Password>
              </wsse:UsernameToken>
          </wsse:Security>
      </soapenv:Header>
      <soapenv:Body>
          <v9:getFileContents>
              <!--Optional:-->
              <streamId>
                <name>${projectStreamName}</name>
              </streamId>
              <fileId>
                  <contentsMD5>${fileContentMD5}</contentsMD5>
                  <filePathname>${filePath}</filePathname>
              </fileId>
          </v9:getFileContents>
      </soapenv:Body>
  </soapenv:Envelope>`;

      const config: AxiosRequestConfig = {
        method: "post",
        url: `${this.token.host}/ws/v9/defectservice`,
        headers: {
          SOAPAction: '"#POST"',
          "Content-Type": "text/xml",
        },
        data: soapRequestObj,
      };
      const { data } = await axios(config);

      // Parse XML response to JSON
      const jsonResponse = await xml2js.parseStringPromise(data);
      if (jsonResponse?.["S:Envelope"]?.["S:Body"]?.[0]?.["ns2:getFileContentsResponse"]?.[0]?.return?.[0]) {
        const compressedFileContent = jsonResponse?.["S:Envelope"]?.["S:Body"]?.[0]?.["ns2:getFileContentsResponse"]?.[0]?.return?.[0];
        if (!compressedFileContent?.contents?.length) {
          logger.info(`${this.token.name} No file content found for projectStreamName: ${projectStreamName}, filePath: ${filePath}`);
          return "";
        }

        const decompressedFileContentData = await this.decompressedFileContent(filePath, compressedFileContent?.contents[0], jsonResponse);
        this.cacheFileContent[filePath] = decompressedFileContentData;
      }
    } catch (err) {
      logger.error(
        `${this.token.name} Failed to getFileContent for projectStreamName: ${projectStreamName}, filePath: ${filePath}, err: ${err}`,
      );
    }
  }

  /**
   * Decompressing file content to plain text
   */
  async decompressedFileContent(filePath, compressedContent, jsonResponse) {
    // remove jsonResponse
    let decompressedString = "";
    try {
      // Convert the compressed content string to a buffer
      const compressedBuffer = Buffer.from(compressedContent, "base64"); // Assuming the content is base64 encoded

      // Decompress the content
      const decompressedBuffer = zlib.unzipSync(compressedBuffer);
      decompressedString = decompressedBuffer.toString();
    } catch (err) {
      logger.error(
        `${
          this.token.name
        } Failed to decompressedFileContent: ${compressedContent} for filePath: ${filePath}, jsonResponse: ${JSON.stringify(
          jsonResponse,
        )} err: ${err}`,
      ); // remove jsonResponse from logs
    }
    return decompressedString && decompressedString.split("\n");
  }

  /**
   * Here we are formatting response received from coverity to an array of array to array objects
   * @param allIssues issued from coverity response
   * @returns formatted objects
   */
  formatCoverityIssueObj(allIssues) {
    const formattedIssueObjects = [];
    try {
      for (const issue of allIssues) {
        const issueObj = issue.reduce((acc, cur) => {
          acc[cur.key] = cur.value;
          return acc;
        }, {});

        if (issueObj.status !== "New") {
          continue;
        }
        formattedIssueObjects.push(issueObj);
      }
    } catch (err) {
      logger.error(`failed to format coverity object for ${this.token.name}, err: ${err}`);
    }
    return formattedIssueObjects;
  }

  /**
   * Here we are finding longest matching substring in files
   * @param allIssues all issues
   * @returns longest match strings in files
   */
  getCommonFilePath(allIssues) {
    let longestMatch = "";
    try {
      const files = allIssues.map(issue => issue.displayFile);
      const firstString = files[0];
      const strLength = firstString.length;

      for (let i = 0; i < strLength; i++) {
        for (let j = i + 1; j <= strLength; j++) {
          const subString = firstString.slice(i, j);

          let isMatch = true;
          for (const str of files) {
            if (!str.includes(subString)) {
              isMatch = false;
              break;
            }
          }

          if (isMatch && subString.length > longestMatch.length) {
            longestMatch = subString;
          }
        }
      }
    } catch (error) {
      logger.error(`${this.token.name}, failed to getCommonFilePath, err: ${error}`);
    }
    return longestMatch;
  }

  async securityEvents() {
    let securityEventList: SecurityEvent[] = [];
    try {
      securityEventList = await this.getAllSecurityIssue();
      logger.info(`${this.token.name} Found overall total issues count: ${securityEventList.length}`);
    } catch (err) {
      logger.error(`Failed to collect security events for ${this.token.name}, host: ${this.token.host}, err: ${err}`);
    }
    return securityEventList;
  }
}

export default Coverity;
