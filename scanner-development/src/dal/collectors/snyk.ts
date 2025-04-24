//https://snyk.docs.apiary.io/#reference/reporting-api/latest-issues/get-list-of-latest-issues
import axios, { AxiosInstance, AxiosRequestConfig } from "axios";
import { ArtifactorySecEventSystem, ArtifactorySecEventType, guessArtifactSystem } from "../../entitis/ArtifactTypes";
import {
  AlertSeverity,
  CweObject,
  Dependency,
  SecurityAlertType,
  SecurityEvent,
  addSeverityChangedReason,
} from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import {
  GetUserOrgsResponse,
  IssueDetails,
  IssueType,
  ProjectDetails,
  ProjectInfo,
  Result,
  SastIssue,
  Severity,
  orgIds,
  orgsAndProjects,
} from "../../entitis/connectorsSpecific/snykTypes";
import { severityReasons } from "../../entitis/service/blameTypes";
import { capitalizeFirstLetter, getLanFromPkgManager, sleep } from "../../helper/commonUtils";
import { isDevelopment, isLocalDevelopment } from "../../helper/envUtils";
import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import { Tool } from "../../policy/rules/code/policyRulesBase";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import FileHelper from "../../helper/IO/fileHlper";
import { ContainerSecurityType } from "../../entitis/artifactoryTypes";
import Constant from "../../entitis/constant";
const logger = loggerImport.getDebugLogger();
const Timeout = require("await-timeout");
const Client = require("snyk-api-client");
const RATE_LIMIT_INTERVAL = 60; // seconds
const MAX_RETRY_ATTEMPTS = 5;
const REST_API_VERSION = "2022-04-06~experimental";

class Snyk extends ExternalSecurityProviderBase {
  host: string;
  private_token: string;
  uniqueRepos = {};
  private axiosInstance: AxiosInstance;

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
  }

  async initLib() {
    try {
      logger.info(`set ${this.token.name}, host: ${this.host}`);
      Client.ClientConfig.set({
        apiToken: this.private_token,
        baseUrl: this.host,
      });
      const axiosConfig: AxiosRequestConfig<any> = {
        baseURL: "https://api.snyk.io",
        timeout: 5000,
      };
      axiosConfig.headers = { Authorization: `token ${this.token.password}` };
      this.axiosInstance = axios.create(axiosConfig);
    } catch (err) {
      logger.error(`Failed to initialize ${this.token.name}, host: ${this.host}, **Upgrade Account**, err: ${err} `);

      StatesHelper.Instance.failedExternalTools.add("snyk");
      StatesHelper.Instance.failedExternalTools.add("snyk-license");
      StatesHelper.Instance.failedExternalTools.add("snyk-container");
      StatesHelper.Instance.failedExternalTools.add("snyk-iac");
      StatesHelper.Instance.failedExternalTools.add("snyk-open-source");
    }
  }

  async securityEvents() {
    let securityEventList: SecurityEvent[] = [];
    let exploitFromCrawler = new Set();

    try {
      logger.info(`try collect ${this.token.name} security events`);

      let sastAlerts = [];
      //Not supported
      // sastAlerts = await this.getSastIssues();
      // logger.info(`found ${sastAlerts.length} SAST alerts`);

      const allAlerts: Result[] = await this.getAlerts();
      let skipAlertCount = 0;

      for (const securityIssue of allAlerts) {
        try {
          //Keep only for debug as it creating a lot of logs
          //logger.info(JSON.stringify(securityIssue.issue.semver));

          if (securityIssue.issue.isIgnored || securityIssue.isFixed) {
            skipAlertCount++;
            continue;
          }

          const repoName = this.extractRepoName(securityIssue);
          const securityAlertType = this.getSecurityAlertType(securityIssue);
          const branchName = this.extractBranchName(securityIssue);
          let securityProvider = "Snyk";
          switch (securityAlertType) {
            case SecurityAlertType.container:
              securityProvider = "Snyk Container";
              break;
            case SecurityAlertType.iac:
              securityProvider = "Snyk IaC";
              break;
            case SecurityAlertType.sca:
              securityProvider = "Snyk Open Source";
              break;
            case SecurityAlertType.license:
              securityProvider = "Snyk License";
              break;
            default:
              break;
          }

          let { recommendation, fixVerStr } = this.extractRecommendation(securityIssue);

          //Ignore sca for sofi as we running the CLI
          if (securityAlertType === SecurityAlertType.sca) {
            if (StatesHelper.Instance.isSofi) {
              continue;
            }
          }

          //License
          if (securityIssue.issue.type === IssueType.License) {
            const securityEvent = new SecurityEvent(
              securityProvider,
              true,
              "",
              securityIssue.introducedDate,
              "",
              "",
              "",
              `${securityIssue.issue.package}@${securityIssue.issue.version}
              is an open source dependency with an unapproved ${securityIssue.issue.title}.
              The package manager is ${securityIssue.project.packageManager}.
              The language of the package is ${securityIssue.issue.language}.`,
              `Library with unapproved ${securityIssue.issue.title} of the package ${securityIssue.issue.package}@${securityIssue.issue.version}`,
              securityIssue.project.targetFile,
              securityIssue.issue.severity,
              securityIssue.issue.url,
              -1,
              AlertSeverity[AlertSeverity.High],
              SecurityAlertType.license,
              recommendation,
              "",
              "",
              0,
              false,
              false,
              "",
              "",
              "",
              "",
              securityIssue.issue.id,
              securityIssue.project.url,
              "",
              repoName,
              "",
              securityIssue.project.targetFile,
              "snyk-license",
            );
            securityEvent.pkgManager = securityIssue.project.packageManager;
            securityEvent.pkgName = securityIssue.issue.package;
            securityEvent.realMatch = `${securityIssue.issue.package}_${securityIssue.issue.version}`;
            securityEvent.linkToExternalProduct = securityIssue?.project?.url || "";
            if (branchName) {
              securityEvent.version = branchName;
            }

            securityEventList.push(securityEvent);
            continue;
          }

          //iac
          if (securityAlertType === SecurityAlertType.iac) {
            const securityEvent = new SecurityEvent(
              securityProvider,
              true,
              "",
              securityIssue.introducedDate,
              "",
              "",
              "",
              securityIssue.issue.title,
              securityIssue.issue.title,
              securityIssue.project.targetFile,
              Severity.Info,
              `Cloud Config Path: ${securityIssue.issue.cloudConfigPath}`,
              -1,
              AlertSeverity[AlertSeverity.High],
              SecurityAlertType.iac,
              "",
              "",
              "",
              0,
              false,
              false,
              "",
              "",
              "",
              "",
              securityIssue.issue.id,
              securityIssue.issue.url,
              "",
              repoName,
              "",
              securityIssue.project.targetFile,
              "snyk-iac",
            );
            securityEvent.lineContent = securityIssue.issue.cloudConfigPath;
            securityEvent.pkgManager = securityIssue.project.packageManager;
            securityEvent.realMatch = `${securityIssue?.issue?.cloudConfigPath}_${securityIssue.issue.id}_${securityIssue.project.id}`;
            securityEvent.linkToExternalProduct = securityIssue?.project?.url || "";
            if (branchName) {
              securityEvent.version = branchName;
            }
            securityEventList.push(securityEvent);
            continue;
          }

          const cve = securityIssue.issue.identifiers?.CVE[0];
          const cwe = securityIssue.issue.identifiers?.CWE[0];
          const ruleId = cve ?? cwe ?? securityIssue.issue.id ?? "no-rule-id";
          const securityEvent = new SecurityEvent(
            securityProvider,
            true,
            "",
            securityIssue.introducedDate,
            "",
            "",
            "",
            securityIssue.issue.title,
            securityIssue.issue.title,
            securityIssue.project.targetFile,
            securityIssue.issue.severity,
            `Rule name: ${securityIssue.issue.id}`,
            -1,
            AlertSeverity[AlertSeverity.High],
            securityAlertType,
            recommendation,
            `${securityIssue.issue.package} ${securityIssue.issue.version}`,
            "",
            0,
            false,
            false,
            "",
            "",
            "",
            "",
            ruleId,
            securityIssue.issue.url,
            "",
            repoName ? repoName : "",
            "",
            securityIssue.project.targetFile,
            securityProvider.toLocaleLowerCase().replaceAll(" ", "-") as Tool,
          );

          securityEvent.realMatch = `${securityIssue.issue.package}_${securityIssue.issue.version}`;
          securityEvent.linkToExternalProduct = securityIssue?.project?.url || "";
          if (branchName) {
            securityEvent.version = branchName;
          }

          securityEvent.pkgManager = this.getPkgManager(securityIssue);
          if (securityEvent.pkgManager) {
            securityEvent.language = getLanFromPkgManager(securityEvent.pkgManager).toLowerCase();
            securityEvent.language = capitalizeFirstLetter(securityEvent.language);
          }

          const cves = securityIssue.issue.identifiers?.CVE ? securityIssue.issue.identifiers?.CVE : [];

          if (securityAlertType === SecurityAlertType.container) {
            securityEvent.securitySubTypeAlertType = SecurityAlertType.sca;
            let dockerName = securityIssue.project.targetFile;
            if (!dockerName) {
              dockerName = securityIssue.project.name;
            }

            if (!dockerName) {
              logger.error(`failed to get dockerName, skipping alert`);
              continue;
            }

            //Default
            securityEvent.containerScanType = ContainerSecurityType.appOnly;

            //Os Vul
            let os;
            let osVersion;
            securityEvent.setIsOsTypeLib(securityIssue.issue.language);
            if (!securityEvent.isOsLib) {
              securityEvent.setIsOsTypeLib(securityIssue?.project?.packageManager);
            }
            if (securityEvent.isOsLib) {
              //If OS
              if (securityIssue?.issue?.packageManager) {
                const items = securityIssue?.issue?.packageManager.split(":");
                if (items.length > 1) {
                  os = items[0];
                  osVersion = items[1];
                }
              }
              if (os) {
                securityEvent.containerScanType = ContainerSecurityType.possibleOsOnly;
                addSeverityChangedReason(severityReasons.osVull, securityEvent, undefined);
              }
            }

            //Base vul
            let baseImage;
            let baseImageOsVersion;
            let isBase;
            if (securityIssue?.project?.packageManager) {
              isBase = Constant.dockerUserInstructions.find(
                i => securityIssue.issue.package.toLowerCase() === "node" || securityIssue.issue.package.toLowerCase() === "python",
              );
            }

            if (dockerName.includes("base-")) {
              baseImage = dockerName;
              if (dockerName.includes(":")) {
                const items = dockerName.split(":");
                baseImage = items[0];
                baseImageOsVersion = items[1];
              }
            }
            if (isBase) {
              baseImage = securityIssue.issue.package;
              baseImageOsVersion = securityIssue.issue.version;
            }
            if (baseImage) {
              securityEvent.containerScanType = ContainerSecurityType.baseOnly;
            }

            //Adjust App code vul
            if (securityEvent.containerScanType === ContainerSecurityType.appOnly) {
              dockerName = securityIssue.project.name;
              if (dockerName.includes(":")) {
                const items = dockerName.split(":");
                dockerName = items[0];
                securityEvent.artifactFilePath = securityIssue.project.targetFile;
              }
            }

            if (securityEvent.containerScanType === ContainerSecurityType.appOnly) {
              addSeverityChangedReason(severityReasons.appContainerVull, securityEvent, undefined);
            }
            if (securityEvent.containerScanType === ContainerSecurityType.baseOnly) {
              addSeverityChangedReason(severityReasons.baseContainerVull, securityEvent, undefined);
            }

            let system = guessArtifactSystem(dockerName);
            if (system === ArtifactorySecEventSystem.Generic) {
              system = guessArtifactSystem(securityIssue?.project?.source);
            }

            securityEvent.artifacts = {
              system: system,
              subType: ArtifactorySecEventType.Docker,
              repoFullName: repoName,
              imageCreatedAt: "",
              dockerVer: "",
              hasPackageManager: false,
              os: os,
              osVersion: osVersion,
              sha: "N/A",
              binariesCount: 0,
              pkgCount: 0,
              dockerFileInRunTime: dockerName,
              registry: system,
              tag: "",
              linkToRegistry: "",
              linkToTask: "",
              baseImage: baseImage,
              baseImageSha: "",
              baseImageRegistry: "",
              baseImageOsVersion: baseImageOsVersion,
              registryName: system,
            };
          }

          securityEvent.cves.push(...cves);
          securityEvent.blame.cve = cve;
          if (typeof securityIssue.issue.identifiers?.CWE === "string") {
            const i = securityIssue.issue.identifiers.CWE;
            securityEvent.blame.cwe.push(i);
            const c = new CweObject();
            c.name = i;
            c.shortName = i;
            securityEvent.blame.cweList.push(c);
          } else if (typeof securityIssue.issue.identifiers?.CWE === "object") {
            securityIssue.issue.identifiers.CWE.forEach(i => {
              securityEvent.blame.cwe.push(i);
              const c = new CweObject();
              c.name = i;
              c.shortName = i;
              securityEvent.blame.cweList.push(c);
            });
            securityEvent.blame.cwe = securityIssue.issue.identifiers.CWE;
          }

          if (securityIssue?.issue?.cvssScore) {
            try {
              securityEvent.blame.cvssScore = parseFloat(securityIssue?.issue?.cvssScore) as number;
            } catch (err) {
              //do nothing
            }
          }

          if (securityIssue.issue?.exploitMaturity) {
            if (securityIssue.issue.exploitMaturity === "no-known-exploit" || securityIssue.issue.exploitMaturity === "Not Defined") {
              securityEvent.blame.hasPublicExploit = false;
              addSeverityChangedReason(severityReasons.noPublicExpolit, securityEvent, undefined);
            } else if (
              securityIssue.issue.exploitMaturity === "proof-of-concept" ||
              securityIssue.issue.exploitMaturity === "Proof of Concept" ||
              securityIssue.issue.exploitMaturity === "mature"
            ) {
              securityEvent.blame.hasPublicExploit = true;
              securityEvent.blame.publicExploitLink = securityIssue.issue.url;
              addSeverityChangedReason(severityReasons.hasPublicExpolit, securityEvent, undefined);
            }
          }
          securityEvent.pkgName = securityIssue.issue.package;

          if (securityEvent.pkgName.includes(":")) {
            securityEvent.groupId = securityEvent.pkgName.split(":")[0];
          }

          securityEvent.fixedVersion = fixVerStr;
          securityEvent.installedVersion = securityIssue.issue.version;

          //Docker file detection
          if (securityIssue?.project?.packageManager === "dockerfile") {
            securityEvent.blame.triggerPackage = new Dependency();
            if (securityIssue?.issue?.packageManager) {
              const items = securityIssue?.issue?.packageManager?.split(":");
              if (items?.length > 1) {
                securityEvent.blame.triggerPackage.name = items[0];
                securityEvent.blame.triggerPackage.version = items[1];
                securityEvent.realMatch = `${securityEvent.fileName}:${securityEvent.pkgName}'@${securityEvent.installedVersion}`;
              } else {
                securityEvent.blame.triggerPackage.name = securityEvent.pkgName;
                securityEvent.blame.triggerPackage.version = securityEvent.installedVersion;
              }
            }
            securityEvent.securitySubTypeAlertType = SecurityAlertType.dockerFileVul;
            addSeverityChangedReason(severityReasons.baseContainerVull, securityEvent, undefined);
          }

          securityEventList.push(securityEvent);
        } catch (error) {
          logger.error(`failed set single ${this.token.name} security alert, ${error}`);
        }
      }

      //Add sast
      sastAlerts.forEach(i => {
        securityEventList.push(i);
      });

      securityEventList.forEach(i => {
        const key = i.repoFullName + "_" + i.severityStr + "_" + i.securityProvider;
        this.uniqueRepos[key] ? (this.uniqueRepos[key] = this.uniqueRepos[key] + 1) : (this.uniqueRepos[key] = 1);
      });

      logger.info(
        `finish collect ${this.token.name} security events count: ${
          allAlerts.length
        }, skipped: ${skipAlertCount}, unique repos: ${JSON.stringify(this.uniqueRepos)}`,
      );

      this.uniqueRepos = {};
    } catch (err) {
      logger.error(`failed to set all ${this.token.name} security events, err: ${err}`);
    }
    StatesHelper.Instance.failedExternalTools.add("snyk");
    StatesHelper.Instance.failedExternalTools.add("snyk-license");
    StatesHelper.Instance.failedExternalTools.add("snyk-container");
    StatesHelper.Instance.failedExternalTools.add("snyk-iac");
    StatesHelper.Instance.failedExternalTools.add("snyk-open-source");

    logger.info(
      `finish collect ${this.token.name} security events, security event list count: ${securityEventList.length}, exploitFromCrawler: ${
        exploitFromCrawler.size
      }, exploitFromCrawlerList: ${Array.from(exploitFromCrawler).join(", ")}`,
    );
    return securityEventList;
  }

  private getPkgManager(securityIssue: any) {
    let r;
    if (securityIssue?.issue?.packageManager) {
      r = securityIssue?.issue?.packageManager;
      if (r === "upstream") {
        r = "";
      }
    }
    return r;
  }

  private extractRecommendation(securityIssue: Result) {
    if (securityIssue.issue.type === IssueType.License) {
      return {
        recommendation: `Based on company policy please look at an alternative library for ${securityIssue.issue.package} utilizing a company approved license.`,
        fixVerStr: "",
      };
    }
    let fixVer = [];
    let fixVerStr = "";

    let recommendation = ``;
    const vulnerable = securityIssue.issue.semver.vulnerable;

    if (vulnerable?.length > 0) {
      for (const vul of vulnerable) {
        const vulArr = vul.split(" ");
        if (vulArr.length === 2 && vulArr[1].charAt(0) === "<") {
          fixVer.push(vulArr[1].replace("<", ""));
        }
        if (vulArr.length === 1 && vulArr[0].charAt(0) === "<") {
          fixVer.push(vulArr[0].replace("<", ""));
        }
      }

      fixVerStr = fixVer.length > 0 ? fixVer.join(", ") : "";
    }

    return { recommendation, fixVerStr };
  }

  private extractRepoName(securityIssue: Result) {
    //Example: cptls/cptls-novations-ui-transition:in-qa:/usr/src/app/package.json
    const cloneRepoIndex = securityIssue.project.name.indexOf(":");
    let repoName = securityIssue.project.name;
    if (cloneRepoIndex != -1) {
      repoName = repoName.substring(0, cloneRepoIndex);
    }
    const branchIndex = repoName.indexOf("(");
    if (branchIndex != -1) {
      repoName = repoName.substring(0, branchIndex);
    }
    //Example: cptls/cptls-novations-ui-transition
    const slashIndex = repoName.lastIndexOf("/");
    if (slashIndex != -1) {
      repoName = repoName.substring(slashIndex + 1, repoName.length);
    }

    //Example: cptls-novations-ui-transition
    repoName = repoName.trim();

    return repoName;
  }

  private extractBranchName(securityIssue: Result) {
    //Example: cptls/cptls-novations-ui-transition(dev):in-qa:/usr/src/app/package.json

    let branchName = "";
    const cloneRepoIndex = securityIssue.project.name.indexOf(":");
    let repoName = securityIssue.project.name;
    if (cloneRepoIndex != -1) {
      repoName = repoName.substring(0, cloneRepoIndex);
    }
    const branchIndex = repoName.indexOf("(");
    if (branchIndex != -1) {
      branchName = repoName.substring(branchIndex + 1, repoName.indexOf(")"));
    }
    return branchName;
  }

  async getAlerts(): Promise<Result[]> {
    const results: Result[] = [];
    try {
      logger.info(`calling Get ${this.token.name} list of orgs IDs`);
      const orgsRes = await Client.Org.listUserOrgs();
      if (orgsRes.httpCode !== 200 || !orgsRes.success) {
        throw orgsRes.error || new Error(`api list user orgs return ${orgsRes.success} with http code ${orgsRes.httpCode}`);
      }
      const orgsResBody: GetUserOrgsResponse = orgsRes.response;
      let { orgs } = orgsResBody;

      //filtering doubleVerify org id's for double verify
      if (this.orgName === "org_lAV5qgryvJ4YPceY") {
        logger.info(`before filter org id for doubleV for ${this.token.name}, orgs: ${orgs.length}`);
        orgs = orgs.filter(
          org =>
            org.id === "81e8b2ad-c65e-4cf0-bcc1-6dccddf87af2" ||
            org.id === "8c823254-bcb5-4904-842a-0ca54e9a7c69" ||
            org.id === "77912ef0-3c91-44da-98b5-ba5d280b233d" ||
            org.id === "ea913f61-de4c-468a-9789-e8c91de5edd7" ||
            org.id === "059bcf6a-9d10-4ef3-84fe-6920123e7af7" ||
            org.id === "754cfd1f-fb0c-49db-a92e-b536fce3be66" ||
            org.id === "3143eb85-1689-414a-802a-651e21a1e0cb" ||
            org.id === "11c8cf10-c820-49b6-b76a-c0ad70bd61fb" ||
            org.id === "44580ce1-5f36-4ce0-8149-fd0508c0837c" ||
            org.id === "334fbcd9-9d4a-46ee-8cd3-1f08150b77cb" ||
            org.id === "40bc114d-adff-4bc6-891e-d255e3270ab2" ||
            org.id === "564e32ab-62df-4ad8-bb82-973376a9cbcc",
        );
        logger.info(`before filter org id for doubleV for ${this.token.name}, orgs: ${orgs.length}`);
      }

      if (orgs && orgs.length === 0) {
        logger.error("api list user orgs returned with empty list");
        return results;
      }

      const orgsIdList = orgs.reduce((pre, curr) => {
        pre.push(curr.id);
        return pre;
      }, [] as Array<string>);

      logger.info(`calling Get ${this.token.name} list of latest issues with ${orgsIdList.length} orgs ${orgsIdList}`);

      let done = false;
      let page = 1;
      while (!done) {
        const res = await this.makeApiRequest(page, orgsIdList);
        const { response } = res;

        if (results.length >= response.total) {
          logger.info(`Get ${this.token.name} list of latest issues total results count: ${results.length}`);
          done = true;
        }

        logger.info(`Get ${this.token.name} list of latest issues (page ${page}) - ${results.length} out of ${response.total}`);

        results.push(...response.results);

        // if (isLocalDevelopment()) {
        //   break;
        // }

        page++;
      }
    } catch (err) {
      let errStr = "";
      try {
        if (err.response != undefined) {
          errStr = JSON.stringify(err.response);
        }
      } catch (err) {}
      logger.error(`failed get ${this.token.name} security alerts from api, error: ${err}, errStr:${errStr}`, err);
    }

    try {
      logger.info(`get ${this.token.name} alerts finished with count: ${results.length}`);

      this.copyToolResults({
        toolName: "snyk",
        data: results as [],
        useStream: true,
      });
    } catch (err) {
      logger.error(`failed in copyToolResults, err ${err}`);
    }

    return results;
  }

  private getSecurityAlertType(securityAlert: Result): SecurityAlertType {
    if (securityAlert.issue.type === IssueType.License) {
      return SecurityAlertType.license;
    } else if (["kubernetes", "ecr"].includes(securityAlert.project.source)) {
      return SecurityAlertType.container;
    } else if (securityAlert.issue.type === IssueType.Vuln) {
      return SecurityAlertType.sca;
    } else if (securityAlert.issue.type === IssueType.Configuration || securityAlert.project.packageManager === "dockerfile") {
      return SecurityAlertType.iac;
    }

    if (
      ["cli", "github", "gitlab", "bitbucket", "github-enterprise", "bitbucket-cloud"].includes(
        securityAlert.project.source.toLowerCase(),
      ) ||
      securityAlert.project.source.toLowerCase().includes("azure") ||
      securityAlert.project.source.toLowerCase().includes("bitbucket")
    ) {
      return SecurityAlertType.sca;
    }

    throw new Error(
      `snyk unknown secuirty issue type - ${securityAlert.issue.type}, issue project source - ${securityAlert.project.source}`,
    );
  }

  async doQuery(page: number, orgsIdList: string[]) {
    return await Client.Report.getListOfLatestIssues({
      queryParams: {
        page: page,
        perPage: 500,
      },
      requestBody: {
        filters: {
          orgs: orgsIdList,
          ignored: false,
          isFixed: false,
        },
      },
    });
  }

  async makeApiRequest(page: number, orgsIdList: string[]) {
    let retryAttempts = 0;
    let waitTime = RATE_LIMIT_INTERVAL * 1000; // convert to milliseconds

    while (retryAttempts < MAX_RETRY_ATTEMPTS) {
      try {
        const res = await Timeout.wrap(this.doQuery(page, orgsIdList), 1000 * 60 * 3, `sync security alerts query timeout, page: ${page}`);
        const { httpCode, success } = res;
        if (httpCode !== 200 || !success) {
          logger.error(`snyk api get list of latest issues return ${success} with http code ${httpCode}`);
          logger.error(`retry attempts: ${retryAttempts + 1}, waiting for ${waitTime / 1000} seconds...`);
          await sleep(waitTime);
          waitTime *= 2; // Double the wait time
          retryAttempts++;
          continue;
        }
        // Successful response
        return res;
      } catch (error) {
        const { response } = error;
        console.error(`API request failed with error: ${response.error ? response.error : JSON.stringify(error)}`);
        // Check for rate limit exceeded error
        const retryText = `retry attempts: ${retryAttempts + 1}, waiting for ${waitTime / 1000} seconds...`;
        if (response.code === 429) {
          logger.error(`snyk api rate limit exceeded, ${retryText}`);
        } else {
          logger.error(`snyk api request failed, ${retryText}`);
        }
        await sleep(waitTime);
        waitTime *= 2; // Double the wait time
        retryAttempts++;
      }
    }

    throw new Error(`snyk api max retry attempts reached (${MAX_RETRY_ATTEMPTS})`);
  }

  async getSastIssues(): Promise<SecurityEvent[]> {
    try {
      if (isLocalDevelopment()) {
        return [];
      }

      let orgId = await this.getOrgID();

      if (this.orgName === "org_lAV5qgryvJ4YPceY") {
        logger.info(`before filter org id for doubleV for ${this.token.name}, orgs: ${orgId.length}`);
        orgId = orgId.filter(
          org =>
            org === "81e8b2ad-c65e-4cf0-bcc1-6dccddf87af2" ||
            org === "8c823254-bcb5-4904-842a-0ca54e9a7c69" ||
            org === "77912ef0-3c91-44da-98b5-ba5d280b233d" ||
            org === "ea913f61-de4c-468a-9789-e8c91de5edd7" ||
            org === "059bcf6a-9d10-4ef3-84fe-6920123e7af7" ||
            org === "754cfd1f-fb0c-49db-a92e-b536fce3be66" ||
            org === "3143eb85-1689-414a-802a-651e21a1e0cb" ||
            org === "11c8cf10-c820-49b6-b76a-c0ad70bd61fb" ||
            org === "44580ce1-5f36-4ce0-8149-fd0508c0837c" ||
            org === "334fbcd9-9d4a-46ee-8cd3-1f08150b77cb" ||
            org === "40bc114d-adff-4bc6-891e-d255e3270ab2" ||
            org === "564e32ab-62df-4ad8-bb82-973376a9cbcc",
        );
        logger.info(`before filter org id for doubleV for ${this.token.name}, orgs: ${orgId.length}`);
      }

      if (orgId.length === 0) {
        logger.error(`Failed to get Snyk orgId`);
        return [];
      }
      const projectIds: Array<orgsAndProjects> = await this.getCodeProject(orgId);
      if (projectIds.length === 0) {
        logger.warn(`Couldnt find any Snyk code project`);
        return [];
      }
      let secEvents: SecurityEvent[] = [];
      for (const orgId of projectIds) {
        for (const projectId of orgId.ProjectIds) {
          try {
            const data = await this.axiosInstance.get(`/orgs/${orgId.OrgId}/issues`, {
              params: { version: REST_API_VERSION, project_id: projectId, limit: 100 },
            });

            const issues: SastIssue = data.data;
            if (issues.data.length === 0) {
              logger.warn(`Couldnt get sast issuse for ${projectId}`);
              continue;
            }
            let projectInfo;
            let retryAttempts = 0;
            while (retryAttempts < MAX_RETRY_ATTEMPTS) {
              projectInfo = await this.getInfoOnProject(orgId.OrgId, projectId);
              if (projectInfo) break;
              retryAttempts++;
            }

            for (const issue in issues.data) {
              retryAttempts = 0;
              let issuesINfo;
              while (retryAttempts < MAX_RETRY_ATTEMPTS) {
                issuesINfo = await this.getInfoOnSastIssues(orgId.OrgId, issues.data[issue].id, projectId);
                if (issuesINfo) break;
                retryAttempts++;
              }
              try {
                const securityEvent = new SecurityEvent(
                  "Snyk Code",
                  true,
                  "",
                  "",
                  "",
                  "",
                  "",
                  issues.data[issue].attributes.title,
                  issuesINfo.data.attributes.title,
                  issuesINfo.data.attributes.primaryFilePath.lastIndexOf("/") !== -1
                    ? issuesINfo.data.attributes.primaryFilePath.substring(
                        issuesINfo.data.attributes.primaryFilePath.lastIndexOf("/") + 1,
                        issuesINfo.data.attributes.primaryFilePath.length,
                      )
                    : issuesINfo.data.attributes.primaryFilePath,
                  issuesINfo.data.attributes.severity,
                  "",
                  issuesINfo.data.attributes.primaryRegion.startLine,
                  AlertSeverity[AlertSeverity.High],
                  issuesINfo.data.attributes.cwe[0] === "CWE-547" ? SecurityAlertType.secrets : SecurityAlertType.sast,
                  "",
                  "",
                  "",
                  issuesINfo.data.attributes.primaryRegion.endLine,
                  false,
                  false,
                  "",
                  "",
                  "",
                  "",
                  issuesINfo.data.attributes.cwe[0],
                  issues.data[issue].links.prev,
                  "",
                  projectInfo.data.attributes.name,
                  "",
                  issuesINfo.data.attributes.primaryFilePath.substring(0, issuesINfo.data.attributes.primaryFilePath.lastIndexOf("/")),
                  "snyk-code",
                );
                securityEvent.realMatch = issuesINfo.data.id;
                securityEvent.filePathForBlameService = `${securityEvent.filePath}/${securityEvent.fileName}`;
                securityEvent.blame.cwe = issuesINfo.data.attributes.cwe;

                secEvents.push(securityEvent);
              } catch (error) {
                logger.error(`Failed to create Snyk sec event ${error}`);
              }
            }
          } catch (error) {
            logger.error(`Failed to get Snyk issues from org ${projectId} ${error}`);
            StatesHelper.Instance.globalApisFails.add("snyk-code");
          }
        }
      }
      return secEvents;
    } catch (err) {
      logger.error(`Failed to get Snyk SAST issues ${err}`);
      return [];
    }
  }

  async getCodeProject(orgsId: string[]): Promise<Array<orgsAndProjects>> {
    try {
      let listOfCodeProjects: Array<orgsAndProjects> = new Array<orgsAndProjects>();
      for (const orgId of orgsId) {
        let projectIdAndIssues = { OrgId: "", ProjectIds: [] };
        projectIdAndIssues.OrgId = orgId;
        const res = await this.axiosInstance.get(`/orgs/${orgId}/projects`, { params: { version: REST_API_VERSION, limit: 100 } });
        const data: ProjectInfo = res.data;
        for (const project of data.data) {
          if (project.attributes.type == "sast") {
            projectIdAndIssues.ProjectIds.push(project.id);
          }
        }
        listOfCodeProjects.push(projectIdAndIssues);
      }
      return listOfCodeProjects;
    } catch (err) {
      logger.error(`Failed to get Snyk codeProject ${err}`);
      return [];
    }
  }

  async getOrgID(): Promise<string[]> {
    try {
      const res = await this.axiosInstance.get(`/orgs`, { params: { version: REST_API_VERSION } });
      const data: orgIds = res.data;
      let orgIds = [];
      for (const org of data.data) {
        orgIds.push(org.id);
      }
      return orgIds;
    } catch (err) {
      logger.error(`Failed to excute Snyk getOrgId ${err}`);
      return [];
    }
  }

  async getInfoOnSastIssues(orgId: string, issuesId: string, projectId: string) {
    try {
      const res = await this.axiosInstance.get(`/orgs/${orgId}/issues/detail/code/${issuesId}`, {
        params: { project_id: projectId, version: REST_API_VERSION },
      });
      const data: IssueDetails = res.data;
      return data;
    } catch (err) {
      logger.error(`Failed to get info on Snyk sast issue ${err} project ID ${projectId} issueID ${issuesId}`);
    }
  }

  async getInfoOnProject(orgID: string, projectID: string) {
    try {
      const res = await this.axiosInstance.get(`/orgs/${orgID}/projects/${projectID}`, {
        params: { version: REST_API_VERSION },
      });
      const data: ProjectDetails = res.data;
      return data;
    } catch (err) {
      logger.error(`${this.token.name}, failed to get project info ${err}`);
    }
  }
}

export default Snyk;
