import loggerImport from "../../logger";
import { Token } from "../../entitis/collectorEntitisTypes";
import { ApplicationManager } from "../../appmgr/AppManager";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import { SimpleSecurityEventBuilder } from "../../helper/tools/securityEventBuilderHelper";
import { CweObject, SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import axios from "axios";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import * as fs from "fs";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import { CXScaJSONReport } from "../../entitis/connectorsSpecific/CXTypes";
import { capitalizeFirstLetter, getLanFromPkgManager } from "../../helper/commonUtils";

const logger = loggerImport.getDebugLogger();
const notFoundUnique = new Set();

export const CXSCAAnalyzer = () => {
  return {
    analyzeScanResults: (repoName: string, scanResult: any): SecurityEvent[] => {
      try {
        const securityEvents: SecurityEvent[] = [];

        StatesHelper.Instance.isCheckMarxEnable = true;

        for (const singleResult of scanResult) {
          if (singleResult.isIgnored) continue;

          let matchToFindInDecencyFile = "";
          let fileName = "";
          if (singleResult.packageId.toLowerCase().includes("npm")) {
            fileName = "package-lock.json";
            matchToFindInDecencyFile = singleResult.packageId.toLowerCase().replace("npm-", "");
          } else if (singleResult.packageId.toLowerCase().includes("pypi")) {
            fileName = "Pipfile.lock";
            matchToFindInDecencyFile = singleResult.packageId.toLowerCase().replace("pypi-", "");
          } else if (singleResult.packageId.toLowerCase().includes("yarn")) {
            fileName = "yarn.lock";
            matchToFindInDecencyFile = singleResult.packageId.toLowerCase().replace("yarn-", "");
          } else if (singleResult.packageId.toLowerCase().includes("nuget")) {
            fileName = "project.lock.json";
            matchToFindInDecencyFile = singleResult.packageId.toLowerCase().replace("nuget-", "");
          } else {
            fileName = "NA";
            notFoundUnique.add(singleResult.packageId);
          }

          const securityEvent = new SimpleSecurityEventBuilder();
          securityEvent.setSecurityProvider("CxSCA");
          securityEvent.setStatus(true);
          securityEvent.setLink("");
          securityEvent.setCreationTime("");
          securityEvent.setClosureTime("");
          securityEvent.setTitle(singleResult.description);
          securityEvent.setFileName(fileName);
          securityEvent.setSeverity(singleResult.severity);
          securityEvent.setStartLine(-1);
          securityEvent.setEndLineNumber(-1);
          securityEvent.setLineContent(matchToFindInDecencyFile);
          securityEvent.setRuleId(`${singleResult.cveName}`);
          securityEvent.setMoreInfoLink(singleResult.references.length > 0 ? singleResult.references[0] : "");
          securityEvent.setSecurityAlertType(SecurityAlertType.sca);
          securityEvent.setViolationInfo(singleResult.description);
          securityEvent.setRepoFullName(repoName);
          const secEvent = securityEvent.generateSecurityEvent();
          secEvent.tools = ["check-marx-sca"];
          secEvent.realMatch = singleResult.packageId;

          let recommendation = `Version installed of ${singleResult.packageId}. Version with fix is ${singleResult.fixResolutionText}. Please upgrade to version ${singleResult.fixResolutionText} or later.`;
          if (
            singleResult.fixResolutionText === undefined ||
            singleResult.fixResolutionText === null ||
            singleResult.fixResolutionText === ""
          ) {
            recommendation = `Version installed of ${singleResult.packageId}. Currently no fix version is available. Please reconsider usage of this library.`;
          }
          secEvent.recommendation = recommendation;
          secEvent.blame.cve = singleResult.cveName;
          if (secEvent.blame.cve) {
            secEvent.cves.push(secEvent.blame.cve);
          }
          secEvent.pkgName = singleResult.packageId;
          secEvent.fixedVersion = singleResult.fixResolutionText;
          secEvent.installedVersion = singleResult.packageId;

          securityEvents.push(secEvent);
        }

        if (notFoundUnique.size > 0) {
          logger.info(`CheckMarx SCA: sec events count: ${securityEvents.length}, not found: ${Array.from(notFoundUnique).join(", ")}`);
        }

        return securityEvents;
      } catch (error) {
        logger.info(`CheckMarx SCA: Error analyzing scan results: ${error}`);
        StatesHelper.Instance.globalApisFails.add("check-marx-sca");
      }
      return [];
    },

    analyzeJsonReport: (repoName: string, scanResult: CXScaJSONReport): SecurityEvent[] => {
      try {
        const securityEvents: SecurityEvent[] = [];

        StatesHelper.Instance.isCheckMarxEnable = true;

        for (const singleResult of scanResult.Vulnerabilities) {
          if (singleResult.IsIgnored) continue;

          let matchToFindInDecencyFile = "";
          let fileName = "";

          const queryPackageId = scanResult.Packages.filter(singlePackage => singlePackage.Id === singleResult.PackageId);

          if (queryPackageId.length > 0 && queryPackageId[0].Locations.length > 0) {
            fileName = queryPackageId[0].Locations[0];
          } else if (singleResult.PackageId.toLowerCase().includes("npm")) {
            fileName = "package-lock.json";
            matchToFindInDecencyFile = singleResult.PackageId.toLowerCase().replace("npm-", "");
          } else if (singleResult.PackageId.toLowerCase().includes("pypi")) {
            fileName = "Pipfile.lock";
            matchToFindInDecencyFile = singleResult.PackageId.toLowerCase().replace("pypi-", "");
          } else if (singleResult.PackageId.toLowerCase().includes("yarn")) {
            fileName = "yarn.lock";
            matchToFindInDecencyFile = singleResult.PackageId.toLowerCase().replace("yarn-", "");
          } else if (singleResult.PackageId.toLowerCase().includes("nuget")) {
            fileName = "project.lock.json";
            matchToFindInDecencyFile = singleResult.PackageId.toLowerCase().replace("nuget-", "");
          } else if (singleResult.PackageId.toLowerCase().includes("Maven")) {
            fileName = "pom.xml";
            matchToFindInDecencyFile = singleResult.PackageId.toLowerCase().replace("Maven-", "");
          } else {
            fileName = "NA";
            notFoundUnique.add(singleResult.PackageId);
          }

          const securityEvent = new SimpleSecurityEventBuilder();
          securityEvent.setSecurityProvider("CxSCA");
          securityEvent.setStatus(true);
          securityEvent.setLink("");
          securityEvent.setCreationTime("");
          securityEvent.setClosureTime("");
          securityEvent.setTitle(singleResult.Description);
          securityEvent.setFileName(fileName);
          securityEvent.setSeverity(singleResult.Severity);
          securityEvent.setStartLine(-1);
          securityEvent.setEndLineNumber(-1);
          securityEvent.setLineContent(matchToFindInDecencyFile);
          securityEvent.setRuleId(`${singleResult.CveName ? singleResult.CveName : "incomplete CVE"}`);
          securityEvent.setMoreInfoLink(singleResult.References.length > 0 ? singleResult.References[0] : "");
          securityEvent.setSecurityAlertType(SecurityAlertType.sca);
          securityEvent.setViolationInfo(singleResult.Description);
          securityEvent.setRepoFullName(repoName);

          const secEvent = securityEvent.generateSecurityEvent();
          secEvent.tools = ["check-marx-sca"];
          secEvent.realMatch = singleResult.PackageId;

          secEvent.recommendation = singleResult.FixResolutionText;
          secEvent.blame.cve = singleResult.CveName;
          if (secEvent.blame.cve) {
            secEvent.cves.push(secEvent.blame.cve);
          }

          let pkgName = singleResult.PackageId;
          let installedVersion = singleResult.PackageId;
          let pkgManager;

          if (singleResult.PackageId.includes("-")) {
            const items = singleResult.PackageId.split("-"); //Example: 'Npm-extend-3.0.1'
            if (items.length > 2) {
              pkgManager = items[0];
              pkgName = items[1];
              installedVersion = items[2];
            }
          }

          secEvent.pkgName = pkgName;
          secEvent.fixedVersion = singleResult.FixResolutionText;
          secEvent.installedVersion = installedVersion;
          secEvent.lineContent = pkgName;

          if (singleResult.Cvss.AttackVector === "NETWORK") {
            secEvent.blame.attackVector = "NETWORK";
          } else {
            secEvent.blame.attackVector = "LOCAL";
          }

          if (pkgManager) {
            secEvent.pkgManager = pkgManager;
            if (secEvent.pkgManager) {
              secEvent.language = getLanFromPkgManager(secEvent.pkgManager).toLowerCase();
              secEvent.language = capitalizeFirstLetter(secEvent.language);
            }
          }

          //CWEex
          if (singleResult.Cwe) {
            const cweObject: CweObject = new CweObject();
            cweObject.name = singleResult.Cwe;
            cweObject.shortName = singleResult.Cwe;
            cweObject.description = singleResult.Description;
            secEvent.blame.cwe.push(singleResult.Cwe);
            secEvent.blame.cweList.push(cweObject);
          }

          //Cvss
          if (singleResult.Cvss) {
            secEvent.blame.cvssScore = singleResult.Cvss.Score;
          }

          //CVE
          secEvent.blame.cve = singleResult.CveName;
          secEvent.blame.cveDescription = singleResult.Description;
          secEvent.ruleId = singleResult.CveName;
          if (secEvent.blame.cve) {
            secEvent.cves.push(secEvent.blame.cve);
          }

          //securityEvent.linkToExternalProduct = `${repo.link}/security/dependabot/${alert.number}`;
          secEvent.realMatch = `${secEvent.pkgName}@${secEvent.installedVersion}`;

          securityEvents.push(secEvent);
        }

        if (notFoundUnique.size > 0) {
          logger.info(`CheckMarx SCA: sec events count: ${securityEvents.length}, not found: ${Array.from(notFoundUnique).join(", ")}`);
        }

        return securityEvents;
      } catch (error) {
        logger.info(`CheckMarx SCA: Error analyzing scan results: ${error}`);
        StatesHelper.Instance.globalApisFails.add("check-marx-sca");
      }
      return [];
    },
  };
};

export type CXScaProjectID = string;
export type CXScaReport = string;

export const CXSca = (username: string, password: string) => {
  let token: string | undefined;
  const projectsMap: Map<string, string> = new Map();
  const scanResults: Map<string, string> = new Map();
  const projectExportedResults: Map<CXScaProjectID, CXScaReport> = new Map();
  const riskReport: Map<string, string> = new Map();

  let isEUToken = false;

  const baseUrls = ["https://platform.checkmarx.net/identity/connect/token", "https://eu.platform.checkmarx.net/identity/connect/token"];

  const apiUrls = ["https://api-sca.checkmarx.net", "https://eu.api-sca.checkmarx.net"];

  return {
    login: async (): Promise<any> => {
      try {
        logger.info(`CheckMarx SCA: logging in...`);

        const params = new URLSearchParams();
        params.append("username", username.split("@")[1]);
        params.append("password", password);
        params.append("acr_values", `Tenant:${username.split("@")[0]}`);
        params.append("scope", "sca_api");
        params.append("client_id", "sca_resource_owner");
        params.append("grant_type", "password");

        for (const baseUrl of baseUrls) {
          logger.info(`CheckMarx SCA: trying to login to ${baseUrl}`);

          try {
            const res: any = await axios.post(baseUrl, params, {
              headers: {
                "Content-Type": "application/x-www-form-urlencoded",
              },
            });
            if (res.status === 200) {
              isEUToken = baseUrl.includes("eu");

              token = res.data.access_token;
              logger.info(`CheckMarx SCA: login successful (${isEUToken ? "EU" : "US"})`);

              return token;
            } else {
              logger.error(`CheckMarx SCA: Failed to login to CheckMarx. Status code: ${res.status}`);
            }
          } catch (error) {
            logger.info(`CheckMarx SCA: error logging in to ${baseUrl}`);
          }
        }
      } catch (error) {
        logger.info(`CheckMarx SCA: Error logging into CheckMarx SCA: ${error}`);
      }

      return token;
    },

    getAllProjects: async (): Promise<any> => {
      logger.info(`CheckMarx SCA: getting all projects...`);

      try {
        const res = await axios.get(`${isEUToken ? apiUrls[1] : apiUrls[0]}/risk-management/projects`, {
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status !== 200) {
          logger.error(`CheckMarx SCA: Failed to login to CheckMarx. Status code: ${res.status}`);
          return null;
        }

        logger.info(`CheckMarx SCA: get all projects successful`);

        const projects: any = res.data;

        for (const project of projects) {
          logger.info(`CheckMarx SCA: project found: ${project.name}`);

          projectsMap.set(`${project.id}`, JSON.stringify(project));
        }
      } catch (error) {
        logger.info(`CheckMarx SAST: Error getting all projects: ${error}`);
        StatesHelper.Instance.globalApisFails.add("check-marx-sca");
      }

      return projectsMap;
    },

    getRiskReport: async (): Promise<any> => {
      logger.info(`CheckMarx SCA: getting the risk report...`);

      try {
        const res = await axios.get(`${isEUToken ? apiUrls[1] : apiUrls[0]}/risk-management/risk-reports`, {
          headers: {
            "Content-Type": "application/json",
            Authorization: `Bearer ${token}`,
          },
        });
        if (res.status !== 200) {
          logger.error(`CheckMarx SCA: (getRiskReport) Failed to login to CheckMarx. Status code: ${res.status}`);
          return null;
        }

        const reports: any = res.data;

        for (const report of reports) {
          const timeHelper: TimeHelper = new TimeHelper("");
          const diffInDays = timeHelper.getTimeIntervalFronNowInDays(report.createdOn);
          if (diffInDays > 180) {
            logger.info(`CheckMarx SCA: project report name: ${report.projectName} are ${diffInDays} days old, ignoring results`);
            continue;
          }

          logger.info(`CheckMarx SCA: project report found: ${report.projectId}`);

          riskReport.set(`${report.riskReportId}`, JSON.stringify(report));
        }
      } catch (error) {
        logger.info(`CheckMarx SCA: Error getting all risk reports: ${error}`);
        StatesHelper.Instance.globalApisFails.add("check-marx-sca");
      }

      return riskReport;
    },

    getAllScanResults: async (): Promise<any> => {
      logger.info(`CheckMarx SCA: getting all scan results...`);

      try {
        for (let [key, value] of riskReport) {
          try {
            const res = await axios.get(`${isEUToken ? apiUrls[1] : apiUrls[0]}/risk-management/risk-reports/${key}/vulnerabilities`, {
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
              },
            });
            if (res.status !== 200) {
              logger.error(`CheckMarx SCA: (getAllScanResults) Failed to login to CheckMarx. Status code: ${res.status}`);
            } else {
              const reportBlob = JSON.parse(value);

              const projectBlob = projectsMap.get(reportBlob.projectId);
              let projectName = "unknown";
              if (projectBlob) {
                const project = JSON.parse(projectBlob);
                projectName = project.name;
              }

              const vulnerabilities: any = res.data;

              scanResults.set(`${projectName}`, JSON.stringify(vulnerabilities));
            }
          } catch (error) {
            logger.info(`CheckMarx SCA: Error parsing vulnerabilities results: ${error}`);
          }
        }
      } catch (error) {
        logger.info(`CheckMarx SCA: Error getting all scan results: ${error}`);
        StatesHelper.Instance.globalApisFails.add("check-marx-sca");
      }

      return scanResults;
    },

    getExportResults: async (): Promise<any> => {
      logger.info(`CheckMarx SCA: getting all scan json reports...`);

      try {
        for (let [key, value] of riskReport) {
          try {
            const res = await axios.get(`${isEUToken ? apiUrls[1] : apiUrls[0]}/risk-management/risk-reports/${key}/export?format=Json`, {
              headers: {
                "Content-Type": "application/json",
                Authorization: `Bearer ${token}`,
              },
            });
            if (res.status !== 200) {
              logger.error(`CheckMarx SCA: (getExportResults) Failed to login to CheckMarx. Status code: ${res.status}`);
            } else {
              const reportBlob = JSON.parse(value);

              const projectBlob = projectsMap.get(reportBlob.projectId);
              let projectName = "unknown";
              if (projectBlob) {
                const project = JSON.parse(projectBlob);
                projectName = project.name;
              }

              const jsonReport: any = res.data;

              projectExportedResults.set(`${projectName}`, JSON.stringify(jsonReport));
            }
          } catch (error) {
            logger.info(`CheckMarx SCA: Error parsing json report results: ${error}`);
          }
        }
      } catch (error) {
        logger.info(`CheckMarx SCA: Error getting all scan json report: ${error}`);
      }

      return projectExportedResults;
    },

    isEUToken: (): boolean => {
      return isEUToken;
    },
  };
};

class checkmarxSCA extends ExternalSecurityProviderBase {
  host: string;
  private_token: string;
  cxsca: any;
  appMgr: ApplicationManager;

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

    logger.info(`CheckMarx SCA: ${this.token.type} Ctx`);

    try {
      this.cxsca = CXSca(this.token.userName, this.token.password);
    } catch (err) {
      logger.error(`Failed to initialize CheckMarx SCA: ${this.token.type}, err: ${err}`);
    }
  }

  async initLib() {
    logger.info(`CheckMarx SCA: ${this.token.type} initLib`);

    try {
      await this.cxsca.login();
      try {
      } catch (err) {
        logger.error(`Failed to initialize CheckMarx SCA: ${this.token.type}, err: ${err}`);
      }

      logger.info(`CheckMarx SCA: ${this.token.type}, successfully logged in to SCA`);
    } catch (err) {
      StatesHelper.Instance.globalApisFails.add("check-marx-sca");
      logger.error(`Failed to initialize CheckMarx SCA: ${this.token.type}, err: ${err}`);
    }
    return [];
  }

  async securityEvents() {
    logger.info(`CheckMarx SCA: ${this.token.type}, securityEvents`);
    try {
      let dumpedResults: any = new Map();
      let dumpedReports: Map<CXScaProjectID, CXScaReport> = new Map();

      const isEUToken = this.cxsca.isEUToken();

      if (process.env.CXCSA_DEBUG) {
        const reports = fs.readFileSync(process.cwd() + "/tests/src/CXSCA/SCAAllscans.json", "utf8");
        dumpedResults = new Map(JSON.parse(reports));
      } else if (!isEUToken) {
        // Fetch all data from CheckMarx SCA servers
        const allProjects: any = await this.cxsca.getAllProjects();
        const riskReport: any = await this.cxsca.getRiskReport();
        dumpedResults = await this.cxsca.getAllScanResults();
      } else {
        const allProjects: any = await this.cxsca.getAllProjects();
        const riskReport: any = await this.cxsca.getRiskReport();
        dumpedReports = await this.cxsca.getExportResults();
      }

      this.copyToolResults({
        toolName: "checkmarxSCA",
        data: JSON.stringify(dumpedResults, null, 2),
      });
      // Parse data from CheckMarx SCA servers
      const accumulatedSecurityEvents: SecurityEvent[] = [];

      if (!isEUToken) {
        for (let [key, value] of dumpedResults) {
          logger.info(`Analyzing ${key}`);
          const currentIssues = JSON.parse(value as string);
          const securityData = CXSCAAnalyzer().analyzeScanResults(key, currentIssues);
          accumulatedSecurityEvents.push(...securityData);
        }
      } else {
        for (let [key, value] of dumpedReports) {
          logger.info(`Analyzing project ${key}`);
          const currentIssues: CXScaJSONReport = JSON.parse(value as string);
          const securityData = CXSCAAnalyzer().analyzeJsonReport(key, currentIssues);
          accumulatedSecurityEvents.push(...securityData);
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
        `CheckMarx SCA: finish collect Security events, count: ${accumulatedSecurityEvents.length}, stats: ${JSON.stringify(stats)}`,
      );

      return accumulatedSecurityEvents;
    } catch (err) {
      logger.error(`Failed to get scan results for CheckMarx SCA: ${this.token.type}, err: ${err}`);
    }

    return [];
  }
}

export default checkmarxSCA;
