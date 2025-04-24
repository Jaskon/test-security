import {
  addSeverityChangedReason,
  AlertSeverity,
  CweObject,
  Dependency,
  Repo,
  SecurityAlertType,
  SecurityEvent,
} from "../../../entitis/codeRepoTypes";
import { Token } from "../../../entitis/collectorEntitisTypes";
import Constant from "../../../entitis/constant";
import { severityReasons } from "../../../entitis/service/blameTypes";
import { ToolConfig } from "../../../entitis/tool/secuirtyToolsConfig";
import { capitalizeFirstLetter, getLanFromPkgManager, handleFileNameReplace } from "../../../helper/commonUtils";
import Iqueue from "../../../helper/queue/Iqueue";
import { cleanVer } from "../../../helper/sbom/sbomHelper";
import StatesHelper from "../../../helper/statesHelper";
import { ToolsExecutionStats } from "../../../helper/toolExecutionStats";
import SecurityToolsHelper from "../../../helper/tools/securityToolsHelper";
import loggerImport from "../../../logger";
import OrgPolicyParser from "../../../policy/org/ruleConfigParser";
import CodeSecurityTool from "../codeSecurityTools";

const logger = loggerImport.getDebugLogger();

const fs = require("fs");

class SnykCli extends CodeSecurityTool {
  constructor(uuid: string, orgPolicyParser: OrgPolicyParser, toolConfig: ToolConfig, queue: Iqueue, orgName: string, token: Token) {
    super(uuid, orgPolicyParser, toolConfig, queue, orgName, token);
  }

  async createSecurityEvents(repo: Repo) {
    const notDuplicate = new Set();
    const duplicate = {};
    const all = {};
    let rawdata;

    try {
      let securityEventList: SecurityEvent[] = [];

      const pathsMap = new Map();
      pathsMap.set("sca", `${repo.securityResDir}/snykSCATest.json`);
      //pathsMap.set("sca", `C:\\Users\\Roman\\Downloads\\snyk (2).json`);

      // pathsMap.set("sast", `${repo.securityResDir}/snykSASTTest.json`);
      // pathsMap.set("iac", `${repo.securityResDir}/snykIACTest.json`);
      // pathsMap.set("container", `${repo.securityResDir}/snykContainerTest.json`);
      let fileExist = false;

      for (const [scanType, scanTypeResultsJson] of pathsMap.entries()) {
        if (!fs.existsSync(scanTypeResultsJson)) {
          logger.warn(`${this.toolConfig.name} for ${scanType} : ${repo.fullName}, path: ${scanTypeResultsJson} not exist`);
          StatesHelper.Instance.addFailedTool("Snyk CLI", repo.id); // roman ?
          continue;
        }

        rawdata = fs.readFileSync(scanTypeResultsJson, "utf-8");
        if (!rawdata) {
          StatesHelper.Instance.addFailedTool("Snyk CLI", repo.id); // roman ?
          logger.warn(`${this.toolConfig.name} empty content for: ${repo.fullName}, path: ${scanTypeResultsJson} are empty`);
          continue;
        }

        fileExist = true;

        //CLI versions have diff foramt
        let snykCliInfoJs = JSON.parse(rawdata);
        if (!Array.isArray(snykCliInfoJs)) {
          if (snykCliInfoJs) {
            snykCliInfoJs = [snykCliInfoJs];
          }
        }

        for (const snykCliInfo of snykCliInfoJs) {
          try {
            if (!snykCliInfo.vulnerabilities) {
              logger.info(`${this.toolConfig.name} empty vulnerabilities for: ${repo.fullName}`);
              continue;
            }

            ToolsExecutionStats.addExecutionStateOfAlertsNumber(
              this.requestId,
              repo.fullName,
              repo.id,
              "repo",
              this.toolConfig.name,
              scanTypeResultsJson,
              snykCliInfo.vulnerabilities.length,
              0,
            );

            logger.info(
              `${this.toolConfig.name} vulnerabilities before filter: ${snykCliInfo.vulnerabilities.length}, for: ${repo.fullName}`,
            );

            for (const snykCliAlert of snykCliInfo.vulnerabilities) {
              if (snykCliAlert.type === "license") {
                continue;
              }

              if (snykCliAlert.from.length == 0) {
                //error
              }

              const replaceInfo = repo.getRepoPathForToolCommand();
              const fileName = handleFileNameReplace(snykCliInfo.displayTargetFile, replaceInfo);

              try {
                const link = "";

                let violationInfo = snykCliAlert.description;
                let severityInfo = AlertSeverity.Medium;
                let recommendation = "";

                let severityStr = snykCliAlert.severity;
                let finalSeverity = severityStr === "" ? AlertSeverity[severityInfo] : severityStr;

                let securityEvent = new SecurityEvent(
                  Constant.SnykCli,
                  true,
                  link,
                  snykCliAlert.creationTime,
                  "",
                  "",
                  "",
                  violationInfo,
                  "",
                  fileName,
                  finalSeverity,
                  `Rule name: ${snykCliAlert.id}, Link for more info: ${snykCliAlert.guideline}`,
                  -1,
                  AlertSeverity[AlertSeverity.High],
                  SecurityAlertType.sca,
                  recommendation,
                  "",
                  "",
                  -1,
                  false,
                  false,
                  "",
                  "",
                  "",
                  "",
                  snykCliAlert.id,
                  link,
                  "",
                  "",
                  "",
                  "",
                  "Snyk CLI",
                );

                const name = snykCliAlert.packageName;
                const ver = snykCliAlert.version;

                if (ver) {
                  securityEvent.installedVersion = cleanVer(ver, "");
                } else {
                  //logger.error(`no ver for: ${fromSinglePkg}, for: ${repo.fullName}`);
                }

                if (!name) {
                  //logger.error(`no name for: ${fromSinglePkg}, for: ${repo.fullName}`);
                }

                securityEvent.version = repo.defaultBranch;
                securityEvent.pkgManager = snykCliAlert.packageManager;
                if (securityEvent.pkgManager) {
                  securityEvent.language = getLanFromPkgManager(securityEvent.pkgManager).toLowerCase();
                  securityEvent.language = capitalizeFirstLetter(securityEvent.language);
                }

                if (snykCliAlert.fixedIn) {
                  if (snykCliAlert.fixedIn.length > 0) {
                    securityEvent.fixedVersion = snykCliAlert.fixedIn.join(", ");
                  }
                }

                let cves = [];
                let cwes = [];
                if (snykCliAlert?.identifiers) {
                  for (const [k, v] of Object.entries(snykCliAlert?.identifiers)) {
                    if (k === "CVE") {
                      cves = v as any;
                    }
                    if (k === "CWE") {
                      cwes = v as any;
                    }
                  }
                }
                for (const cwe of cwes) {
                  const cweObject: CweObject = new CweObject();
                  cweObject.name = cwe;
                  cweObject.shortName = cwe;
                  cweObject.description = "N/A";
                  securityEvent.blame.cwe.push(cwe);
                  securityEvent.blame.cweList.push(cweObject);
                }

                if (snykCliAlert?.cvssScore) {
                  securityEvent.blame.cvssScore = snykCliAlert.cvssScore;
                }
                securityEvent.blame.cveDescription = snykCliAlert.description;

                securityEvent.pkgName = name;

                if (securityEvent.pkgName.includes(":")) {
                  securityEvent.groupId = securityEvent.pkgName.split(":")[0];
                }

                securityEvent.blame.cve = cves.length > 0 ? cves[0] : "";
                securityEvent.cves = cves.length > 0 ? cves : [];

                if (snykCliAlert.exploit) {
                  if (snykCliAlert.exploit === "no-known-exploit" || snykCliAlert.exploit === "Not Defined") {
                    securityEvent.blame.hasPublicExploit = false;
                    addSeverityChangedReason(severityReasons.noPublicExpolit, securityEvent, undefined);
                  } else if (snykCliAlert.exploit === "proof-of-concept" || snykCliAlert.exploit === "Proof of Concept") {
                    securityEvent.blame.hasPublicExploit = true;

                    let url = "N/A";
                    try {
                      const urlInfo = snykCliAlert.references.find(i => i.title === "PoC");
                      if (urlInfo) {
                        url = urlInfo.url;
                      }
                    } catch (err) {
                      //do nothing
                    }
                    securityEvent.blame.publicExploitLink = url;
                    addSeverityChangedReason(severityReasons.hasPublicExpolit, securityEvent, undefined);
                  }
                }

                securityEvent.realMatch = `${securityEvent.pkgName}@${securityEvent.installedVersion}`;
                securityEvent.lineContent = `${securityEvent.pkgName}@${securityEvent.installedVersion}`;
                securityEvent.blame.publishedExploitDate = snykCliAlert.publicationTime;

                if (snykCliAlert.packageManager === "maven" || snykCliAlert.language === "java") {
                  const from = snykCliAlert.from;
                  if (from) {
                    if (from.length > 1) {
                      const pkgVer = from[1];
                      const index = pkgVer.lastIndexOf("@");
                      if (index != -1) {
                        const nameTp = pkgVer.substring(0, index);
                        const verTp = pkgVer.substring(index + 1, pkgVer.length);
                        if (nameTp !== snykCliAlert.packageName && verTp !== snykCliAlert.version) {
                          securityEvent.blame.triggerPackage = new Dependency();
                          securityEvent.blame.triggerPackage.name = nameTp;
                          securityEvent.blame.triggerPackage.version = verTp;
                        }
                      }
                    }
                  }
                }

                const u = SecurityToolsHelper.getUniqueForSca(securityEvent);
                if (all[u]) {
                  const item = all[u];
                  if (item.raw.from.length < snykCliAlert.from.length) {
                    item.raw.from = snykCliAlert.from;
                    item.secEvent = securityEvent;
                  }
                } else {
                  all[u] = {
                    raw: snykCliAlert,
                    secEvent: securityEvent,
                  };
                }

                if (notDuplicate.has(u)) {
                  if (securityEvent.blame.cve) {
                    if (duplicate[u]) {
                      duplicate[u].push(snykCliAlert);
                    } else {
                      duplicate[u] = [snykCliAlert];
                    }
                  }
                } else {
                  securityEventList.push(securityEvent);
                  notDuplicate.add(u);
                }
              } catch (err) {
                logger.error(`${this.toolConfig.name}, failed add single snyk cli for repo: ${repo.name}, err: ${err}`, err);
                // StatesHelper.Instance.addFailedTool("snyk-cli", repo.id);
              }
            }
          } catch (err) {
            logger.error(`${this.toolConfig.name}, failed add snyk cli for repo: ${repo.name}, err: ${err}`, err);
            StatesHelper.Instance.addFailedTool("Snyk CLI", repo.id);
          }
        }
      }

      securityEventList = Object.values(all).map(i => (i as any).secEvent);
      if (fileExist) {
        ToolsExecutionStats.addExecutionStateOfAlertsNumber(
          this.requestId,
          repo.fullName,
          repo.id,
          "repo",
          this.toolConfig.name,
          "",
          0,
          securityEventList.length,
        );

        logger.info(`${this.toolConfig.name} Info after filter ${securityEventList.length}, repo: ${repo.name}`);
      }

      if (securityEventList.length > 15000) {
        logger.info(`${this.toolConfig.name} losing alerts due to cap, original count: ${securityEventList.length}, repo: ${repo.name}`);
        securityEventList = securityEventList.slice(0, 15000);
      }

      this.printStatsForSecEvents(securityEventList, repo);

      return securityEventList;
    } catch (err) {
      logger.error(
        `${this.toolConfig.name} failed to parse results failed add snyk cli for repofor tool snyk cli for repo: ${repo.name}, err: ${err}, rawdata: ${rawdata}`,
        err,
      );
      return [];
    }
  }
}

export default SnykCli;
