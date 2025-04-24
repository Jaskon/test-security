import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import { ApiSecurityItem } from "../../../entitis/apiTypes";
import { AlertSeverity, Repo, repoType, SecurityAlertType, SecurityEvent } from "../../../entitis/codeRepoTypes";
import { Token } from "../../../entitis/collectorEntitisTypes";
import { Constant } from "../../../entitis/constant";
import { ToolConfig } from "../../../entitis/tool/secuirtyToolsConfig";
import EnumHelper from "../../../helper/enumHelper";
import Iqueue from "../../../helper/queue/Iqueue";
import StatesHelper from "../../../helper/statesHelper";
import { getSwaggerFileInfo } from "../../../helper/swagerAPIhelper";
import { ToolsExecutionStats } from "../../../helper/toolExecutionStats";
import loggerImport from "../../../logger";
import OrgPolicyParser from "../../../policy/org/ruleConfigParser";
import CodeSecurityTool from "../codeSecurityTools";

const logger = loggerImport.getDebugLogger();

const fs = require("fs");

class Checkov extends CodeSecurityTool {
  constructor(uuid: string, orgPolicyParser: OrgPolicyParser, toolConfig: ToolConfig, queue: Iqueue, orgName: string, token: Token) {
    super(uuid, orgPolicyParser, toolConfig, queue, orgName, token);
  }

  async applicationSecurity(repo) {
    try {
      let path = `${repo.securityResDir}/${this.toolConfig.fileNameOutput}`;
      if (process.env.USE_LOCAL_CHECKOV_OUTPUT) {
        path = "./src/appmgr/__mocks__/TrivySbom/checkov.json";
      }

      if (!fs.existsSync(path)) {
        logger.warn(`checkov for: ${repo.fullName}, path: ${path} not exist`);
        StatesHelper.Instance.addFailedTool("checkov", repo.id); // roman ?
        return [];
      }

      const apiSecurityItems: ApiSecurityItem[] = await getSwaggerFileInfo(path, repo);

      if (apiSecurityItems.length > 0) {
        logger.info(`finish for repo: ${repo.fullName} get getSwaggerFileInfo, after filter count: ${apiSecurityItems.length}`);
      }

      return apiSecurityItems;
    } catch (err) {
      logger.error(`failed applicationSecurity tool checkov for repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool("checkov", repo.id); // roman ?
    }
    return [];
  }

  async createSecurityEvents(repo: Repo) {
    let apiSecEvents = 0;
    let tooLongSnippetsCounter = 0;
    try {
      let securityEventList: SecurityEvent[] = [];
      const enumHelper: EnumHelper = new EnumHelper();

      let path = `${repo.securityResDir}/${this.toolConfig.fileNameOutput}`;
      if (process.env.USE_LOCAL_CHECKOV_OUTPUT) {
        path = "./src/appmgr/__mocks__/TrivySbom/checkov.json";
      }

      if (!fs.existsSync(path)) {
        logger.warn(`checkov for: ${repo.fullName}, path: ${path} not exist`);
        StatesHelper.Instance.addFailedTool("checkov", repo.id); // roman ?
        return [];
      }

      this.copyToolResults({ repoName: repo.name, dir: path });

      let rawdata = fs.readFileSync(path, "utf-8");
      if (!rawdata) {
        logger.warn(`checkov empty content for: ${repo.fullName}, path: ${path} are empty`);
        StatesHelper.Instance.addFailedTool("checkov", repo.id); // roman ?
        return [];
      }

      let totalVulsFromTool = 0;

      let checkovInfoJs = JSON.parse(rawdata);
      if (!Array.isArray(checkovInfoJs)) {
        if (checkovInfoJs?.results?.failed_checks) {
          checkovInfoJs = [checkovInfoJs];
        } else {
          logger.warn(`checkov not array content for: ${repo.fullName}, path: ${path}`);
          StatesHelper.Instance.addFailedTool("checkov", repo.id); // roman ?
          return [];
        }
      }

      for (const checkovInfo of checkovInfoJs) {
        if (checkovInfo.results == undefined) continue;
        if (checkovInfo.results.failed_checks == undefined) continue;

        logger.info(`${this.toolConfig.name} Info before filter ${checkovInfo?.results?.failed_checks?.length} repo ${repo.fullName}`);
        this.addGlobalStats(this.toolConfig.defaultType, this.toolConfig.name, checkovInfo?.results?.failed_checks?.length, repo);

        for (const checkovAlert of checkovInfo.results.failed_checks) {
          try {
            const fileName = checkovAlert.file_path.substring(1);
            const startLine = checkovAlert.file_line_range[0];
            const endLine = checkovAlert.file_line_range?.length > 1 ? checkovAlert.file_line_range[1] : -1;
            totalVulsFromTool++;

            // see https://gitlab.com/oxsecurity/app/tool-runner/-/blob/bf0df9de1b11dd71484655c983c6b0c6ea0aaf83/src/runner/augment-tool-results.ts

            let snippet = checkovAlert?.oxwrapper?.snippet ?? "";
            if (snippet.length > 400) {
              logger.error(`checkov alert snippet is too long, more than 400 characters, reduced length to from ${snippet.length} to 400`);
              snippet = snippet.slice(0, 399);
            }
            let match = snippet;

            // added in case _OX not provides data or local debug
            if (!match || !snippet) {
              if (checkovAlert?.code_block && checkovAlert.code_block.length > 0 && checkovAlert.code_block[0].length > 0) {
                match = checkovAlert.code_block[0][1];
                checkovAlert.code_block.forEach(item => {
                  snippet += item[1];
                });
              }
            }

            if (!match) {
              continue;
            }
            if (!snippet) {
              logger.warn(`checkovAlert: no snippet found, using match as snippet add checkov for repo: ${repo.name}`);
              snippet = match;
            }

            if (checkovAlert.check_id === "CKV_AWS_7" && snippet.includes("deletion_window_in_days")) {
              logger.info(`avoiding CKV_AWS_7 FP ${snippet}`);
              continue;
            }

            let isSecurityApi = false;
            if (checkovAlert.check_id.includes("CKV_OPENAPI")) {
              isSecurityApi = true;
            }

            let link =
              repo.type === repoType.awsCodeCommit
                ? repo.fileLink + fileName + repo.linkFilePreffix + startLine + "-" + startLine
                : repo.fileLink + fileName + repo.linkFilePreffix + startLine;
            if (startLine < 0) {
              link = repo.fileLink + fileName;
            }

            let e = enumHelper.stringToSecurityAlertEnum(`${checkovAlert.check_id}`);

            let title = "";
            let violationInfo = "";
            let severityInfo = AlertSeverity.Medium;
            let recommendation = "";
            const oxwrapper = checkovAlert?.oxwrapper;
            if (e == SecurityAlertType.secrets) {
              continue;
            } else {
              e = SecurityAlertType.iac;
              violationInfo = checkovAlert.check_name;
              title = checkovAlert.check_class == null ? checkovAlert.check_name : checkovAlert.check_class;
              severityInfo = AlertSeverity.Medium;
              if (oxwrapper?.recommendation) {
                recommendation = checkovAlert.oxwrapper.recommendation;
              } else {
                recommendation = `Please consider fix the code at file ${fileName} line ${startLine}`;
              }

              if (
                violationInfo.toLowerCase().endsWith("exists") ||
                violationInfo.toLowerCase().includes("ensure") ||
                title.toLowerCase().includes("high entropy string")
              ) {
                severityInfo = AlertSeverity.Low;
              } else {
                severityInfo = AlertSeverity.Medium;
              }
            }

            let severityStr = this.toolSeverity.getSeverityToolBaseOnRuleId(checkovAlert.check_id, "");
            if (severityStr === Constant.ignoreRuleBasedOnSeverity) {
              continue;
            }
            let finalSeverity = severityStr === "" ? AlertSeverity[severityInfo] : severityStr;
            if (oxwrapper?.title) {
              violationInfo = oxwrapper.title;
            }

            let securityEvent = new SecurityEvent(
              isSecurityApi ? "OX API Security" : SourceToolType["Infrastructure as Code Scan"],
              true,
              link,
              new Date().toLocaleString(),
              "",
              "",
              "",
              violationInfo,
              "",
              fileName,
              finalSeverity,
              `Rule name: ${checkovAlert.check_id}, Link for more info: ${checkovAlert.guideline}, Code line: ${snippet}`,
              startLine,
              AlertSeverity[AlertSeverity.High],
              e,
              recommendation,
              match,
              snippet,
              endLine,
              true,
              false,
              "",
              "",
              "",
              "",
              checkovAlert.check_id,
              checkovAlert.guideline,
              repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
              repo.fullName,
              repo.insideFolder,
              repo.monoRepoChild ? repo.name.substring(1) + "/" + fileName : fileName,
              "checkov",
            );
            if (oxwrapper?.title) {
              securityEvent.title = checkovAlert.oxwrapper.title;
            }
            if (oxwrapper?.description) {
              securityEvent.description = checkovAlert.oxwrapper.description;
            }
            if (oxwrapper?.eduVideoLink) {
              securityEvent.eduVideoLink = checkovAlert.oxwrapper.eduVideoLink;
            }
            if (oxwrapper?.cwe?.length) {
              securityEvent.cweList = oxwrapper.cwe;
            }

            if (isSecurityApi) {
              securityEvent.securitySubTypeAlertType = SecurityAlertType.securityApi;
              apiSecEvents++;
            }

            securityEvent.version = repo.defaultBranch;
            securityEvent.realMatch = securityEvent.lineContent.substring(0, 300);
            securityEvent.lineContent = securityEvent.lineContent.trim().replace(/\s+/g, " ");
            securityEventList.push(securityEvent);
          } catch (err) {
            // StatesHelper.Instance.addFailedTool("checkov", repo.id) // roman
            logger.error(`checkovAlert: ${JSON.stringify(checkovAlert)}, failed add checkov for repo: ${repo.name}, err: ${err}`);
          }
        }
      }

      ToolsExecutionStats.addExecutionStateOfAlertsNumber(
        this.requestId,
        repo.fullName,
        repo.id,
        "repo",
        this.toolConfig.name,
        path,
        totalVulsFromTool,
        securityEventList.length,
      );

      logger.info(
        `${this.toolConfig.name} Info after filter ${securityEventList.length} repo: ${repo.name}, apiSecEvents: ${apiSecEvents}`,
      );

      if (securityEventList.length > 15000) {
        logger.info(`${this.toolConfig.name} losing alerts due to cap, original count: ${securityEventList.length}`);
        securityEventList = securityEventList.slice(0, 15000);
      }

      this.printStatsForSecEvents(securityEventList, repo);

      return securityEventList;
    } catch (err) {
      logger.error(`failed to parse results for tool checkov for repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool("semgrep", repo.id);
      return [];
    }
  }
}

export default Checkov;
