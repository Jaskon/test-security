import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import { readFile, stat } from "node:fs/promises";
import { extname } from "node:path";
import { addSeverityChangedReason, AlertSeverity, Repo, repoType, SecurityAlertType, SecurityEvent } from "../../../entitis/codeRepoTypes";
import { Token } from "../../../entitis/collectorEntitisTypes";
import Constant from "../../../entitis/constant";
import { ExtraInfo } from "../../../entitis/issuesTypes";
import { ChangeCategory, severityReasons } from "../../../entitis/service/blameTypes";
import { ToolConfig } from "../../../entitis/tool/secuirtyToolsConfig";
import { ToolNameForUI } from "../../../entitis/tool/toolsTypes";
import { enableByPolicy, handleFileNameReplace } from "../../../helper/commonUtils";
import EnumHelper from "../../../helper/enumHelper";
import Iqueue from "../../../helper/queue/Iqueue";
import StatesHelper from "../../../helper/statesHelper";
import { ToolsExecutionStats } from "../../../helper/toolExecutionStats";
import { SemgrepResults, semgrepSchema, ToolValidator } from "../../../helper/toolValidator/toolValidator";
import loggerImport from "../../../logger";
import OrgPolicyParser from "../../../policy/org/ruleConfigParser";
import { Tool } from "../../../policy/rules/code/policyRulesBase";
import CodeSecurityTool from "../codeSecurityTools";

const logger = loggerImport.getDebugLogger();

class Semgrep extends CodeSecurityTool {
  enumHelper: EnumHelper = new EnumHelper();

  constructor(uuid: string, orgPolicyParser: OrgPolicyParser, toolConfig: ToolConfig, queue: Iqueue, orgName: string, token: Token) {
    super(uuid, orgPolicyParser, toolConfig, queue, orgName, token);
  }

  async createSecurityEvents(repo: Repo) {
    try {
      let securityEventList: SecurityEvent[] = [];

      const semgrepOutputPath = `${repo.securityResDir}/${this.toolConfig.fileNameOutput}`;

      if (!stat(semgrepOutputPath).catch(() => false)) {
        logger.warn(`[${this.toolConfig.name}] path: ${semgrepOutputPath} not exist`);
        StatesHelper.Instance.addFailedTool("semgrep", repo.id);
        return [];
      }

      let totalVulsFromTool = 0;
      let skipped = 0;

      this.copyToolResults({ repoName: repo.name, dir: semgrepOutputPath });
      const rawdata = JSON.parse(await readFile(semgrepOutputPath, "utf-8"));

      let semgrepInfoJs: SemgrepResults;
      try {
        semgrepInfoJs = ToolValidator.validateToolResult("semgrep", rawdata, semgrepSchema);
      } catch (err) {
        StatesHelper.Instance.addFailedTool("semgrep", repo.id);
        return [];
      }

      logger.info(`[${this.toolConfig.name}] Info before filter ${semgrepInfoJs.results.length} repo ${repo.fullName}`);

      if (semgrepInfoJs.results.length > 15000) {
        logger.info(`[${this.toolConfig.name}] losing alerts due to cap, original count: ${semgrepInfoJs.results.length}`);
        semgrepInfoJs.results = semgrepInfoJs.results.slice(0, 15000);
      }

      this.addGlobalStats(this.toolConfig.defaultType, this.toolConfig.name, semgrepInfoJs.results.length, repo);

      let ruleName = "";
      for (const result of semgrepInfoJs.results) {
        try {
          const oxwrapper = result.extra?.oxwrapper;
          let skipTags: boolean = false;
          let lineContent = result.extra.lines;
          if (lineContent.length > 200) {
            skipTags = true;
            lineContent = lineContent.substring(0, 200);
          }
          totalVulsFromTool++;
          const replaceInfo = repo.getRepoPathForToolCommand();
          const fileName = handleFileNameReplace(result.path, replaceInfo);
          let type = SecurityAlertType.sast;
          let toolName = SourceToolType["Code Security"];

          let link =
            repo.type === repoType.awsCodeCommit
              ? repo.fileLink + fileName + repo.linkFilePreffix + result.start.line + "-" + result.start.line
              : repo.fileLink + fileName + repo.linkFilePreffix + result.start.line;
          if (result.start.line < 0) {
            link = repo.fileLink + fileName;
          }

          let language = "text";
          let isSilent = false;
          let extention = extname(fileName).toLowerCase();
          if (Constant.otherLanguages.hasOwnProperty(extention)) {
            language = Constant.otherLanguages[extention];
          }
          if (result.check_id.startsWith("var.ox.")) {
            (toolName = SourceToolType["Secret/PII Scan"]), (ruleName = result.check_id.replace("var.ox.", ""));
            if (ruleName.startsWith("silent")) {
              isSilent = true;
              if (StatesHelper.Instance.isPipelineScan) {
                logger.info(`[${this.toolConfig.name}] skipping silent signature of ${result.check_id}`); // should not get here at all anymore
                continue;
              }
            }
            if (result.check_id.startsWith("var.ox.cicd.")) {
              if (ruleName === "cicd.github-actions.pin-actions-to-commit-sha") {
                // GlobalCodeRepoData.Instance.handleActions(result, repo);
              }
            } else if (result.check_id.startsWith("var.ox.iac.")) {
              type = SecurityAlertType.iac;
              toolName = SourceToolType["Infrastructure as Code Scan"];
            } else if (result.check_id.startsWith("var.ox.sast.")) {
              type = SecurityAlertType.sast;
              toolName = SourceToolType["Code Security"];
            } else if (result.check_id.startsWith("var.ox.sensitive-logs.")) {
              type = SecurityAlertType.secrets; // to be changed to a new SecurityAlertType later
              toolName = SourceToolType["Secret/PII Scan"];
            } else if (result.check_id.startsWith("var.ox.tagging.")) {
              if (Constant.programmingLangExtRegex.exec(result.path) && !skipTags) {
                if (!result.check_id.includes("silent")) {
                  let extraInfo: ExtraInfo[] = [];
                  extraInfo.push({
                    key: "Snippet",
                    link: link,
                    snippet: {
                      fileName: fileName,
                      text: lineContent,
                      language: language,
                      snippetLineNumber: result.start.line,
                    },
                  });

                  try {
                    if (oxwrapper?.severityFactors) {
                      oxwrapper.severityFactors.forEach((sfKey: string) => {
                        if (severityReasons.hasOwnProperty(sfKey)) {
                          const sf = severityReasons[sfKey];
                          repo.addRepoSeverityChangedReason(sf, extraInfo);
                          if (sf.changeCategory === ChangeCategory.Framework && sf?.framework) {
                            repo.addFramework(sf, sf.framework);
                          }
                        } else {
                          logger.error(`[${this.toolConfig.name}] severity factor not found of ruleId: ${result.check_id} ${sfKey}`);
                        }
                      });
                    }
                  } catch (err) {}
                }
              }
              continue;
            }
          } else {
            ruleName = result.check_id.replace("var.semgrep-rules.", "");
          }

          if (type === SecurityAlertType.sast) {
            const isSemGrepEnabled = enableByPolicy(ToolNameForUI.semgrep);
            if (!isSemGrepEnabled) {
              continue;
            }
          }

          let sourceToolName: Tool = "semgrep";
          if (this.toolConfig.name.toLowerCase() === "semgrep pro") {
            sourceToolName = "semgrep CLI";
          }

          const securityEvent = new SecurityEvent(
            toolName,
            true,
            link,
            new Date().toLocaleString(),
            "",
            "",
            "",
            result.extra.message,
            oxwrapper?.title || result.extra?.message || "",
            fileName,
            this.toolSeverity.getSeverityToolBaseOnRuleId(ruleName, lineContent) || result.extra.severity,
            `Rule name: ${ruleName}`,
            result.start.line,
            AlertSeverity[AlertSeverity.High],
            type,
            oxwrapper?.recommendation || "",
            lineContent,
            lineContent,
            result.end.line,
            true,
            false,
            "",
            "",
            "",
            "",
            ruleName,
            "",
            repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
            repo.fullName,
            repo.insideFolder,
            repo.monoRepoChild ? repo.name.substring(1) + "/" + fileName : fileName,
            sourceToolName,
            result.extra.metavars,
          );

          securityEvent.version = repo.defaultBranch;
          securityEvent.description = oxwrapper?.description || "";
          securityEvent.privateVisability = repo.privateVisability;
          securityEvent.isSilent = isSilent;

          try {
            if (oxwrapper?.severityFactors) {
              oxwrapper.severityFactors.forEach((sfKey: string) => {
                if (severityReasons.hasOwnProperty(sfKey)) {
                  addSeverityChangedReason(severityReasons[sfKey], securityEvent, repo, []);
                } else {
                  logger.error(`[${this.toolConfig.name}] severity factor not found of ruleId: ${result.check_id} ${sfKey}`);
                }
              });
            }
          } catch (err) {}

          if (oxwrapper?.cwe?.length) {
            securityEvent.cweList = oxwrapper.cwe;
          }

          let realMatch = result.extra.lines;
          if (realMatch.length > 100) {
            realMatch = realMatch.substring(0, 100);
          }

          securityEvent.realMatch = realMatch;
          securityEvent.lineContent = securityEvent.lineContent.trim().replace(/\s+/g, " ");

          if (!securityEvent.realMatch) {
            logger.error(`[${this.toolConfig.name}] failed add for repo: ${repo.name}, no match`);
            continue;
          }

          securityEventList.push(securityEvent);
        } catch (err) {
          logger.error(`[${this.toolConfig.name}] failed add for repo: ${repo.name}`, err);
          StatesHelper.Instance.addFailedTool("semgrep", repo.id);
        }
      }

      ToolsExecutionStats.addExecutionStateOfAlertsNumber(
        this.requestId,
        repo.fullName,
        repo.id,
        "repo",
        this.toolConfig.name,
        semgrepOutputPath,
        totalVulsFromTool,
        securityEventList.length,
      );

      logger.info(`[${this.toolConfig.name}] Info after filter ${securityEventList.length} repo ${repo.name}, skipped: ${skipped}`);

      this.printStatsForSecEvents(securityEventList, repo);

      return securityEventList;
    } catch (err) {
      logger.error(`[${this.toolConfig.name}] failed to parse results for repo: ${repo.name}`, err);
      StatesHelper.Instance.addFailedTool("semgrep", repo.id);
      return [];
    }
  }
}

export default Semgrep;
