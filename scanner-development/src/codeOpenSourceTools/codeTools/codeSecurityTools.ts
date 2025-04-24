import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import PromisePool from "@supercharge/promise-pool/dist";
import { v4 } from "uuid";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { addSeverityChangedReason, Repo, repoType, SecurityAlertType, SecurityEvent, VCSType } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { Constant } from "../../entitis/constant";
import { ExtraInfo } from "../../entitis/issuesTypes";
import { ChangeReason, LATERAL_MOVEMENT_GROUPS, secretTagMapping, severityReasons } from "../../entitis/service/blameTypes";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";
import { ZipType } from "../../helper/compression/unzipHelper";
import EnumHelper from "../../helper/enumHelper";
import { isUploadToS3 } from "../../helper/envUtils";
import { getSharedFolder } from "../../helper/generalUtils";
import localToolRunner from "../../helper/localToolRunner";
import Iqueue from "../../helper/queue/Iqueue";
import StatesHelper from "../../helper/statesHelper";
import { ToolsExecutionStats } from "../../helper/toolExecutionStats";
import loggerImport from "../../logger";
import secretMapping from "../../policy/org/config/secretMapping.json";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import { Tool } from "../../policy/rules/code/policyRulesBase";
import SecurityToolBase from "../base/securityToolsBase";
import CodeToolConfiguration from "../codeTools/codeToolConfiguration";

const crypto = require("crypto");
const logger = loggerImport.getDebugLogger();
const path = require("path");
const fs = require("fs");
const Git_Leaks_Tool_Name = "Gitleaks";

class CodeSecurityTool extends SecurityToolBase {
  constructor(
    uuid: string,
    orgPolicyParser: OrgPolicyParser,
    toolConfig: ToolConfig,
    securityToolsQueue: Iqueue,
    orgName: string,
    token: Token,
  ) {
    const codeToolConfiguration: CodeToolConfiguration = new CodeToolConfiguration(uuid, toolConfig, token);

    super(uuid, orgPolicyParser, toolConfig, securityToolsQueue, orgName, codeToolConfiguration);
  }

  async runViaShell(repoObj: any) {
    const repo: Repo = repoObj as Repo;

    try {
      let command = this.toolConfiguration.getCommand(repo);
      if (command.includes("oxwrapper.py --base64")) {
        const cmd = command.split("--cmd")[1].trim();
        const base64Cmd = Buffer.from(cmd).toString("base64");
        command = command.replace(cmd, base64Cmd);
      }

      const res = await this.toolConfiguration.runShell(repo.name, command);
      if (res == true) return true;
    } catch (err) {
      logger.error(`[${this.toolConfig.name}] failed to run shell on: ${repo.name}`, err);
    }
    return null;
  }

  async runViaSQS(repoObj: any, secTool: any, ignoredTools: any, failedTools: any) {
    const repo: Repo = repoObj as Repo;
    let sizeInMG = 0;

    try {
      //Ignore tools due to some logic
      const ignoredTool = repo.ignoredTools.find(i => this.toolConfig.name.toLowerCase() === i.toLowerCase());
      if (ignoredTool) {
        logger.info(`[${this.toolConfig.name}] skipping ${repo.name} due to internal logic`);
        ignoredTools.push(secTool);
        return null;
      }

      //Check if a heavy task
      let heavyTask = false;

      if (
        this.toolConfig.name.toLowerCase() === "gitleaks" ||
        this.toolConfig.name.toLowerCase() === "semgrep" ||
        this.toolConfig.name.toLowerCase() === "devskim"
      ) {
        sizeInMG = (repo.sizeInBytes as number) / 1000000;
        if (sizeInMG > 100 || repo.filesCount > 1000) {
          {
            if (this.toolConfig.name.toLowerCase() === "gitleaks" && repo.repositoryHistorySize !== -1) {
              if (repo.largeGitHistory) {
                heavyTask = true;
                StatesHelper.Instance.uniqueReposForHeavyTasks.add(repo.fullName);
                logger.info(
                  `[${this.toolConfig.name}] using heavy task Q for repo: ${repo.fullName}, history size: ${repo.repositoryHistorySize}, files count: ${repo.filesCount}`,
                );
              }
            } else {
              heavyTask = true;
              StatesHelper.Instance.uniqueReposForHeavyTasks.add(repo.fullName);
              logger.info(
                `[${this.toolConfig.name}] using heavy task Q for repo: ${repo.fullName}, size in mg: ${sizeInMG}, repositoryHistorySize: ${repo.repositoryHistorySize}, files count: ${repo.filesCount}`,
              );
            }
          }
        }
      }

      let command = this.toolConfiguration.getCommand(repo);
      if (this.toolConfig.name.toLowerCase() === "semgrep") {
        if (heavyTask) {
          command = command.replace("#CPU_COMMAND#", StatesHelper.Instance.SEMGREPHEAVY_QUEUE_KEY_HEAVY_TASK_CPU);
        } else {
          command = command.replace("#CPU_COMMAND#", StatesHelper.Instance.SEMGREP_QUEUE_KEY_CPU);
        }

        if (StatesHelper.Instance.isPipelineScan) {
          command = command.replace("#OX_CONFIG#", "--config=/var/ox/sast --config=/var/ox/iac --config=/var/ox/sensitive-logs");
        } else {
          command = command.replace("#OX_CONFIG#", "--config=/var/ox");
        }
      }

      const url = this.toolConfiguration.getUrlForSqs(heavyTask);

      //code_only, git_only, all
      let copyType = CopyType.CodeOnly;
      if (repo.isMonoRepoParentOrChild) {
        copyType = CopyType.CodeOnly;
      }
      if (this.toolConfig.name.toLowerCase() === "gitleaks" && !repo.isMonoRepoParentOrChild) {
        copyType = CopyType.All;
      }
      if (StatesHelper.Instance.isPipelineScan) {
        copyType = CopyType.CodeOnly;
      }

      //If this is onPrem the zip folder is the actual code folder without a zip
      //If we are on SAST then we need the parent folder in case its mono repo and if not the regular repo
      const cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;

      if (repo.vcsType !== VCSType.tfvc) {
        if (
          this.toolConfig.name.toLowerCase().includes("trivy") ||
          this.toolConfig.name.toLowerCase() === "syft" ||
          this.toolConfig.name.toLowerCase() === "grype" ||
          (this.toolConfig.name.toLowerCase() === Constant.snykCLItool.toLowerCase() && !this.toolConfig.fullCodeOverride)
        ) {
          let path = `${cloneDir}/${ZipType.LeanCodeDependencyTools}`;
          if (repo.parentRepoOfMonoRepo) {
            const monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;
            path = `${cloneDir}/${monoRepoChildSubfolder}/${ZipType.LeanCodeDependencyTools}`;
          }

          if (fs.existsSync(path)) {
            const stats = fs.statSync(path);
            if (stats.size < 100) {
              logger.info(`[${this.toolConfig.name}] skipping due to size, ${path} size = ${stats.size}`);
              ignoredTools.push(secTool);
              return null;
            }
            copyType = CopyType.LeanCodeDependencyToolsOnly;
          } else {
            copyType = CopyType.LeanCodeOnly;
          }
        } else if (this.toolConfig.name.toLowerCase() === "checkov") {
          let path = `${cloneDir}/${ZipType.LeanCode}`;
          if (fs.existsSync(path)) {
            const stats = fs.statSync(path);
            if (stats.size < 100) {
              logger.info(`[${this.toolConfig.name}] skipping, ${path} size = ${stats.size}`);
              ignoredTools.push(secTool);
              return null;
            }
            copyType = CopyType.LeanCodeOnly;
          }
        }
      } else if (repo.vcsType === VCSType.tfvc) {
        copyType = CopyType.CodeOnly;
      }

      const commandForLogs = command;
      if (command.includes("oxwrapper.py --base64")) {
        if (process.env.DOCKER_DEBUG) {
          command = command
            .replaceAll(`${process.env.OX_SHARED_DATA}/scratch`, "/mnt/scratch")
            .replaceAll(process.env.OX_SHARED_DATA, "/var/shared-data");
        }
        const cmd = command.split("--cmd")[1].trim();
        const base64Cmd = Buffer.from(cmd).toString("base64");
        command = command.replace(cmd, base64Cmd);
      }
      //If onPrem take the clone dir and use shared file system
      //If SAST use unique zip destination folder
      let toolCopyDestination = repo.getRepoForToolsBasedOnEnv();

      const monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;

      const msg = {
        MessageId: v4(),
        type: Constant.codeToolType,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        rawCommand: this.toolConfig.command,
        url: url,
        toolName: this.toolConfig.name,
        nameForExternalService: this.toolConfig.nameForExternalService,
        repoName: repo.fullName,
        sizeMB: repo.sizeInBytes,
        resultPath: `${repo.securityResDir}/${this.toolConfig.fileNameOutput}`,
        timeout: this.toolConfig.timeout,
        orgDisplayName: process.env["companyName"],
        criticalTool: this.toolConfig.critical,
        cloneDir: cloneDir,
        copyType: copyType,
        toolCopyDestination: toolCopyDestination,
        isMonoRepoChild: repo.monoRepoChild,
        monoRepoChildSubfolder: monoRepoChildSubfolder,
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: repo.ignoredMonoRepoChildrenSubfolders,
        putInQueueTime: Date.now(),
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };
      this.requestId = msg.MessageId;

      localToolRunner().ifConfiguredToRunToolsLocallyThen().updateToolRunnerMessage(msg);

      const info = { url: url, msg: msg };
      const msgSendRes = await this.securityToolsQueue.sendQueueMessage(info);
      msg.command = commandForLogs;
      if (msgSendRes == false) {
        logger.error(`[${this.toolConfig.name}] failed to send msg on ${repo.name}, msg: ${JSON.stringify(msg)}`);
        ignoredTools.push(secTool);
        failedTools.push(secTool);
        return null;
      } else {
        logger.info(
          `[${this.toolConfig.name}] SEND msg on ${repo.name}, sizeInMG: ${sizeInMG}, filescount: ${repo.filesCount} msg: ${JSON.stringify(
            msg,
          )}`,
        );
      }

      return msg;
    } catch (err) {
      logger.error(`[${this.toolConfig.name}] failed to push msg tool on ${repo.name}`, err);
    }

    failedTools.push(secTool);
    ignoredTools.push(secTool);

    return null;
  }

  async createSecurityEvents(repoObj: any) {
    const repo: Repo = repoObj as Repo;

    try {
      let securityEvents: SecurityEvent[] = await this.collectedResults(repo);
      let filteredSecurityEvents: SecurityEvent[] = [];
      const filteredSecurityEventsFromGitHistory: SecurityEvent[] = [];

      for (const securityEvent of securityEvents) {
        try {
          //mishel remove
          if (this.toolExclusions.ExcludedAlert(securityEvent.fileName, securityEvent.lineContent, securityEvent)) {
            continue;
          }

          if (securityEvent.securityAlertType === SecurityAlertType.sast) {
            if (this.toolExclusions.ExcludedSASTAlert(securityEvent.fileName, securityEvent)) continue;
          }

          //Add to relevant list, according to if its from git history or not
          if (securityEvent.fromCommitHistory) {
            filteredSecurityEventsFromGitHistory.push(securityEvent);
          } else {
            filteredSecurityEvents.push(securityEvent);
          }
        } catch (err) {
          logger.error(
            `[${this.toolConfig.name}] failed to add security event on ${repo.name} securityEvent ${JSON.stringify(securityEvent)}`,
            err,
          );
        }
      }

      if (filteredSecurityEventsFromGitHistory.length > 0) {
        let withoutDuplication = [];
        for (const item of filteredSecurityEventsFromGitHistory) {
          if (filteredSecurityEvents.find(i => i.lineContent === item.lineContent) == undefined) {
            withoutDuplication.push(item);
          }
        }
        filteredSecurityEvents = [...filteredSecurityEvents, ...withoutDuplication];
      }

      logger.info(`[${this.toolConfig.name}] Info after filter ${filteredSecurityEvents.length} repo ${repo.name}`);

      this.printStatsForSecEvents(filteredSecurityEvents, repo);
      return filteredSecurityEvents;
    } catch (err) {
      logger.error(`[${this.toolConfig.name}] failed to parse results on: ${repo.name}`, err);
    }
    return [];
  }

  private async collectedResults(repo: Repo) {
    let rawdata = "";

    try {
      const securityEventList: SecurityEvent[] = [];
      const uniqueGitFromHistory = new Set<string>();

      const filePath = `${repo.securityResDir}/${this.toolConfig.fileNameOutput}`;

      if (fs.existsSync(filePath)) {
        rawdata = fs.readFileSync(filePath, "utf-8");
        if (rawdata === "") {
          logger.info(`[${this.toolConfig.name}] cannot find output content file: ${filePath} for repo: ${repo.fullName}`);
          StatesHelper.Instance.addFailedTool(this.toolConfig.name.toLowerCase() as Tool, repo.id);
          return [];
        }
        this.copyToolResults({ repoName: repo.name, dir: filePath });
        let toolResults = JSON.parse(rawdata);

        if (
          toolResults.runs == undefined ||
          toolResults.runs == null ||
          toolResults.runs.length === 0 ||
          toolResults.runs[0].results == null
        ) {
          logger.info(`[${this.toolConfig.name}] cannot find any alerts for content file: ${filePath} for repo: ${repo.fullName}`);
          StatesHelper.Instance.addFailedTool(this.toolConfig.name.toLowerCase() as Tool, repo.id);
          return [];
        }

        logger.info(`[${this.toolConfig.name}] Info before filter ${toolResults.runs[0].results.length} repo ${repo.fullName}`);
        this.addGlobalStats(this.toolConfig.defaultType, this.toolConfig.name, toolResults.runs[0].results.length, repo);

        let secResults = toolResults.runs[0].results;

        const stats = {
          dynamic: 0,
          none: 0,
          index: 0,
          savedFileRead: 0,
          skippedByLineNumber: 0,
          skippedDueToHighCharsNumber: 0,
          pii: 0,
        };

        if (secResults.length > 5000 && this.toolConfig.name.toLowerCase() === "gitleaks") {
          logger.info(`[${this.toolConfig.name}] losing alerts due to cap, original count: ${secResults.length}`);
          secResults = secResults.slice(0, 3000);
        }
        if (secResults.length > 15000 && this.toolConfig.name.toLowerCase() !== "gitleaks") {
          logger.info(`[${this.toolConfig.name}] losing alerts due to cap, original count: ${secResults.length}`);
          secResults = secResults.slice(0, 15000);
        }

        const alertCountMap = {};
        const { results, errors } = await PromisePool.for(secResults)
          .withConcurrency(400)
          .process(async (toolResult: any) => {
            await this.collectInfo(securityEventList, toolResult, toolResults, uniqueGitFromHistory, repo, stats, alertCountMap);
          });

        logger.info(`[${this.toolConfig.name}] post - got ${securityEventList.length} security events for ${repo.fullName}`);

        ToolsExecutionStats.addExecutionStateOfAlertsNumber(
          this.requestId,
          repo.fullName,
          repo.id,
          "repo",
          this.toolConfig.name,
          filePath,
          toolResults.runs[0].results.length,
          securityEventList.length,
        );

        logger.info(
          `[${this.toolConfig.name}] finish collect security alerts for repo: ${repo.fullName}, count: ${
            securityEventList.length
          }, uniqueGitFromHistory: ${uniqueGitFromHistory.size}, states: ${JSON.stringify(stats)}, total issues: ${
            securityEventList.length
          }`,
        );

        return securityEventList;
      } else {
        logger.info(`[${this.toolConfig.name}] cannot find output file: ${filePath} for repo: ${repo.fullName}`);
        // StatesHelper.Instance.addFailedTool(this.toolConfig.name.toLowerCase() as Tool, repo.id); // roman ?
      }
    } catch (err) {
      logger.error(`[${this.toolConfig.name}] cannot parse sarif file repo: ${repo.name}`, err);
      StatesHelper.Instance.addFailedTool(this.toolConfig.name.toLowerCase() as Tool, repo.id);
    }
    return [];
  }

  async collectInfo(
    securityEventList: SecurityEvent[],
    toolResult: any,
    toolResults: any,
    uniqueGitFromHistory: Set<string>,
    repo: Repo,
    stats: any,
    alertCountMap: Record<string, number>,
  ) {
    try {
      stats.index++;

      const replaceInfo = repo.getRepoForToolsBasedOnEnv();

      let fileName = this.fileHelper.getFileNameAccordingToLinkPage(
        toolResult.locations[0].physicalLocation.artifactLocation.uri,
        replaceInfo,
      );

      // logger.error(`----------`);
      // const fileLinkPath = repo.fileLink.split("/");
      // logger.error(`file link path: ${repo.fileLink} `);
      // const fileNamePath = fileName.split("/");
      // logger.error(`file name path: ${repo.fileLink} `);

      //Line number
      let startLine = toolResult.locations[0].physicalLocation.region.startLine;
      let endLine = toolResult.locations?.[0]?.contextRegion?.endLine ? toolResult.locations?.[0]?.contextRegion?.endLine : -1;
      if (endLine == -1) {
        endLine = toolResult.locations?.[0].physicalLocation?.region?.endLine
          ? toolResult.locations[0].physicalLocation.region?.endLine
          : -1;
      }
      if (endLine == -1) {
        endLine = startLine;
      }

      //Line and Snippet content extract from sarif
      let lineContent = toolResult?.locations[0]?.physicalLocation?.region?.snippet?.text || "";
      let snippet = toolResult?.locations[0]?.physicalLocation?.contextRegion?.snippet?.text || "";

      //Handle cases where not line content available
      if (lineContent == undefined || lineContent === "") {
        lineContent = snippet;
      }

      const isGitleaks = this.toolConfig.name.toLowerCase() === Git_Leaks_Tool_Name.toLowerCase();
      const historyResult = isGitleaks ? toolResult?.properties?._OX?.fromHistory ?? false : false;

      //General rule info
      const ruleInfo = toolResults?.runs?.[0]?.tool?.driver?.rules?.find(i => i?.id === toolResult.ruleId);
      let fnlcKey;
      if (isGitleaks) {
        fnlcKey = fileName + "_" + lineContent + "_" + ruleInfo.id;
        if (historyResult) {
          // We already encounter this secret for this file, don't generate new security event
          if (uniqueGitFromHistory.has(fnlcKey)) {
            return;
          }
          // add to cache to avoid multiple alerts for same lineContent of the same file
          uniqueGitFromHistory.add(fnlcKey);

          startLine = 0;
        } else {
          // all match indices in this specific file for same line content
          const matchIndices = toolResult?.properties?._OX?.matchIndices ?? [];
          const matchCount = matchIndices.length;

          // something went wrong if it's a non-history result, but no matches are found, don't generate new security event
          // if (matchCount === 0 && !process.env.DEBUG) {
          //   logger.info(`no matches found for ${fnlcKey} in ${fileName}`)
          //   return;
          // }

          // first time seeing an alert for this file, this lineContent, set count and proceed
          if (!alertCountMap[fnlcKey]) {
            alertCountMap[fnlcKey] = 1;
          } else {
            // second time seeing an alert for this file, this lineContent
            // if there are still more matches, update count and proceed
            if (matchCount > alertCountMap[fnlcKey]) {
              alertCountMap[fnlcKey]++;
            } else if (!process.env.DEBUG) {
              // we exhausted all matches in the latest version of the file, don't generate new security event
              return;
            }
          }
        }
      }

      //Violation and link info
      let violationInfo = "";
      let linkForToolDescription = "";
      if (ruleInfo != undefined) {
        linkForToolDescription = ruleInfo.helpUri;
        violationInfo = ruleInfo?.help?.text
          ? ruleInfo?.help?.text
          : ruleInfo?.fullDescription
          ? ruleInfo.fullDescription.text
          : ruleInfo.name;
      }
      if (violationInfo == "" && violationInfo != undefined) {
        violationInfo = toolResult.ruleId;
      }

      let securityAlertType: SecurityAlertType = SecurityAlertType[this.toolConfig.defaultType];
      if (this.toolConfig.dynamicIdentifyType) {
        securityAlertType = new EnumHelper().stringToSecurityAlertEnum(`${violationInfo}_${toolResult.message.text}`);
      } else {
        if (securityAlertType === SecurityAlertType.sast) {
          const dynamic = new EnumHelper().stringToSecurityAlertEnum(`${violationInfo}_${toolResult.message.text}`);
          if (dynamic != securityAlertType) {
            stats["dynamic"]++;
            return;
          }
        }
      }

      //Severity from config based on violation and rule id
      let severity = this.toolSeverity.getSeverityToolBaseOnRuleId(toolResult.ruleId, violationInfo);
      if (severity) {
        if (severity === Constant.ignoreRuleBasedOnSeverity) {
          stats["none"]++;
          return;
        }
      } else {
        severity = toolResult?.level ? toolResult.level : this.toolSeverity.getSevirtyBasedOnProperty(toolResult);
        if (!severity && ruleInfo != undefined) {
          severity = ruleInfo?.defaultConfiguration?.level;
          if (severity == undefined) {
            severity = "";
          }
        }
        if (!severity) {
          severity = this.toolConfig.defaultSeverity;
        }
      }
      //Commit info
      const commitName = toolResult?.partialFingerprints?.author ? toolResult.partialFingerprints.author : null;
      const commitSha = toolResult?.partialFingerprints?.commitSha ? toolResult.partialFingerprints.commitSha : null;
      const commitEmail = toolResult?.partialFingerprints?.email ? toolResult.partialFingerprints.email : null;
      const commitDescription = toolResult?.partialFingerprints?.commitMessage ? toolResult.partialFingerprints.commitMessage : null;
      const commitDate = toolResult?.partialFingerprints?.date ? toolResult.partialFingerprints.date : null;

      //Additional info
      let additionalInfo = `Rule name: ${toolResult.ruleId}`;
      if (linkForToolDescription != "" && linkForToolDescription != undefined) {
        additionalInfo += `, Link for more info: ${linkForToolDescription}`;
      } else {
        linkForToolDescription = "";
      }

      fileName = this.fixDupOfFilePath(repo, fileName);

      let language = "text";
      let extention = path.extname(fileName).toLowerCase();
      if (Constant.otherLanguages.hasOwnProperty(extention)) {
        language = Constant.otherLanguages[extention];
      }

      let updatedLink =
        repo.type === repoType.awsCodeCommit
          ? repo.fileLink + fileName + repo.linkFilePreffix + startLine + "-" + startLine
          : repo.fileLink + fileName + repo.linkFilePreffix + startLine;
      if (startLine < 0) {
        updatedLink = repo.fileLink + fileName;
      }

      let title = "";
      const oxwrapper = toolResult?.properties?.oxwrapper;
      let description = oxwrapper?.description;
      let eduVideoLink = oxwrapper?.eduVideoLink;
      let recommendation = oxwrapper?.recommendation;
      if (oxwrapper?.title) {
        title = oxwrapper.title;
      } else {
        title = isGitleaks ? "" : toolResult.message.text;
      }

      let provider = SourceToolType["Code Security"];
      if (isGitleaks) {
        provider = SourceToolType["Secret/PII Scan"];
      }

      let securityEvent = new SecurityEvent(
        provider,
        true,
        historyResult ? repo.commitLink + commitSha : updatedLink,
        new Date().toLocaleString(),
        "",
        "",
        "",
        violationInfo,
        title,
        fileName,
        severity,
        additionalInfo,
        startLine,
        "low",
        securityAlertType,
        recommendation,
        lineContent.toString(),
        snippet,
        endLine,
        true,
        historyResult,
        commitName,
        commitSha,
        commitEmail,
        commitDate,
        toolResult.ruleId,
        linkForToolDescription,
        repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
        repo.fullName,
        repo.insideFolder,
        repo.monoRepoChild ? repo.name.substring(1) + "/" + fileName : fileName,
        this.toolConfig.name.toLowerCase() as Tool,
      );

      securityEvent.version = repo.defaultBranch;
      securityEvent.eduVideoLink = eduVideoLink;
      securityEvent.description = description;
      if (oxwrapper?.cwe?.length) {
        securityEvent.cweList = oxwrapper.cwe;
      }

      securityEvent.privateVisability = repo.privateVisability;

      //Overwrite severity for secrets of public repos
      if (securityAlertType === SecurityAlertType.secrets) {
        if (toolResult?.properties?.tags) {
          for (const tag of toolResult.properties.tags) {
            if (tag === "silent") {
              if (StatesHelper.Instance.isPipelineScan) {
                logger.info(`[${this.toolConfig.name}] skipping silent signature of ${securityEvent.ruleId}`);
                return;
              }
              securityEvent.isSilent = true;
            } else if (tag === "generic") {
              securityEvent.isGeneric = true;
            } else if (tag === "pii") {
              securityEvent.isPII = true;
              securityEvent.securitySubTypeAlertType = SecurityAlertType.PII;
              stats.pii++;
              if (securityEvent.ruleId !== "email-address") {
                const piiExistAlready = repo.severityChangedReason.find(s => s.shortName == severityReasons.piiProcessing.shortName);
                if (!piiExistAlready) {
                  const piiProcessingReason = ChangeReason.copy(severityReasons.piiProcessing);
                  piiProcessingReason.requiredHits = 0;
                  repo.addRepoSeverityChangedReason(piiProcessingReason);
                }
              }
            } else if (lineContent) {
              let extraInfo: ExtraInfo[] = [];
              const lastPartLength = Math.max(Math.ceil(lineContent.length / 3), Math.min(8, lineContent.length - 1), 0);
              const reducted = lineContent.substring(0, lineContent.length - lastPartLength) + "*".repeat(lastPartLength);
              extraInfo.push({
                key: "Snippet",
                link: securityEvent.link,
                snippet: {
                  fileName: fileName,
                  text: reducted,
                  language: language,
                  snippetLineNumber: startLine,
                },
              });

              if (secretTagMapping.hasOwnProperty(tag)) {
                if (secretMapping.groups.hasOwnProperty(tag)) {
                  securityEvent.secretGroup = tag;
                }
                addSeverityChangedReason(secretTagMapping[tag], securityEvent, repo, extraInfo);
                if (LATERAL_MOVEMENT_GROUPS.includes(tag)) {
                  addSeverityChangedReason(severityReasons.lateralMovement, securityEvent, repo);
                }
              }
            }
          }

          // refactor all of this into methods
          // Possible filter some of the events
          // collect only 15 for each repo for each rule
          // but we keep counting them

          let removed = false;
          for (const tag of toolResult.properties.tags) {
            if (tag === "pii") {
              let key = `${repo.name}_${securityEvent.ruleId}`;

              if (securityEvent.fromCommitHistory === true) {
                // for policy pii in history
                key = key + "_history";
              } else if (securityEvent.fromCommitHistory === false) {
                // for policy pii in code
                key = key + "_code";
              }

              // static counter used to show total in policy - keep for now
              StatesHelper.Instance.piiEventsCounter[key] = StatesHelper.Instance.piiEventsCounter[key] + 1 || 1;

              if (StatesHelper.Instance.piiEventsCounter[key] > Constant.piiCollectLimit) {
                removed = true;
                break;
              }
            }
          }
          if (removed) {
            return;
          }
        }

        // for pii we use pii SF else we use secrets SF
        if (securityEvent.isPII) {
          const lastPartLength = Math.max(Math.ceil(lineContent.length / 3), Math.min(8, lineContent.length - 1), 0);
          const reducted = lineContent.substring(0, lineContent.length - lastPartLength) + "*".repeat(lastPartLength);
          const extraInfo: ExtraInfo[] = [];
          extraInfo.push({
            key: "Snippet",
            link: securityEvent.link,
            snippet: {
              fileName: fileName,
              text: reducted,
              language: language,
              snippetLineNumber: startLine,
            },
          });
          if (repo.privateVisability) {
            addSeverityChangedReason(severityReasons.piiInPrivateRepo, securityEvent, repo, extraInfo);
          } else {
            addSeverityChangedReason(severityReasons.piiInPublicRepo, securityEvent, repo, extraInfo);
          }
        } else {
          if (repo.privateVisability) {
            addSeverityChangedReason(severityReasons.secretInPrivateRepo, securityEvent, repo);
          } else {
            addSeverityChangedReason(severityReasons.secretInPublicRepo, securityEvent, repo);
          }
        }
      }

      securityEvent.blame.commitDescription = commitDescription;
      // if (securityAlertType === SecurityAlertType.secrets && !securityEvent.blame.cwe.includes(Constant.SECRET_IN_CODE_CWE)) {
      //   securityEvent.blame.cweList.push(Constant.SECRET_IN_CODE_CWE_ITEM);
      // }

      securityEvent.realMatch =
        toolResult?.locations[0]?.physicalLocation?.contextRegion?.snippet?.text ||
        toolResult?.locations[0]?.physicalLocation?.region?.snippet?.text ||
        securityEvent.lineContent;

      // if (!securityEvent.realMatch) {
      //   const shouldRun = isDevelopment() || isLocalDevelopment();
      //   if (!shouldRun) {
      //     logger.error(`failed add ${this.toolConfig.name} for repo: ${repo.name}, no match`);
      //     return;
      //   } else {
      //     securityEvent.realMatch = `${securityEvent.fileName}-${securityEvent.ruleId}-${securityEvent.fromCommitHistory}`;
      //     logger.info(`setting alternative realMatch: ${securityEvent.realMatch}`);
      //   }
      // }

      securityEvent.secretWithoutObfuscation = securityEvent.realMatch;
      if (isGitleaks) {
        if (securityEvent.realMatch) {
          securityEvent.realMatch = crypto.createHash("md5").update(securityEvent.realMatch).digest("hex");
        }
      } else {
        securityEvent.realMatch = securityEvent.realMatch.substring(0, 300);
      }
      securityEvent.lineContent = securityEvent.lineContent.trim().replace(/\s+/g, " ");

      securityEventList.push(securityEvent);
    } catch (err) {
      logger.error(`[${this.toolConfig.name}] failed add for repo: ${repo.name}`, err);
    }
  }

  copyToolResults({ repoName, dir }: { repoName: string; dir: string }): void {
    if (!isUploadToS3()) return;
    const oxDir = getSharedFolder(this.uuid) + "/ox-security";
    const telemetryDir = oxDir + "/telemetry-" + this.uuid;
    const repoDir = telemetryDir + "/security-report/" + repoName;
    const toolDir = repoDir + "/" + this.toolConfig.name;

    try {
      if (!fs.existsSync(toolDir)) {
        fs.mkdirSync(toolDir, { recursive: true });
      }
      this.fileHelper.copyFileSync(dir, toolDir);
    } catch (err) {
      logger.error(`[${this.toolConfig.name}] failed to copy result file for repo name ${repoName}`, err);
    }
  }

  addGlobalStats(type: string, provider: string, count: number, repo: Repo) {
    try {
      const unique = `${type}_${provider}`;
      if (StatesHelper.Instance.alertsPerCategoryFromTool[unique] == undefined) {
        StatesHelper.Instance.alertsPerCategoryFromTool[unique] = count;
      } else {
        StatesHelper.Instance.alertsPerCategoryFromTool[unique] += count;
      }
    } catch (err) {
      logger.error(`[${this.toolConfig.name}] cannot set states for repo: ${repo.fullName}`, err);
    }
  }

  printStatsForSecEvents(securityEvents: SecurityEvent[], repo: Repo) {
    try {
      const stats = {};
      securityEvents.forEach(i => {
        const unique = `${i.severityStr}_${i.securityAlertTypeStr}_${i.tool}`;
        if (stats[unique] == undefined) {
          stats[unique] = 1;
        } else {
          stats[unique]++;
        }

        if (StatesHelper.Instance.alertsPerCategoryAndProvider[unique] == undefined) {
          StatesHelper.Instance.alertsPerCategoryAndProvider[unique] = 1;
        } else {
          StatesHelper.Instance.alertsPerCategoryAndProvider[unique]++;
        }

        const uniqueCat = `${i.severityStr}_${i.securityAlertTypeStr}`;
        if (StatesHelper.Instance.alertsPerCategory[uniqueCat] == undefined) {
          StatesHelper.Instance.alertsPerCategory[uniqueCat] = 1;
        } else {
          StatesHelper.Instance.alertsPerCategory[uniqueCat]++;
        }
      });

      if (Object.keys(stats).length == 0) {
        return;
      }

      logger.info(`[${this.toolConfig.name}] stats for repo: ${repo.fullName}, stats: ${JSON.stringify(stats)}`);

      StatesHelper.Instance.totalCodeSecurityAlertsBeforePolicyEval += securityEvents.length;
    } catch (err) {
      logger.error(`[${this.toolConfig.name}] cannot print states for repo: ${repo.fullName}`, err);
    }
  }
  fixDupOfFilePath(repo: Repo, fileName) {
    try {
      const fileLinkPath = repo.fileLink.split("/");
      const fileNamePath = fileName.split("/");

      let newFileName;
      if (fileLinkPath.length > 1 && fileNamePath.length > 0) {
        if (fileLinkPath[fileLinkPath.length - 3] === fileNamePath[0]) {
          newFileName = fileNamePath.slice(2).join("/");
        } else if (fileLinkPath[fileLinkPath.length - 2] === fileNamePath[0]) {
          newFileName = fileNamePath.slice(1).join("/");
        }
      }
      if (newFileName) return newFileName;
      return fileName;
    } catch (err) {
      logger.error(`[${this.toolConfig.name}] Cant fix fileName in case of duplication`, err);
      return fileName;
    }
  }
}

export default CodeSecurityTool;
