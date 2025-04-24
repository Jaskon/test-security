const util = require("util");
const exec = util.promisify(require("child_process").exec);
import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import {
  CodeRepoTypes,
  File,
  Repo,
  repoResourceType,
  resourceType,
  SecurityAlertType,
  SecurityEvent,
  VCSType,
} from "../../entitis/codeRepoTypes";
import Constant, { OXtools } from "../../entitis/constant";
import { AlertDepJackingRequest, AlertDepJackingResponse, DepJackingFileInfo } from "../../entitis/service/alertDepJackingTypes";
import { getSharedFolder } from "../../helper/generalUtils";
import FileHelper from "../../helper/IO/fileHlper";
import loggerImport from "../../logger";
import { escapeCharsFromPath } from "../commonUtils";
import { isK8Mode, isUploadToS3 } from "../envUtils";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";

const onPrem = process.env.redisOnPrem != undefined;
const onSast = process.env.MONGO_CONN === "atlas";
const isk8 = isK8Mode();
const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();

class AlertDepJacking {
  alertDepJackingHelperQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;
  supportedLanguages: string[] = ["javascript", "python"];

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.alertDepJackingHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
  }

  async setAlertDepJacking(repo: Repo, repoObj: any, files: File[]) {
    if (StatesHelper.Instance.isPipelineScan || process.env.SKIP_DEP_JACKING) {
      return;
    }

    try {
      const requests: AlertDepJackingRequest = new AlertDepJackingRequest();

      if (repo.dependencyGraphInfoPath && repo.dependencyGraphInfoPath != null) {
        if (fs.existsSync(repo.dependencyGraphInfoPath)) {
          const data = fs.readFileSync(repo.dependencyGraphInfoPath, "utf8");
          requests.dependencyGraphInfo = JSON.parse(data);

          if (!requests.dependencyGraphInfo || requests.dependencyGraphInfo.length === 0) {
            logger.info(`will not set alert dep jacking for repo: ${repo.fullName}, dependencyGraphInfo are empty`);
            return;
          }
          let hasSupportedLanguage = false;
          requests.dependencyGraphInfo.forEach(item => {
            if (this.supportedLanguages.includes(item.language.toLowerCase())) {
              hasSupportedLanguage = true;
              return;
            }
          });
          if (!hasSupportedLanguage) {
            logger.info(`will not set alert dep jacking for repo: ${repo.fullName}, hasSupportedLanguage not supported`);
            return;
          }
        } else {
          logger.info(`will not set alert dep jacking for repo: ${repo.fullName}`);
          return;
        }
      }

      files.forEach(i => {
        if (i.name === ".npmrc") {
          const data = fs.readFileSync(i.path, "utf8");
          if (data) {
            const depJackingFile: DepJackingFileInfo = new DepJackingFileInfo();
            depJackingFile.content = data;
            depJackingFile.filepath = i.fileNameWithoutDisk;
            depJackingFile.type = "npmrc";
          }
        }
      });

      logger.info(`try set alert dep jacking request for repo: ${repo.fullName}`);

      const input = await this.sendAndWaitForRes(requests, repo);

      if (!input.isSuccessful) {
        logger.error(`alert dep jacking for repo: ${repo.fullName}, came back with isSuccessful: false`);
        StatesHelper.Instance.addFailedTool(repoResourceType.depJacking, repo.id);
        this.addDepJackingToolsAsFailed(repo);
        return;
      }

      this.createAlertDepJackingFromResponse(input, repoObj, repo);
      logger.info(`finish set alert dep jacking for repo: ${repo.fullName}`);
      this.createAlertDepConfusionFromResponse(input, repoObj, repo);
      logger.info(`finish set alert dep confusion scope for repo: ${repo.fullName}`);
      this.createAlertDepConfusionPkgFromResponse(input, repoObj, repo);
      logger.info(`finish set alert dep confusion package for repo: ${repo.fullName}`);
    } catch (err) {
      this.addDepJackingToolsAsFailed(repo);
      logger.error(`failed set alert dep jacking for all security alerts for repo: ${repo.fullName}, err: ${err}`);
    }
  }

  private addDepJackingToolsAsFailed(repo: Repo) {
    repo.addFailedSecurityTools(OXtools.depJacking);
    repo.addFailedSecurityTools(OXtools.depConfusionAlert);
  }

  private createAlertDepJackingFromResponse(resOfAllAlertRec: AlertDepJackingResponse, repoObj: any, repo: Repo) {
    try {
      logger.info(
        `number of alert dep jacking results before digest for repo: ${repo.fullName} count: ${
          resOfAllAlertRec?.typosquatted?.length ?? 0
        }`,
      );

      if (!resOfAllAlertRec?.typosquatted) {
        return;
      }
      if (resOfAllAlertRec.typosquatted.length === 0) {
        return;
      }

      const allSecEvents: SecurityEvent[] = repoObj[CodeRepoTypes[CodeRepoTypes.securityEvents]];

      let alertAdd = 0;
      for (const alert of resOfAllAlertRec.typosquatted) {
        try {
          const event = new SecurityEvent(
            SourceToolType.SBOM,
            true,
            repo.fileLink,
            new Date().toString(),
            "",
            "",
            "",
            `Typosquatting of a dependency '${alert.pkgName}' in ${alert.registry} registry.`,
            `${alert.pkgName} is suspiciously similar to the widely used package '${alert.legitimatePkgName}' in the public ${alert.registry} registry.`,
            alert.fileName,
            "high",
            ``,
            0,
            "",
            SecurityAlertType.typosquatting,
            `Replace fradulent package '${alert.pkgName}' with the legitimate package '${alert.legitimatePkgName}'`,
            "",
            "",
            -1,
            true,
            false,
            "",
            "",
            "",
            "",
            "Generic-DepJacking", // do not change
            "", // link to pbom.dev ?
            repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
            repo.fullName,
            repo.insideFolder,
            repo.monoRepoChild ? repo.name.substring(1) + "/" + alert.fileName : alert.fileName,
            OXtools.depJacking,
          );

          event.version = repo.defaultBranch;
          event.pkgName = alert.pkgName;
          event.installedVersion = alert.installedVersion;
          event.legitimatePkgName = alert.legitimatePkgName;
          event.registry = alert.registry;
          event.legitimatePkgLink = alert.legitimatePkgLink; //liad add hear
          event.similarityScore = alert.similarityScore;
          event.realMatch = `${alert.pkgName}@${event.installedVersion}`;
          event.linkPrefix = repo.linkFilePreffix;

          allSecEvents.push(event);

          alertAdd++;
        } catch (err) {
          logger.error(`fail alert dep jacking single alert, repo: ${repo.fullName}, err: $${err}`);
          StatesHelper.Instance.addFailedTool(repoResourceType.depJacking, repo.id);
          repo.addFailedSecurityTools(OXtools.depJacking);
        }
      }

      logger.info(
        `finish alert dep jacking alerts for repo: ${repo.fullName}, total response: ${resOfAllAlertRec.typosquatted.length} for single chunk, alert add: ${alertAdd}`,
      );
    } catch (err) {
      logger.error(`fail alert dep jacking alerts for repo: ${repo.fullName}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.depJacking, repo.id);
      repo.addFailedSecurityTools(OXtools.depJacking);
    }
  }

  private createAlertDepConfusionFromResponse(resOfAllAlertRec: AlertDepJackingResponse, repoObj: any, repo: Repo) {
    try {
      logger.info(
        `number of alert dependency confusion results before digest for repo: ${repo.fullName} count: ${
          resOfAllAlertRec?.depConfusionScopes?.length ?? 0
        }`,
      );

      if (!resOfAllAlertRec?.depConfusionScopes) {
        return;
      }
      if (resOfAllAlertRec.depConfusionScopes.length === 0) {
        return;
      }

      const allSecEvents: SecurityEvent[] = repoObj[CodeRepoTypes[CodeRepoTypes.securityEvents]];

      let alertAdd = 0;
      for (const alert of resOfAllAlertRec.depConfusionScopes) {
        try {
          const event = new SecurityEvent(
            SourceToolType.SBOM,
            true,
            "",
            new Date().toString(),
            "",
            "",
            "",
            `NA`,
            `NA`,
            alert.filePath,
            "high",
            ``,
            0,
            "",
            SecurityAlertType.depConfusionScopes,
            "",
            "",
            "",
            -1,
            true,
            false,
            "",
            "",
            "",
            "",
            "Generic-DepJacking", // do not change
            "", // link to pbom.dev ?
            repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
            repo.fullName,
            repo.insideFolder,
            repo.monoRepoChild ? repo.name.substring(1) + "/" + alert.filePath : alert.filePath,
            OXtools.depConfusionAlert,
          );

          event.version = repo.defaultBranch;
          event.orgScopeId = alert.orgScopeId;
          event.privateRegistryName = alert.privateRegistryName;
          event.privateRegistryUrl = alert.privateRegistryUrl;
          event.isOrgScopeAvailable = alert.isOrgScopeAvailable;
          event.publicRegistry = alert.publicRegistry;
          event.fileName = alert.filePath;
          event.scopeRegisteredBy = alert.scopeRegisteredBy;

          allSecEvents.push(event);
          alertAdd++;
        } catch (err) {
          logger.error(`fail alert dep jacking single alert, repo: ${repo.fullName}, err: ${err}`);
          // StatesHelper.Instance.globalApisFails.add(resourceType.depConfusionAlert);
          repo.addFailedSecurityTools(OXtools.depConfusionAlert);
        }
      }

      logger.info(
        `finish alert dep confusion alerts for repo: ${repo.fullName}, total response: ${resOfAllAlertRec.depConfusionScopes.length} for single chunk, alert add: ${alertAdd}`,
      );
    } catch (err) {
      logger.error(`fail alert dep confusion alerts for repo: ${repo.fullName}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(resourceType.depConfusionAlert, repo.id); // michelle ?
      repo.addFailedSecurityTools(OXtools.depConfusionAlert);
    }
  }

  private createAlertDepConfusionPkgFromResponse(resOfAllAlertRec: AlertDepJackingResponse, repoObj: any, repo: Repo) {
    try {
      logger.info(
        `number of alert dependency confusion packages results before digest for repo: ${repo.fullName} count: ${
          resOfAllAlertRec?.depConfusionScopes?.length ?? 0
        }`,
      );

      if (!resOfAllAlertRec?.depConfusionPkgs) {
        return;
      }
      if (resOfAllAlertRec.depConfusionPkgs.length === 0) {
        return;
      }

      const allSecEvents: SecurityEvent[] = repoObj[CodeRepoTypes[CodeRepoTypes.securityEvents]];

      let alertAdd = 0;
      for (const alert of resOfAllAlertRec.depConfusionPkgs) {
        try {
          if (this.orgName === "org_5rvGe4lwDV8RhaIA") {
            console.log(`inside creating secEven depConfusion, repo fileLink: ${repo.fileLink}, filePath: ${alert.filePath}`);
          }
          const recommendation = "";

          const event = new SecurityEvent(
            SourceToolType.SBOM,
            true,
            repo.fileLink,
            new Date().toString(),
            "",
            "",
            "",
            `dependency confusion of package '${alert.packageNameId}' in ${alert.publicRegistry} registry instead of ${alert.privateRegistryName}`,
            `The private package name '${alert.packageNameId}' is also used as scope in the public ${alert.publicRegistry} registry, which leads to dependency confusion.`,
            alert.filePath,
            "high",
            ``,
            0,
            "",
            SecurityAlertType.depConfusionPkgs,
            recommendation,
            "",
            "",
            0,
            true,
            false,
            "",
            "",
            "",
            "",
            "Generic-DepJacking", // do not change
            "", // link to pbom.dev ?
            repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
            repo.fullName,
            repo.insideFolder,
            repo.monoRepoChild ? repo.name.substring(1) + "/" + alert.filePath : alert.filePath,
            OXtools.depConfusionAlert,
          );

          event.version = repo.defaultBranch;
          event.pkgName = alert.packageNameId;
          event.installedVersion = alert.packageVersion;
          event.privateRegistryName = alert.privateRegistryName;
          event.privateRegistryUrl = alert.privateRegistryUrl;
          event.isPkgAvailable = alert.isPkgAvailable;
          event.publicRegistry = alert.publicRegistry;
          event.fileName = alert.filePath;
          event.pkgRegisteredBy = alert.pkgRegisteredBy;
          event.language = alert.language;
          event.type = alert.type;
          event.realMatch = `${alert.packageNameId}@${event.installedVersion}`;
          event.linkPrefix = repo.linkFilePreffix;

          allSecEvents.push(event);

          alertAdd++;
        } catch (err) {
          logger.error(`fail alert dep jacking single alert, repo: ${repo.fullName}, err: ${err}`);
          repo.addFailedSecurityTools(OXtools.depConfusionAlert);
          // StatesHelper.Instance.addFailedTool(repoResourceType.depConfusionPkgAlert, repo.id);
        }
      }

      logger.info(
        `finish alert dep packages confusion alerts for repo: ${repo.fullName}, total response: ${resOfAllAlertRec.depConfusionScopes.length} for single chunk, alert add: ${alertAdd}`,
      );
    } catch (err) {
      logger.error(`fail alert dep packages confusion alerts for repo: ${repo.fullName}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.depConfusionPkgAlert, repo.id); // michelle ?
      repo.addFailedSecurityTools(OXtools.depConfusionAlert);
    }
  }

  private async sendAndWaitForRes(requests: AlertDepJackingRequest, repo: Repo, index: number = 1) {
    let data;
    const requestId = uuid.v4();

    try {
      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;

      logger.info(`sending request to alert dep jacking service for repo: ${repo.fullName}`);

      let url = onSast ? process.env.DEP_JACKING_SERVICE_SQS_URL : process.env.DEP_JACKING_QUEUE_KEY;
      if (isk8) {
        url = process.env.DEP_JACKING_QUEUE_KEY;
      }

      const dirToPutRes = `${repo.alertDepJackingDir}/${requestId}`;
      fs.mkdirSync(dirToPutRes, { recursive: true });

      const filePathRequest = `${dirToPutRes}/depjackingRequest.json`;
      fs.writeFileSync(filePathRequest, JSON.stringify(requests));

      const filePathRes = `${dirToPutRes}/depjacking.json`;

      //If this is onPrem the zip folder is the actual code folder without a zip
      //If we are on SAST then we need the parent folder in case its mono repo and if not the regular repo
      let cloneDir = "";
      let toolCopyDestination = "";
      let monoRepoChildSubfolder = "";
      if (repo.realRepo) {
        cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;

        toolCopyDestination = repo.getRepoForToolsBasedOnEnv();
        if (!onPrem || isk8) {
          toolCopyDestination = `${toolCopyDestination}/${index.toString()}`;
        }

        monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;
      }

      let command = this.getCommand(filePathRequest, dirToPutRes, toolCopyDestination);
      command = escapeCharsFromPath(command);

      let copyType = CopyType.LeanCodeOnly;
      let path = "";
      if (monoRepoChildSubfolder) {
        path = `${cloneDir}/${monoRepoChildSubfolder}/leanCodeDependencyTools.zip`;
      } else {
        path = `${cloneDir}/leanCodeDependencyTools.zip`;
      }

      const msg = {
        MessageId: requestId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "alert-depjacking-service",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 900000,
        orgDisplayName: process.env["companyName"],
        cloneDir: cloneDir,
        copyType: copyType,
        toolCopyDestination: toolCopyDestination,
        isMonoRepoChild: repo.monoRepoChild,
        monoRepoChildSubfolder: monoRepoChildSubfolder,
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: repo.ignoredMonoRepoChildrenSubfolders,
        putInQueueTime: new Date().getTime(),
        shouldSkipLocalCopy: false,
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(
        `about to send msg to queue for alert dep jacking, repo: ${repo.fullName}, num of requests: 1, msg: ${JSON.stringify(msg)}`,
      );

      //From Debug(shell)
      if (process.env.DEBUG) {
        const reqRes = await this.runShell(repo.name, msg.localCommand);
        const data = fs.readFileSync(filePathRes, "utf8");
        const alertDepJackingRe = JSON.parse(data);
        return alertDepJackingRe;
      }

      //From SAST(sqs)
      const reqRes = await this.alertDepJackingHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        ToolsExecutionStats.addExecutionStateOnFail(
          requestId,
          OXtools.depJacking,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          -1,
          ToolError.SendToQueue,
        );
        logger.error(`fail alert dep jacking, sendAndWaitForRes !reqRes for repo: ${repo.fullName}`);
        this.addDepJackingToolsAsFailed(repo);
        return null;
      }

      logger.info(
        `about to start waiting for alert dep jacking requests, repo: ${repo.fullName}, num of requests: 1, msg: ${JSON.stringify(msg)}`,
      );

      this.copyToolResults({ repoName: repo.name, dir: filePathRequest });
      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromAlertRec = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 15; // 60 seconds * 15 = 15 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.depJacking,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );

          StatesHelper.Instance.scanInfoStats.failedDepJackingTimeout++;
          StatesHelper.Instance.scanInfoStats.failedDepJackingTimeoutRepoNames.push(repo.name);
          StatesHelper.Instance.addFailedTool("dep-confusion", repo.id);
          StatesHelper.Instance.addFailedTool("dep-confusion-alert", repo.id);
          StatesHelper.Instance.addFailedTool("dep-jacking", repo.id);

          logger.error(`fail alert dep jacking, sendAndWaitForRes counter <=0 for repo: ${repo.fullName}`);
          this.addDepJackingToolsAsFailed(repo);
          return null;
        }

        //Failed from alert dep jacking
        if (fs.existsSync(failedFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.depJacking,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.FailedFileFound,
          );

          StatesHelper.Instance.scanInfoStats.failedDepJackingBatches++;
          StatesHelper.Instance.scanInfoStats.failedDepJackingRepoNames.push(repo.name);
          StatesHelper.Instance.addFailedTool("dep-confusion", repo.id);
          StatesHelper.Instance.addFailedTool("dep-confusion-alert", repo.id);
          StatesHelper.Instance.addFailedTool("dep-jacking", repo.id);

          logger.error(`fail alert dep jacking, sendAndWaitForRes fs.existsSync for repo: ${repo.fullName}`);
          this.addDepJackingToolsAsFailed(repo);
          return null;
        }

        //Done from alert dep jacking
        if (fs.existsSync(doneFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `done file discovered from alert dep jacking response, repo: ${repo.fullName}, num of requests: 1, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromAlertRec = true;
          break;
        }

        //10 seconds
        await this.sleep();
        counter--;
      }

      if (!fs.existsSync(filePathRes)) {
        let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
        ToolsExecutionStats.addExecutionStateOnFail(
          requestId,
          OXtools.depJacking,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );

        StatesHelper.Instance.scanInfoStats.failedDepJackingBatches++;
        StatesHelper.Instance.scanInfoStats.failedDepJackingRepoNames.push(repo.name);
        StatesHelper.Instance.addFailedTool("dep-confusion", repo.id);
        StatesHelper.Instance.addFailedTool("dep-confusion-alert", repo.id);
        StatesHelper.Instance.addFailedTool("dep-jacking", repo.id);

        logger.error(`fail alert dep jacking, sendAndWaitForRes !fs.existSync for repo: ${repo.fullName}`);
        this.addDepJackingToolsAsFailed(repo);
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      data = fs.readFileSync(filePathRes, "utf8");
      const alertDepJackingRes = JSON.parse(data);

      //Delete after reading
      this.copyToolResults({ repoName: repo.name, dir: filePathRes });
      this.fileHelper.deleteFile(filePathRes);
      this.fileHelper.deleteFile(filePathRequest);

      const failed = new Set<string>();
      ToolsExecutionStats.addToExecutionStatsFromFile(
        doneFilePath,
        requestId,
        OXtools.depJacking,
        repo.fullName,
        repo.id,
        "repo",
        repo.cloneDir,
        failed,
      );
      if (failed.size > 0) {
        logger.error(`fail alert dep jacking, sendAndWaitForRes failed.size > 0 for repo: ${repo.fullName}`);
        this.addDepJackingToolsAsFailed(repo);
        return null;
      }

      logger.info(
        `finish waiting for alert dep jacking, repo: ${repo.fullName}, num of requests: 1, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, alert dep jacking res number: ${alertDepJackingRes.length}, counter: ${counter}`,
      );

      return alertDepJackingRes;
    } catch (err) {
      ToolsExecutionStats.addExecutionStateOnFail(requestId, OXtools.depJacking, repo.fullName, repo.id, "repo", "", -1, ToolError.Generic);
      StatesHelper.Instance.scanInfoStats.failedDepJackingBatches++;
      StatesHelper.Instance.scanInfoStats.failedDepJackingRepoNames.push(repo.name);
      StatesHelper.Instance.addFailedTool("dep-confusion", repo.id);
      StatesHelper.Instance.addFailedTool("dep-confusion-alert", repo.id);
      StatesHelper.Instance.addFailedTool("dep-jacking", repo.id);

      this.addDepJackingToolsAsFailed(repo);

      logger.error(
        `failed to send batch of security alerts to alert dep jacking service for repo: ${repo.fullName}, data: ${data}, err: ${err}`,
      );
    }
    return null;
  }

  async runShell(requesterName: string, command: string) {
    try {
      await this.shell(requesterName, command);
      return true;
    } catch (err) {
      logger.error(`failed run shell command: ${command} to run err: ${err}`);
    }
    return false;
  }

  async shell(requesterName, command: string) {
    try {
      logger.info(`try run from shell, repo: ${requesterName}: cmd: ${command}`);

      const { stdout, stderr } = await exec(command, {
        maxBuffer: 1024 * 1024 * 10,
        env: { ...process.env, FOO: "ah" },
      });
      logger.debug(`stdout:, ${JSON.stringify(stdout, null, 4)}`);
      logger.debug(`stderr:, ${JSON.stringify(stderr, null, 4)}`);
    } catch (err) {
      logger.error(
        `uuid: ${this.uuid} shell command: ${command} failed to run error: ${err} stdout: ${err.stdout + "\n"} stderr: ${
          err.stderr + "\n"
        }`,
      );

      logger.info(`finish run from shell, requester name: ${requesterName} cmd: ${command}`);
    }
  }

  copyToolResults({ repoName, dir }: { repoName: string; dir: string }): void {
    if (isUploadToS3()) {
      const oxDir = getSharedFolder(this.uuid) + "/ox-security";
      const telemetryDir = oxDir + "/telemetry-" + this.uuid;
      const repoDir = telemetryDir + "/security-report/" + repoName;
      const toolDir = repoDir + "/depJacking";

      try {
        if (!fs.existsSync(toolDir)) {
          fs.mkdirSync(toolDir, { recursive: true });
        }
        this.fileHelper.copyFileSync(dir, toolDir);
      } catch (err) {
        logger.error(`failed to copy tool depJ result file for repo name ${repoName}`);
      }
    }
  }

  getCommand(requestPath: string, outputDir: string, repoDir: string) {
    if (process.env.DEBUG) {
      return `python ${process.env.DEP_JACKING_PATH} --events-path ${requestPath} --output-dir ${outputDir}`;
    }
    return `python /src/dependency_jacking.py --source ${repoDir} --events-path ${requestPath} --output-dir ${outputDir}`;
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 10);
  }
}

export default AlertDepJacking;
