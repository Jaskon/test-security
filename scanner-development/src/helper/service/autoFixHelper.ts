const util = require("util");
const exec = util.promisify(require("child_process").exec);
import { setTimeout } from "node:timers/promises";
import { Repo, SecurityEvent } from "../../entitis/codeRepoTypes";
import { OXtools } from "../../entitis/constant";
import { AutoFixRequest, AutoFixResponse } from "../../entitis/service/autoFixTypes";
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

class AutoFixHelper {
  AutoFixHelperQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.AutoFixHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
  }

  async sendAutoFix(securityAlerts: SecurityEvent[], repo: Repo) {
    try {
      if (securityAlerts.length == 0) {
        return;
      }

      logger.info(`[AutoFix] try generate requests for repo: ${repo.fullName}, alerts: ${securityAlerts.length}`);

      let requests: AutoFixRequest[] = [];

      for (const securityAlert of securityAlerts) {
        try {
          if (securityAlert.askedOnceForAutoFix) {
            return;
          }
          if (securityAlert.skipEnrichment) {
            return;
          }
          if (!securityAlert.oxTool) {
            return;
          }

          securityAlert.askedOnceForAutoFix = true;
          const autoFixRequest: AutoFixRequest = new AutoFixRequest();

          autoFixRequest.analysisUid = this.uuid;
          autoFixRequest.orgId = this.orgName;
          autoFixRequest.uid = securityAlert.uid;
          autoFixRequest.category = securityAlert.securityAlertTypeStr;
          autoFixRequest.ruleId = securityAlert.ruleId;
          autoFixRequest.snippet = securityAlert.snippetContent;
          autoFixRequest.fileName = securityAlert.fileName;
          autoFixRequest.pkgName = securityAlert.pkgName || securityAlert.blame?.triggerPackage?.name;
          autoFixRequest.installedVersion = securityAlert.installedVersion || securityAlert.blame?.triggerPackage?.version;
          autoFixRequest.fixedVersion = securityAlert.fixedVersion;

          requests.push(autoFixRequest);
        } catch (err) {
          logger.error(`[AutoFix] failed to generate single request for repo: ${repo.fullName}`, err);
        }
      }

      requests = requests.filter(i => i != undefined);

      if (requests.length > 0) {
        let i = 0;
        const chunks = this.splitToChunks(requests, repo);
        const proms = chunks.map(c => {
          i++;
          return this.sendAndWaitForRes(c as AutoFixRequest[], repo, i);
        });
        const resProms = await Promise.all(proms);

        let input = resProms.filter(i => i != null);
        input = input.flat();

        this.updateSecurityAlertsWithAutoFixInfo(input, securityAlerts, repo);
      }

      logger.info(
        `[AutoFix] finish set for repo: ${repo.fullName}, security alerts: ${securityAlerts.length}, requests: ${requests.length}`,
      );
    } catch (err) {
      logger.error(`[AutoFix] failed set for all security alerts for repo: ${repo.fullName}`, err);
    }
  }

  private updateSecurityAlertsWithAutoFixInfo(resOfAllAutoFixResults: AutoFixResponse[], alerts: SecurityEvent[], repo: Repo) {
    let attached = 0;
    let notFoundById = 0;

    try {
      logger.info(`[AutoFix] number of results before digest for repo: ${repo.fullName} count: ${resOfAllAutoFixResults.length}`);

      for (const autoFix of resOfAllAutoFixResults) {
        try {
          const singleAutoFixResponse: SecurityEvent = alerts.find(i => i.uid === autoFix.uid);
          if (singleAutoFixResponse == undefined) {
            logger.error(`[AutoFix] fail to find security alert for uid: ${autoFix.uid}, repo: ${repo.fullName}`);
            notFoundById++;
            continue;
          }

          attached++;
          singleAutoFixResponse.autoFixResponse = autoFix;
        } catch (err) {
          logger.error(`[AutoFix] fail single alert uid: ${autoFix.uid}, repo: ${repo.fullName}`, err);
        }
      }
    } catch (err) {
      logger.error(`[AutoFix] fail alerts for repo: ${repo.fullName}`, err);
    }
    logger.info(
      `[AutoFix] finish alerts for repo: ${repo.fullName}, attached: ${attached}, notFoundById: ${notFoundById}, total response: ${resOfAllAutoFixResults.length} for single chunk`,
    );
  }

  private async sendAndWaitForRes(requests: AutoFixRequest[], repo: Repo, index: number) {
    let data;
    const requestId = uuid.v4();

    try {
      if (requests.length == 0) {
        return null;
      }

      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;

      logger.info(`[AutoFix] sending request for repo: ${repo.fullName}, count: ${requests.length}`);

      let url = onSast ? process.env.AUTOFIX_SERVICE_SQS_URL : process.env.AUTOFIX_SERVICE_QUEUE_KEY;
      if (isk8) {
        url = process.env.AUTOFIX_SERVICE_QUEUE_KEY;
      }

      const dirToPutRes = `${repo.autoFixValidationDir}/${requestId}`;
      fs.mkdirSync(dirToPutRes, { recursive: true });

      const filePathRequest = `${dirToPutRes}/autoFixRequest.json`;
      fs.writeFileSync(filePathRequest, JSON.stringify(requests));

      const filePathRes = `${dirToPutRes}/autoFix.json`;

      //If this is onPrem the zip folder is the actual code folder without a zip
      //If we are on SAST then we need the parent folder in case its mono repo and if not the regular repo
      let cloneDir = "";
      let toolCopyDestination = "";
      let monoRepoChildSubfolder = "";
      if (repo.realRepo) {
        cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;

        toolCopyDestination = repo.getRepoForToolsBasedOnEnv();
        if ((!process.env.DEBUG || process.env.DOCKER_DEBUG) && (!onPrem || isk8)) {
          toolCopyDestination = `${toolCopyDestination}/${index.toString()}`;
        }

        monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;
      }

      let command = this.getCommand(filePathRequest, dirToPutRes, toolCopyDestination);
      command = escapeCharsFromPath(command);

      const msg = {
        MessageId: requestId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "auto-fix-service",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 900000,
        orgDisplayName: process.env["companyName"],
        cloneDir: cloneDir,
        toolCopyDestination: toolCopyDestination,
        isMonoRepoChild: repo.monoRepoChild,
        monoRepoChildSubfolder: monoRepoChildSubfolder,
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: repo.ignoredMonoRepoChildrenSubfolders,
        putInQueueTime: new Date().getTime(),
        shouldSkipLocalCopy: true,
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(
        `[AutoFix] about to send msg to queue for repo: ${repo.fullName}, num of requests: ${requests.length}, msg: ${JSON.stringify(msg)}`,
      );
      this.copyToolResults({ repoName: repo.name, dir: filePathRequest });
      //From Debug(shell)
      if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
        const reqRes = await this.runShell(repo.name, msg.localCommand);
        const data = fs.readFileSync(filePathRes, "utf8");
        const autofixRes = JSON.parse(data);
        return autofixRes;
      }

      //From SAST(sqs)
      const reqRes = await this.AutoFixHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        ToolsExecutionStats.addExecutionStateOnFail(
          requestId,
          OXtools.autoFix,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          -1,
          ToolError.SendToQueue,
        );

        repo.addFailedSecurityTools(OXtools.autoFix);
        return null;
      }

      logger.info(
        `[AutoFix] about to start waiting for repo: ${repo.fullName}, num of requests: ${requests.length}, msg: ${JSON.stringify(msg)}`,
      );

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromAutoFix = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 15; // 60 seconds * 15 = 15 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.autoFix,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );

          StatesHelper.Instance.scanInfoStats.failedAutoFixTimeout++;
          StatesHelper.Instance.scanInfoStats.failedAutoFixTimeoutRepoNames.push(repo.name);

          repo.addFailedSecurityTools(OXtools.autoFix);
          return null;
        }

        //Failed from auto fix
        if (fs.existsSync(failedFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.autoFix,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.ResFileNotFound,
          );

          StatesHelper.Instance.scanInfoStats.failedAutoFixBatches++;
          StatesHelper.Instance.scanInfoStats.failedAutoFixRepoNames.push(repo.name);

          repo.addFailedSecurityTools(OXtools.autoFix);
          return null;
        }

        //Done from auto fix
        if (fs.existsSync(doneFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `[AutoFix] done file discovered from response, repo: ${repo.fullName}, num of requests: ${requests.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromAutoFix = true;
          break;
        }

        //10 seconds
        await setTimeout(10 * 1000);
        counter--;
      }

      if (!fs.existsSync(filePathRes)) {
        let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
        ToolsExecutionStats.addExecutionStateOnFail(
          requestId,
          OXtools.autoFix,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );

        StatesHelper.Instance.scanInfoStats.failedAutoFixBatches++;
        StatesHelper.Instance.scanInfoStats.failedAutoFixRepoNames.push(repo.name);

        repo.addFailedSecurityTools(OXtools.autoFix);
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      data = fs.readFileSync(filePathRes, "utf8");
      const autoFixRes = JSON.parse(data);
      this.copyToolResults({ repoName: repo.name, dir: filePathRes });

      //Delete after reading
      this.fileHelper.deleteFile(filePathRes);
      this.fileHelper.deleteFile(filePathRequest);

      const failed = new Set<string>();
      ToolsExecutionStats.addToExecutionStatsFromFile(
        doneFilePath,
        requestId,
        OXtools.autoFix,
        repo.fullName,
        repo.id,
        "repo",
        repo.cloneDir,
        failed,
      );
      if (failed.size > 0) {
        repo.addFailedSecurityTools(OXtools.autoFix);
        return null;
      }

      logger.info(
        `[AutoFix] finish waiting for repo: ${repo.fullName}, num of requests: ${requests.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, auto fix res number: ${autoFixRes.length}, counter: ${counter}`,
      );

      return autoFixRes;
    } catch (err) {
      logger.error(`[AutoFix] failed to send batch of security alerts for repo: ${repo.fullName}, data: ${data}`, err);

      repo.addFailedSecurityTools(OXtools.autoFix);
      ToolsExecutionStats.addExecutionStateOnFail(requestId, OXtools.autoFix, repo.fullName, repo.id, "repo", "", -1, ToolError.Generic);

      StatesHelper.Instance.scanInfoStats.failedAutoFixBatches++;
      StatesHelper.Instance.scanInfoStats.failedAutoFixRepoNames.push(repo.name);
    }

    return null;
  }

  splitToChunks(array, repo: Repo) {
    const chunkSize = process.env.DEBUG && !process.env.DOCKER_DEBUG ? 20000 : 5000;
    const chunks: any[] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      const c = array.slice(i, i + chunkSize);
      chunks.push(c);
    }
    return chunks;
  }

  async runShell(requesterName: string, command: string) {
    try {
      await this.shell(requesterName, command);
      return true;
    } catch (err) {
      logger.error(`[AutoFix] failed run shell command: ${command} to run`, err);
    }
    return false;
  }

  async shell(requesterName, command: string) {
    try {
      logger.info(`[AutoFix] try run from shell, repo: ${requesterName}: cmd: ${command}`);

      const { stdout, stderr } = await exec(command, {
        maxBuffer: 1024 * 1024 * 10,
        env: { ...process.env, FOO: "ah" },
      });
      logger.debug(`stdout:, ${JSON.stringify(stdout, null, 4)}`);
      logger.debug(`stderr:, ${JSON.stringify(stderr, null, 4)}`);
    } catch (err) {
      logger.error(
        `[AutoFix] shell command: ${command} failed to run error: ${err} stdout: ${err.stdout + "\n"} stderr: ${err.stderr + "\n"}`,
        err,
      );

      logger.info(`[AutoFix] finish run from shell, requester name: ${requesterName} cmd: ${command}`);
    }
  }

  copyToolResults({ repoName, dir }: { repoName: string; dir: string }): void {
    if (isUploadToS3()) {
      const oxDir = getSharedFolder(this.uuid) + "/ox-security";
      const telemetryDir = oxDir + "/telemetry-" + this.uuid;
      const repoDir = telemetryDir + "/security-report/" + repoName;
      const toolDir = repoDir + "/autoFix";

      try {
        if (!fs.existsSync(toolDir)) {
          fs.mkdirSync(toolDir, { recursive: true });
        }
        this.fileHelper.copyFileSync(dir, toolDir);
      } catch (err) {
        logger.error(`[AutoFix] failed to copy tool result file for repo name ${repoName}`, err);
      }
    }
  }

  getCommand(requestPath: string, outputDir: string, repoDir: string) {
    if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
      return `python ${process.env.AUTO_FIX_PATH} --events-path ${requestPath} --output-dir ${outputDir} --lazy`;
    }
    return `python /src/autofix_cli.py --events-path ${requestPath} --output-dir ${outputDir} --lazy`;
  }
}

export default AutoFixHelper;
