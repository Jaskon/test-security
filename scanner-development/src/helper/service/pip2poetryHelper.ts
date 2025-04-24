import { exec } from "child_process";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { Repo, VCSType } from "../../entitis/codeRepoTypes";
import { OXtools } from "../../entitis/constant";
import { CliToolsImage, Pip2PoetryTypesResponse } from "../../entitis/service/pip2PoetryTypes";
import { getSharedFolder } from "../../helper/generalUtils";
import FileHelper from "../../helper/IO/fileHlper";
import loggerImport from "../../logger";
import { escapeCharsFromPath } from "../commonUtils";
import { isUploadToS3 } from "../envUtils";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";

const fs = require("fs");

const logger = loggerImport.getDebugLogger();
const sharedDir = process.env.OX_SHARED_DATA === "undefined" ? "/var/shared-data" : process.env.OX_SHARED_DATA;
const uuid = require("uuid");

class Pip2poetryHelper {
  pip2poetryHelperQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.pip2poetryHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
  }

  async setRepoPip2poetryHelperInfo(repo: Repo, cliToolsImages: CliToolsImage[]) {
    try {
      if (repo.vcsType === VCSType.tfvc) {
        return;
      }

      //This data needed for blame and we dont need blame in delta
      if (repo.isDelta) {
        logger.info(`skipping big pip2poetry, repo:${repo.fullName}`);
        return;
      }

      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;

      await this.sendAndWaitForRes(repo, cliToolsImages);

      logger.info(`finish get pip2poetry, repo:${repo.fullName}, cliToolsImages: ${cliToolsImages.join(", ")}`);
    } catch (err) {
      logger.error(`failed set all pip2poetry, repo:${repo.fullName}, err: ${err}`);
    }
  }

  private async sendAndWaitForRes(repo: Repo, cliToolsImages: CliToolsImage[]) {
    let uniqueId = uuid.v4();
    try {
      const dirToPutRes = `${repo.pipPoetryDir}/${uniqueId}`;
      fs.mkdirSync(dirToPutRes, { recursive: true });

      let url = process.env.PIP2POETRY_QUEUE_KEY;

      let cloneDir = "";
      let toolCopyDestination = "";
      let monoRepoChildSubfolder = "";
      if (repo.realRepo) {
        cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;
        toolCopyDestination = repo.getRepoForToolsBasedOnEnv();
        monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;
      }

      const filePathRes = `${dirToPutRes}/leanCodeDependencyTools.zip`;

      const extraDataInfo = monoRepoChildSubfolder ? `${cloneDir}/${monoRepoChildSubfolder}/extraData.json` : `${cloneDir}/extraData.json`;

      const fileOnDisk = monoRepoChildSubfolder
        ? `${cloneDir}/${monoRepoChildSubfolder}/leanCodeDependencyTools.zip`
        : `${cloneDir}/leanCodeDependencyTools.zip`;

      let command = this.getCommand(cloneDir, toolCopyDestination, monoRepoChildSubfolder);
      if (StatesHelper.Instance.isSofi) {
        command += " --scanners sca";
      }
      command = escapeCharsFromPath(command);

      const msg = {
        MessageId: uniqueId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "pip2poetry",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 1800000,
        orgDisplayName: process.env["companyName"],
        cloneDir: cloneDir,
        copyType: CopyType.CodeOnly,
        toolCopyDestination: toolCopyDestination,
        isMonoRepoChild: repo.monoRepoChild,
        monoRepoChildSubfolder: monoRepoChildSubfolder,
        shouldAdditionallyScanRootFiles: repo.monoRepoChild,
        ignoredSubfolders: repo.ignoredMonoRepoChildrenSubfolders,
        putInQueueTime: new Date().getTime(),
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = { url: url, msg: msg };

      logger.info(`about to send msg to queue for pip2poetry, repo:${repo.fullName}, uniqueId: ${uniqueId}, msg: ${JSON.stringify(msg)}`);

      if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
        const reqRes = await this.runShell(repo.name, msg.localCommand);
        await this.sleep();
        // if (fs.existsSync(filePathRes)) {
        // const data = fs.readFileSync(filePathRes, "utf8");
        // pip2poetryRes = JSON.parse(data);
        // }
        return filePathRes;
      }

      const reqRes = await this.pip2poetryHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        repo.addFailedSecurityTools(OXtools.pip2poetry);
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.pip2poetry,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          -1,
          ToolError.SendToQueue,
        );
        logger.error(`failed enter item to pip2poetry Q, uniqueId: ${uniqueId}, repo:${repo.fullName}, msg: ${JSON.stringify(msg)}`);
        return null;
      }

      logger.info(
        `about to start waiting for pip2poetry requests, uniqueId: ${uniqueId} repo:${repo.fullName}, msg: ${JSON.stringify(msg)}`,
      );

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromPip2poetry = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 30; // 60 seconds * 30 = 30 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          repo.addFailedSecurityTools(OXtools.pip2poetry);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.pip2poetry,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );
          StatesHelper.Instance.scanInfoStats.failedPip2poetryTimeout++;
          StatesHelper.Instance.scanInfoStats.failedPip2poetryTimeoutRepoNames.push(repo.name);
          return null;
        }

        //Failed from pip2poetry
        if (fs.existsSync(failedFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          repo.addFailedSecurityTools(OXtools.pip2poetry);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.pip2poetry,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.ResFileNotFound,
          );
          StatesHelper.Instance.scanInfoStats.failedPip2poetryBatches++;
          StatesHelper.Instance.scanInfoStats.failedPip2poetryBatchesNames.push(repo.name);
          return null;
        }

        //Done from pip2poetry
        if (fs.existsSync(doneFilePath)) {
          const failed = new Set<string>();
          ToolsExecutionStats.addToExecutionStatsFromFile(
            doneFilePath,
            uniqueId,
            OXtools.pip2poetry,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            failed,
          );
          if (failed.size > 0) {
            repo.addFailedSecurityTools(OXtools.pip2poetry);
            return null;
          }
          doneFromPip2poetry = true;
          break;
        }

        //10 seconds
        await this.sleep();
        counter--;
      }

      if (!doneFromPip2poetry && !fs.existsSync(fileOnDisk)) {
        let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
        repo.addFailedSecurityTools(OXtools.pip2poetry);
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.pip2poetry,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );
        StatesHelper.Instance.scanInfoStats.failedPip2poetryBatches++;
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

      //Parse additional info for performance boost
      const extraDataFileExist = fs.existsSync(extraDataInfo);
      try {
        if (extraDataFileExist) {
          const data = fs.readFileSync(extraDataInfo, "utf8");
          const pip2PoetryExtaDatRes: Pip2PoetryTypesResponse = JSON.parse(data);

          //Delete after reading
          this.copyToolResults({ repoName: repo.name, dir: extraDataInfo });
          this.fileHelper.deleteFile(extraDataInfo);

          const uniqueImages = new Set();
          if (pip2PoetryExtaDatRes?.snykImages?.length > 0 && StatesHelper.Instance.isSofi) {
            pip2PoetryExtaDatRes.snykImages.forEach(i => {
              if (uniqueImages.has(i.queueKey)) {
                logger.error(`duplicate queue key: ${JSON.stringify(i)}, repo:${repo.fullName}`);
                return;
              }

              uniqueImages.add(i.queueKey);
              cliToolsImages.push(i);
            });
            logger.info(
              `snykImages, repo: ${repo.fullName}, uniqueId: ${uniqueId}, snykImages: ${JSON.stringify(
                cliToolsImages,
              )}, dirToPutRes: ${dirToPutRes}`,
            );
          } else {
            logger.info(`snykImages, repo: ${repo.fullName}, no snykImages`);
          }
        }
      } catch (err) {
        repo.addFailedSecurityTools(OXtools.pip2poetry);
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.pip2poetry,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          -1,
          ToolError.Generic,
        );
        logger.error(`failed get Pip2PoetryTypesResponse: ${uniqueId}, repo:${repo.fullName}, msg: ${JSON.stringify(msg)}`);
      }

      logger.info(
        `finish waiting for pip2poetry, repo: ${
          repo.fullName
        }, extraDataFileExist: ${extraDataFileExist}, uniqueId: ${uniqueId}, repo ignored tools: ${repo.ignoredTools.join(
          ", ",
        )}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, counter: ${counter}`,
      );
    } catch (err) {
      logger.error(`failed to send batch of pip2poetry request, repo: ${repo.fullName}, uniqueId: ${uniqueId}, err: ${err}`);
      repo.addFailedSecurityTools(OXtools.pip2poetry);
      ToolsExecutionStats.addExecutionStateOnFail(uniqueId, OXtools.pip2poetry, repo.fullName, repo.id, "repo", "", -1, ToolError.Generic);
    }
  }

  getCommand(outputDir: string, repoDir: string, monoRepoChildSubfolder) {
    let exec_path: string | undefined = "/src/pip2poetry.py";
    if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
      exec_path = process.env.PIP2POETRY_PATH;
    }
    if (monoRepoChildSubfolder) {
      return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir} --monorepo ${monoRepoChildSubfolder}`;
    } else {
      return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir}`;
    }
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
      const toolDir = repoDir + "/pip2poetry";

      try {
        if (!fs.existsSync(toolDir)) {
          fs.mkdirSync(toolDir, { recursive: true });
        }
        this.fileHelper.copyFileSync(dir, toolDir);
      } catch (err) {
        logger.error(`failed to copy tool pip2poetry result file for repo name ${repoName}`);
      }
    }
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 10);
  }
}

export default Pip2poetryHelper;
