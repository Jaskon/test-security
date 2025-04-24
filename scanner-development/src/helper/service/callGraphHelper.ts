import { exec } from "child_process";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { Repo } from "../../entitis/codeRepoTypes";
import { OXtools } from "../../entitis/constant";
import FileHelper from "../../helper/IO/fileHlper";
import loggerImport from "../../logger";
import { escapeCharsFromPath } from "../commonUtils";
import { isK8Mode, isUploadToS3 } from "../envUtils";
import { getSharedFolder, replaceAll } from "../generalUtils";
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
const sharedDir = process.env.OX_SHARED_DATA === "undefined" ? "/var/shared-data" : process.env.OX_SHARED_DATA;

class CallGraphHelper {
  callGraphHelperQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;
  filePathResForCallGraph: string;
  dirToPutResForCallGraph: string;
  uniqueIdForCallGraph: string;
  resExist: boolean = false;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.callGraphHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
  }

  async sendRepoCallGraphInfo(repo: Repo) {
    try {
      if (StatesHelper.Instance.isWalmart) {
        return;
      }

      if (StatesHelper.Instance.isPipelineScan || process.env.SKIP_CALL_GRAPH) {
        return;
      }

      if (!StatesHelper.Instance.isCallGraphEnable) {
        logger.info(`sendRepoCallGraphInfo call graph is disabled`);
        return;
      }

      //This data needed for blame and we dont need blame in delta
      if (repo.isDelta) {
        logger.info(`skipping call graph, repo:${repo.fullName}`);
        return;
      }

      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;

      await this.sendReq(repo);
    } catch (err) {
      logger.error(`failed set all call graph, repo:${repo.fullName}, err: ${err}`);
    }
  }

  async waitForRes(repo: Repo) {
    let uniqueId;

    try {
      if (StatesHelper.Instance.isWalmart) {
        return;
      }

      if (StatesHelper.Instance.isPipelineScan || process.env.SKIP_CALL_GRAPH) {
        return;
      }

      if (!StatesHelper.Instance.isCallGraphEnable) {
        logger.info(`waitForRes call graph is disabled`);
        return;
      }

      if (repo.isDelta) {
        logger.info(`skipping waiting for call graph due to delta, repo:${repo.fullName}`);
        return;
      }

      if (!this.uniqueIdForCallGraph) {
        logger.info(`skipping waiting for call graph no uniqueIdForCallGraph, repo:${repo.fullName}`);
        return;
      }

      const filePathRes = this.filePathResForCallGraph;
      const dirToPutRes = this.dirToPutResForCallGraph;
      const failedFilePath = `${dirToPutRes}/.fail`;
      const doneFilePath = `${this.filePathResForCallGraph}.done`;
      uniqueId = this.uniqueIdForCallGraph;
      let doneFromCallGraph = false;

      logger.info(
        `about to start waiting for call graph requests, uniqueId: ${uniqueId} repo:${repo.fullName}, dirToPutRes: ${dirToPutRes}`,
      );

      const startProcessTime = new Date().getTime();

      let counter = 6 * 30; // 60 seconds * 30 = 30 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          repo.addFailedSecurityTools(OXtools.callGraph);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.callGraph,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );
          let errInfo = `failed set call graph timeout, repo:${repo.fullName}, uniqueId: ${uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`;
          logger.error(`${errInfo}`);
          StatesHelper.Instance.scanInfoStats.failedCallGraphTimeout++;
          StatesHelper.Instance.scanInfoStats.failedCallGraphTimeoutRepoNames.push(repo.name);
          return;
        }

        //Failed from call graph
        if (fs.existsSync(failedFilePath)) {
          //setToolInfoFromDoneFile(doneFilePath, this.orgName, this.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          repo.addFailedSecurityTools(OXtools.callGraph);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.callGraph,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.ResFileNotFound,
          );
          let errInfo = `failed file discovered from call graph service response, repo:${repo.fullName}, uniqueId: ${uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`;
          logger.error(`${errInfo}`);
          StatesHelper.Instance.scanInfoStats.failedCallGraphBatches++;
          StatesHelper.Instance.scanInfoStats.failedCallGraphBatchesNames.push(repo.name);

          return;
        }

        //Done from call graph
        if (fs.existsSync(doneFilePath)) {
          //setToolInfoFromDoneFile(doneFilePath, this.orgName, this.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `done file discovered from call graph response, uniqueId: ${uniqueId}, repo:${repo.fullName}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromCallGraph = true;
          break;
        }

        //10 seconds
        await this.sleep();
        counter--;
      }

      await this.sleep();
      if (!fs.existsSync(filePathRes)) {
        let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
        repo.addFailedSecurityTools(OXtools.callGraph);
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.callGraph,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );
        let errInfo = `response file from call graph not exist on disk, repo: ${repo.fullName}, uniqueId: ${uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, done from call graph, done file: ${doneFromCallGraph}, dirToPutRes: ${dirToPutRes}`;
        logger.error(`${errInfo}`);
        StatesHelper.Instance.scanInfoStats.failedCallGraphBatches++;

        return;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      this.copyToolResults({ repoName: repo.name, dir: filePathRes });

      logger.info(
        `finish waiting for call graph, repo: ${repo.fullName}, uniqueId: ${uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, counter: ${counter}`,
      );

      ToolsExecutionStats.addToExecutionStatsFromFile(
        filePathRes,
        uniqueId,
        OXtools.callGraph,
        repo.fullName,
        repo.id,
        "repo",
        repo.cloneDir,
        new Set<string>(),
      );

      this.resExist = true;
    } catch (err) {
      let errInfo = `failed to wait for batch of call graph request, repo: ${repo.fullName}, uniqueId: ${uniqueId}, err: ${err}`;
      repo.addFailedSecurityTools(OXtools.callGraph);
      ToolsExecutionStats.addExecutionStateOnFail(uniqueId, OXtools.callGraph, repo.fullName, repo.id, "repo", "", -1, ToolError.Generic);
      logger.error(`${errInfo}`);
    }
  }

  private async sendReq(repo: Repo) {
    logger.info(`running callGraph for: ${this.orgName}`);
    const callGraphDir = `${sharedDir}/${this.orgName}/scan_${replaceAll(this.uuid, "-", "_")}/callGraph`;
    const uniqueId = uuid.v4();

    try {
      const url = process.env.CALL_GRAPH_QUEUE_KEY;

      if (!url && !process.env.DEBUG) {
        return null;
      }

      this.dirToPutResForCallGraph = `${callGraphDir}/${uniqueId}`;
      fs.mkdirSync(this.dirToPutResForCallGraph, { recursive: true });

      this.filePathResForCallGraph = `${this.dirToPutResForCallGraph}/callGraph.json`;

      let cloneDir = "";
      let toolCopyDestination = "";
      let monoRepoChildSubfolder = "";
      if (repo.realRepo) {
        cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;

        toolCopyDestination = repo.getRepoForToolsBasedOnEnv();

        monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;
      }

      let command = this.getCommand(this.dirToPutResForCallGraph, toolCopyDestination, monoRepoChildSubfolder);
      command = escapeCharsFromPath(command);

      const msg = {
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "call-graph",
        repoName: repo.fullName,
        resultPath: this.filePathResForCallGraph,
        timeout: 1800000,
        orgDisplayName: process.env["companyName"],
        cloneDir: cloneDir,
        copyType: CopyType.CodeOnly,
        toolCopyDestination: toolCopyDestination,
        isMonoRepoChild: repo.monoRepoChild,
        monoRepoChildSubfolder: monoRepoChildSubfolder,
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: repo.ignoredMonoRepoChildrenSubfolders,
        putInQueueTime: new Date().getTime(),
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(`about to send msg to queue for call graph, repo:${repo.fullName}, uniqueId: ${uniqueId}, msg: ${JSON.stringify(msg)}`);

      if (process.env.DEBUG) {
        const reqRes = await this.runShell(repo.name, msg.localCommand);
        await this.sleep();
        await this.sleep();
      }

      const reqRes = await this.callGraphHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        repo.addFailedSecurityTools(OXtools.callGraph);
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.callGraph,
          repo.fullName,
          repo.id,
          "repo",
          "",
          -1,
          ToolError.SendToQueue,
        );
        logger.error(`failed enter item to call graph Q, uniqueId: ${uniqueId}, repo:${repo.fullName}, msg: ${JSON.stringify(msg)}`);
        return null;
      }

      this.uniqueIdForCallGraph = uniqueId;
    } catch (err) {
      let errInfo = `failed to send batch of call graph request, repo: ${repo.fullName}, uniqueId: ${uniqueId}, err: ${err}`;
      logger.error(`${errInfo}`);
    }
    StatesHelper.Instance.scanInfoStats.failedCallGraphBatches++;
  }

  getCommand(outputDir: string, repoDir: string, monoRepoChildSubfolder) {
    let exec_path: string | undefined = "/src/call-graph.py";
    if (process.env.DEBUG) {
      exec_path = process.env.CALL_GRAPH_PATH;
      if (monoRepoChildSubfolder) {
        return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir} --monorepo ${monoRepoChildSubfolder}`;
      } else {
        return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir}`;
      }
    }
    return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir}`;
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
      const toolDir = repoDir + "/callGraph";

      try {
        if (!fs.existsSync(toolDir)) {
          fs.mkdirSync(toolDir, { recursive: true });
        }
        this.fileHelper.copyFileSync(dir, toolDir);
      } catch (err) {
        logger.error(`failed to copy tool callG result file for repo name ${repoName}`);
      }
    }
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 10);
  }
}

export default CallGraphHelper;
