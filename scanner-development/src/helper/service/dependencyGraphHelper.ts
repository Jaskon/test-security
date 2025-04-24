import { exec } from "child_process";
import { setTimeout } from "node:timers/promises";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { File, Repo, VCSType } from "../../entitis/codeRepoTypes";
import { OXtools } from "../../entitis/constant";
import loggerImport from "../../logger";
import { copyToolInfo, escapeCharsFromPath } from "../commonUtils";
import { isK8Mode } from "../envUtils";
import { replaceAll } from "../generalUtils";
import Iqueue from "../queue/Iqueue";
import StatesHelper, { PerformanceType } from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";
import AlertDepJacking from "./alertDepJacking";

const onSast = process.env.MONGO_CONN === "atlas";
const isk8 = isK8Mode();
const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();
const sharedDir = process.env.OX_SHARED_DATA === "undefined" ? "/var/shared-data" : process.env.OX_SHARED_DATA;

class DependencyGraphHelper {
  dependencyGraphHelperQ: Iqueue;
  depJackingQueue: Iqueue;
  uuid: string;
  orgName: string;
  alertDepJacking: AlertDepJacking;

  constructor(queue: Iqueue, depJackingQueue: Iqueue, uuid: string, orgName: string) {
    this.dependencyGraphHelperQ = queue;
    this.depJackingQueue = depJackingQueue;
    this.uuid = uuid;
    this.orgName = orgName;

    this.alertDepJacking = new AlertDepJacking(queue, this.uuid, this.orgName);
  }

  async setRepoDependencyGraphInfo(repo: Repo, repoObj: any, files: File[]) {
    try {
      const isFastScan = StatesHelper.Instance.pipelineScanInfo.performance === PerformanceType.fast;
      const isFastestScan = StatesHelper.Instance.pipelineScanInfo.performance === PerformanceType.fastest;
      const canRunFastScan = StatesHelper.Instance.canRunFastPipelineScan;
      const canRunFastestScan = StatesHelper.Instance.canRunFastestPipelineScan;

      if (StatesHelper.Instance.isPipelineScan && ((isFastScan && canRunFastScan) || (isFastestScan && canRunFastestScan))) {
        logger.info(
          `skipping dependecy graph check during ${StatesHelper.Instance.pipelineScanInfo.performance} mode on pipeline scan over repo - ${repo.fullName}`,
        );
        return;
      }

      if (repo.vcsType === VCSType.tfvc) {
        return;
      }

      //This data needed for blame and we dont need blame in delta
      if (repo.isDelta) {
        logger.info(`skipping big dependency graph, repo:${repo.fullName}`);
        return;
      }

      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;

      logger.info(`try get dependency graph, repo:${repo.fullName}`);
      repo.dependencyGraphInfoPath = await this.sendAndWaitForRes(repo);
      logger.info(`finish get dependency graph, repo:${repo.fullName}`);

      await this.alertDepJacking.setAlertDepJacking(repo, repoObj, files);
    } catch (err) {
      logger.error(`failed set all dependency graph, repo:${repo.fullName}, err: ${err}`);
    }
  }

  private async sendAndWaitForRes(repo: Repo) {
    const dependencyGraphDir = `${sharedDir}/${this.orgName}/scan_${replaceAll(this.uuid, "-", "_")}/dependencyGraph`;
    const uniqueId = uuid.v4();
    let dependencyGraphRes = [];
    try {
      let url = onSast ? process.env.DEPENDENCY_GRAPH_SQS_URL : process.env.DEPENDENCY_GRAPH_QUEUE_KEY;
      if (isk8 || process.env.DOCKER_DEBUG) {
        url = process.env.DEPENDENCY_GRAPH_QUEUE_KEY;
      }

      if (!url && !process.env.DEBUG) {
        return null;
      }

      const dirToPutRes = `${dependencyGraphDir}/${uniqueId}`;
      fs.mkdirSync(dirToPutRes, { recursive: true });

      const filePathRes = `${dirToPutRes}/dependencyGraph.json`;

      let cloneDir = "";
      let toolCopyDestination = "";
      let monoRepoChildSubfolder = "";
      if (repo.realRepo) {
        cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;

        toolCopyDestination = repo.getRepoForToolsBasedOnEnv();

        monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;
      }

      let command = this.getCommand(dirToPutRes, toolCopyDestination, cloneDir, monoRepoChildSubfolder);
      command = escapeCharsFromPath(command);

      let copyType = CopyType.LeanCodeOnly;
      let path = "";
      if (monoRepoChildSubfolder) {
        path = `${cloneDir}/${monoRepoChildSubfolder}/leanCodeDependencyTools.zip`;
      } else {
        path = `${cloneDir}/leanCodeDependencyTools.zip`;
      }
      if (fs.existsSync(path)) {
        const stats = fs.statSync(path);
        if (stats.size < 100) {
          logger.info(`skipping dependency-graph, ${path} size = ${stats.size}`);
          return null;
        }
        copyType = CopyType.LeanCodeDependencyToolsOnly;
      }

      const msg = {
        MessageId: uniqueId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "dependency-graph",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 1800000,
        orgDisplayName: process.env["companyName"],
        cloneDir: cloneDir,
        copyType: copyType,
        toolCopyDestination: toolCopyDestination,
        isMonoRepoChild: repo.monoRepoChild,
        monoRepoChildSubfolder: monoRepoChildSubfolder,
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: repo.ignoredMonoRepoChildrenSubfolders,
        putInQueueTime: new Date().getTime(),
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = { url, msg };

      logger.info(
        `about to send msg to queue for dependency graph, repo:${repo.fullName}, uniqueId: ${uniqueId}, msg: ${JSON.stringify(msg)}`,
      );

      if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
        const reqRes = await this.runShell(repo.name, msg.localCommand);
        await setTimeout(10 * 1000);
        return filePathRes;
      }

      const reqRes = await this.dependencyGraphHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        repo.addFailedSecurityTools(OXtools.dependencyG);
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.dependencyG,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          -1,
          ToolError.SendToQueue,
        );
        logger.error(`failed enter item to dependency graph Q, uniqueId: ${uniqueId}, repo:${repo.fullName}, msg: ${JSON.stringify(msg)}`);
        return null;
      }

      logger.info(
        `about to start waiting for dependency graph requests, uniqueId: ${uniqueId} repo:${repo.fullName}, msg: ${JSON.stringify(msg)}`,
      );

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromDependencyGraph = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 30; // 60 seconds * 30 = 30 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          StatesHelper.Instance.scanInfoStats.failedDependencyGraphTimeout++;
          StatesHelper.Instance.scanInfoStats.failedDependencyGraphTimeoutRepoNames.push(repo.name);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          repo.addFailedSecurityTools(OXtools.dependencyG);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.dependencyG,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );
          return null;
        }

        //Failed from dependency graph
        if (fs.existsSync(failedFilePath)) {
          StatesHelper.Instance.scanInfoStats.failedDependencyGraphBatches++;
          StatesHelper.Instance.scanInfoStats.failedDependencyGraphBatchesNames.push(repo.name);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          repo.addFailedSecurityTools(OXtools.dependencyG);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.dependencyG,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.FailedFileFound,
          );
          return null;
        }

        //Done from dependency graph
        if (fs.existsSync(doneFilePath)) {
          const failed = new Set<string>();
          ToolsExecutionStats.addToExecutionStatsFromFile(
            doneFilePath,
            uniqueId,
            OXtools.dependencyG,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            failed,
          );
          if (failed.size > 0) {
            repo.addFailedSecurityTools(OXtools.dependencyG);
            return null;
          }
          doneFromDependencyGraph = true;
          break;
        }

        //10 seconds
        await setTimeout(10 * 1000);
        counter--;
      }

      await setTimeout(10 * 1000);
      if (!fs.existsSync(filePathRes)) {
        StatesHelper.Instance.scanInfoStats.failedDependencyGraphBatches++;
        let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

        repo.addFailedSecurityTools(OXtools.dependencyG);
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.dependencyG,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

      logger.info(
        `finish waiting for dependency graph, repo: ${repo.fullName}, uniqueId: ${uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, counter: ${counter}, graphs count: ${dependencyGraphRes.length} graphCount: ${dependencyGraphRes.length}`,
      );
      copyToolInfo(repo.name, filePathRes, "dependencyGraph", this.uuid);
      return filePathRes;
    } catch (err) {
      repo.addFailedSecurityTools(OXtools.dependencyG);
      ToolsExecutionStats.addExecutionStateOnFail(uniqueId, OXtools.dependencyG, repo.fullName, repo.id, "repo", "", -1, ToolError.Generic);
      StatesHelper.Instance.scanInfoStats.failedDependencyGraphBatches++;
      logger.error(`failed to send batch of dependency graph request, repo: ${repo.fullName}, uniqueId: ${uniqueId}, err: ${err}`);
    }
  }

  getCommand(outputDir: string, repoDir: string, cloneDir: string, monoRepoChildSubfolder: string) {
    let exec_path = "/src/dependency-graph.py";
    if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
      exec_path = process.env.DEPENDENCY_GRAPH_PATH;
    }
    if (monoRepoChildSubfolder) {
      return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir} --monorepo ${monoRepoChildSubfolder} --zip-dir ${cloneDir}`;
    } else {
      return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir} --zip-dir ${cloneDir}`;
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
}

export default DependencyGraphHelper;
