import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { Repo, VCSType } from "../../entitis/codeRepoTypes";
import { OXtools } from "../../entitis/constant";
import loggerImport from "../../logger";
import { copyToolInfo, escapeCharsFromPath, sleep } from "../commonUtils";
import { isDevelopment } from "../envUtils";
import { replaceAll } from "../generalUtils";
import FileHelper from "../IO/fileHlper";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds, ScanErrorName, sendScannerRepoErrorTelemetry } from "../telemetry-utils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";

const uuidObj = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();
const sharedDir = process.env.OX_SHARED_DATA === "undefined" ? "/var/shared-data" : process.env.OX_SHARED_DATA;

class LlmClientBase {
  serviceHelperQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;
  appName: string;
  repo: Repo;
  inputFileName: string;
  dirToPutRes: string;
  uniqueId: string;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.serviceHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);

    this.uniqueId = uuidObj.v4();
    const serviceDir = `${sharedDir}/${this.orgName}/scan_${replaceAll(this.uuid, "-", "_")}/llmClient`;

    //need to call s.mkdirSync(this.dirToPutRes, { recursive: true }); before calling sendAndWaitForRes
    this.dirToPutRes = `${serviceDir}/${this.uniqueId}`;
    this.inputFileName = `${this.dirToPutRes}/llmClientInput.json`;
  }

  async sendAndWaitForRes() {
    logger.info(`[${this.constructor.name}] calling service for: repo:${this.appName}`);
    try {
      let url = process.env.LLMCLIENT_QUEUE_KEY;
      if (!url && !process.env.DEBUG) {
        return null;
      }

      const filePathRes = `${this.dirToPutRes}/llmClient.json`;

      let command = this.getCommand(this.dirToPutRes, this.inputFileName);
      command = escapeCharsFromPath(command);
      copyToolInfo(this.repo.name, this.inputFileName, this.constructor.name, this.uuid);

      const msg = {
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "llm-client",
        repoName: this.repo.fullName,
        resultPath: filePathRes,
        timeout: 1800000,
        orgDisplayName: process.env["companyName"],
        cloneDir: "",
        copyType: CopyType.LeanCodeOnly,
        toolCopyDestination: "",
        isMonoRepoChild: "",
        monoRepoChildSubfolder: "",
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: "",
        putInQueueTime: new Date().getTime(),
        shouldSkipLocalCopy: true,
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(
        `[${this.constructor.name}] about to send msg to queue, repo:${this.appName}, uniqueId: ${this.uniqueId}, msg: ${JSON.stringify(
          msg,
        )}`,
      );

      const reqRes = await this.serviceHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        this.repo.addFailedSecurityTools(OXtools.llmClient);
        ToolsExecutionStats.addExecutionStateOnFail(
          this.uniqueId,
          OXtools.llmClient,
          this.repo.fullName,
          this.repo.id,
          "repo",
          this.dirToPutRes,
          -1,
          ToolError.SendToQueue,
        );
        logger.error(
          `[${this.constructor.name}] failed enter item to Q, uniqueId: ${this.uniqueId}, repo:${this.repo.fullName}, msg: ${JSON.stringify(
            msg,
          )}`,
        );

        this.repo.addFailedSecurityTools(OXtools.llmClient);
        return null;
      }

      logger.info(
        `[${this.constructor.name}] about to start waiting for requests, uniqueId: ${this.uniqueId} repo:${
          this.repo.fullName
        }, msg: ${JSON.stringify(msg)}`,
      );

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${this.dirToPutRes}/.fail`;
      let doneFromLlmClient = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 30; // 60 seconds * 30 = 30 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          this.repo.addFailedSecurityTools(OXtools.llmClient);
          ToolsExecutionStats.addExecutionStateOnFail(
            this.uniqueId,
            OXtools.llmClient,
            this.repo.fullName,
            this.repo.id,
            "repo",
            this.dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );
          let errInfo = `[${this.constructor.name}] failed set timeout, repo:${this.repo.fullName}, uniqueId: ${this.uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${this.dirToPutRes}`;
          logger.error(`${errInfo}`);
          StatesHelper.Instance.scanInfoStats.failedLlmClientTimeout++;
          StatesHelper.Instance.scanInfoStats.failedLlmClientTimeoutRepoNames.push(this.repo.name);
          await sendScannerRepoErrorTelemetry(ScanErrorName.FailedLlmClientTimeout, errInfo, this.orgName, this.uuid, this.uniqueId);

          this.repo.addFailedSecurityTools(OXtools.llmClient);
          return null;
        }

        //Failed from service
        if (fs.existsSync(failedFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          this.repo.addFailedSecurityTools(OXtools.llmClient);
          ToolsExecutionStats.addExecutionStateOnFail(
            this.uniqueId,
            OXtools.llmClient,
            this.repo.fullName,
            this.repo.id,
            "repo",
            this.dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.ResFileNotFound,
          );
          let errInfo = `[${this.constructor.name}] failed file discovered from service response, repo:${this.repo.fullName}, uniqueId: ${this.uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${this.dirToPutRes}`;
          logger.error(`${errInfo}`);
          StatesHelper.Instance.scanInfoStats.failedLlmClientBatches++;
          StatesHelper.Instance.scanInfoStats.failedLlmClientBatchesNames.push(this.repo.name);

          await sendScannerRepoErrorTelemetry(ScanErrorName.FailedLlmClientBatches, errInfo, this.orgName, this.uuid, this.uniqueId);

          this.repo.addFailedSecurityTools(OXtools.llmClient);
          return null;
        }

        //Done from service
        if (fs.existsSync(doneFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `[${this.constructor.name}] done file discovered from response, uniqueId: ${this.uniqueId}, repo:${this.repo.fullName}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${this.dirToPutRes}`,
          );
          doneFromLlmClient = true;
          break;
        }

        //10 seconds
        await sleep(10 * 1000);
        counter--;
      }

      await sleep(10 * 1000);
      if (!fs.existsSync(filePathRes)) {
        let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
        this.repo.addFailedSecurityTools(OXtools.llmClient);
        ToolsExecutionStats.addExecutionStateOnFail(
          this.uniqueId,
          OXtools.llmClient,
          this.repo.fullName,
          this.repo.id,
          "repo",
          this.dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );
        let errInfo = `[${this.constructor.name}] response file not exist on disk, repo: ${this.repo.fullName}, uniqueId: ${this.uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, done from Llm Client, done file: ${doneFromLlmClient}, dirToPutRes: ${this.dirToPutRes}`;
        logger.error(`${errInfo}`);
        StatesHelper.Instance.scanInfoStats.failedLlmClientBatches++;

        await sendScannerRepoErrorTelemetry(ScanErrorName.FailedLlmClientBatches, errInfo, this.orgName, this.uuid, this.uniqueId);

        this.repo.addFailedSecurityTools(OXtools.llmClient);
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      copyToolInfo(this.repo.name, filePathRes, this.constructor.name, this.uuid);
      logger.info(
        `[${this.constructor.name}] finish waiting, repo: ${this.repo.fullName}, uniqueId: ${this.uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${this.dirToPutRes}, counter: ${counter}`,
      );

      return filePathRes;
    } catch (err) {
      this.repo.addFailedSecurityTools(OXtools.llmClient);
      ToolsExecutionStats.addExecutionStateOnFail(
        this.uniqueId,
        OXtools.llmClient,
        this.repo.fullName,
        this.repo.id,
        "repo",
        "",
        -1,
        ToolError.Generic,
      );
      let errInfo = `[${this.constructor.name}] failed to send batch of request, repo: ${this.repo.fullName}, uniqueId: ${this.uniqueId}, err: ${err}`;
      logger.error(`${errInfo}`);
      await sendScannerRepoErrorTelemetry(ScanErrorName.FailedLlmClientBatches, errInfo, this.orgName, this.uuid, this.uniqueId);
      StatesHelper.Instance.scanInfoStats.failedLlmClientBatches++;

      this.repo.addFailedSecurityTools(OXtools.llmClient);
    }
  }

  getCommand(outputDir: string, inputFilePath: string) {
    let exec_path: string | undefined = "/src/llm_client_cli.py";
    if (process.env.DEBUG) {
      exec_path = process.env.LLM_CLIENT_PATH;
    }
    return `python ${exec_path} --output-dir ${outputDir} --events-path ${inputFilePath}`;
  }
}

export default LlmClientBase;
