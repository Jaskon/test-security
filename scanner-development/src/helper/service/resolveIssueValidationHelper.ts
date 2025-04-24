const util = require("util");
const exec = util.promisify(require("child_process").exec);
import { OxCategoriesIds } from "@oxappsec/ox-consolidated-categories";
import { CategoryId } from "@oxappsec/ox-consolidated-categories/lib/src/ox-categories/types";
import { Application } from "../../appmgr/application";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { Repo } from "../../entitis/codeRepoTypes";
import { OXtools } from "../../entitis/constant";
import { RunTimeBaseDoc } from "../../entitis/service/autoFixTypes";
import loggerImport from "../../logger";
import MongoHelper from "../../mongo/mongoHelper";
import { Tool } from "../../policy/rules/code/policyRulesBase";
import { escapeCharsFromPath } from "../commonUtils";
import { isK8Mode, isLocalDevelopment } from "../envUtils";
import FileHelper from "../IO/fileHlper";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";
const onPrem = process.env.redisOnPrem != undefined;
const isk8 = isK8Mode();
const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();

class ResolveIssueValidationHelper {
  resolveIssuesHelperQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;
  mongoHelper: MongoHelper<RunTimeBaseDoc>;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.resolveIssuesHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
  }

  async sendToResolveIssues(app: Application, relevantApps: Set<string>) {
    let repoName;

    try {
      const repo: Repo = app.appInfo.repo.code_repo;

      if (!StatesHelper.Instance.isCharterBank) {
        if (repo.isDelta) {
          logger.info(`repo: ${repo.id} name: ${repo.fullName} is delta. skipping resolve issues`);
          return;
        }
        if (!relevantApps.has(repo.id)) {
          logger.info(`repo: ${repo.id} name: ${repo.fullName} is not relevant. skipping resolved issues`);
          return;
        }
      }

      repoName = repo.fullName;

      StatesHelper.Instance.scanInfoStats.resolveIssuesRepos++;

      logger.info(`try send to resolve issues repo: ${repo.fullName}`);
      await this.sendWithoutWaitForRes(repo);
      await this.waitForRes(repo);
      logger.info(`finish send to resolve issues repo: ${repo.fullName}`);
    } catch (err) {
      logger.error(`failed send to resolve issues for repo: ${repoName}, err: ${err}`);
    }
  }

  private async sendWithoutWaitForRes(repo: Repo) {
    let data;
    const uniqueId = uuid.v4();

    try {
      const url = process.env.RESOLVED_ISSUES_QUEUE;
      const { realRepo } = repo;

      const dirToPutRes = `${repo.resolveIssuesValidationDir}`;
      fs.mkdirSync(dirToPutRes, { recursive: true });

      const filePathRes = `${dirToPutRes}/resolveIssueValidation.json`;

      //If this is onPrem the zip folder is the actual code folder without a zip
      //If we are on SAST then we need the parent folder in case its mono repo and if not the regular repo
      let cloneDir = "";
      let toolCopyDestination = "";
      let monoRepoChildSubfolder = "";
      if (repo.realRepo) {
        cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;
        toolCopyDestination = repo.getRepoForToolsBasedOnEnv();
        if (!process.env.DEBUG && (!onPrem || isk8)) {
          toolCopyDestination = `${toolCopyDestination}/1`;
        }
        monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;
      }

      let command = this.getCommand(repo, toolCopyDestination, monoRepoChildSubfolder);

      command = escapeCharsFromPath(command);

      const msg = {
        MessageId: uniqueId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "resolve-issue-checker-service",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 900000,
        orgDisplayName: process.env["companyName"],
        cloneDir: cloneDir, // path to unzip folder?
        toolCopyDestination: toolCopyDestination,
        isMonoRepoChild: repo.monoRepoChild,
        monoRepoChildSubfolder: monoRepoChildSubfolder,
        shouldAdditionallyScanRootFiles: false,
        shouldSkipActiveScanCheck: StatesHelper.Instance.waitForResolveIssues,
        ignoredSubfolders: repo.ignoredMonoRepoChildrenSubfolders,
        putInQueueTime: new Date().getTime(),
        shouldSkipSSH: isLocalDevelopment(),
        copyType: CopyType.CodeOnly,
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };
      if (realRepo) {
        msg["shouldSkipUnzip"] = true;
      } else {
        msg["shouldSkipLocalCopy"] = true;
      }

      if (isLocalDevelopment()) {
        const reqRes = await this.runShell(repo.name, msg.localCommand);
        const data = fs.readFileSync(filePathRes, "utf8");
        const scaVerificationRes = JSON.parse(data);
        return scaVerificationRes;
      }

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(`about to send msg to queue for resolve issues validation, repo: ${repo.fullName}, resolve issue verification service`);

      const reqRes = await this.resolveIssuesHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.resolveIssue,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          -1,
          ToolError.SendToQueue,
        );
        logger.error(`failed enter item to resolve issues validation Q, repo: ${repo.fullName}, resolve issue verification service`);
        return null;
      }
    } catch (err) {
      let errInfo = `failed to send resolve issue verification service for repo: ${repo.fullName}, data: ${data}, err: ${err}`;
      ToolsExecutionStats.addExecutionStateOnFail(
        uniqueId,
        OXtools.resolveIssue,
        repo.fullName,
        repo.id,
        "repo",
        "",
        -1,
        ToolError.Generic,
      );
      logger.error(`${errInfo}`);
    }
    StatesHelper.Instance.scanInfoStats.failedResolvedIssuesValidation++;
  }

  private async runShell(requesterName: string, command: string) {
    try {
      await this.shell(requesterName, command);
      return true;
    } catch (err) {
      logger.error(`failed run shell command: ${command} to run err: ${err}`);
    }
    return false;
  }

  private async shell(requesterName, command: string) {
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

  private async waitForRes(repo: Repo) {
    const uniqueId = uuid.v4();

    try {
      if (!StatesHelper.Instance.waitForResolveIssues) {
        return;
      }

      logger.info(`start wait for resolve issues validation for: ${repo.fullName}`);

      const dirToPutRes = `${repo.resolveIssuesValidationDir}`;
      const filePathRes = `${dirToPutRes}/resolveIssueValidation.json`;

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromResolveIssueValidation = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 15; // 60 seconds * 5 = 5 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.resolveIssue,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );
          let errInfo = `failed set resolve issues validation due to timeout, repo: ${repo.fullName}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`;
          logger.error(`${errInfo}`);
          StatesHelper.Instance.scanInfoStats.failedResolvedIssuesValidationTimeout++;

          return null;
        }

        //Failed from resolve issues validation
        if (fs.existsSync(failedFilePath)) {
          //setToolInfoFromDoneFile(doneFilePath, this.orgName, this.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.resolveIssue,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.ResFileNotFound,
          );
          let errInfo = `failed file discovered from resolve issues validation service for resolve issues validation response, repo: ${repo.fullName}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`;
          logger.error(`${errInfo}`);
          StatesHelper.Instance.scanInfoStats.failedResolvedIssuesValidation++;

          return null;
        }

        //Done from resolve issues validation
        if (fs.existsSync(doneFilePath)) {
          //setToolInfoFromDoneFile(doneFilePath, this.orgName, this.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `done file discovered from resolve issues validation service response, repo: ${repo.fullName}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromResolveIssueValidation = true;
          break;
        }

        //10 seconds
        await this.sleep();
        counter--;
      }

      // if (!fs.existsSync(filePathRes)) {
      //   let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      //   //Dvir uncomment when u ready
      //   let errInfo = `response file from resolve issues validation not exist on disk, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, done from resolve issues validation: ${doneFromResolveIssueValidation}, repo: ${repo.fullName}, dirToPutRes: ${dirToPutRes}`;
      //   logger.error(`${errInfo}`);
      //   StatesHelper.Instance.scanInfoStats.failedResolvedIssuesValidation++;

      //   await sendScannerRepoErrorTelemetry(ScanErrorName.FailedResolveIssueValidation, errInfo, this.orgName, this.uuid, repo.fullName);
      //   return null;
      // }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

      logger.info(
        `finish waiting for resolve issues validation, repo: ${repo.fullName}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, counter: ${counter}`,
      );
    } catch (err) {
      ToolsExecutionStats.addExecutionStateOnFail(
        uniqueId,
        OXtools.resolveIssue,
        repo.fullName,
        repo.id,
        "repo",
        "",
        -1,
        ToolError.Generic,
      );
      logger.error(`failed wait for repo: ${repo.fullName}, err: ${err}`);
    }
  }

  private getCommand(repo: Repo, toolCopyDestination: string, monoRepoChildSubfolder: string) {
    let toolsAsString = "";
    const failedTools: Tool[] = [];
    const failedToolsMap = StatesHelper.Instance.failedToolsMap.get(repo.id);
    if (failedToolsMap) {
      failedTools.push(...failedToolsMap);
    }

    if (StatesHelper.Instance.failedExternalTools) {
      failedTools.push(...StatesHelper.Instance.failedExternalTools);
    }
    if (StatesHelper.Instance.globalApisFails) {
      failedTools.push(...StatesHelper.Instance.globalApisFails);
    }
    if (failedTools.length === 0 && StatesHelper.Instance.failedArtifactsScan.size === 0) {
      toolsAsString = "NONE";
    } else {
      for (const tool of failedTools) {
        toolsAsString = toolsAsString + ` ${tool}`;
      }
      for (const atrifact of StatesHelper.Instance.failedArtifactsScan) {
        toolsAsString = toolsAsString + ` ${atrifact}`;
      }
    }

    const mongoUri = process.env.MONGODB_URI;
    let modifiedMongoUri = mongoUri.split("?")[0];
    let { realRepo, monoRepoChild } = repo;
    if (realRepo === undefined) {
      realRepo = false;
      monoRepoChild = false;
    }
    let toolCopyDest: string = toolCopyDestination || "NONE";
    let monoRepoChildSubfolderParam: string = monoRepoChildSubfolder || "NONE";
    let monoRepoChildParam = monoRepoChild ?? false;
    let appId = repo.id;
    if (!realRepo) {
      toolCopyDest = "NONE";
      monoRepoChildSubfolderParam = "NONE";
    }
    const appIdEncrypted = encryptToBase64(appId);

    const envVarString = this.envValuesForResolvedIssues.join(" ");
    const categoriesString = this.ResolvedIssuecategories.join(",");

    const command = `MONGODB_URI=${modifiedMongoUri} ${envVarString} /usr/local/bin/node /app/dist/main.js ${this.orgName} ${
      this.uuid
    } ${appIdEncrypted} ${String(realRepo)} ${String(
      monoRepoChildParam,
    )} ${toolCopyDest} ${monoRepoChildSubfolderParam} ${categoriesString} ${toolsAsString}`; // "trivy" "semgrep"
    return command;
  }

  private get ResolvedIssuecategories(): CategoryId[] {
    const categories: CategoryId[] = [
      OxCategoriesIds.CodeSecurity,
      OxCategoriesIds.SecretScan,
      OxCategoriesIds.IaC,
      OxCategoriesIds.OpenSourceSecurity,
      OxCategoriesIds.SBOM,
      OxCategoriesIds.CICDSecurity,
      OxCategoriesIds.DevProccess,
      OxCategoriesIds.CloudSecurity,
    ];

    if (StatesHelper.Instance.containerSecResolvedIssuesEnabled) {
      categories.push(OxCategoriesIds.ContainerSecurity);
    }

    return categories;
  }

  private get envValuesForResolvedIssues(): string[] {
    const envKeyNames = [
      "SERVER_ENVIRONMENT",
      "REPORT_SERVICE_HOST_URL",
      "AUTH0_BASE_URL",
      "AUTH0_BACK_2_BACK_API_CLIENT_ID",
      "AUTH0_BACK_2_BACK_API_CLIENT_SECRET",
      "AUTH0_BACK_2_BACK_API_AUDIENCE",
      "AUTH0_GRANT_TYPE",
      "REDIS_HOST",
      "REDIS_PORT",
    ];

    const envValues = envKeyNames.map(keyName => `${keyName}=${process.env[keyName]}`);
    return envValues;
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 10);
  }
}

export default ResolveIssueValidationHelper;

const encryptToBase64 = (text: string) => {
  try {
    const buffer = Buffer.from(text, "utf-8");
    const base64 = buffer.toString("base64");
    return base64;
  } catch (error) {
    console.error("Encryption failed:", error);
    return null;
  }
};
