const util = require("util");
const exec = util.promisify(require("child_process").exec);
import { addSeverityChangedReason, Repo, SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { Dictionary } from "../../entitis/commonTypes";
import { OXtools } from "../../entitis/constant";
import { severityReasons } from "../../entitis/service/blameTypes";
import { SecretValidationRequest, SecretValidationResponse } from "../../entitis/service/secretValidationTypes";
import loggerImport from "../../logger";
import FileHelper from "../IO/fileHlper";
import { escapeCharsFromPath } from "../commonUtils";
import { replaceAll } from "../generalUtils";
import { ShardFolderUtils } from "../sharedFolderUtils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";
import { isK8Mode } from "./../envUtils";
import Iqueue from "./../queue/Iqueue";
import StatesHelper from "./../statesHelper";
import { millisToMinutesAndSeconds } from "./../telemetry-utils";

const onPrem = process.env.redisOnPrem != undefined;
const onSast = process.env.MONGO_CONN === "atlas";
const isk8 = isK8Mode();
const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();

class SecretValidationHelper {
  SecretValidationQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.SecretValidationQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
  }

  async validateSecrets(securityAlerts: SecurityEvent[], repo: Repo, type: string) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      const secrets: SecurityEvent[] = securityAlerts.filter(
        i =>
          (i.securityAlertType === SecurityAlertType.secrets ||
            (i.securityAlertType === SecurityAlertType.container && i.securitySubTypeAlertType === SecurityAlertType.secrets)) &&
          !i.askedOnceForSecretValidation &&
          i.oxTool &&
          !i.isPII &&
          !i.skipEnrichment,
      );

      if (secrets.length == 0) {
        return;
      }

      logger.info(`try validate secrets for repo: ${repo.fullName}, secrets alerts: ${secrets.length}`);

      const requests: SecretValidationRequest[] = secrets.map(i => {
        const secretValidationRequest: SecretValidationRequest = new SecretValidationRequest();
        i.askedOnceForSecretValidation = true;
        secretValidationRequest.ruleId = i.ruleId;
        secretValidationRequest.toolName = i.tool;
        secretValidationRequest.snippet = i.snippetContent;
        secretValidationRequest.uid = i.uid;
        return secretValidationRequest;
      });

      if (requests.length > 0) {
        const chunks = this.splitToChunks(requests, repo);
        const proms = chunks.map(c => {
          return this.sendAndWaitForRes(c as SecretValidationRequest[], repo);
        });
        const resProms = await Promise.all(proms);

        let input = resProms.filter(i => i != null);
        input = input.flat();

        this.updateSecretsWithSecretValidationServiceResults(input, secrets, repo, type);
      }

      logger.info(`finish set secret validation for repo: ${repo.fullName}, security alerts: ${securityAlerts.length}`);
    } catch (err) {
      logger.error(`failed set secret validation for all security alerts for repo: ${repo.fullName}, err: ${err}`);
    }
  }

  private updateSecretsWithSecretValidationServiceResults(
    resOfAllSecretValidationResults: SecretValidationResponse[],
    secrets: SecurityEvent[],
    repo: Repo,
    type: string,
  ) {
    let attached = 0;
    let notFoundById = 0;
    let failedToValidate = 0;

    try {
      logger.info(
        `number of validated secrets results before digest for type: ${type}, repo: ${repo.fullName} count: ${resOfAllSecretValidationResults.length}`,
      );

      for (const validatedSecrets of resOfAllSecretValidationResults) {
        try {
          const singleSecretValidationResponse: SecurityEvent = secrets.find(i => i.uid === validatedSecrets.uid);
          if (singleSecretValidationResponse == undefined) {
            logger.error(`fail to find security alert for secret validation uid: ${validatedSecrets.uid}, repo: ${repo.fullName}`);
            notFoundById++;
            continue;
          }

          attached++;
          if (validatedSecrets.success) {
            if (validatedSecrets.valid) {
              singleSecretValidationResponse.validSecret = true;
              addSeverityChangedReason(severityReasons.activeSecret, singleSecretValidationResponse, repo);
            } else {
              singleSecretValidationResponse.validSecret = false;
              addSeverityChangedReason(severityReasons.inactiveSecret, singleSecretValidationResponse, repo);
            }
            singleSecretValidationResponse.secretChecked = true;
          } else if (validatedSecrets.processed) {
            //Do nothing
          } else {
            failedToValidate++;
          }
        } catch (err) {
          // this.setFailedEnrichmentTools(repo, [validatedSecrets]);
          logger.error(`fail to validate single secret alert uid: ${validatedSecrets.uid}, repo: ${repo.fullName}`);
        }
      }
    } catch (err) {
      // this.setFailedEnrichmentTools(repo, resOfAllSecretValidationResults);
      logger.error(`fail to validate all secrets alerts for repo: ${repo.fullName}, err: ${err}`);
    }

    logger.info(
      `finish to validate all secrets alerts for type: ${type}, repo: ${repo.fullName}, attached: ${attached}, notFoundById: ${notFoundById}, failedToValidate: ${failedToValidate}, total response: ${resOfAllSecretValidationResults.length} for single chunk`,
    );
  }

  private setFailedEnrichmentTools(repo: Repo, requests: SecretValidationRequest[] | SecretValidationResponse[]) {
    requests.forEach(r => {
      if (r.toolName) {
        repo.addFailedSecurityTools(r.toolName);
      } else {
        logger.error(`could not setFailedEnrichmentTools to secret for request uid: ${r.uid}, toolName: ${r.toolName}`);
      }
    });
  }

  private async sendAndWaitForRes(requests: SecretValidationRequest[], repo: Repo) {
    let data;
    let requestId = uuid.v4();

    try {
      if (requests.length == 0) {
        return null;
      }

      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;

      logger.info(`sending request to secret validation service for repo: ${repo?.fullName}, count: ${requests.length}`);

      let url = onSast ? process.env.SECRET_VALIDATION_SQS_URL : process.env.SECRET_VALIDATION_QUEUE_KEY;
      if (isk8) {
        url = process.env.SECRET_VALIDATION_JS_QUEUE_KEY;
      }

      let dirToPutRes;
      if (repo.realRepo) {
        dirToPutRes = `${repo.secretValidationDir}/${requestId}/cloudSecretValidation`;
      } else {
        const scanSharedFolderPath = ShardFolderUtils.getScanSharedFolderPath(this.orgName, this.uuid);
        dirToPutRes = `${scanSharedFolderPath}/${replaceAll(requestId, "-", "_")}/cloudSecretValidation`;
      }

      fs.mkdirSync(dirToPutRes, { recursive: true });

      const filePathRequest = `${dirToPutRes}/secretValidationRequest.json`;
      fs.writeFileSync(filePathRequest, JSON.stringify(requests));
      const filePathRes = `${dirToPutRes}/secretValidator.json`;

      let command = this.getCommand(filePathRequest, dirToPutRes);
      command = escapeCharsFromPath(command);

      const msg = {
        MessageId: requestId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "secret-validation-service",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 900000,
        orgDisplayName: process.env["companyName"],
        cloneDir: "",
        toolCopyDestination: "",
        isMonoRepoChild: repo.monoRepoChild,
        monoRepoChildSubfolder: "",
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: null,
        putInQueueTime: new Date().getTime(),
        shouldSkipLocalCopy: true,
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(
        `about to send msg to queue for secret validation, repo: ${repo.fullName}, num of requests: ${
          requests.length
        }, msg: ${JSON.stringify(msg)}`,
      );

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromSecretValidation = false;

      //From Debug(shell)
      if (process.env.DEBUG != undefined) {
        const reqRes = await this.runShell(repo.name, msg.localCommand);
        const data = fs.readFileSync(filePathRes, "utf8");
        const SecretValidationRes = JSON.parse(data);
        return SecretValidationRes;
      }

      //From SAST(sqs)
      const reqRes = await this.SecretValidationQ.sendQueueMessage(info);
      if (!reqRes) {
        ToolsExecutionStats.addExecutionStateOnFail(
          requestId,
          OXtools.secretValidator,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          -1,
          ToolError.SendToQueue,
        );

        this.setFailedEnrichmentTools(repo, requests);
        return null;
      }

      logger.info(
        `about to start waiting for secret validation, repo: ${repo.fullName}, num of requests: ${requests.length}, msg: ${JSON.stringify(
          msg,
        )}`,
      );

      const startProcessTime = new Date().getTime();

      let counter = 6 * 15; // 60 seconds * 15 = 15 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.secretValidator,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );

          StatesHelper.Instance.scanInfoStats.failedSecretTimeout++;
          StatesHelper.Instance.scanInfoStats.failedSecretTimeoutRepoNames.push(repo.name);

          this.setFailedEnrichmentTools(repo, requests);
          return null;
        }

        //Failed from secretv validation
        if (fs.existsSync(failedFilePath)) {
          //setToolInfoFromDoneFile(doneFilePath, this.orgName, this.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.secretValidator,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.ResFileNotFound,
          );

          StatesHelper.Instance.scanInfoStats.failedSecretBatches++;
          StatesHelper.Instance.scanInfoStats.failedSecretRepoNames.push(repo.name);

          this.setFailedEnrichmentTools(repo, requests);
          return null;
        }

        //Done from secret validation
        if (fs.existsSync(doneFilePath)) {
          //setToolInfoFromDoneFile(doneFilePath, this.orgName, this.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `done file discovered from secret validation response, repo: ${repo.fullName}, num of requests: ${requests.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromSecretValidation = true;
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
          OXtools.secretValidator,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );

        StatesHelper.Instance.scanInfoStats.failedSecretBatches++;
        StatesHelper.Instance.scanInfoStats.failedSecretRepoNames.push(repo.name);

        this.setFailedEnrichmentTools(repo, requests);
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      data = fs.readFileSync(filePathRes, "utf8");
      const secretValidationRes = JSON.parse(data);

      //Delete after reading
      this.fileHelper.deleteFile(filePathRes);
      this.fileHelper.deleteFile(filePathRequest);

      const failed = new Set<string>();
      ToolsExecutionStats.addToExecutionStatsFromFile(
        doneFilePath,
        requestId,
        OXtools.secretValidator,
        repo.fullName,
        repo.id,
        "repo",
        repo.cloneDir,
        failed,
      );
      if (failed.size > 0) {
        this.setFailedEnrichmentTools(repo, requests);
        return null;
      }

      logger.info(
        `finish waiting for secret validation, repo: ${repo.fullName}, num of requests: ${requests.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, secret validation res number: ${secretValidationRes.length}, counter: ${counter}`,
      );

      return secretValidationRes;
    } catch (err) {
      ToolsExecutionStats.addExecutionStateOnFail(
        requestId,
        OXtools.secretValidator,
        repo.fullName,
        repo.id,
        "repo",
        "",
        -1,
        ToolError.Generic,
      );
      logger.error(
        `failed to send and wait for res of batch of security alerts to secret validation service for repo: ${repo.fullName}, data: ${data}, err: ${err}`,
      );

      StatesHelper.Instance.scanInfoStats.failedSecretBatches++;
      StatesHelper.Instance.scanInfoStats.failedSecretRepoNames.push(repo.name);

      this.setFailedEnrichmentTools(repo, requests);
      return null;
    }
  }

  splitToChunks(array, repo: Repo) {
    const chunkSize = process.env.DEBUG ? 20000 : 500;
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

  getCommand(requestPath: string, outputDir: string) {
    if (process.env.DEBUG) {
      return `/usr/local/bin/node ${process.env.SECRETS_VALDITOR_PATH} --events-path ${requestPath} --output-dir ${outputDir}`;
    }

    return `/usr/local/bin/node /app/lib/secret-validator.js --events-path ${requestPath} --output-dir ${outputDir}`;
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 10);
  }
}

export default SecretValidationHelper;
