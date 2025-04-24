const util = require("util");
const exec = util.promisify(require("child_process").exec);
import { Credentials } from "@aws-sdk/types/dist-types/credentials";
import { Application } from "../../appmgr/application";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import getAwsKeys, { AWSAccountCredentials } from "../../codeOpenSourceTools/cloudTools/specifcTools/AWSCredentialsProvider";
import { addSeverityChangedReason, Repo, SecurityAlertType, SecurityEvent, VCSType } from "../../entitis/codeRepoTypes";
import { OXtools } from "../../entitis/constant";
import { severityReasons } from "../../entitis/service/blameTypes";
import { Deployment, IacValidatorTypesRequest, IacValidatorTypesResponse } from "../../entitis/service/iacValidatorTypes";
import loggerImport from "../../logger";
import { escapeCharsFromPath } from "../commonUtils";
import { isK8Mode } from "../envUtils";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";
import FileHelper from "../IO/fileHlper";

const onPrem = process.env.redisOnPrem != undefined;
const onSast = process.env.MONGO_CONN === "atlas";
const isk8 = isK8Mode();
const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();

class IacVerificationHelper {
  IacHelperQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.IacHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
  }

  async setIacValidator(securityAlerts: SecurityEvent[], app: Application) {
    if (StatesHelper.Instance.isPipelineScan) {
      return;
    }

    const repoTempCast: any = app.appInfo.repo == null ? null : (app.appInfo.repo as any);
    if (repoTempCast == null) {
      return;
    }
    const repo: Repo = repoTempCast.code_repo as Repo;

    if (repo.vcsType === VCSType.tfvc) return;

    try {
      if (securityAlerts.length == 0) {
        return;
      }

      logger.info(`try generate iac validator requests for repo: ${repo.fullName}, alerts: ${securityAlerts.length}`);

      let requests: IacValidatorTypesRequest[] = [];
      securityAlerts.forEach(securityAlert => {
        try {
          //Dont ask again on the same sec alert for, safety check.
          if (securityAlert.askedOnceForIacValidator) {
            return;
          }
          if (securityAlert.securityAlertType != SecurityAlertType.iac) {
            return;
          }

          securityAlert.askedOnceForIacValidator = true;
          const iacValidatorRequest: IacValidatorTypesRequest = new IacValidatorTypesRequest();
          iacValidatorRequest.uid = securityAlert.uid;
          iacValidatorRequest.fileName = securityAlert.fileName;
          iacValidatorRequest.ruleId = securityAlert.ruleId;
          iacValidatorRequest.snippet = securityAlert.snippetContent;
          iacValidatorRequest.toolName = securityAlert.tool;
          requests.push(iacValidatorRequest);
        } catch (err) {
          logger.error(`failed to generate single iac validator request for repo: ${repo.fullName}, alert`);
        }
      });

      requests = requests.filter(i => i != undefined);

      if (requests.length > 0) {
        let i = 0;
        const chunks = this.splitToChunks(requests, repo);
        const awsCredentials = await getAwsKeys().fetchCredentials();

        const updateUsingCredentials = async (cred: AWSAccountCredentials) => {
          for (;;) {
            const proms = chunks.map(c => {
              i++;
              return this.sendAndWaitForRes(c as IacValidatorTypesRequest[], repo, i, cred);
            });
            const resProms = await Promise.all(proms);

            let input = resProms.filter(i => i != null);
            input = input.flat();

            this.updateSecurityAlertsWithIacValidator(input, securityAlerts, repo);

            // Handle Expiration Issues (reissue the key)
            // Check output for correctness
            //cred = await getAwsKeys().fetchKeyByName(cred.name);

            break;
          }
        };

        // Todo: Eyal - Make sure you reduce the validation issues when you test with the next key

        for (const cred of awsCredentials) {
          const token = await getAwsKeys().fetchKeyByName(cred.name);
          if (token) {
            await updateUsingCredentials(token);
          } else {
            logger.error(`${cred.name} cannot be found or reissued`);
          }
        }
      }

      logger.info(
        `finish set iac validator for repo: ${repo.fullName}, security alerts: ${securityAlerts.length}, requests: ${requests.length}`,
      );
    } catch (err) {
      logger.error(`failed set iac validator for all security alerts for repo: ${repo.fullName}, err: ${err}`);
    }
  }

  private updateSecurityAlertsWithIacValidator(resOfAllIacValidators: IacValidatorTypesResponse[], alerts: SecurityEvent[], repo: Repo) {
    let attached = 0;
    let notFoundById = 0;

    try {
      logger.info(`number of iac validator results before digest for repo: ${repo.fullName} count: ${resOfAllIacValidators.length}`);

      for (const iacValidatorSingleRes of resOfAllIacValidators) {
        try {
          const singleIacValidatorResponse: SecurityEvent = alerts.find(i => i.uid === iacValidatorSingleRes.uid) as any;

          if (singleIacValidatorResponse == undefined) {
            logger.error(`fail to find security alert for iac validator uid: ${iacValidatorSingleRes.uid}, repo: ${repo.fullName}`);
            notFoundById++;
            continue;
          }

          attached++;
          singleIacValidatorResponse.iacValidatorTypesResponse = iacValidatorSingleRes;

          if (iacValidatorSingleRes.success) {
            let validIssue: boolean = false;
            iacValidatorSingleRes.deployments.forEach((deployment: Deployment) => {
              if (deployment.valid) {
                validIssue = true;
                // do something with var
              }
            });
            if (validIssue) {
              addSeverityChangedReason(severityReasons.deployedInsecureConfiguration, singleIacValidatorResponse, repo);
            } else {
              addSeverityChangedReason(severityReasons.undeployedInsecureConfiguration, singleIacValidatorResponse, repo);
            }
          }
        } catch (err) {
          logger.error(`fail iac single alert, repo: ${repo.fullName}, err: ${err}`);
        }
      }
    } catch (err) {
      logger.error(`fail iac validator alerts for repo: ${repo.fullName}`);
    }
    logger.info(
      `finish iac validator alerts for repo: ${repo.fullName}, attached: ${attached}, notFoundById: ${notFoundById}, total response: ${resOfAllIacValidators.length} for single chunk`,
    );
  }

  private async sendAndWaitForRes(requests: IacValidatorTypesRequest[], repo: Repo, index: number, credentials: Credentials) {
    let data;
    const requestId = uuid.v4();

    try {
      if (requests.length == 0) {
        return null;
      }

      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;

      logger.info(`sending request to iac validator service for repo: ${repo.fullName}, count: ${requests.length}`);

      let url = onSast ? process.env.IAC_VERIFICATION_SERVICE_SQS_URL : process.env.IAC_VERIFICATION_SERVICE_QUEUE_KEY;
      if (isk8) {
        url = process.env.IAC_VERIFICATION_SERVICE_QUEUE_KEY;
      }

      const dirToPutRes = `${repo.iacValidatorDir}/${requestId}`;
      fs.mkdirSync(dirToPutRes, { recursive: true });

      const filePathRequest = `${dirToPutRes}/iacValiditorRequest.json`;
      fs.writeFileSync(filePathRequest, JSON.stringify(requests));

      let filePathRes = `${dirToPutRes}/iacValiditor.json`;

      //If this is onPrem the zip folder is the actual code folder without a zip
      //If we are on SAST then we need the parent folder in case its mono repo and if not the regular repo
      let cloneDir = "";
      let toolCopyDestination = "";
      let monoRepoChildSubfolder = "";
      if (repo.realRepo) {
        cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;

        toolCopyDestination = repo.getRepoForToolsBasedOnEnv();
        if (!process.env.DEBUG && (!onPrem || isk8)) {
          toolCopyDestination = `${toolCopyDestination}/${index.toString()}`;
        }

        monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;
      }

      let command = this.getCommand(filePathRequest, dirToPutRes, toolCopyDestination, credentials);
      command = escapeCharsFromPath(command);

      const msg = {
        MessageId: requestId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "iac-validator-service",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 900000,
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

      logger.info(
        `about to send msg to queue for iac, repo: ${repo.fullName}, num of requests: ${requests.length}, msg: ${JSON.stringify(msg)}`,
      );

      //From Debug(shell)
      if (process.env.DEBUG) {
        const reqRes = await this.runShell(repo.name, msg.localCommand);
        const data = fs.readFileSync(filePathRes, "utf8");
        const iacVerificationRes = JSON.parse(data);
        return iacVerificationRes;
      }

      //From SAST(sqs)
      const reqRes = await this.IacHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        ToolsExecutionStats.addExecutionStateOnFail(
          requestId,
          OXtools.iacValidator,
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
        `about to start waiting for iac validator requests, repo: ${repo.fullName}, num of requests: ${
          requests.length
        }, msg: ${JSON.stringify(msg)}`,
      );

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromIacVerification = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 15; // 60 seconds * 15 = 15 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.iacValidator,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );

          StatesHelper.Instance.scanInfoStats.failedIacValidatorTimeout++;
          StatesHelper.Instance.scanInfoStats.failedIacValidatorTimeoutRepoNames.push(repo.name);

          this.setFailedEnrichmentTools(repo, requests);
          return null;
        }

        //Failed from iac
        if (fs.existsSync(failedFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.iacValidator,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.ResFileNotFound,
          );

          StatesHelper.Instance.scanInfoStats.failedIacValidatorBatches++;
          StatesHelper.Instance.scanInfoStats.failedIacValidatorRepoNames.push(repo.name);

          this.setFailedEnrichmentTools(repo, requests);
          return null;
        }

        //Done from iac
        if (fs.existsSync(doneFilePath)) {
          //setToolInfoFromDoneFile(doneFilePath, this.orgName, this.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `done file discovered from iac validator response, repo: ${repo.fullName}, num of requests: ${requests.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromIacVerification = true;
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
          OXtools.iacValidator,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );

        StatesHelper.Instance.scanInfoStats.failedIacValidatorBatches++;
        StatesHelper.Instance.scanInfoStats.failedIacValidatorRepoNames.push(repo.name);

        this.setFailedEnrichmentTools(repo, requests);
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      data = fs.readFileSync(filePathRes, "utf8");
      const iacValidatorRes = JSON.parse(data);

      //Delete after reading
      this.fileHelper.deleteFile(filePathRes);
      this.fileHelper.deleteFile(filePathRequest);

      const failed = new Set<string>();
      ToolsExecutionStats.addToExecutionStatsFromFile(
        doneFilePath,
        requestId,
        OXtools.iacValidator,
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
        `finish waiting for iac, repo: ${repo.fullName}, num of requests: ${requests.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, iac validator res number: ${iacValidatorRes.length}, counter: ${counter}`,
      );

      return iacValidatorRes;
    } catch (err) {
      ToolsExecutionStats.addExecutionStateOnFail(
        requestId,
        OXtools.iacValidator,
        repo.fullName,
        repo.id,
        "repo",
        "",
        -1,
        ToolError.Generic,
      );
      logger.error(
        `failed to send batch of security alerts to iac validator service for repo: ${repo.fullName}, data: ${data}, err: ${err}`,
      );

      this.setFailedEnrichmentTools(repo, requests);
      StatesHelper.Instance.scanInfoStats.failedIacValidatorBatches++;
      StatesHelper.Instance.scanInfoStats.failedIacValidatorRepoNames.push(repo.name);
    }

    return null;
  }

  private setFailedEnrichmentTools(repo: Repo, requests: IacValidatorTypesRequest[]) {
    requests.forEach(r => {
      repo.addFailedSecurityTools(r.toolName);
    });
  }

  splitToChunks(array, repo: Repo) {
    const chunkSize = process.env.DEBUG ? 20000 : 200;
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

  getCommand(requestPath: string, outputDir: string, repoDir: string, credentials: Credentials) {
    if (process.env.DEBUG) {
      return `SERVER_ENVIRONMENT=${process.env.SERVER_ENVIRONMENT} AWS_ACCESS_KEY_ID=${credentials.accessKeyId} AWS_SECRET_ACCESS_KEY=${credentials.secretAccessKey} AWS_SESSION_TOKEN=${credentials.sessionToken} python ${process.env.IAC_VALIDATOR_PATH} --source ${repoDir} --events-path ${requestPath} --output-dir ${outputDir}`;
    }
    return `SERVER_ENVIRONMENT=${process.env.SERVER_ENVIRONMENT} AWS_ACCESS_KEY_ID=${credentials.accessKeyId} AWS_SECRET_ACCESS_KEY=${credentials.secretAccessKey} AWS_SESSION_TOKEN=${credentials.sessionToken} python /src/iac_validator_cli.py --source ${repoDir} --events-path ${requestPath} --output-dir ${outputDir}`;
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 10);
  }
}

export default IacVerificationHelper;
