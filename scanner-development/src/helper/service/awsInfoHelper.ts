const util = require("util");
const exec = util.promisify(require("child_process").exec);
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import loggerImport from "../../logger";
import { escapeCharsFromPath } from "../commonUtils";
import { isOnPrem } from "../envUtils";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";

const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();

class AWSinfoHelper {
  awsCrawlerQ: Iqueue;
  uuid: string;
  orgName: string;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.awsCrawlerQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
  }

  async setInfoAWS(token: Token) {
    try {
      if (isOnPrem()) {
        logger.info(`OnPrem - not running`);
        return;
      }

      logger.info(`try set set AWS info`);

      await this.sendReq(token);

      logger.info(`finish set set AWS info`);
    } catch (err) {
      logger.error(`failed setInfoAWS, err: ${err}`);
    }
  }

  private async sendReq(token: Token) {
    try {
      let url = process.env.OX_RESEARCH_AWS_INFO_QUEUE_KEY;

      let command = this.getCommand(token);
      command = escapeCharsFromPath(command);

      const msg = {
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "awsInfo",
        repoName: "",
        resultPath: "",
        timeout: 1800000,
        orgDisplayName: process.env["companyName"],
        cloneDir: "",
        copyType: CopyType.LeanCodeOnly,
        toolCopyDestination: "",
        isMonoRepoChild: "",
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

      //Debug
      //logger.info(`about to send msg to queue for aws crawler, msg: ${JSON.stringify(msg)}`);

      if (process.env.DEBUG) {
        const reqRes = await this.runShell("aws", msg.localCommand);
        return;
      }

      const reqRes = await this.awsCrawlerQ.sendQueueMessage(info);
      if (!reqRes) {
        logger.error(`failed enter item to aws crawler Q, msg: ${JSON.stringify(msg)}`);
        return null;
      }
    } catch (err) {
      let errInfo = `failed to send batch of aws crawler, err: ${err}`;
      logger.error(`${errInfo}`);
    }
  }

  getCommand(token: Token) {
    let exec_path: string | undefined = "/src/apigw_main.py";
    if (process.env.DEBUG) {
      exec_path = process.env.AWS_CRAWLER;
    }

    return `OX_RESEARCH_BUCKET=${process.env.OX_RESEARCH_BUCKET} ox_customer_AWS_ACCESS_KEY_ID=${token.password} ox_customer_AWS_SECRET_ACCESS_KEY=${token.secret} ox_customer_AWS_SESSION_TOKEN=${token.tokenSession} python ${exec_path} --output-dir /mnt/scratch --customer-id ${this.orgName}_${StatesHelper.Instance.companyName} `;
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

export default AWSinfoHelper;
