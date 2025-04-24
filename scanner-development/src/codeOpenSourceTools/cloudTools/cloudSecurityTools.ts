import { v4 } from "uuid";
import { CloudResourcesToRun } from "../../entitis/cloudTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { Constant } from "../../entitis/constant";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";
import { isK8Mode, isUploadToS3 } from "../../helper/envUtils";
import { getSharedFolder } from "../../helper/generalUtils";
import getProwlerPredictorInstance from "../../helper/mlOps/prowler/prowlerPredictor";
import Iqueue from "../../helper/queue/Iqueue";
import loggerImport from "../../logger";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import SecurityToolBase from "../base/securityToolsBase";
import CloudToolConfiguration from "../cloudTools/cloudToolConfiguration";
const fs = require("fs");

const logger = loggerImport.getDebugLogger();

class CloudSecurityTool extends SecurityToolBase {
  outputResDir;

  constructor(
    uuid: string,
    orgPolicyParser: OrgPolicyParser,
    toolConfig: ToolConfig,
    securityToolsQueue: Iqueue,
    orgName: string,
    protected token: Token,
  ) {
    const codeToolConfiguration: CloudToolConfiguration = new CloudToolConfiguration(uuid, toolConfig, token);

    super(uuid, orgPolicyParser, toolConfig, securityToolsQueue, orgName, codeToolConfiguration);

    this.outputResDir = process.env.OX_SHARED_DATA == undefined ? "/var/shared-data" : process.env.OX_SHARED_DATA;

    this.outputResDir = `${this.outputResDir}/${this.orgName}/${this.uuid}/cloudSecurity/${this.toolConfig.name}/`;
    this.fileHelper.createDir(this.outputResDir);
  }

  async runViaShell(cloudResourcesToExecuteObj: any) {
    const cloudResourceToExecute: CloudResourcesToRun = cloudResourcesToExecuteObj as CloudResourcesToRun;

    try {
      const command = this.toolConfiguration.getCommand(cloudResourceToExecute);
      const res = await this.toolConfiguration.runShell(cloudResourceToExecute.name, command);
      return res;
    } catch (err) {
      logger.error(`failed to run shell ${this.toolConfig.name} on: ${cloudResourceToExecute.name}, err: ${err}`);
    }
    return null;
  }

  async runViaSQS(cloudResourcesToExecuteObj: any, secTool: any, ignoredTools: any, failedTools: any) {
    const cloudResourceToExecute: CloudResourcesToRun = cloudResourcesToExecuteObj as CloudResourcesToRun;

    try {
      //Check if heavy task
      let heavyTask = false;

      const enable = isK8Mode() || process.env.RUN_TOOLS_LOCALLY;
      if (enable) {
        if (this.toolConfig.name.toLowerCase() === "prowler") {
          heavyTask = getProwlerPredictorInstance().predict(cloudResourcesToExecuteObj.id);
        }
      }

      let command = this.toolConfiguration.getCommand(cloudResourceToExecute);
      const url = this.toolConfiguration.getUrlForSqs(heavyTask);

      const commandForLogs = command;
      if (command.includes("oxwrapper.py --base64")) {
        const cmd = command.split("--cmd")[1].trim();
        const base64Cmd = Buffer.from(cmd).toString("base64");
        command = command.replace(cmd, base64Cmd);
      }

      const msg = {
        MessageId: v4(),
        type: Constant.cloudToolType,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command,
        url: url,
        toolName: this.toolConfig.name,
        sizeMB: -1,
        repoName: cloudResourceToExecute.idForTools,
        nameForExternalService: this.toolConfig.nameForExternalService,
        resultPath: `${cloudResourceToExecute.fileForResults}`,
        timeout: this.toolConfig.timeout,
        orgDisplayName: process.env["companyName"],
        criticalTool: this.toolConfig.critical,
        putInQueueTime: new Date().getTime(),
      };
      this.requestId = msg.MessageId;

      const msgCopy = JSON.parse(JSON.stringify(msg));
      msgCopy.command = "";

      const info = { url: url, msg: msg };
      const msgSendRes = await this.securityToolsQueue.sendQueueMessage(info);
      msg.command = commandForLogs;
      if (msgSendRes == false) {
        logger.error(`failed to send msg ${this.toolConfig.name} on ${cloudResourceToExecute.name}, msg: ${JSON.stringify(msgCopy)}`);
        failedTools.push(secTool);

        return null;
      } else {
        logger.info(`SEND msg ${this.toolConfig.name} on ${cloudResourceToExecute.name}, msg: ${JSON.stringify(msgCopy)}`);
      }

      return msg;
    } catch (err) {
      logger.error(`failed to push msg tool ${this.toolConfig.name} on ${cloudResourceToExecute.name} err ${err}`, err);
    }

    failedTools.push(secTool);
    return null;
  }

  copyToolResults({ cloudResourceName, dir }: { cloudResourceName: string; dir: string }): void {
    if (!isUploadToS3()) return;
    const oxDir = getSharedFolder(this.uuid) + "/ox-security";
    const telemetryDir = oxDir + "/telemetry-" + this.uuid;
    const toolDir = telemetryDir + "/security-report/" + this.toolConfig.name;
    try {
      if (!fs.existsSync(toolDir)) {
        fs.mkdirSync(toolDir, { recursive: true });
      }
      this.fileHelper.copyFileSync(dir, toolDir);
    } catch (err) {
      logger.error(`failed to copy tool ${this.toolConfig.name} result file for repo name ${cloudResourceName}`);
    }
  }

  //In case we will have generic way to parse cloud tools output like sarif
  createSecurityEvents(item: any) {
    throw new Error("Method not implemented.");
  }
}

export default CloudSecurityTool;
