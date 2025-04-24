import { v4 } from "uuid";
import { ArtifactoryDownloadToRun } from "../../entitis/artifactoryTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { Constant } from "../../entitis/constant";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";
import Iqueue from "../../helper/queue/Iqueue";
import loggerImport from "../../logger";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import SecurityToolBase from "../base/securityToolsBase";
import ArtifactoryToolConfiguration from "./artifactoryDownloadConfiguration";

const logger = loggerImport.getDebugLogger();

class ArtifactoryDownloadTool extends SecurityToolBase {
  constructor(
    uuid: string,
    orgPolicyParser: OrgPolicyParser,
    toolConfig: ToolConfig,
    securityToolsQueue: Iqueue,
    orgName: string,
    token: Token,
  ) {
    const codeToolConfiguration = new ArtifactoryToolConfiguration(uuid, toolConfig, token);

    super(uuid, orgPolicyParser, toolConfig, securityToolsQueue, orgName, codeToolConfiguration);
  }

  async runViaShell(resource: ArtifactoryDownloadToRun) {
    try {
      const command = this.toolConfiguration.getCommand(resource);
      const res = await this.toolConfiguration.runShell(resource.imageDetail.name, command);
      return res;
    } catch (err) {
      logger.error(`failed to run shell ${this.toolConfig.name} on: ${resource.imageDetail.name}, err: ${err}`);
    }
    return null;
  }

  async runViaSQS(resource: ArtifactoryDownloadToRun, secTool: any, ignoredTools: any, failedTools: any) {
    try {
      const command = this.toolConfiguration.getCommand(resource);
      const url = this.toolConfiguration.getUrlForSqs();

      const msg = {
        MessageId: v4(),
        type: Constant.artifactoryToolType,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command,
        url: url,
        toolName: this.toolConfig.name,
        sizeMB: -1,
        repoName: resource.imageDetail.name,
        nameForExternalService: this.toolConfig.nameForExternalService,
        resultPath: `${resource.artifactoryResultsDir}/${this.toolConfig.fileNameOutput}`,
        timeout: this.toolConfig.timeout,
        orgDisplayName: process.env["companyName"],
        criticalTool: this.toolConfig.critical,
        putInQueueTime: new Date().getTime(),
        shouldSkipLocalCopy: true,
      };
      this.requestId = msg.MessageId;

      const msgCopy = JSON.parse(JSON.stringify(msg));
      msgCopy.command = "";

      const info = { url: url, msg: msg };
      const msgSendRes = await this.securityToolsQueue.sendQueueMessage(info);
      if (msgSendRes == false) {
        logger.error(`failed to send msg on artifact ${this.toolConfig.name} on ${resource.imageDetail.name}, msg: ${JSON.stringify(msg)}`);
        failedTools.push(secTool);

        return null;
      } else {
        logger.info(`SEND msg  on artifact  ${this.toolConfig.name} on ${resource.imageDetail.name}, msg: ${JSON.stringify(msg)}`);
      }

      return msg;
    } catch (err) {
      logger.error(`failed to push msg tool ${this.toolConfig.name} on ${resource.imageDetail.name} err ${err}`, err);
    }

    failedTools.push(secTool);
    return null;
  }

  //In case we will have generic way to parse cloud tools output like sarif
  createSecurityEvents(item: any) {
    throw new Error("Method not implemented.");
  }
}

export default ArtifactoryDownloadTool;
