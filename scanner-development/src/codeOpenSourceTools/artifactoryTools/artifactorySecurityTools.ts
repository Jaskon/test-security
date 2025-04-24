import fs from "fs";
import { v4 } from "uuid";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { ArtifactoryResourceToRun } from "../../entitis/artifactoryTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { Constant } from "../../entitis/constant";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";
import { isUploadToS3 } from "../../helper/envUtils";
import { getSharedFolder } from "../../helper/generalUtils";
import Iqueue from "../../helper/queue/Iqueue";
import loggerImport from "../../logger";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import SecurityToolBase from "../base/securityToolsBase";
import ArtifactoryToolConfiguration from "./artifactoryToolConfiguration";
const pathEx = require("path");
const logger = loggerImport.getDebugLogger();

class ArtifactorySecurityTool extends SecurityToolBase {
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

  async runViaShell(resource: ArtifactoryResourceToRun) {
    try {
      const command = this.toolConfiguration.getCommand(resource);
      const res = await this.toolConfiguration.runShell(resource.imageDetail.name, command);
      return res;
    } catch (err) {
      logger.error(`failed to run shell ${this.toolConfig.name} on: ${resource.imageDetail.name}, err: ${err}`);
    }
    return null;
  }

  async runViaSQS(resource: ArtifactoryResourceToRun, secTool: any, ignoredTools: any, failedTools: any) {
    try {
      let command = this.toolConfiguration.getCommand(resource);
      const url = this.toolConfiguration.getUrlForSqs(resource.imageDetail.isHeavy);

      let copyType;
      let shouldSkipLocalCopy = true;
      let toolCopyDestinationOnLocalMachine;
      let imageFolderLocation;
      if (this.toolConfig.name.toLocaleLowerCase() === "gitleaks") {
        copyType = CopyType.DockerImage;
        shouldSkipLocalCopy = false;
        toolCopyDestinationOnLocalMachine = resource.toolCopyDestination;
        imageFolderLocation = pathEx.dirname(resource.netShareDownloadArtifactPathForScan);
      }

      if (command.includes("oxwrapper.py --base64")) {
        const cmd = command.split("--cmd")[1].trim();
        const base64Cmd = Buffer.from(cmd).toString("base64");
        command = command.replace(cmd, base64Cmd);
      }

      const msg = {
        MessageId: v4(),
        type: Constant.artifactoryToolType,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command,
        localCommand: command,
        url: url,
        copyType: copyType,
        toolName: this.toolConfig.name,
        repoName: resource.imageDetail.name,
        cloneDir: imageFolderLocation,
        resultPath: `${resource.dirWhereToPutRes}/${this.toolConfig.fileNameOutput}`,
        timeout: this.toolConfig.timeout,
        orgDisplayName: process.env["companyName"],
        isMonoRepoChild: false,
        monoRepoChildSubfolder: "",
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: null,
        putInQueueTime: new Date().getTime(),
        shouldSkipLocalCopy: shouldSkipLocalCopy,
        toolCopyDestination: toolCopyDestinationOnLocalMachine,
      };
      this.requestId = msg.MessageId;

      if (process.env.DOCKER_DEBUG) {
        msg.cloneDir = msg.cloneDir.replace(process.env.OX_SHARED_DATA, "/shared");
        msg.resultPath = msg.resultPath.replace(process.env.OX_SHARED_DATA, "/shared");
      }

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

  copyToolResults({ cloudResourceName, dir }: { cloudResourceName: string; dir: string }): void {
    if (!isUploadToS3()) return;
    const oxDir = getSharedFolder(this.uuid) + "/ox-security";
    const telemetryDir = oxDir + "/telemetry-" + this.uuid;
    const repoDir = telemetryDir + "/security-report/" + cloudResourceName;
    const toolDir = repoDir + "/" + this.toolConfig.name;
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

export default ArtifactorySecurityTool;
