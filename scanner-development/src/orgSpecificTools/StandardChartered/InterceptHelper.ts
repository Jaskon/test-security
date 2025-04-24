import { mkdir, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout } from "node:timers/promises";
import { v4 } from "uuid";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { SecurityEvent } from "../../entitis/codeRepoTypes";
import Constant from "../../entitis/constant";
import { fileExists } from "../../helper/IO/fileHlper";
import EnvQueueFactory from "../../helper/queue/envQueueFactory";
import Iqueue from "../../helper/queue/Iqueue";
import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";
import { InterceptConfig } from "./InterceptConfig";
import { InterceptReport } from "./InterceptReport";
import { InterceptResource, ToolCommand, ToolDefinition } from "./types";
import { isLocalDevelopment } from "../../helper/envUtils";
const logger = loggerImport.getDebugLogger();
const sharedDir = process.env.OX_SHARED_DATA === "undefined" ? "/var/shared-data" : process.env.OX_SHARED_DATA;

export class InterceptHelper {
  private static interceptQueue?: Iqueue;

  static async collectSecEvents(resource: InterceptResource, orgId: string, scanId: string): Promise<SecurityEvent[]> {
    try {
      if (!StatesHelper.Instance.isCharterBank || StatesHelper.Instance.isPipelineScan) {
        return [];
      }
      const toolConfig = await InterceptConfig.fetchToolDefinition(resource.type, orgId);
      if (!toolConfig) {
        logger.error(`[${InterceptHelper.name}] Failed to fetch tool config for ${resource.type}`);
        return [];
      }
      if (!toolConfig.metadata.target.includes(resource.name) && !isLocalDevelopment()) {
        // We don't need to run intercept on this target
        return [];
      }
      const results = await Promise.all(
        toolConfig.metadata.runs.map(async run => {
          try {
            const resultPath = await this.prepareRun(resource, orgId, scanId, toolConfig);
            const toolOutputPath = await this.runIntercept(resultPath, resource, orgId, scanId, run);
            return InterceptReport.createSecurityEvents(toolOutputPath, toolConfig.metadata);
          } catch (err) {
            logger.error(`[${InterceptHelper.name}] Failed to run intercept-${resource.type} for ${resource.name}`, err);
            return [];
          }
        }),
      );
      return results.flat();
    } catch (err) {
      logger.error(`[${InterceptHelper.name}] Failed to run intercept-${resource.type} for ${resource.name}`, err);
      return [];
    }
  }

  private static async prepareRun(resource: InterceptResource, orgId: string, scanId: string, toolConfig: ToolDefinition): Promise<string> {
    // Create policy file
    const policyDir = `${sharedDir}/${orgId}/scan_${scanId.replaceAll("-", "_")}/intercept/${v4()}`;
    await mkdir(policyDir, { recursive: true });
    await writeFile(join(policyDir, "policy.yaml"), Buffer.from(toolConfig.policy_file, "base64"));

    if (resource.type === "kong") {
      const kongConfig = await InterceptConfig.fetchKongConfiguration(resource);
      await writeFile(join(policyDir, "kong-configuration.json"), JSON.stringify(kongConfig));
    }
    return policyDir;
  }

  private static async runIntercept(
    resultPath: string,
    resource: InterceptResource,
    orgId: string,
    scanId: string,
    toolCommand: ToolCommand,
  ): Promise<string> {
    try {
      const resultFilePath = join(resultPath, toolCommand.sarif);
      if (process.env.RUN_INTERCEPT_LOCAL) {
        logger.info(
          `[${InterceptHelper.name}] not running intercept locally with command: ${this.getCommand(resultPath, resource, toolCommand)}`,
        );
        return join(__dirname, "mocks", toolCommand.sarif);
      }
      const doneFilePath = `${resultFilePath}.done`;
      const failedFilePath = `${resultFilePath}.fail`;
      const url = process.env.INTERCEPT_QUEUE_KEY;

      const msg: Record<string, any> = {
        MessageId: v4(),
        toolName: `intercept-${resource.type}`,
        uuid: scanId,
        orgID: orgId,
        timeout: 60 * 1000, // 1 minute
        resultPath: resultFilePath,
        doneFilePath: doneFilePath,
        dirToPutRes: resultPath,
        putInQueueTime: Date.now(),
        command: this.getCommand(resultPath, resource, toolCommand),
        localCommand: this.getCommand(resultPath, resource, toolCommand),
      };

      if (resource.type === "generic") {
        msg.type = Constant.codeToolType;
        msg.repoName = resource.repo.fullName;
        msg.cloneDir = resource.repo.codeZipDir;
        msg.copyType = CopyType.CodeOnly;
        msg.toolCopyDestination = resource.repo.getRepoForToolsBasedOnEnv();
        msg.isMonoRepoChild = false;
        msg.monoRepoChildSubfolder = false;
        msg.shouldAdditionallyScanRootFiles = false;
        msg.isPipelineScan = false;
      }
      if (!this.interceptQueue) {
        this.interceptQueue = EnvQueueFactory.getQueue(scanId, null, orgId);
      }
      logger.info(`[${InterceptHelper.name}] about to send a message ${JSON.stringify(msg)}`);
      await this.interceptQueue.sendQueueMessage({ url, msg });

      let counter = 30; // with a wait of 10s each time, is 5 minutes
      while (true) {
        //Timeout
        if (counter <= 0) {
          throw new Error("Failed intercept due to timeout");
        }
        //Failed
        if (await fileExists(failedFilePath)) {
          throw new Error("Failed intercept");
        }
        //Done
        if (await fileExists(doneFilePath)) {
          break;
        }
        //10 seconds
        await setTimeout(10 * 1000);
        counter--;
      }
      if (!(await fileExists(resultFilePath))) {
        throw new Error(`Failed intercept due to missing file ${resultFilePath}`);
      }
      return resultFilePath;
    } catch (err) {
      throw new Error(`Failed intercept due to error: ${err}`);
    }
  }

  private static getCommand(resultPath: string, resource: InterceptResource, toolCommand: ToolCommand): string {
    let command = `cd ${resultPath} && intercept config -a ./policy.yaml && `;
    switch (resource.type) {
      case "kong":
        command += `intercept ${toolCommand.command} -t .`;
        break;
      case "solace":
        command += `INTERCEPT_BAUTH=${resource.username}:${resource.password} intercept ${toolCommand.command}`;
        break;
      case "generic":
        command += `intercept ${toolCommand.command} -t ${resource.repo.getRepoPathForToolCommand()}`;
        break;
    }
    return `'${command}'`;
  }
}
