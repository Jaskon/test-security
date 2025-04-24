import memoryDB from "@oxappsec/ox-memory-db";
import { subscriberService } from "@oxappsec/ox-unified-pubsub";
import * as fs from "fs";
import { hash } from "../helper/hash";
import { millisToTimeStr } from "../helper/performance";
import StatesHelper from "../helper/statesHelper";
import { waitFor } from "../helper/timeHelper";
import loggerImport from "../logger";
import { CopyType, ParsingRequest, ReturnStatus, ScannerMessage } from "./OXParserToolHandlerTypes";
const logger = loggerImport.getDebugLogger();

async function waitForAllRequestsCompletion(handlers: Map<string, Function>) {
  const messageHandler = async (recordData: string[]) => {
    try {
      for (const record of recordData) {
        const message = JSON.parse(record);

        if (message.body.toolName !== "oxparser") {
          logger.debug(`Skipping message with toolName ${message.body.toolName}`);
          continue;
        }

        if (message.body.resultPath) {
          let resultStatus: ReturnStatus | null = null;

          if (message.res) {
            resultStatus = JSON.parse(message.res);
          }

          const functor = handlers.get(message.body.resultPath.split("/").pop());

          if (functor) {
            logger.info(`Entry: ${message.body.resultPath} finished in ${millisToTimeStr(message.endTime - message.startTime)}`);
            logger.info(`Received record: ${JSON.stringify(record)}`);
            await functor(resultStatus ? resultStatus.scanStatus : "fail");
          } else {
            logger.debug(`No functor for ${message.body.resultPath.split("/").pop()} found`);
          }
        } else {
          logger.error("No resultPath found in message");
        }
      }
    } catch (e) {
      logger.error(`Exception caught in messageHandler with error: ${e}`);
    }
  };

  const { subscriber } = subscriberService(messageHandler, process.env.PUBSUB_TOPIC_NAME || "tool-runner-done");

  if (subscriber) {
    await subscriber.start("*");
  }
}

function createConditionalObserver(): {
  isConditionMet: () => boolean;
  setConditionMet: () => void;
} {
  let innerCondition = false;

  return {
    isConditionMet: (): boolean => {
      return innerCondition;
    },
    setConditionMet: () => {
      innerCondition = true;
    },
  };
}

export default class OXParserToolHandler {
  static handlers = new Map<string, Function>();
  static conditionHandlers = new Map<string, ReturnType<typeof createConditionalObserver>>();
  static flagNotifier;
  static pubSubRegistered = false;
  static currentBulkId = hash(`${Math.random() * 10000}:${new Date().getTime()}`);
  static bulkRequests: ParsingRequest[] = [];

  static cleanUp(id: string) {
    this.conditionHandlers.delete(id);
  }

  static async sendAndWaitRequest(
    requests: ParsingRequest[],
    failedSet: Set<string>,
    sendMessagesToToolRunner: (requests: ParsingRequest[]) => Promise<void>,
    filePath: string,
    bulkOpTimeout = 30,
    retryCount = 3,
    timeout = 600 /* 5 min */,
  ): Promise<Promise<void>[]> {
    const waitPromises: Promise<void>[] = [];
    const flag = createConditionalObserver();
    let recRetryCount = retryCount;

    for (const rec of requests) {
      rec.logs.map(l => this.conditionHandlers.set(l, flag));
      this.bulkRequests.push(rec);
    }

    const deleteFileSafely = (filePath: string) => {
      try {
        if (fs.existsSync(filePath)) {
          fs.unlinkSync(filePath);
          logger.info(`deleteFileSafely: Deleted file ${filePath}`);
        } else {
          logger.info(`deleteFileSafely: File ${filePath} does not exist`);
        }
      } catch (e) {
        logger.error(`deleteFileSafely: ${e}`);
      }
    };

    const checkDiskFile = (filePath: string) => {
      if (fs.existsSync(filePath)) {
        logger.info(`Reading result file: ${filePath}`);

        const messageBuffer = fs.readFileSync(filePath);
        fs.unlinkSync(filePath);

        try {
          const message = JSON.parse(messageBuffer.toString());
          if (message.res) {
            logger.info(`Received result: ${JSON.stringify(message)}`);
            const status: ReturnStatus = JSON.parse(message.res);
            if (status.scanStatus === "success") {
              //flag = true;
              const handler = this.handlers.get(message.body.resultPath.split("/").pop());
              if (handler) {
                logger.info(`Entry: ${message.body.resultPath} finished, running handler with status: ${status.scanStatus}`);
                handler(status);
                return true;
              }
            }
          }
        } catch (e) {
          logger.error(`Failed in checkDiskFile, with error: ${e}`);
        }
      }

      return false;
    };

    let outerDoneFile = this.currentBulkId;

    setTimeout(async () => {
      if (this.bulkRequests.length === 0) return;

      const tempRequestArray: ParsingRequest[] = [...this.bulkRequests];
      this.bulkRequests.length = 0;

      const singleRequest: ParsingRequest = {
        id: this.currentBulkId,
        logs: tempRequestArray.map(l => l.logs).flat(),
        uuid: requests[0].uuid,
      };

      const doneFile = `${filePath}/${singleRequest.id}.done`;
      outerDoneFile = doneFile;

      logger.info(`Setting wait function for: ` + doneFile);
      logger.info(`Setting functor for: ` + `${singleRequest.id}`);

      this.handlers.set(`${singleRequest.id}`, (scanStatus: string) => {
        logger.info(`Received confirmation for ${singleRequest.id} with status: ${scanStatus}, and retry count: ${recRetryCount}`);

        deleteFileSafely(doneFile);

        if (scanStatus === "success" || !recRetryCount--) {
          if (recRetryCount > 0) {
            failedSet.delete(singleRequest.id);
            this.handlers.delete(`${singleRequest.id}`);
            memoryDB.del.execute(`${singleRequest.id}`);
            logger.info(`Removing ${singleRequest.id} from functor map and failed list`);
          }

          for (const singleLogId of singleRequest.logs) {
            const conditionObserver = this.conditionHandlers.get(singleLogId);

            if (conditionObserver) {
              conditionObserver.setConditionMet();
            }
          }
        } else {
          logger.info(`Retrying ${singleRequest.id} with retry count: ${recRetryCount}`);
          failedSet.add(singleRequest.id);
          sendMessagesToToolRunner([singleRequest]);
        }
      });

      // Update the current random ID
      this.currentBulkId = hash(`${Math.random() * 10000}:${new Date().getTime()}`);

      await sendMessagesToToolRunner([singleRequest]);
    }, bulkOpTimeout * 1000);

    waitPromises.push(waitFor(_ => checkDiskFile(outerDoneFile) || flag.isConditionMet(), timeout));

    if (!this.pubSubRegistered) {
      this.pubSubRegistered = true;
      await waitForAllRequestsCompletion(this.handlers);
    }

    return waitPromises;
  }
}

export class scanPath {
  static fullPath: string = "";
  static localFullPath: string = "";

  static getOutputFolderForOXResults(isMountedForLocalDevelopment = false): string {
    if (this.fullPath === "") {
      this.fullPath = `/var/shared-data/${StatesHelper.Instance.orgName}/scan_${StatesHelper.Instance.uuid.replaceAll("-", "_")}`;

      this.localFullPath = `${process.env.OX_SHARED_DATA}/${StatesHelper.Instance.orgName}/scan_${StatesHelper.Instance.uuid.replaceAll(
        "-",
        "_",
      )}`;

      if (!fs.existsSync(this.localFullPath)) {
        fs.mkdirSync(this.localFullPath, { recursive: true });
      }
    }

    if (isMountedForLocalDevelopment) {
      return this.localFullPath;
    }

    return this.fullPath;
  }
}

export async function sendParseMessagesToToolRunner(
  requests: ParsingRequest[],
  toolName = process.env.OXPARSER_QUEUE_KEY_PIPELINE || "RunOxParserPipeline",
) {
  for (const request of requests) {
    await memoryDB.queueSet.execute(request.id, 300, JSON.stringify(request));

    const toolRunnerRequest: ScannerMessage = {
      uuid: StatesHelper.Instance.uuid,
      orgID: StatesHelper.Instance.orgName,
      command: `/usr/local/bin/node /app/src/Cli/cli.js parse ${request.id}`,
      url: "https://url",
      toolName: "oxparser",
      repoName: `${request.id}`,
      timeout: 600000,
      resultPath: `${scanPath.getOutputFolderForOXResults()}/${request.id}`,
      cloneDir: "",
      copyType: CopyType.CodeOnly,
      isMonoRepoChild: false,
      localCommand: "",
      monoRepoChildSubfolder: "",
      shouldAdditionallyScanRootFiles: false,
      ignoredSubfolders: null,
      orgDisplayName: StatesHelper.Instance.companyName,
      putInQueueTime: new Date().getTime(),
      rawCommand: "",
      toolCopyDestination: "",
    };

    await memoryDB.queuerPush.execute(toolName, JSON.stringify(toolRunnerRequest));
  }
}

export async function sendEnrichMessagesToToolRunner(
  requests: ParsingRequest[],
  toolName = process.env.OXPARSER_QUEUE_KEY_ENRICHMENT || "RunOxParserEnrichment",
) {
  for (const request of requests) {
    await memoryDB.queueSet.execute(request.id, 300, JSON.stringify(request));

    const toolRunnerRequest: ScannerMessage = {
      uuid: StatesHelper.Instance.uuid,
      orgID: StatesHelper.Instance.orgName,
      command: `/usr/local/bin/node /app/src/Cli/cli.js enrich ${request.id}`,
      url: "https://url",
      toolName: "oxparser",
      repoName: `${request.id}`,
      timeout: 600000,
      resultPath: `${scanPath.getOutputFolderForOXResults()}/${request.id}`,
      cloneDir: "",
      copyType: CopyType.CodeOnly,
      isMonoRepoChild: false,
      localCommand: "",
      monoRepoChildSubfolder: "",
      shouldAdditionallyScanRootFiles: false,
      ignoredSubfolders: null,
      orgDisplayName: StatesHelper.Instance.companyName,
      putInQueueTime: new Date().getTime(),
      rawCommand: "",
      toolCopyDestination: "",
    };

    await memoryDB.queuerPush.execute(toolName, JSON.stringify(toolRunnerRequest));
  }
}
