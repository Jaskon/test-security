const dotenv = require("dotenv");
dotenv.config();

const express = require("express");
import { DescribeServicesCommand, ECSClient } from "@aws-sdk/client-ecs";
import AWS from "aws-sdk";
import fs from "fs";
import path from "path";
import { exit } from "process";
import { Consumer } from "sqs-consumer";
import { v4 as uuid } from "uuid";
import { AsyncTracker } from "./async-tracker.service";
import redisCacheDB from "./cache/CacheInterface";
import CollectorManager from "./dal/collectorManager";
import { ArtifactConnectorsTypes, ArtifactorySecEventSystem } from "./entitis/ArtifactTypes";
import { CICDConnectorsTypes } from "./entitis/cicidRepoTypes";
import { repoType } from "./entitis/codeRepoTypes";
import { Token } from "./entitis/collectorEntitisTypes";
import { ScanStatus } from "./entitis/commonTypes";
import Constant from "./entitis/constant";
import { CredentialsType } from "./entitis/IdentityProvider";
import { ConnectorName, ScannerMessage } from "./entitis/service/connector-message-types";
import { staticConnectors } from "./helper/connectorsSpecific/tokensHelper";
import { isDevelopment, isK8Mode, isLocalDevelopment, isOnPrem, isStaging } from "./helper/envUtils";
import { getSharedFolder } from "./helper/generalUtils";
import { isBase64 } from "./helper/hash";
import FileHelper, { deleteFolderRecursive } from "./helper/IO/fileHlper";
import MemoryMonitorHelper from "./helper/IO/memoryMonitorHelper";
import { decryptBase64Credential } from "./helper/kms/decrypt-credential";
import { PipeLineHelper } from "./helper/pipelineHelper";
import { RepositoryMatcher } from "./helper/repository-matching/RepositoryMatcher";
import { ScanDoneService } from "./helper/scanDone/ScanDoneService";
import StatesHelper from "./helper/statesHelper";
import { ScanPhaseTime, sendScannerPhaseTimeTelemetry, stopSendingTelemetry } from "./helper/telemetry-utils";
import TimeHelper from "./helper/timeHelper";
import { uploader } from "./helper/uploader/uploader";
import loggerImport from "./logger";
import { CveToolsService } from "./mongo/cve-tools.service";
import MongoCancelScan from "./mongo/mongoCancelScan";
import MongoConnect from "./mongo/mongoConnect";
import OrgPolicyParser from "./policy/org/ruleConfigParser";
import RuleManager from "./policy/rules/ruleManager";
const logger = loggerImport.getDebugLogger();
const onAWS = process.env.MONGO_CONN === "atlas";

let debug = process.env.DEBUG != undefined;
const isDebugPipelineScan = process.env.DEBUG_PIPELINE_SCAN != undefined;
let runningInsideLambda = true;
let sigTermReceived = false;

//Globals members
let global_registerForSigterm = false;
let global_currentOrg = "";
let global_CurrentUid = "";
let global_currentScanInProgress = false;
let global_sqs_app: Consumer = null;
let ruleManager: RuleManager = null;
let runningOnK8 = false;
let scanMsg = null;

//Exit from service
let global_existTimeoutInSecondsFromEnv = process.env.EXIST_TIMEOUT == undefined ? 1000 * 60 * 4 : Number(process.env.EXIST_TIMEOUT);

//Monitor for new version of scanner
let initialDate = null;
let client;
let command;
const AWS_ASSUME_ROLE_ACCESS_KEY_ID = process.env.AWS_ACCESS_KEY_ID || "";
const AWS_ASSUME_ROLE_SECRET_ACCESS_KEY = process.env.AWS_SECRET_ACCESS_KEY || "";

const debugLocal = process.env.DEBUG != undefined;
//Cancel command
let mongoCancelScan: MongoCancelScan;

process.on("SIGUSR2", function () {
  try {
    logger.info(`uuid: ${global_CurrentUid}, org: ${global_currentOrg}, SIGUSR2 received`);
  } catch (err) {
    logger.error(`uuid: ${global_CurrentUid}, org: ${global_currentOrg}, error in SIGUSR2, err: ${err}`, err);
  }
});

process.on("uncaughtException", err => {
  try {
    logger.error("Uncaught Exception thrown:", err);

    // Handle the error safely
    logger.error(`uuid: ${global_CurrentUid}, org: ${global_currentOrg}, error - uncaughtException...., err: ${err}`);
    logger.error(`uuid: ${global_CurrentUid}, org: ${global_currentOrg}, error - uncaughtException...., err2: ${err.stack}`);
    logger.error(`uuid: ${global_CurrentUid}, org: ${global_currentOrg}, error - uncaughtException...., err3: ${JSON.stringify(err)}`);
  } catch (errEx) {
    logger.error(`uuid: ${global_CurrentUid}, org: ${global_currentOrg}, failed to print err: ${err} due to err: ${errEx}`, errEx);
  }
});

process.on("unhandledRejection", err => {
  try {
    logger.error("Unhandled Rejection thrown:", err);

    // Handle the error safely
    logger.error(`uuid: ${global_CurrentUid}, org: ${global_currentOrg}, error - unhandledRejection...., err: ${err}`);
    logger.error(`uuid: ${global_CurrentUid}, org: ${global_currentOrg}, error - unhandledRejection...., err2: ${(err as Error)?.stack}`);
    logger.error(`uuid: ${global_CurrentUid}, org: ${global_currentOrg}, error - unhandledRejection...., err3: ${JSON.stringify(err)}`);
  } catch (errEx) {
    logger.error(`uuid: ${global_CurrentUid}, org: ${global_currentOrg}, failed to print err: ${err} due to err: ${errEx}`, errEx);
  }
});

async function SIGTERM() {
  if (global_registerForSigterm) {
    return;
  }
  global_registerForSigterm = true;

  logger.info("SIGTERM - (Scanner) Start monitoring for shutdown signals");

  process.on("SIGTERM", async () => {
    logger.info("SIGTERM - (Scanner) The service is about to shut down");

    sigTermReceived = true;
    process.env.sigTermReceived = "true";

    logger.info(`SIGTERM - uuid ${global_CurrentUid}, org: ${global_currentOrg}, setting signal to exit to true`);

    closeSqs();

    if (ruleManager) {
      await ruleManager.resultsHandler.onCancelScan();
      await ruleManager.deleteAllFolders(false);
    } else {
      logger.info(`SIGTERM - uuid ${global_CurrentUid}, org: ${global_currentOrg}, ruleManager is not init yet`);
    }

    const resRetry = false; //await onRetryScan(global_CurrentUid, scanMsg, ruleManager);
    if (!resRetry) {
      // logger.info(`failed to set retry scan, going to remove active scan`);
      // const p1 = ruleManager.resultsHandler.mongoActiveScan.setDone();
      // await Promise.all([p1]);
      // logger.info(`failed to set retry scan, finish to remove active scan`);

      if (global_currentScanInProgress) {
        // log needed for dashboard to view scanner process, do not modify the "received SIGTERM during scan in progress" log.
        logger.error("received SIGTERM during scan in progress");

        const mongoConnect = new MongoConnect(global_CurrentUid, global_currentOrg);
        const err = {
          message: `Incident ID: ${global_CurrentUid}, organization ID: ${global_currentOrg} - shutdown unexpectedly, please run scan again `,
          code: 410,
          description: "",
        };

        await handleMainError(mongoConnect, global_currentOrg, global_CurrentUid, err, false, false);

        await stopSendingTelemetry();
      }
    }

    logger.info(`SIGTERM - #### uuid ${global_CurrentUid}, org: ${global_currentOrg}, exiting...`);
    process.exit(0);
  });
}

function setAWSObj() {
  try {
    if (initialDate != null) {
      return;
    }

    initialDate = new Date();

    const credentials =
      debugLocal == false
        ? null
        : {
            accessKeyId: AWS_ASSUME_ROLE_ACCESS_KEY_ID,
            secretAccessKey: AWS_ASSUME_ROLE_SECRET_ACCESS_KEY,
            sessionToken: process.env.AWS_SESSION_TOKEN,
          };

    client = new ECSClient({
      credentials,
      region: process.env.REGION,
    });
    command = new DescribeServicesCommand({
      services: [process.env.SCANNER_SERVICE_NAME],
      include: ["TAGS"],
      cluster: process.env.CLUSTER_NAME,
    });
  } catch (err) {
    logger.error(
      `${new Date().toUTCString()}, uid: ${global_CurrentUid}, org: ${global_currentOrg}, failed init aws obj, err: ${err}`,
      err,
    );
  }
}

function logScannerVersion() {
  try {
    logger.info(`Scanner version: ${fs.readFileSync(path.join(__dirname, "..", "version.json"), "utf-8")}`);
  } catch (e) {
    logger.error(`Unable to log scanner version, e: ${e}`, e);
  }
}

function setIntervalToExist() {
  setAWSObj();

  setInterval(async function () {
    try {
      if (global_currentScanInProgress) {
        // log needed for dashboard to view scanner process, do not modify the "not exiting current scan in progress" log.
        logger.info(`not exiting current scan in progress`);
        return;
      }

      const response = await client.send(command);

      const tags = response.services[0].tags;
      const updateAtTag = tags.find(t => t.key === "updatedAt");
      if (updateAtTag != undefined || updateAtTag != null) {
        const updateTime = new Date(updateAtTag.value);
        if (updateTime.getTime() > initialDate.getTime()) {
          logger.info(
            `${new Date().toUTCString()}, uid: ${global_CurrentUid}, org: ${global_currentOrg}, there is new version of a scanner, updateAtTag: ${
              updateAtTag.value
            }, tagTime: ${updateTime.getTime()}, initialDate: ${initialDate.getTime()},exiting...`,
          );
          closeSqs();
          logger.info(`uid: ${global_CurrentUid}, org: ${global_currentOrg}, exiting...`);
          process.exit(0);
        }
        logger.info(
          `${new Date().toUTCString()}, uid: ${global_CurrentUid}, org: ${global_currentOrg}, no new version available yet last update of updateAtTag: ${
            updateAtTag.value
          }`,
        );
      }
    } catch (err) {
      logger.error(
        `${new Date().toUTCString()}, uid: ${global_CurrentUid}, org: ${global_currentOrg}, failed check tags for new versions, exiting..., err: ${err}`,
        err,
      );
      closeSqs();
      logger.info(`uid: ${global_CurrentUid}, org: ${global_currentOrg}, exiting...`);
      process.exit(0);
    }
  }, global_existTimeoutInSecondsFromEnv);
}

function setIntervalToCheckHang() {
  setInterval(async function () {
    try {
      if (global_currentScanInProgress) {
        if (process.env.lastApplicationFinishTime == undefined) {
          process.env.lastApplicationFinishTime = new Date().toString();
          return;
        }
        const timeStr = process.env.lastApplicationFinishTime;

        let openTime = new Date(timeStr);
        const openTimeInfo = openTime.getTime();
        const seconds = (new Date().getTime() - openTimeInfo) / 1000;
        const minutes = seconds / 60;

        logger.debug(
          `${new Date().toUTCString()}, uid: ${global_CurrentUid}, minutes: ${minutes}, org: ${global_currentOrg}, scan in progress, last application finish time: ${timeStr}`,
        );

        const boundM = isK8Mode() ? 17 : 5;

        if (minutes > boundM) {
          process.env.startCheckSecurityEventsFromDisk = "true";

          if (minutes > 25) {
            //const outputResDir = process.env.OX_SHARED_DATA == undefined ? "/var/shared-data" : process.env.OX_SHARED_DATA;
            // const errStr = `${new Date().toUTCString()}, uid: ${global_CurrentUid},, org: ${global_currentOrg}, scan maybe HANG, last application finish time: ${timeStr}, minutes: ${minutes}`;
            // logger.warn(errStr);

            if (minutes > 360) {
              process.env.enforceExit = "true";
              logger.info(
                `${new Date().toUTCString()}, uid: ${global_CurrentUid},org: ${global_currentOrg}, exist due hang scan was called`,
              );
              await ruleManager.resultsHandler.onCancelScan();
              await ScanDoneService.Instance.publishScanDoneMessage(
                ruleManager.uuid,
                ruleManager.orgName,
                StatesHelper.Instance.scanType,
                ScanStatus.Failed,
              );
            }
          }
        }
      }
    } catch (err) {
      logger.error(
        `${new Date().toUTCString()}, uid: ${global_CurrentUid}, org: ${global_currentOrg}, failed check last application finish time, err: ${err}`,
        err,
      );
    }
  }, 60000);
}

async function sleep(interval) {
  const delay = (ms: number) => new Promise(res => setTimeout(res, ms));
  await delay(interval);
}

const waitForCancelEvent = new Promise(async (resolve, reject) => {
  try {
    logger.info(`${new Date().toUTCString()}, uid: ${global_CurrentUid}, org: ${global_currentOrg}, Start monitor cancel event`);

    while (true) {
      if (process.env.enforceExit == "true") {
        logger.info(`${new Date().toUTCString()}, uid: ${global_CurrentUid}, org: ${global_currentOrg}, cancel scan event arrive`);
        resolve(true);
      }
      await sleep(1000 * 5);
    }
  } catch (err) {
    logger.error(
      `${new Date().toUTCString()}, uid: ${global_CurrentUid}, org: ${global_currentOrg}, failed wait for cancel scan event, err: ${err}`,
      err,
    );
  }
  resolve(false);
});

function setIntervalToCheckScanCancel() {
  process.env.enforceExit = "false";

  setInterval(async function () {
    try {
      if (global_currentScanInProgress && mongoCancelScan != undefined && process.env.DEBUG == undefined) {
        const isScanCanceled = await mongoCancelScan.shouldExist();
        const isCriticalErrorExists = await StatesHelper.Instance.criticalErrorExist();
        const hasPipelineScanTimedOut = PipeLineHelper.Instance.shouldTimeOutScan();

        if (!isScanCanceled && !isCriticalErrorExists && !hasPipelineScanTimedOut) {
          return;
        }

        process.env.enforceExit = "true";
        logger.info(
          `${new Date().toUTCString()}, uid: ${global_CurrentUid}, org: ${global_currentOrg}, cancel scan was called, ` +
            `${JSON.stringify({
              isScanCanceled,
              isCriticalErrorExists,
              hasPipelineScanTimedOut,
            })}`,
        );

        await ruleManager.resultsHandler.onCancelScan();
        if (isScanCanceled) {
          try {
            const res = await mongoCancelScan.mongoModelCancelScan.model.deleteOne({
              scanId: this.uuid,
            });
            if (res.deletedCount != 1) {
              const errInfo = `Remove cancel scan failed active scan is count is not 1, count: ${res.deletedCount}, uid: ${this.uuid}, org: ${this.org}`;
              logger.error(errInfo);
            } else {
              logger.info(`Remove cancel scan, count: ${res.deletedCount}, uid: ${this.uuid}, org: ${this.org}`);
            }
          } catch (err) {
            const errInfo = `failed cancel scan, err: ${err}`;
            logger.error(errInfo, err);
          }
        }

        await ScanDoneService.Instance.publishScanDoneMessage(
          ruleManager.uuid,
          ruleManager.orgName,
          StatesHelper.Instance.scanType,
          hasPipelineScanTimedOut ? ScanStatus.TimedOut : ScanStatus.Failed,
        );
      }
    } catch (err) {
      logger.error(
        `${new Date().toUTCString()}, uid: ${global_CurrentUid}, org: ${global_currentOrg}, failed cancel scan, err: ${err}`,
        err,
      );
    }
  }, 10000);
}

function setIntervalToPrintMemorySnapshot() {
  process.env.enforceExit = "false";

  setInterval(
    async function () {
      try {
        if (global_currentScanInProgress && mongoCancelScan != undefined) {
          await MemoryMonitorHelper.Instance.printSnapshot(global_currentOrg, global_CurrentUid, "task");
        }
      } catch (err) {
        logger.error(
          `${new Date().toUTCString()}, uid: ${global_CurrentUid}, org: ${global_currentOrg}, failed take memory snapshot, err: ${err}`,
          err,
        );
      }
    },
    isDevelopment() ? 1000 * 60 * 1 : 1000 * 60 * 5,
  );
}

function closeSqs() {
  try {
    if (global_sqs_app == null) {
      logger.info(`uid: ${global_CurrentUid}, org: ${global_currentOrg}, global sqs is null skip close`);
      return;
    }

    logger.info(`uid: ${global_CurrentUid}, org: ${global_currentOrg}, try to close sqs customer`);
    global_sqs_app.stop();

    logger.info(`uid: ${global_CurrentUid}, org: ${global_currentOrg}, finish to close sqs customer`);
  } catch (err) {
    logger.error(`uid: ${global_CurrentUid}, org: ${global_currentOrg}, failed to close sqs customer`, err);
  }
}

const PORT = process.env.PORT || 36542;
const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

async function main() {
  try {
    runningOnK8 = isK8Mode();
    const runningOnPrem = isOnPrem();

    logger.info(`Starting the app (pid: ${process.pid})`);

    logScannerVersion();

    //Register to SIGTERM as first action
    await SIGTERM();

    setIntervalToCheckScanCancel();
    setIntervalToPrintMemorySnapshot();
    setIntervalToCheckHang();
    if (!runningOnK8 && !runningOnPrem) {
      setIntervalToExist();
    }

    //Debug
    if (debug) {
      await debug_main(uuid());
      exit(0);
    }

    //K8
    if (runningOnK8) {
      await scanInK8Mode();
      return;
    }

    //On-Prem
    if (runningOnPrem) {
      await startPullRedisToWaitForScan();
      return;
    }

    //Sast AWS
    if (onAWS) {
      await scanInSQSMode();
      return;
    }
  } catch (err) {
    logger.error(`err happen in main, err: ${err}`, err);
  }
}

AsyncTracker.runWithAsyncTracker(main);

async function startPullRedisToWaitForScan() {
  logger.info(`running in on prem mode`);
  while (true) {
    await onPremScan();
    await sleep(1000 * 2);
  }
}

async function scanInK8Mode() {
  logger.info(
    `running in k8 mode, env var SCANNER_RUN_AS_TASK: ${process.env.SCANNER_RUN_AS_TASK}, TASK_JSON_PATH: ${process.env.TASK_JSON_PATH}`,
  );

  if (!process.env.TASK_JSON_PATH) {
    logger.error(`running in k8 mode, but path to message are: ${process.env.TASK_JSON_PATH}`);
    process.exit(1);
  }

  const pathToMsg = process.env.TASK_JSON_PATH;
  const data = fs.readFileSync(pathToMsg, "utf8");
  const message = JSON.parse(data);
  const msg = {
    MessageBody: message.MessageBody,
    MessageDeduplicationId: message.MessageDeduplicationId,
  };
  scanMsg = data;

  await pushMessageToStartScan(msg, "K8");

  logger.info("finish scan for K8 mode exiting...");
  await stopSendingTelemetry();
  process.exit(0);
}

export async function SASTscan(message: any) {
  let mongoConnect: MongoConnect = null;
  let companyScanned = "";
  let isDemo = false;
  let demoAdded = false;
  let companyName = "no_name";
  let messageId = "";
  let isScheduledScan = false;
  let isFullScan = false;
  let isPipelineScan = false;

  try {
    const queuedTokens = [];
    let report = null;

    const jsonBody = message.MessageBody;
    const body = JSON.parse(jsonBody) as ScannerMessage;
    StatesHelper.Instance.scanType = body.scanType;

    logger.info(`Parsed the body: ${jsonBody}`);
    messageId = message.MessageDeduplicationId;
    if (messageId === "" || messageId == undefined) {
      logger.error(`FATAL ERROR, received message id is ${messageId}`);
      return false;
    }

    companyScanned = body.org_id;

    //Set isScheduledScan
    isScheduledScan = body.isScheduledScan;
    if (isScheduledScan != undefined) {
      if (isScheduledScan) {
        StatesHelper.Instance.isScheduledScan = true;
      }
    }

    //Set isFullScan
    isFullScan = body.isFullScan;
    if (isFullScan != undefined) {
      if (isFullScan) {
        logger.info(`isFullScan: ${isFullScan}, running full scan`);
        StatesHelper.Instance.isFullScan = true;
      } else {
        logger.info(`isFullScan: ${isFullScan}, running delta scan`);
      }
    } else {
      logger.info(`isFullScan: ${isFullScan}, running delta scan`);
    }

    //romanzit
    if (companyScanned === "org_L5YIDlR6nGIwyM4b" || companyScanned === "org_3dJe55m0ye6URIfd") {
      logger.info(`overwite isFullScan: ${isFullScan}, running full scan`);
      StatesHelper.Instance.isFullScan = true;
    }

    //Set isPipelineScan
    isPipelineScan = body.isPipelineScan;
    if (isPipelineScan != undefined) {
      if (isPipelineScan) {
        StatesHelper.Instance.isPipelineScan = true;
        PipeLineHelper.Instance.setDataFromScannerMessage(body);
        PipeLineHelper.Instance.setScanTimeout();
        PipeLineHelper.Instance.orgId = companyScanned;
        PipeLineHelper.Instance.uuid = messageId;
        PipeLineHelper.Instance.performance = body.performance;
      }
    }

    AsyncTracker.setValue(
      "ox-scan-type",
      StatesHelper.Instance.isPipelineScan ? "pipeline" : StatesHelper.Instance.isFullScan ? "full" : "delta",
    );

    StatesHelper.Instance.setConcurrentRepoScans();
    StatesHelper.Instance.setSemgrepCPU();

    if ("org_display_name" in body) companyName = body.org_display_name;

    process.env["companyName"] = companyName == undefined ? "no_name" : companyName;
    process.env["messageId"] = messageId == undefined ? "messageId" : messageId;
    process.env["orgId"] = companyScanned == undefined ? "messageId" : companyScanned;

    if (messageId === "" || messageId == undefined) {
      logger.error(`FATAL ERROR, received message companyScanned is ${companyScanned}`);
      return false;
    }

    logger.info(`Read message uid: ${messageId}, org id: ${companyScanned}, org name: ${companyName}`);

    loggerImport.updateUniqueId(messageId, body.org_id);
    // log needed for dashboard to view scanner process, do not modify the "scan request received" log.
    logger.info("scan request received");

    //Set global data
    if (global_CurrentUid === global_CurrentUid && companyScanned === global_currentOrg) {
      logger.error(`WARNING RECEIVE SAME UID FOR THE SAME ORG, uid ${messageId}, org: ${companyScanned}`);
    }
    global_CurrentUid = messageId;
    global_currentOrg = companyScanned;
    StatesHelper.Instance.companyName = companyName;

    const scanStarted = body.startTime;
    try {
      if (!scanStarted) {
        logger.error(`no scan started provided, data: ${scanStarted}`);
        StatesHelper.Instance.scanStartDate = new Date();
      } else {
        const elapsedTime = ((new Date().getTime() - scanStarted) / 1000).toFixed(2);
        logger.info(
          `time in seconds we waiting between start and scanner receive the msg is: ${elapsedTime}, global_currentOrg: ${global_currentOrg} `,
        );

        StatesHelper.Instance.scanInfoStats.ScanInQueueTime = `${elapsedTime} seconds`;
        StatesHelper.Instance.pipelineScanInfo.scannerTimeInQueue = Number(((new Date().getTime() - scanStarted) / 1000).toFixed(2));

        await sendScannerPhaseTimeTelemetry(
          ScanPhaseTime.ScanFromStartToMsg,
          global_currentOrg,
          global_CurrentUid,
          Number((new Date().getTime() - scanStarted) / 1000),
        );
        StatesHelper.Instance.scanStartDate = new Date(scanStarted);
      }
    } catch (err) {
      logger.error(`failed to set scan started, err: ${err}, scan started: ${scanStarted}`, err);
    }

    logger.info(`set global_CurrentUid: ${global_CurrentUid}, global_currentOrg: ${global_currentOrg}`);

    logger.info(`start scan ###### UID: ${messageId}`);

    const oxDir = getSharedFolder(messageId) + "/ox-security";

    const dir = oxDir + "/" + messageId + "/";
    const telemetryDir = dir + "telemetry-" + messageId;
    try {
      if (!runningInsideLambda && !fs.existsSync(oxDir)) {
        fs.mkdirSync(oxDir);
      }

      if (!runningInsideLambda && !fs.existsSync(telemetryDir)) {
        fs.mkdirSync(telemetryDir);
      }

      if (!runningInsideLambda && !fs.existsSync(dir)) {
        fs.mkdirSync(dir);
      }
    } catch (err) {
      logger.info(err);
    }

    const fileHelper = new FileHelper(messageId);

    for (const connector of body.configuredConnectors) {
      staticConnectors.push(connector);
      const url = connector.hostURL;
      let username = "";
      let token = "";
      let tenant = "";
      let projectId = "";
      let organizationId = "";
      let apiKey = "";
      let apiAccessKey = "";
      let apiSecretKey = "";
      let subscriptionId = "";
      let clientSecret = "";
      let tenantId = "";
      let clientId = "";
      let installationId = null;
      let gitHubAppId = null;
      let authUrl = "";
      let apiUrl = "";
      let awsExternalId = "";
      let awsAccessSecret = "";
      let awsAccessKey = "";
      // Bitbucket app
      let appKey = null;
      let clientKey = null;
      let sharedSecret = null;

      let vcs_type = connector.name;
      logger.info(`Read vcs_type: ${vcs_type}`);

      if (isDemo && !demoAdded) {
        vcs_type = "demo";

        const demoConnectorTest: Token = new Token(
          "code_repo",
          "demoConnector",
          "demoConnector",
          "",
          "https://api.github.com_demo",
          "demo_ghp_demo",
          false,
          "",
          "",
          "",
          true,
          0,
        );
        queuedTokens.push(demoConnectorTest);

        queuedTokens.push(
          new Token("external", "checkmarxSAST", "checkmarxSAST", "aaaaa", "aaaaa", "aaaa", true, "aaaa", "aaaa", "aaaa", true, 0),
        );

        const awsConnector: Token = new Token(
          "cloud",
          Constant.oxCloudConnectorName,
          Constant.oxCloudConnectorName,
          "",
          "",
          "awsExternalId",
          false,
          "",
          "",
          "",
          true,
          1,
          "awsAccessSecret",
          "",
          "awsAccessKey",
        );
        queuedTokens.push(awsConnector);

        queuedTokens.push(new Token("citool", "gitlabci", CICDConnectorsTypes.Gitlab, "", "", "aaaaaaa", false, "", "", "", true, 1));

        demoAdded = true;
        logger.info("demo org was added, ignoring any other token");
      }

      if (vcs_type === ConnectorName.EKS && connector?.isConfigured) {
        StatesHelper.Instance.isEKSEnabled = true;
        logger.info("AWS EKS enabled");
      }

      if (!("credentials" in connector) || ("credentials" in connector && connector.credentials.length === 0)) {
        const name = connector.name.toUpperCase();

        if (connector.isConfigured) {
          logger.info(`${name} is configured`);
          process.env[`TOOLS_${name}`] = "enabled";

          if (name === "DEPENDABOT") {
            StatesHelper.Instance.dependabotEnable = true;
            logger.info("dependabot enable");
          }

          if (name === "GITLAB DEPENDENCY SCANNING") {
            StatesHelper.Instance.gitLabDependencyScanningEnable = true;
            logger.info("gitLabDependencyScanning enable");
          }

          if (name === "GITLAB SAST") {
            StatesHelper.Instance.gitlabSastEnable = true;
            logger.info("gitlabSast enable");
          }

          if (name === "GITLAB SECRET DETECTION") {
            StatesHelper.Instance.gitlabSecretDetectionEnable = true;
            logger.info("gitlabSecretDetection enable");
          }

          if (name === "GITHUB SECRET DETECTION") {
            StatesHelper.Instance.githubSecretDetectionEnable = true;
            logger.info("githubSecretDetectionEnable enable");
          }

          if (name === "GITHUB SAST") {
            StatesHelper.Instance.githubSastEnable = true;
            logger.info("githubSastEnable enable");
          }

          if (["TRIVY-SCA", "TRIVY-SBOM"].includes(name)) {
            logger.info("enable trivy");
            process.env.TOOLS_TRIVY = "enabled";
          }
        } else {
          logger.info(`${name} is disabled`);
          process.env[`TOOLS_${name}`] = "disabled";
        }
        continue;
      }

      //
      // Credentials are an array for several tokens
      // We read the first
      //
      if (!connector.credentials || connector.credentials.length === 0 || !connector.isConfigured) {
        continue; // No one supplied the credentials
      }

      const credentials = connector.credentials;

      for (const cred of credentials) {
        if ("idpToken" in cred) {
          token = cred.idpToken;
        } else if (cred.credentialsType === CredentialsType.TokenAndUser && "token" in cred && "name" in cred) {
          token = cred.token;
          username = cred.name;
        } else if (cred.credentialsType === CredentialsType.TokenAndProjectId && "token" in cred && "projectId" in cred) {
          token = cred.token;
          projectId = cred.projectId;
        } else if (
          cred.credentialsType === CredentialsType.ClientIdSecretApiUrl &&
          "clientId" in cred &&
          "clientSecret" in cred &&
          "apiUrl" in cred
        ) {
          clientSecret = cred.clientSecret;
          clientId = cred.clientId;
          apiUrl = cred.apiUrl;
        } else if ("token" in cred) {
          token = cred.token;
        } else if ("password" in cred && "name" in cred) {
          token = cred.password;
          username = cred.name as any;
        } else if ("name" in cred) {
          // For Jenkins
          // @ts-ignore
          username = cred.name;
        } else if ("awsExternalId" in cred) {
          awsExternalId = cred.awsExternalId;
        } else if (cred.credentialsType === CredentialsType.APISecretAndAccessKey && "apiAccessKey" in cred && "apiSecretKey" in cred) {
          apiAccessKey = cred.apiAccessKey;
          apiSecretKey = cred.apiSecretKey;
        } else if (cred.credentialsType === CredentialsType.GitHubApp && "installationId" in cred && "installationToken" in cred) {
          token = cred.installationToken;
          installationId = cred.installationId.toString();
          gitHubAppId = cred.gitHubAppId;
        } else if (
          cred.credentialsType === CredentialsType.BitbucketApp &&
          "appKey" in cred &&
          "clientKey" in cred &&
          "sharedSecret" in cred
        ) {
          appKey = cred.appKey;
          clientKey = cred.clientKey;
          sharedSecret = cred.sharedSecret;
        } else if (
          connector.credentialsType === CredentialsType.TenantClientsubscriptionIdSecret &&
          "tenantId" in cred &&
          "clientId" in cred &&
          "clientSecret" in cred &&
          "subscriptionId" in cred
        ) {
          subscriptionId = cred.subscriptionId as string;
          clientSecret = cred.clientSecret;
          tenantId = cred.tenantId as string;
          clientId = cred.clientId;
        } else if (cred.credentialsType === CredentialsType.UserPasswordOnly && "password" in cred && "name" in cred) {
          username = cred.name as any;
          token = cred.password;
        } else if (cred.credentialsType === CredentialsType.TokenOnly && "password" in cred) {
          token = cred.password as any;
        }
        if (connector.credentialsType === CredentialsType.ClientIdClientSecret && "clientId" in cred && "clientSecret" in cred) {
          clientId = cred.clientId;
          clientSecret = cred.clientSecret;
        }
        if ("tenant" in cred) {
          tenant = cred.tenant as any;
        }
        if ("apiKey" in cred && "organizationId" in cred && "name" in cred && "password" in cred) {
          apiKey = cred.apiKey as any;
          organizationId = cred.organizationId as any;
          username = cred.name as any;
          token = cred.password;
        }

        if (cred.extraOptionalCreds) {
          if ("extraOptionalCreds" in cred && "atlassian" in cred.extraOptionalCreds) {
            if ("apiKey" in cred.extraOptionalCreds?.atlassian && "organizationId" in cred.extraOptionalCreds?.atlassian) {
              apiKey = cred.extraOptionalCreds.atlassian.apiKey;
              organizationId = cred.extraOptionalCreds?.atlassian.organizationId;
            }
          }
        }

        if (isBase64(token)) {
          token = await decryptBase64Credential(token);
        }
        if (sharedSecret) {
          if (isBase64(sharedSecret)) {
            sharedSecret = await decryptBase64Credential(sharedSecret);
          }
        }
        if (clientSecret) {
          if (isBase64(clientSecret)) {
            clientSecret = await decryptBase64Credential(clientSecret);
          }
        }
        if (apiSecretKey) {
          if (isBase64(apiSecretKey)) {
            apiSecretKey = await decryptBase64Credential(apiSecretKey);
          }
        }
        if (awsExternalId) {
          awsExternalId = await decryptBase64Credential(awsExternalId);
        }

        if (vcs_type === "Wiz") {
          const wizToken = new Token("external", "wiz", "wiz", clientId, apiUrl, clientSecret, true, "", "", "", true, 1);
          wizToken.authUrl = url;
          wizToken.apiUrl = apiUrl;
          wizToken.clientId = clientId;
          wizToken.clientSecret = clientSecret;
          queuedTokens.push(wizToken);
        }

        if (vcs_type === "JFrog") {
          const jfrogToken: Token = new Token(
            "artifactory",
            "jfrogArtifacts",
            "jfrogArtifacts",
            username,
            url,
            token,
            true,
            "",
            "",
            "",
            true,
            1,
          );
          queuedTokens.push(jfrogToken);
        }

        if (vcs_type === ArtifactorySecEventSystem.GCP_ARTIFACTS) {
          const jfrogToken: Token = new Token(
            "artifactory",
            "gkrArtifacts",
            ArtifactorySecEventSystem.GCP_ARTIFACTS,
            projectId,
            "",
            token,
            true,
            "",
            "",
            "",
            true,
            1,
          );
          queuedTokens.push(jfrogToken);
        }

        if (vcs_type === ArtifactorySecEventSystem.GCP_CONTAINER) {
          const jfrogToken: Token = new Token(
            "artifactory",
            "googleContainerRegistry",
            ArtifactorySecEventSystem.GCP_CONTAINER,
            projectId,
            "",
            token,
            true,
            "",
            "",
            "",
            true,
            1,
          );
          queuedTokens.push(jfrogToken);
        }

        if (vcs_type === "GitHub") {
          queuedTokens.push(
            new Token(
              "code_repo",
              "github",
              repoType.github,
              installationId ?? "",
              url,
              token,
              false,
              "",
              "",
              "",
              true,
              1,
              "",
              "",
              gitHubAppId ?? "",
            ),
          );
          queuedTokens.push(
            new Token(
              "citool",
              "githubci",
              CICDConnectorsTypes.Github,
              installationId ?? "",
              url,
              token,
              false,
              "",
              "",
              "",
              true,
              1,
              "",
              "",
              gitHubAppId ?? "",
            ),
          );
        }

        if (vcs_type.toLowerCase() === "Azure TFS".toLowerCase()) {
          console.debug(`init azure team foundation server for company ${global_currentOrg}, url: ${url}`);
          queuedTokens.push(new Token("code_repo", "AzureTFS", repoType.azureTFS, "", url, token, false, "", "", "", true, 1));
        }

        if (vcs_type.toLowerCase() === "PAN: Prisma Cloud - Containers".toLowerCase()) {
          queuedTokens.push(
            new Token("artifactory", "prismaArtifacts", "prismaArtifacts", username, url, token, true, "", "", "", true, 1),
          );
        }

        if (vcs_type.toLowerCase() === "PAN: Prisma Cloud".toLowerCase()) {
          const prismaCspm: Token = new Token("cloud", "prismaCSPM", "prismaCSPM", username, url, token, true, "", "", "", true, 1);
          queuedTokens.push(prismaCspm);
        }

        if (vcs_type.toLowerCase() === "aws") {
          // Check if this is onprem (this key will exist)
          if ("awsAccessKey" in cred) {
            //Decrypt fields
            if (cred.awsOnpremEncryptedCredentials && isBase64(cred.awsOnpremEncryptedCredentials)) {
              const decryptedFields = await decryptBase64Credential(cred.awsOnpremEncryptedCredentials);
              const decryptedFieldsInfo = JSON.parse(decryptedFields);
              awsExternalId = decryptedFieldsInfo.awsExternalId;
              awsAccessSecret = decryptedFieldsInfo.awsAccessSecret;
              awsAccessKey = cred.awsAccessKey;
            }
          }

          const awsConnector: Token = new Token(
            "cloud",
            Constant.oxCloudConnectorName,
            Constant.oxCloudConnectorName,
            //@ts-ignore
            cred.awsRoleArn,
            "",
            awsExternalId,
            false,
            "",
            "",
            "",
            true,
            1,
            awsAccessSecret,
            "",
            awsAccessKey,
          );

          queuedTokens.push(awsConnector);
        }

        try {
          if (vcs_type === "BlackDuck") {
            const blackDuck: Token = new Token("external", "blackDuck", "blackDuck", "", url, token, true, "", "", "", true, 1);
            queuedTokens.push(blackDuck);
          }
          if (vcs_type === "Sonarqube") {
            const sonarqube: Token = new Token("external", "sonarQube", "sonarQube", "", url, token, true, "", "", "", true, 1);
            queuedTokens.push(sonarqube);
          }
          if (vcs_type === "Veracode") {
            logger.info(`new connector, Veracode was added, org: ${global_currentOrg}`);
          }

          if (vcs_type.toLowerCase() === "sonatype") {
            const sonaType: Token = new Token("external", "sonaType", "sonaType", username, url, token, true, "", "", "", true, 1);
            queuedTokens.push(sonaType);
          }

          if (vcs_type.toLowerCase() === "coverity") {
            const coverity: Token = new Token("external", "coverity", "coverity", username, url, token, true, "", "", "", true, 1);
            queuedTokens.push(coverity);
          }
        } catch (err) {
          console.error(`failed add new connector, err: ${err}`);
        }

        if (vcs_type === "GitLab") {
          const gitlabHost = url == "" ? "https://gitlab.com" : url;
          queuedTokens.push(new Token("code_repo", "gitlab", repoType.gitlab, "", gitlabHost, token, false, "", "", "", true, 1));
          queuedTokens.push(new Token("citool", "gitlabci", CICDConnectorsTypes.Gitlab, "", gitlabHost, token, false, "", "", "", true, 1));
        }

        if (vcs_type === "GitLab Container Registry") {
          const gitlabHost = url == "" ? "https://gitlab.com" : url;
          queuedTokens.push(
            new Token(
              "artifactory",
              "gitlabArtifacts",
              ArtifactConnectorsTypes.GitLabContainerRegistry,
              "",
              gitlabHost,
              token,
              false,
              "",
              "",
              "",
              true,
              1,
            ),
          );
        }

        if (vcs_type === "Gerrit") {
          const t = new Token("code_repo", "gerrit", repoType.gerrit, username, url, token, false, "", "", "", true, 1);
          if (cred?.optionalFields?.SSHKey) {
            t.sshToken = cred?.optionalFields?.SSHKey;
            logger.info("Gerrit using ssh key");
          }
          queuedTokens.push(t);
        }

        if (vcs_type === "Semgrep CLI") {
          const t: Token = new Token("external", "semgrepcli", "semgrepcli", "", "", token, true, "", "", "", true, 1);
          if (cred?.optionalFields?.Config) {
            t.configFilePath = cred?.optionalFields?.Config;
            logger.info("Semgrep CLI using config file");
          }
          queuedTokens.push(t);
        }

        if (vcs_type === "AWS CodeCommit") {
          if (
            (cred.credentialsType === CredentialsType.AWSAssumeRoleCodeCommit ||
              cred.credentialsType === CredentialsType.AWSAssumeRoleCodeCommitOrganization) &&
            "awsRoleArn" in cred
          ) {
            const awsCodeCommitConnector: Token = new Token(
              "code_repo",
              "awsCodeCommit",
              repoType.awsCodeCommit,
              cred.awsRoleArn,
              "",
              awsExternalId,
              false,
              "",
              "",
              "",
              true,
              1,
              awsAccessSecret,
              "",
              awsAccessKey,
              "",
              "",
              "",
              "",
              "",
              "",
            );
            queuedTokens.push(awsCodeCommitConnector);
          } else {
            const t = new Token(
              "code_repo",
              "awsCodeCommit",
              repoType.awsCodeCommit,
              "",
              url,
              "",
              false,
              "",
              "",
              "",
              true,
              1,
              token,
              "",
              username,
              "",
              "",
              "",
              "",
              "",
              "",
            );
            queuedTokens.push(t);
          }
        }

        if (vcs_type.toLowerCase() === "azure") {
          const auzreHost = url === "" ? "https://dev.azure.com" : url;
          const splited = url.split("/");
          const userName = splited[splited.length - 1];

          queuedTokens.push(new Token("code_repo", "azure", repoType.azure, userName, auzreHost, token, true, "", "", "", true, 0));
          queuedTokens.push(
            new Token("citool", "azureci", CICDConnectorsTypes.AzurePipeLine, userName, auzreHost, token, true, "", "", "", true, 1),
          );
        }

        //ACR
        if (vcs_type === "Azure Container Registry") {
          const auzreHost = url === "" ? "https://dev.azure.com" : url;
          queuedTokens.push(
            new Token(
              "artifactory",
              "azureContainerRegistry",
              ArtifactorySecEventSystem.AZURE_CONTAINER_REGISTRY,
              "00000000-0000-0000-0000-000000000000",
              auzreHost,
              token,
              true,
              "",
              "",
              "",
              true,
              1,
              "",
              "",
              "",
              tenantId,
              clientId,
              clientSecret,
              subscriptionId,
            ),
          );
        }

        //Docker Hub Registry
        if (vcs_type === "Docker Hub") {
          queuedTokens.push(
            new Token(
              "artifactory",
              "dockerHubRegistry",
              ArtifactorySecEventSystem.DOCKER_HUB,
              username,
              "docker.io",
              token,
              true,
              "",
              "",
              "",
              true,
              1,
              "",
              "",
              "",
            ),
          );
        }

        //Nexus Registry
        if (vcs_type === "Nexus Container Registry") {
          queuedTokens.push(
            new Token(
              "artifactory",
              "nexusContainerRegistry",
              ArtifactorySecEventSystem.NEXUS_CONTAINER_REGISTRY,
              username,
              url,
              token,
              true,
              "",
              "",
              "",
              true,
              1,
              "",
              "",
              "",
            ),
          );
        }

        //GoHarbor Registry
        if (vcs_type === "GoHarbor Container Registry") {
          queuedTokens.push(
            new Token(
              "artifactory",
              "goharborContainerRegistry",
              ArtifactorySecEventSystem.GOHARBOR_CONTAINER_REGISTRY,
              username,
              url,
              token,
              true,
              "",
              "",
              "",
              true,
              1,
              "",
              "",
              "",
            ),
          );
        }

        if (vcs_type === "Checkmarx-SAST") {
          queuedTokens.push(new Token("external", "checkmarxSAST", "checkmarxSAST", username, url, token, true, "", "", "", true, 1));
        }
        // HCL AppScan
        if (vcs_type.toLowerCase() === "hcl") {
          const hclToken = new Token("external", "hcl", "hcl", username, url, token, true, "", "", "", true, 1);
          queuedTokens.push(hclToken);
        }

        if (vcs_type.toLowerCase() === "fortify-sast" || vcs_type.toLowerCase() === "fortify-secrets") {
          const fortifyToken = new Token("external", "fortify", "fortify", "", url, "", true, "", "", "", true, 1);
          fortifyToken.clientId = clientId;
          fortifyToken.clientSecret = clientSecret;
          queuedTokens.push(fortifyToken);
        }

        if (vcs_type.toLowerCase() === "snyk") {
          queuedTokens.push(new Token("external", "snyk", "snyk", username, url, token, true, "", "", "", true, 1));
        }

        if (
          vcs_type.toLowerCase() === "semgrep-api-sca" ||
          vcs_type.toLowerCase() === "semgrep-api-sast" ||
          vcs_type.toLowerCase() === "semgrep-api-secrets"
        ) {
          queuedTokens.push(
            new Token("external", "semgrepEnterprise", "semgrepEnterprise", username, url, token, true, "", "", "", true, 1),
          );
        }

        if (vcs_type.toLowerCase() === "klocwork") {
          const klockworkToken = new Token("external", "klocwork", "klocwork", username, url, token, true, "", "", "", true, 1);
          queuedTokens.push(klockworkToken);
        }

        if (vcs_type.toLowerCase() === "orca") {
          const orcaToken = new Token("external", "orca", "orca", username, "", token, true, "", "", "", true, 1);
          orcaToken.password = token;
          queuedTokens.push(orcaToken);
        }

        if (vcs_type.toLowerCase() === "veracode") {
          const veraCodeToken: Token = new Token(
            "external",
            "veraCode",
            "veraCode",
            apiAccessKey,
            url,
            apiSecretKey,
            true,
            "",
            "",
            "",
            true,
            1,
          );
          queuedTokens.push(veraCodeToken);
        }

        if (
          vcs_type.toLowerCase() === "spectral-sca" ||
          vcs_type.toLowerCase() === "spectral-secrets" ||
          vcs_type.toLowerCase() === "spectral-iac"
        ) {
          const spectralToken: Token = new Token("external", "spectral", "spectral", "", url, token, true, "", "", "", true, 1);
          queuedTokens.push(spectralToken);
        }
        if (vcs_type === "Checkmarx-SCA") {
          queuedTokens.push(
            new Token("external", "checkmarxSCA", "checkmarxSCA", `${tenant}@${username}`, url, token, true, "", "", "", true, 1),
          );
        }

        if (vcs_type === "Bitbucket") {
          const t = new Token("code_repo", "bitbucket", repoType.bitbucket, username, url, token, false, "", "", "", true, 1);
          t.apiKey = apiKey;
          t.organizationId = organizationId;

          // Bitbucket app
          t.appKey = appKey;
          t.clientKey = clientKey;
          t.sharedSecret = sharedSecret;
          queuedTokens.push(t);
        }

        if (vcs_type === "Bitbucket stash") {
          queuedTokens.push(
            new Token("code_repo", "bitbucketStash", repoType.bitbucketStash, username, url, token, false, "", "", "", true, 1),
          );
        }

        if (vcs_type === "CircleCI") {
          queuedTokens.push(
            new Token(
              "citool",
              "circleci",
              CICDConnectorsTypes.CircleCI,
              "",
              "",
              token, //process.env.CIRCLECI,
              false,
              "",
              "",
              "",
              true,
              1,
            ),
          );
        }

        if (vcs_type === "DroneCI") {
          queuedTokens.push(new Token("citool", "droneci", CICDConnectorsTypes.DroneCI, "", url, token, false, "", "", "", true, 1));
        }

        if (vcs_type === "Jenkins") {
          queuedTokens.push(new Token("citool", "jenkins", CICDConnectorsTypes.Jenkins, username, url, token, false, "", "", "", true, 1));
        }

        if (vcs_type.toLowerCase() === "kong") {
          queuedTokens.push(new Token("external", "kong", "kong", "", url, token, true, "", "", "", true, 1));
          StatesHelper.Instance.kongHostUrl = url;
          StatesHelper.Instance.kongToken = token;
        }

        if (vcs_type.toLowerCase() === "solace") {
          queuedTokens.push(new Token("external", "solace", "solace", username, "", token, true, "", "", "", true, 1));
          StatesHelper.Instance.solaceUsername = username;
          StatesHelper.Instance.solacePassword = token;
        }
      }
    }

    mongoConnect = new MongoConnect(messageId, companyScanned);
    mongoCancelScan = new MongoCancelScan(messageId, companyScanned, mongoConnect);
    RepositoryMatcher.init(mongoConnect, messageId, companyScanned);
    CveToolsService.init(mongoConnect, messageId, companyScanned);

    try {
      const collectorManager: CollectorManager = new CollectorManager(messageId, companyScanned, mongoConnect, body);
      const orgPolicyParser: OrgPolicyParser = new OrgPolicyParser(messageId);
      const connectorsPolicyConfiguration = orgPolicyParser.getOrgPolicy().connectors;

      let connectorsProm = [];
      for (const token of queuedTokens) {
        if (connectorsPolicyConfiguration != undefined) {
          let policyConfiguration = connectorsPolicyConfiguration.filter(i => i.type === token.type);
          if (policyConfiguration.length > 0) {
            connectorsProm.push(collectorManager.setCollector(token, orgPolicyParser));
            continue;
          }
        }
        connectorsProm.push(collectorManager.setCollector(token, orgPolicyParser));
      }
      await Promise.all([connectorsProm]);
      ruleManager = new RuleManager(
        messageId,
        collectorManager,
        orgPolicyParser,
        companyScanned,
        mongoConnect,
        isScheduledScan,
        isPipelineScan,
      );

      report = await ruleManager.run();
    } catch (err) {
      const errInfo = {
        code: 500,
        message: `Incident ID: ${messageId}, organization ID: ${companyScanned} - unexpected error, err: ${err}`,
        description: err,
      };

      await handleMainError(mongoConnect, companyScanned, messageId, errInfo, isScheduledScan, isPipelineScan);
    }

    // log needed for dashboard to view scanner process, do not modify the "scan finished" log.
    logger.info("scan finished");
    const uploadDate = new Date();
    const s3dir = `${uploadDate.getFullYear()}/${uploadDate.getMonth() + 1}/${uploadDate.getDate()}/${companyScanned}`;
    if (report === null) {
      logger.info("The report is empty ");

      // OxMonoRepo org_1oXJ83N6Hdqbz6Qj
      // SmokeTest2 org_KKdhIQOhEQ7wHomp
      if (
        (isDevelopment() ||
          isStaging() ||
          StatesHelper.Instance.orgName === "org_1oXJ83N6Hdqbz6Qj" ||
          StatesHelper.Instance.orgName === "org_KKdhIQOhEQ7wHomp") &&
        process.env.REPORT_BUCKET_AWS_ACCESS_KEY &&
        process.env.REPORT_BUCKET_AWS_SECRET_ACCESS_KEY
      ) {
        logger.info(`before upload to s3 shared folder dir ${getSharedFolder(messageId)}`);
        fileHelper.copyFileSync(oxDir + `/ox-security.log.${TimeHelper.getTime()}`, telemetryDir);

        await uploader().uploadZipped(getSharedFolder(messageId), s3dir);
        deleteFolderRecursive(getSharedFolder(messageId));
      }

      deleteFolderRecursive(dir);

      const err = {
        code: 500,
        message: `Incident ID: ${messageId}, organization ID: ${companyScanned} - unexpected error`,
        description: "The report is empty",
      };

      await handleMainError(mongoConnect, companyScanned, messageId, err, isScheduledScan, isPipelineScan);

      return false;
    }

    if ((isDevelopment() || isStaging()) && process.env.REPORT_BUCKET_AWS_ACCESS_KEY && process.env.REPORT_BUCKET_AWS_SECRET_ACCESS_KEY) {
      try {
        const delay = ms => new Promise(res => setTimeout(res, ms));
        await delay(1000);

        const pathToUpload = getSharedFolder(messageId);
        logger.info(`try upload to s3 from source: ${pathToUpload}`);

        await uploader().uploadZipped(pathToUpload, s3dir);
        deleteFolderRecursive(getSharedFolder(messageId));
      } catch (err) {
        logger.error(`uuid: ${messageId}, org: ${companyScanned} upload logs err: ${err}`, err);
      }
    }

    if (process.env.MONGO_CONN !== "atlas") redisCacheDB.instance.flush();

    deleteFolderRecursive(dir);

    return true;
  } catch (err) {
    logger.error(`ERROR in SQS Main details: uuid: ${messageId}, org: ${companyScanned} scan err: ${err}`, err);

    process.nextTick(() => {
      logger.error(`ERROR in SQS Main through the nextTick`);
    });

    const errInfo = {
      code: 500,
      message: `Incident ID: ${messageId}, organization ID: ${companyScanned} - unexpected error, err: ${err}`,
      description: err,
    };

    await handleMainError(mongoConnect, companyScanned, messageId, errInfo, isScheduledScan, isPipelineScan);
    return false;
  }
}

const handleMainError = async (mongoConnect, companyScanned, uid, err, isScheduledScan: boolean, isPipelineScan: boolean) => {
  try {
    let ruleManager = new RuleManager(
      uid,
      new CollectorManager(uid, companyScanned, mongoConnect, null),
      new OrgPolicyParser(uid),
      companyScanned,
      mongoConnect,
      isScheduledScan,
      isPipelineScan,
    );

    await ruleManager.handleError(err);
  } catch (err) {
    logger.error(`uuid: ${uid}, org: ${companyScanned}, failed handle main crush, err: ${err}`, err);
  }
};

// Main queue scan system
async function onPremScan() {
  if (sigTermReceived) {
    logger.info("SIGTERM received exiting...");
    process.exit(0);
  }

  if (global_currentScanInProgress) {
    return;
  }

  const scanRequest = await redisCacheDB.instance.nonHashedGet("ScanConnectors");

  if (scanRequest !== null && !global_currentScanInProgress) {
    logger.info("on prem queued scan in progress");
    global_currentScanInProgress = true;

    const scan = SASTscan(scanRequest as any);
    await Promise.race([scan, waitForCancelEvent]);

    logger.info("on prem scan existing...");

    global_currentScanInProgress = false;
    await stopSendingTelemetry();
    process.exit(0);
  }
}

async function debug_main(messageId: string) {
  AsyncTracker.setValue("ox-scan-id", messageId);
  AsyncTracker.setValue("ox-org-id", process.env.COMPANY);

  try {
    global_currentScanInProgress = true;

    const snyk: Token = new Token("external", "snyk", "snyk", "", "https://snyk.io", "" || "use .env please", true, "", "", "", true, 1);

    const orca: Token = new Token(
      "external",
      "orca",
      "orca",
      "",
      "https://app.eu.orcasecurity.io/api",
      process.env.ORCA_UPSTREAM,
      true,
      "",
      "",
      "",
      true,
      1,
    );

    const klockwork: Token = new Token(
      "external",
      "klocwork",
      "klocwork",
      process.env.KLOCWORK_USERNAME || "use .env please",
      process.env.KLOCWORK_HOST || "use .env please", //--> hots
      process.env.KLOCWORK_PASSWORD || "use .env please",
      true,
      "",
      "",
      "",
      true,
      1,
    );

    const blackDuck: Token = new Token(
      "external",
      "blackDuck",
      "blackDuck",
      "",
      process.env.BLACKDUCK_URL || "use .env please", //--> hots
      process.env.BLACKDUCK_TOKEN || "use .env please",
      true,
      "",
      "",
      "",
      true,
      1,
    );

    const sonarQube: Token = new Token(
      "external",
      "sonarQube",
      "sonarQube",
      "",
      process.env.SONARQUBE_URL || "use .env please", //--> hots
      process.env.SONARQUBE_TOKEN || "use .env please",
      true,
      "",
      "",
      "",
      true,
      1,
    );

    const hcl: Token = new Token(
      "external",
      "hcl",
      "hcl",
      process.env.APPSCAN_KEY_ID || "use .env please",
      process.env.APPSCAN_URL || "use .env please", //--> host
      process.env.APPSCAN_SECRET || "use .env please",
      true,
      "",
      "",
      "",
      true,
      1,
    );

    const fortify: Token = new Token(
      "external",
      "fortify",
      "fortify",
      process.env.FORTIFY_CLIENT_ID || "use .env please",
      process.env.FORTIFY_HOST || "use .env please", //--> host
      process.env.FORTIFY_CLIENT_SECRET || "use .env please",
      true,
      "",
      "",
      "",
      true,
      1,
    );
    fortify.clientId = process.env.FORTIFY_CLIENT_ID || "use .env please";
    fortify.clientSecret = process.env.FORTIFY_CLIENT_SECRET || "use .env please";

    const prismaArtifacts: Token = new Token(
      "artifactory",
      "prismaArtifacts",
      "prismaArtifacts",
      process.env.PRISMA_ARTIFACTS_USER || "use .env please",
      process.env.PRISMA_ARTIFACTS_URL || "use .env please",
      process.env.PRISMA_ARTIFACTS_PASS || "use .env please",
      true,
      "",
      "",
      "",
      true,
      0,
    );

    const prismaArtifacts2: Token = new Token(
      "artifactory",
      "prismaArtifacts",
      "prismaArtifacts",
      process.env.PRISMA_ARTIFACTS_USER || "use .env please",
      process.env.PRISMA_ARTIFACTS_URL || "use .env please",
      process.env.PRISMA_ARTIFACTS_PASS || "use .env please",
      true,
      "",
      "",
      "",
      true,
      0,
    );

    const prismaCspm: Token = new Token(
      "cloud",
      "prismaCSPM",
      "prismaCSPM",
      process.env.PRISMA_CSPM_USER,
      process.env.PRISMA_CSPM_URL,
      process.env.PRISMA_CSPM_PASS,
      true,
      "",
      "",
      "",
      true,
      0,
    );

    const epGitHub: Token = new Token(
      "code_repo",
      "github",
      repoType.github,
      "",
      "",
      process.env.EYALATOX_GITHUB || "use .env",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const tokenGitHub: Token = new Token(
      "code_repo",
      "github",
      repoType.github,
      "",
      "https://api.github.com",
      process.env.GITHUB_TOKEN || "use .env",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const dorGitHub: Token = new Token(
      "code_repo",
      "github",
      repoType.github,
      "",
      "https://api.github.com",
      process.env.GITHUB_ACCESS_TOKEN || "use .env",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const tokenGitHubApp: Token = new Token(
      "code_repo",
      "github",
      repoType.github,
      "41006450",
      "",
      JSON.stringify({
        installationToken: process.env.OX_GITHUB_APP_INSTALLATION_TOKEN,
        createdAt: "",
        token: process.env.OX_GITHUB_APP_INSTALLATION_TOKEN,
      }),
      false,
      "",
      "",
      "",
      true,
      1,
      "",
      "",
      "378705",
    );

    const jfrogsToken: Token = new Token(
      "artifactory",
      "jfrogArtifacts",
      "jfrogArtifacts",
      process.env.DIGITAL_ASSETS_USERNAME || "user .env please",
      process.env.DIGITAL_ASSETS_URL || "use .env please",
      process.env.DIGITAL_ASSETS_TOKEN || "use .env please",
      true,
      "",
      "",
      "",
      true,
      0,
    );

    const gkrToken: Token = new Token(
      "artifactory",
      "gkrArtifacts",
      ArtifactorySecEventSystem.GCP_ARTIFACTS,
      process.env.GCR_PROJECT,
      "",
      process.env.GCR_PASS,
      true,
      "",
      "",
      "",
      true,
      0,
    );

    const gcrToken: Token = new Token(
      "artifactory",
      "googleContainerRegistry",
      ArtifactorySecEventSystem.GCP_CONTAINER,
      process.env.GCR_PROJECT,
      "",
      process.env.GCR_PASS,
      true,
      "",
      "",
      "",
      true,
      0,
    );

    const acrToken: Token = new Token(
      "artifactory",
      "azureContainerRegistry",
      ArtifactorySecEventSystem.AZURE_CONTAINER_REGISTRY,
      process.env.OR_USERNAME_GKR || "use .env please",
      process.env.OR_URL_GKR || "use .env please",
      process.env.OR_TOKEN || "use .env please",
      true,
      "",
      "",
      "",
      true,
      0,
      "",
      "",
      "",
      process.env.ACR_TENAT_ID,
      process.env.ACR_CLIENT_ID,
      process.env.ACR_CLIENT_SECRET,
      process.env.ACR_SUB_ID,
    );

    const nexusToken: Token = new Token(
      "artifactory",
      "nexusContainerRegistry",
      ArtifactorySecEventSystem.NEXUS_CONTAINER_REGISTRY,
      process.env.NEXUS_USERNAME || "use .env please",
      process.env.NEXUS_URL || "use .env please",
      process.env.NEXUS_PASSWORD || "use .env please",
      true,
      "",
      "",
      "",
      true,
      0,
      "",
      "",
      "",
    );

    const dockerHubToken: Token = new Token(
      "artifactory",
      "dockerHubRegistry",
      ArtifactorySecEventSystem.DOCKER_HUB,
      process.env.DOCKER_HUB_USERNAME || "use .env please",
      "docker.io",
      process.env.DOCKER_HUB_PASS || "use .env please",
      true,
      "",
      "",
      "",
      true,
      0,
    );

    const goHarborToken: Token = new Token(
      "artifactory",
      "goharborContainerRegistry",
      ArtifactorySecEventSystem.GOHARBOR_CONTAINER_REGISTRY,
      process.env.GOHARBOR_USERNAME || "use .env please",
      process.env.GOHARBOR_URL || "use .env please",
      process.env.GOHARBOR_PASSWORD || "use .env please",
      true,
      "",
      "",
      "",
      true,
      0,
    );

    const gitlabArtifactToken: Token = new Token(
      "artifactory",
      "gitlabArtifacts",
      "gitlabArtifacts",
      "",
      "https://gitlab.com",
      process.env.GITLAB_TOKEN,
      true,
      "",
      "",
      "",
      true,
      0,
    );

    const demoConnectorTest: Token = new Token(
      "code_repo",
      "demoConnector",
      "demoConnector",
      "",
      "",
      "ddd" || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const tokenGitHubCI: Token = new Token(
      "citool",
      "githubci",
      CICDConnectorsTypes.Github,
      "",
      "https://api.github.plus500.com",
      process.env.GITHUB_TOKEN_DEMO || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const circleci = new Token(
      "citool",
      "circleci",
      CICDConnectorsTypes.CircleCI,
      "",
      "",
      process.env.CIRCLECI || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
    );
    const idpBitbucket1 = {
      scopes: "webhook account pullrequest",
      access_token: process.env.BITBUCKET_ACCESS_TOKEN || "use .env please",
      expires_in: 7200,
      token_type: "bearer",
      state: "authorization_code",
      refresh_token: process.env.BITBUCKET_REFRESH_TOKEN || "use .env please",
    };

    const bitbucket: Token = new Token(
      "code_repo",
      "bitbucket",
      repoType.bitbucket,
      "dorox",
      "https://api.bitbucket.org/2.0",
      process.env.BITBUCKET_TOKEN || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      process.env.BITBUCKET_API_KEY || "use .env please",
      process.env.BITBUCKET_ORG_ID || "use .env please",
    );

    const bitbucketAppToken = new Token(
      "code_repo",
      "bitbucket",
      repoType.bitbucket,
      "",
      "https://api.bitbucket.org/2.0",
      "",
      false,
      "",
      "",
      "",
      true,
      1,
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      process.env.BIT_BUCKET_API_KEY || "use .env please",
      process.env.BIT_BUCKET_ORG_ID || "use .env please",
    );
    bitbucketAppToken.clientKey = process.env.BIT_BUCKET_CLIENT_KEY || "use .env please";
    bitbucketAppToken.sharedSecret = process.env.BIT_BUCKET_SHARED_SECRET || "use .env please";
    bitbucketAppToken.appKey = process.env.BIT_BUCKET_APP_KEY || "use .env please";

    const bitbucketStash: Token = new Token(
      "code_repo",
      "bitbucketStash",
      repoType.bitbucketStash,
      process.env.BITBUCKET_STASH_USER || "use .env please",
      process.env.BITBUCKET_STASH_URL || "use .env please",
      process.env.BITBUCKET_STASH_PASS || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const gitlab: Token = new Token(
      "code_repo",
      "gitlab",
      repoType.gitlab,
      "",
      "https://gitlab.com",
      process.env.GITLAB_TOKEN || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const oxGitlab: Token = new Token(
      "code_repo",
      "gitlab",
      repoType.gitlab,
      "",
      "https://gitlab.com",
      process.env.OX_GITLAB || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const wizToken: Token = new Token(
      "external",
      "wiz",
      "wiz",
      process.env.WIZ_CLIENT_ID || "use .env please",
      process.env.WIZ_API_URL || "use .env please",
      process.env.WIZ_CLIENT_SECRET || "use .env please",
      true,
      "",
      "",
      "",
      true,
      1,
    );
    wizToken.authUrl = process.env.WIZ_AUTH_URL;
    wizToken.clientSecret = process.env.WIZ_CLIENT_SECRET;
    wizToken.clientId = process.env.WIZ_CLIENT_ID;
    wizToken.apiUrl = process.env.WIZ_API_URL;

    const gitlabCICD: Token = new Token(
      "citool",
      "gitlabci",
      CICDConnectorsTypes.Gitlab,
      "",
      "https://gitlab.com",
      process.env.GITLAB_TOKEN || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const tokenGitHubCID: Token = new Token(
      "citool",
      "githubci",
      CICDConnectorsTypes.Github,
      "",
      "",
      process.env.GITHUB_TOKEN || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const graphString = "alex";
    const mapOfSec = {};
    //GraphHelper.handleGraph(graphString, mapOfSec);

    const mamanToken = new Token(
      "code_repo",
      "azure",
      repoType.azure,
      "MamanGroup",
      "https://dev.azure.com/MamanGroup",
      process.env.MAMAN_TOKEN,
      true,
      "",
      "",
      "",
      true,
      1,
    );

    const tokenAzureRepo: Token = new Token(
      "code_repo",
      "azure",
      repoType.azure,
      "dor",
      "https://dev.azure.com/",
      process.env.AZURE_TOKEN || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const idpToken = {
      access_token: "",
      token_type: "jwt-bearer",
      expires_in: "3599",
      refresh_token: "",
      scope:
        "vso.auditlog vso.build vso.code_full vso.code_status vso.graph_manage vso.identity_manage vso.memberentitlementmanagement_write vso.packaging vso.project_manage vso.release vso.security_manage vso.wiki vso.work_write vso.authorization_grant",
    };

    const IdptokenAzureRepo: Token = new Token(
      "code_repo",
      "azure",
      repoType.azure,
      "",
      "https://dev.azure.com/888holdings",
      JSON.stringify(idpToken),
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const IdptokenAzureRepo2: Token = new Token(
      "code_repo",
      "azure",
      repoType.azure,
      "",
      "http://ec2-3-250-80-75.eu-west-1.compute.amazonaws.com:8080",
      process.env.AZURE_TOKEN,
      false,
      "",
      "",
      "",
      true,
      1,
    );

    let jenkinsUrl = process.env.JENKINS_URL || "use .env please";
    let jenkinsName = process.env.JENKINS_USER || "use .env please";
    let jenkinsToken = process.env.JENKINS_TOKEN || "use .env please";

    const jenkins = new Token(
      "citool",
      "jenkins",
      CICDConnectorsTypes.Jenkins,
      jenkinsName,
      jenkinsUrl,
      jenkinsToken,
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const myaws = new Token(
      "cloud",
      Constant.oxCloudConnectorName,
      Constant.oxCloudConnectorName,
      "arn:aws:iam::857809147732:role/OxAWSIntegrationRole-0a1913683f95",
      "",
      "c7569a22-620b-4529-8c78-ac86495667e2",
      false,
      "",
      "",
      "",
      true,
      1,
      process.env.CLOUD_AWS_SECRET_ACCESS_KEY || "use .env please",
      process.env.AWS_SESSION_TOKEN,
      process.env.CLOUD_AWS_ACCESS_KEY || "use .env please",
    );

    const awsCodeCommit = new Token(
      "code_repo",
      "awsCodeCommit",
      repoType.awsCodeCommit,
      process.env.AWS_EXTERNAL_ID || "use .env please",
      "",
      process.env.AWS_ROLE_ARN || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
    );

    const demoAWS = new Token(
      "cloud",
      Constant.oxCloudConnectorName,
      Constant.oxCloudConnectorName,
      "arn:aws:iam::203043666164:role/OxAWSIntegrationRole-02c556abba67",
      "",
      "074d70f6-1f7a-4e1d-a245-3090645aaf72",
      false,
      "",
      "",
      "",
      true,
      1,
      process.env.CLOUD_AWS_SECRET_ACCESS_KEY || "use .env please",
      process.env.AWS_SESSION_TOKEN,
      process.env.CLOUD_AWS_ACCESS_KEY || "use .env please",
    );

    const awsConnectorOnprem = new Token(
      "cloud",
      Constant.oxCloudConnectorName,
      Constant.oxCloudConnectorName,
      "arn:aws:iam::857809147732:role/DevOxOnpremAWSIntegrationRole",
      "",
      "46829b74-9e79-472d-bce4-7fb0d17de2a5",
      false,
      "",
      "",
      "",
      true,
      1,
      process.env.AWS_SECRET_ACCESS_KEY || "use .env please",
      "",
      process.env.AWS_ACCESS_KEY_ID || "use .env please",
    );

    const azureTestToken = new Token(
      "citool",
      "azureci",
      CICDConnectorsTypes.AzurePipeLine,
      "",
      "https://dev.azure.com",
      process.env.AZURE_TOKEN || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const url = `https://dev.azure.com/888holdings`;
    const auzreHost = url;
    const splited = url.split("/");
    const userName = splited[splited.length - 1];

    // const azureReposToken = new Token(
    //   "code_repo",
    //   "azure",
    //   repoType.azure,
    //   userName,
    //   auzreHost,
    //   process.env.AZURE_TOKEN || "use .env please",
    //   false,
    //   "",
    //   "",
    //   "",
    //   true,
    //   1
    // );

    // azure tfs
    const azureTeamFoundationServerToken = new Token(
      "code_repo",
      "AzureTFS",
      repoType.azureTFS,
      "",
      "http://ec2-3-250-80-75.eu-west-1.compute.amazonaws.com:8080/tfs",
      process.env.AZURE_TFS_TOKEN || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const gerritToken = new Token(
      "code_repo",
      "gerrit",
      repoType.azureTFS,
      "sa-external-oxsecurity",
      "https://gerrit.yext.com",
      process.env.GERRIT_TOKEN,
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const awsCodeCommitToken = new Token(
      "code_repo",
      "awsCodeCommit",
      repoType.awsCodeCommit,
      "",
      "",
      "",
      false,
      "",
      "",
      "",
      true,
      1,
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
      "",
    );

    const azureCItoken = new Token(
      "citool",
      "azureci",
      CICDConnectorsTypes.AzurePipeLine,
      "",
      "https://dev.azure.com/888holdings",
      JSON.stringify(idpToken),
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const cxSast = new Token(
      "external",
      "checkmarxSAST",
      "checkmarxSAST",
      "admin@cx" || "username",
      "https://4bb1-188-211-162-64.ngrok-free.app" || "url",
      "Found12Bugs!" || "",
      true,
      "",
      "",
      "",
      true,
      0,
    );

    const cxSca = new Token(
      "external",
      "checkmarxSCA",
      "checkmarxSCA",
      process.env.CX_SCA_URL || "username",
      process.env.CX_SCA_URL || "username",
      process.env.CX_SCA_PASS || "password",
      true,
      "",
      "",
      "",
      true,
      0,
    );

    const droneCI: Token = new Token(
      "citool",
      "droneci",
      CICDConnectorsTypes.DroneCI,
      "",
      process.env.DRONECI_URL || "use .env please",
      process.env.DRONECI_TOKEN || "use .env please",
      false,
      "",
      "",
      "",
      true,
      1,
    );

    const sonaType: Token = new Token(
      "external",
      "sonaType",
      "sonaType",
      process.env.SONA_TYPE_USER_CODE || "use .env please",
      process.env.SONA_TYPE_URL || "use .env please", //--> hots
      process.env.SONA_TYPE_PASS_CODE || "use .env please",
      true,
      "",
      "",
      "",
      true,
      1,
    );

    const veraCodeToken: Token = new Token(
      "external",
      "veraCode",
      "veraCode",
      process.env.VERACODE_USERNAME || "use .env please",
      process.env.VERACODE_HOST || "use .env please", //--> hots
      process.env.VERACODE_PASSWORD || "use .env please",
      true,
      "",
      "",
      "",
      true,
      1,
    );

    const coverityToken: Token = new Token(
      "external",
      "coverity",
      "coverity",
      process.env.COVERITY_USERNAME || "use .env please",
      process.env.COVERITY_HOST || "use .env please", //--> hots
      process.env.COVERITY_PASSWORD || "use .env please",
      true,
      "",
      "",
      "",
      true,
      1,
    );

    const azureToken: Token = new Token(
      "azureContainerRegistry",
      "azureContainerRegistry",
      ArtifactorySecEventSystem.AZURE_CONTAINER_REGISTRY,
      "00000000-0000-0000-0000-000000000000",
      "",
      process.env.ACR_PASS,
      true,
      "",
      "",
      "",
      true,
      0,
    );

    const spectralToken: Token = new Token(
      "external",
      "spectral",
      "spectral",
      "",
      process.env.SPECTRAL_URL || "process.env.SPECTRAL_URL",
      process.env.SPECTRAL_PASS || "process.env.SPECTRAL_PASS",
      true,
      "",
      "",
      "",
      true,
      1,
    );

    const semgrepToken: Token = new Token(
      "external",
      "semgrepEnterprise",
      "semgrepEnterprise",
      "",
      process.env.SEMGREP_URL || "use .env please",
      process.env.SEMGREP_TOKEN || "use .env please",
      true,
      "",
      "",
      "",
      true,
      1,
    );

    const uuidInfo = messageId;

    logger.info(`###########: UID: ${uuidInfo}`);

    const mongoConnect: MongoConnect = new MongoConnect(uuidInfo, process.env.COMPANY);
    mongoCancelScan = new MongoCancelScan(messageId, process.env.COMPANY, mongoConnect);
    RepositoryMatcher.init(mongoConnect, messageId, process.env.COMPANY);
    CveToolsService.init(mongoConnect, messageId, process.env.COMPANY);

    // let jsonBody = fs.readFileSync(
    //   "C:\\Users\\Roman\\Downloads\\parsedMessage.txt",
    //   "utf8"
    // );
    // const body = JSON.parse(jsonBody);

    // when running pipeline scan locally, set process.env.DEBUG_PIPELINE_SCAN=true,
    // and pass a connector matching a token with a repository you want to scan in `monitoredResources`
    const pipelineScanGitHubConnector = {
      id: "1",
      name: "GitHub",
      monitoredResources: {
        "559851543": {
          id: "559851543",
          name: "github-actions-integration-test",
          isMonitored: true,
          resourceType: "edge",
          sourceBranch: "main",
        },
      },
      monitorAllResources: false,
      monitorAllNewlyCreatedResources: null,
    };

    const pipelineScanGitlabConnector = {
      id: "2",
      name: "Gitlab",
      monitoredResources: {
        /* "34125875": {
          id: "34125875",
          name: "sarif-service",
          isMonitored: true,
          resourceType: "edge",
          sourceBranch: "introduce-dv-files",
          targetBranch: "development",
        }, */
        "51638799": {
          id: "51638799",
          name: "gitlab-webhooks-service",
          isMonitored: true,
          resourceType: "edge",
          sourceBranch: "OX-999",
          targetBranch: "development",
          sha: "72116c08507f9bc5f7f39d2f476f965207c76f37",
        },
      },
      monitorAllResources: false,
      monitorAllNewlyCreatedResources: null,
    };

    const pipelineScanAzureConnector = {
      id: "12",
      name: "Azure",
      monitoredResources: {
        /* "7ae63696-2625-484a-bf58-7c055b4f6866": {
          id: "7ae63696-2625-484a-bf58-7c055b4f6866",
          name: "pipeline-task-integration-test",
          isMonitored: true,
          resourceType: "edge",
          sourceBranch: "main",
        }, */
        "47932fdd-c63d-423e-b19d-dbf088f9b42c": {
          id: "47932fdd-c63d-423e-b19d-dbf088f9b42c",
          name: "pipeline-task-integration-monorepo-test",
          isMonitored: true,
          resourceType: "edge",
          sourceBranch: "main",
        },
      },
      monitorAllResources: false,
      monitorAllNewlyCreatedResources: null,
    };

    const pipelineScanBitbucketConnector = {
      id: "3",
      name: "Bitbucket",
      monitoredResources: {
        "{fec703be-8a4b-4741-89c1-ac3bd3ed87e3}": {
          id: "{fec703be-8a4b-4741-89c1-ac3bd3ed87e3}",
          name: "ox-bbp-integration/dva",
          isMonitored: true,
          resourceType: "edge",
          children: [],
          sourceBranch: "OX-001",
          targetBranch: "master",
          sha: "c85b013a91ebca1c061e2d125c3b8af4c596d81b",
        },
      },
      monitorAllResources: false,
      monitorAllNewlyCreatedResources: null,
    };

    const debugPipelneScanBody = {
      configuredConnectors: [pipelineScanGitlabConnector],
      pipelineScanJobInfo: JSON.stringify({
        cicdType: "GitLabWebhooks",
        jobId: "1089215219",
        jobTriggeredAt: "2023-12-12T12:01:56.878Z",
        jobTriggeredBy: "Yury Imbro",
        jobTriggeredReason: "Merge Request: update",
        pullRequestId: "2",
      }),
    };

    let body: any = "";

    if (isDebugPipelineScan) {
      body = debugPipelneScanBody;
      PipeLineHelper.Instance.setDataFromScannerMessage(body);
      PipeLineHelper.Instance.setScanTimeout();
      PipeLineHelper.Instance.orgId = process.env.COMPANY;
      PipeLineHelper.Instance.uuid = uuidInfo;
    }

    const collectorManager: CollectorManager = new CollectorManager(
      uuidInfo,
      process.env.COMPANY,
      mongoConnect,
      body as unknown as ScannerMessage,
    );
    const orgPolicyParser: OrgPolicyParser = new OrgPolicyParser(uuidInfo);
    const connectorsPolicyConfiguration = orgPolicyParser.getOrgPolicy().connectors;

    StatesHelper.Instance.scanStartDate = new Date();
    StatesHelper.Instance.isPipelineScan = isDebugPipelineScan;

    StatesHelper.Instance.setSemgrepCPU();

    //const tokens = [demoConnectorTest];
    //const tokens = [myaws];
    // const tokens = [azureCItoken, IdptokenAzureRepo];
    //const tokens = [IdptokenAzureRepo];
    // const tokens = [tokenGitHub, semgrepToken];
    // const tokens = [oxGitlab];
    // const tokens = [wizToken];
    // const tokens = [prismaCspm];
    // const tokens = [dorGitHub];
    // const tokens = [wizToken];
    //const tokens = [prismaArtifacts, tokenGitHub];
    // const tokens = [gitlab];
    //const tokens = [jfrogsToken, gitlab];
    //const tokens = [cxSca, cxSast, IdptokenAzureRepo];
    // const tokens = [gitlabArtifactToken];
    // const tokens = [tokenGitHub, gcrToken, wizToken];
    // const tokens = [snyk];
    // const tokens = [prismaArtifacts2];
    // const tokens = [awsCodeCommit];
    // const tokens = [cxSast];
    const tokens = [oxGitlab];
    // const tokens = [bitbucketAppToken];
    //const tokens = [spectralToken];
    // const tokens = [tokenGitHub, hcl];
    // const tokens = [orca];
    // const tokens = [wizToken];

    if (isLocalDevelopment()) {
      StatesHelper.Instance.kongHostUrl = "https://kong.loca.lt";
      StatesHelper.Instance.kongToken = "";
      StatesHelper.Instance.solaceUsername = "username";
      StatesHelper.Instance.solacePassword = "admin";
    }

    // const tokens = [gkrToken];
    // const tokens = [fortify];
    // const tokens = [veraCodeToken];

    // testing blockmode for secrets in log:

    //nikunj@ox.security
    // const interceptor: Interceptor = new Interceptor();
    // await interceptor.createSecurityEvents("c:\\temp\toolOutput.srif");

    let connectorsProm = [];

    for (const token of tokens) {
      if (connectorsPolicyConfiguration != undefined) {
        let policyConfiguration = connectorsPolicyConfiguration.filter(i => i.type === token.type);
        if (policyConfiguration.length > 0) {
          connectorsProm.push(collectorManager.setCollector(token, orgPolicyParser));
          continue;
        }
      }
      connectorsProm.push(collectorManager.setCollector(token, orgPolicyParser));
    }

    await Promise.all([connectorsProm]);
    ruleManager = new RuleManager(
      uuidInfo,
      collectorManager,
      orgPolicyParser,
      process.env.COMPANY,
      mongoConnect,
      false,
      isDebugPipelineScan,
    );
    const res = await Promise.race([ruleManager.run(), waitForCancelEvent]);
  } catch (err) {
    logger.error(err, err);
  }
}

function setAWSConfig() {
  if (
    typeof process.env.SQS_AWS_ACCESS_KEY !== "undefined" &&
    process.env.AWS_SQS_POLLING !== null &&
    typeof process.env.SQS_AWS_SECRET_ACCESS_KEY !== "undefined" &&
    process.env.SQS_AWS_SECRET_ACCESS_KEY !== null
  ) {
    AWS.config.update({
      region: "eu-west-1",
      accessKeyId: process.env.SQS_AWS_ACCESS_KEY,
      secretAccessKey: process.env.SQS_AWS_SECRET_ACCESS_KEY,
    });
  } else {
    AWS.config.update({
      region: "eu-west-1",
    });
  }
}

async function pushMessageToStartScan(message: any, mode: string) {
  try {
    logger.info(`${mode}! Scan request received ${JSON.stringify(message)}`);
    logger.info(`process.env.NODE_OPTIONS: ${process.env.NODE_OPTIONS}`);

    setAWSConfig();

    if (sigTermReceived) {
      logger.info("SIGTERM received exiting from main...");
      return;
    }

    global_currentScanInProgress = true;

    const scan = SASTscan(message);

    await Promise.race([scan, waitForCancelEvent]);

    global_currentScanInProgress = false;
  } catch (err) {
    global_currentScanInProgress = false;
    logger.error(`SQS! ${new Date().toUTCString()}, err during dequeue, msg: ${message.Body}, err: ${err}`, err);
  }
}

async function scanInSQSMode() {
  global_sqs_app = Consumer.create({
    queueUrl: `${process.env.SQS_QUEUE_URL}`,
    handleMessage: async message => {
      global_currentScanInProgress = true;

      const msg = {
        MessageBody: message.Body,
        MessageDeduplicationId: message.MessageId,
      };

      await pushMessageToStartScan(msg, "SAST");
    },
    sqs: new AWS.SQS(),
  });

  //SQS consumer
  global_sqs_app.on("error", err => {
    try {
      logger.info(
        `SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, get general err for sqs consumer: ${
          err.message
        }, exiting...`,
      );
    } catch (err) {
      logger.error(
        `SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, failed process general err for for sqs consumer: ${
          err.message
        }`,
        err,
      );
    }
  });

  global_sqs_app.on("processing_error", err => {
    try {
      logger.info(
        `SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, get err for sqs consumer: ${
          err.message
        }, exiting...`,
      );
    } catch (err) {
      logger.error(
        `SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, failed process err for for sqs consumer: ${
          err.message
        }`,
        err,
      );
    }
  });

  global_sqs_app.on("timeout_error", err => {
    try {
      logger.info(
        `SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, get err for sqs consumer timeout, err: ${
          err.message
        }`,
      );
    } catch (err) {
      logger.error(
        `SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, failed process err for for sqs consumer timeout, err: ${
          err.message
        }`,
        err,
      );
    }
  });

  global_sqs_app.on("message_processed", err => {
    try {
      logger.info(
        `SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, message_processed, exiting..., mes:${JSON.stringify(
          err,
        )}`,
      );
    } catch (err) {
      logger.error(`SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, message_processed`, err);
    }
  });

  global_sqs_app.on("response_processed", () => {
    try {
      logger.info(`SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, response_processed, exiting...`);
      closeSqs();
      logger.info(`uid: ${global_CurrentUid}, org: ${global_currentOrg}, exiting...`);
      process.exit(0);
    } catch (err) {
      logger.error(`SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, response_processed`, err);
    }
  });

  global_sqs_app.on("message_received", () => {
    try {
      logger.info(`SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, message_received`);
    } catch (err) {
      logger.error(`SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, message_received`, err);
    }
  });

  global_sqs_app.on("stopped", () => {
    try {
      logger.info(`SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, stopped, exiting...`);
    } catch (err) {
      logger.error(`SQS! ${new Date().toUTCString()} uid: ${global_CurrentUid}, org: ${global_currentOrg}, stopped`, err);
    }
  });

  global_sqs_app.start();
}
