import fs from "fs";
import path from "path";
import { v4 as uuidGen, v4 } from "uuid";
import { Application as ApplicationInfo } from "../../appmgr/application";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { SecurityEvent } from "../../entitis/codeRepoTypes";
import { RunTimeBaseDoc } from "../../entitis/service/autoFixTypes";
import loggerImport from "../../logger";
import MongoHelper from "../../mongo/mongoHelper";
import { escapeCharsFromPath } from "../commonUtils";
import { isLocalDevelopment } from "../envUtils";
import FileHelper from "../IO/fileHlper";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";

const logger = loggerImport.getDebugLogger();

class ACMHelper {
  private static _instance: ACMHelper;
  ACMHelperQ: Iqueue;
  // uuid: string;
  // orgName: string;
  fileHelper: FileHelper;
  mongoHelper: MongoHelper<RunTimeBaseDoc>;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  matchCloudEventsToMatchedArtifacts(applications: ApplicationInfo[], cloudEvents) {
    logger.info(`start looking for connections for ${applications.length} apps, having ${cloudEvents.length} events`);

    try {
      const containersFromRuntimeSha = new Map();
      const containersFromRuntimeName = new Map();

      // Group cloud events by sha and name
      cloudEvents.forEach(event => {
        const sha = event.artifacts.sha;
        const name = path.basename(event.artifacts.dockerFileInRunTime);

        if (sha && sha !== "N/A") {
          containersFromRuntimeSha.set(sha, (containersFromRuntimeSha.get(sha) || []).concat(event));
        }

        containersFromRuntimeName.set(name, (containersFromRuntimeName.get(name) || []).concat(event));
      });

      // Process applications
      const imageMap = new Map();

      applications.forEach(app => {
        app.appInfo.artifactory.registryImage.forEach(image => {
          const name = path.basename(image.image.location);
          const shaKey = image.image.imageDigestWithoutPrefix;

          imageMap.set(shaKey, { app, name });
          imageMap.set(name, { app, name });
        });
      });

      // Process cloud events
      cloudEvents.forEach(event => {
        const sha = event.artifacts.sha;
        const name = path.basename(event.artifacts.dockerFileInRunTime);

        if (sha && containersFromRuntimeSha.has(sha)) {
          const events = containersFromRuntimeSha.get(sha);
          this.processSecurityEvents(events, imageMap.get(sha), "sha");
        }
        if (containersFromRuntimeName.has(name)) {
          const events = containersFromRuntimeName.get(name);
          this.processSecurityEvents(events, imageMap.get(name), "name");
        }
      });

      cloudEvents = cloudEvents.filter(e => !e.correlatedCloudEvent);
    } catch (e) {
      logger.error(`failed matchCloudEventsToMatchedArtifacts`, e);
    }
  }

  processSecurityEvents(events, imageData, correlationType) {
    try {
      if (events && imageData) {
        const { app, name } = imageData;
        const { artifactory } = app.appInfo;

        events.forEach(event => {
          artifactory.securityEvents.push(event);
          event.correlatedCloudEvent = true;
          logger.info(`found connection image by ${correlationType}: ${name}, event: ${event}`);
        });
      }
    } catch (e) {
      logger.error(`failed processSecurityEvents`, e);
    }
  }

  // handle Artifacts-to-Cloud-Matching
  async handleACM(applications: ApplicationInfo[], cloudEvents: SecurityEvent[]) {
    try {
      const appIds = [];

      for (const app of applications) {
        appIds.push(app.uuid);
      }

      // create map of events
      // create request
      const eventsById = new Map();
      const cloudEventsRequest = [];

      for (const event of cloudEvents) {
        eventsById.set(event.uid, event);
        try {
          cloudEventsRequest.push({ uid: event.uid, artifact: event.artifacts });
        } catch (e) {
          const nana = "";
        }
      }

      let request = { appIds, cloudEventsRequest };
      const dir = applications[0].appInfo.repo.code_repo.acmDir;
      const dirToPutRes = `${dir}/${uuidGen()}`;

      fs.mkdirSync(dirToPutRes, { recursive: true });

      let filePathRequest = `${dirToPutRes}/acmRequest.json`;
      if (process.env.DEBUG) {
        filePathRequest = "/Users/dors/cleanScanner/artifact-cloud-matcher/src/acm/acmRequest.json";
      }

      fs.writeFileSync(filePathRequest, JSON.stringify(request));

      // const batchSize = 100;

      // function writeChunk(chunk, isFirstChunk) {
      //   const flag = isFirstChunk ? "w" : "a";
      //   fs.writeFileSync(filePathRequest, JSON.stringify(chunk), { flag });
      // }

      // for (let i = 0; i < request.cloudEventsRequest.length; i += batchSize) {
      //   const batch = request.cloudEventsRequest.slice(i, i + batchSize);
      //   request.cloudEventsRequest = batch;
      //   writeChunk(request, i === 0);
      // }

      let filePathRes = `${dirToPutRes}/acmResponse.json`;
      if (process.env.DEBUG) {
        filePathRes = "/Users/dors/cleanScanner/artifact-cloud-matcher/src/acm/acmResponse.json";
      }

      if (!process.env.DOR && !isLocalDevelopment()) {
        // send request
        await this.sendWithoutWaitForRes(filePathRequest, filePathRes);
        // get response
        await this.waitForRes(dirToPutRes, filePathRes);
      }

      // parse response here
      const rawJson = fs.readFileSync(filePathRes, "utf8");
      const res = JSON.parse(rawJson);

      for (const app of applications) {
        try {
          const name = app.appInfo.repo.code_repo.name.toLowerCase();
          const matches = res[name];

          if (!matches) {
            continue;
          }

          matches.map(eventId => app.appInfo.artifactory.securityEvents.push(eventsById.get(eventId)));
        } catch (e) {
          logger.error(`failed to find match from acm response for ${StatesHelper.Instance.orgName}`, e);
        }
      }
      const bp = "";
    } catch (e) {
      logger.error(`failed to handle acm for ${StatesHelper.Instance.orgName}`, e);
    }
  }

  private async sendWithoutWaitForRes(requestPath, responsePath) {
    let data;

    try {
      const url = process.env.ARTIFACTCLOUDMATCHER_QUEUE_KEY;

      let command = this.getCommand(requestPath, responsePath);
      logger.info(`about to send cmd for ACM: ${command}`);
      command = escapeCharsFromPath(command);

      const msg = {
        MessageId: v4(),
        uuid: StatesHelper.Instance.uuid,
        orgID: StatesHelper.Instance.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "artifact-cloud-matcher",
        repoName: "acm",
        resultPath: responsePath,
        timeout: 900000,
        orgDisplayName: StatesHelper.Instance.companyName,
        cloneDir: "", // path to unzip folder?
        toolCopyDestination: requestPath,
        isMonoRepoChild: false,
        monoRepoChildSubfolder: "",
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: null,
        putInQueueTime: new Date().getTime(),
        shouldSkipSSH: isLocalDevelopment(),
        copyType: CopyType.None,
        rawCommand: "",
        shouldSkipLocalCopy: true,
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      // if (isLocalDevelopment()) {
      //   const reqRes = await this.runShell(repo.name, msg.localCommand);
      //   const data = fs.readFileSync(filePathRes, "utf8");
      //   const scaVerificationRes = JSON.parse(data);
      //   return scaVerificationRes;
      // }

      const info = { url: url, msg: msg };

      logger.info(`about to send msg to queue for ACM, org: ${StatesHelper.Instance.orgName}, ACM. (MessageId: ${msg.MessageId})`);

      const reqRes = await ACMHelper.Instance.ACMHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        logger.error(`failed enter item to acm Q`);
        return null;
      }
    } catch (e) {
      logger.error(`sendWithoutWaitForRes failed in ACM helper`, e);
      // await sendScannerRepoErrorTelemetry(ScanErrorName.FailedResolveIssueValidation, errInfo, this.orgName, this.uuid, repo.fullName);
    }
    // StatesHelper.Instance.scanInfoStats.failedResolvedIssuesValidation++;
  }

  private async waitForRes(dirToPutRes, filePathRes) {
    try {
      logger.info(`start wait for acm response for: ${StatesHelper.Instance.orgName}`);

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromACM = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 15; // 60 seconds * 5 = 5 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          let errInfo = `failed set acm due to timeout, org: ${StatesHelper.Instance.orgName}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`;
          logger.error(`${errInfo}`);
          // StatesHelper.Instance.scanInfoStats.failedResolvedIssuesValidationTimeout++;

          // await sendScannerRepoErrorTelemetry(
          //   ScanErrorName.FailedResolveIssueValidationTimeout,
          //   errInfo,
          //   StatesHelper.Instance.orgName,
          //   StatesHelper.Instance.uuid,
          //   StatesHelper.Instance.orgName,
          // );
          return null;
        }

        //Failed from resolve issues validation
        if (fs.existsSync(failedFilePath)) {
          // setToolInfoFromDoneFile(doneFilePath, StatesHelper.Instance.orgName, StatesHelper.Instance.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          let errInfo = `failed file discovered from acm service for resolve issues validation response, org: ${StatesHelper.Instance.orgName}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`;
          logger.error(`${errInfo}`);
          // StatesHelper.Instance.scanInfoStats.failedResolvedIssuesValidation++;

          // await sendScannerRepoErrorTelemetry(
          //   ScanErrorName.FailedResolveIssueValidation,
          //   errInfo,
          //   StatesHelper.Instance.orgName,
          //   StatesHelper.Instance.uuid,
          //   StatesHelper.Instance.orgName,
          // );
          return null;
        }

        //Done from resolve issues validation
        if (fs.existsSync(doneFilePath)) {
          // setToolInfoFromDoneFile(doneFilePath, StatesHelper.Instance.orgName, StatesHelper.Instance.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `done file discovered from acm service response, org: ${StatesHelper.Instance.orgName}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromACM = true;
          break;
        }

        //10 seconds
        await this.sleep();
        counter--;
      }

      if (!fs.existsSync(filePathRes)) {
        let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

        let errInfo = `response file from acm not exist on disk, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, done from acm: ${doneFromACM}, org: ${StatesHelper.Instance.orgName}, dirToPutRes: ${dirToPutRes}`;
        logger.error(`${errInfo}`);
        StatesHelper.Instance.scanInfoStats.failedResolvedIssuesValidation++;

        // await sendScannerRepoErrorTelemetry(ScanErrorName.FailedResolveIssueValidation, errInfo, this.orgName, this.uuid, repo.fullName);
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

      logger.info(
        `finish waiting for acm, org: ${StatesHelper.Instance.orgName}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, counter: ${counter}`,
      );
    } catch (err) {
      logger.error(`failed wait for org: ${StatesHelper.Instance.orgName}, err: ${err}`);
    }
  }

  getCommand(requestPath: string, outputDir: string) {
    const mongoUri = process.env.MONGODB_URI;
    let modifiedMongoUri = mongoUri.split("?")[0];

    const command = `MONGODB_URI=${modifiedMongoUri} SERVER_ENVIRONMENT=${process.env.SERVER_ENVIRONMENT} /usr/local/bin/node /app/dist/main.js ${StatesHelper.Instance.orgName} ${StatesHelper.Instance.uuid} ${requestPath} ${outputDir}`;
    return command;
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 10);
  }
}

export default ACMHelper;
