const util = require("util");
const exec = util.promisify(require("child_process").exec);
import memoryDB from "@oxappsec/ox-memory-db";
import { DockerHubInfo, DockerhubRequest } from "../../entitis/DockerhubTypes";
import isDockerHubResponseRequired from "../../helper/featureFlags/isDockerHubResponseRequired";
import loggerImport from "../../logger";
import { escapeCharsFromPath } from "../commonUtils";
import { isLocalDevelopment } from "../envUtils";
import { replaceAll } from "../generalUtils";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";

const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();

class DockerhubHelper {
  DockerhubQueue: Iqueue;
  uuid: string;
  orgName: string;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.DockerhubQueue = queue;
    this.uuid = uuid;
    this.orgName = orgName;
  }

  async sendAndWaitForRes(request: DockerhubRequest, repo: string, atFinalizing: boolean = false) {
    let data;
    const startProcessTime = new Date().getTime();

    try {
      if (!request) {
        return null;
      }

      // First check in cache if we even need to make a request to dockerhub and return the results if they exist
      const cacheKey = replaceAll(`${request.imageName}:${request.imageTag}`, "/", "-");
      logger.info(`Looking for dockerhub results in cache for ${cacheKey}`);
      const cacheResult = (await getDockerHubCache().get(cacheKey)) as DockerHubInfo;
      if (cacheResult) {
        logger.info(`Found dockerhub results in cache for ${cacheKey}`);
        return cacheResult;
      }
      logger.info(`Didn't find dockerhub results in cache for ${cacheKey}`);

      let url = process.env.DOCKERHUB_SERVICE_QUEUE_KEY;

      const sharedDir = process.env.OX_GLOBAL_DATA == undefined ? "/var/shared-data" : process.env.OX_GLOBAL_DATA;
      const dockerhub = `${sharedDir}/${this.orgName}/scan_${this.uuid.replaceAll("-", "_")}/dockerhub`;
      const dockerhubDir = `${dockerhub}/`;

      const dirToPutRes = `${dockerhubDir}${uuid.v4()}`;
      fs.mkdirSync(dirToPutRes, { recursive: true });

      let imageNameFormatted = request.imageName.replaceAll("/", "_");
      imageNameFormatted = imageNameFormatted.replaceAll("\\.", "-");
      let imageTagFormatted = request.imageTag.replaceAll("/", "_");
      imageTagFormatted = imageTagFormatted.replaceAll("\\.", "-");

      const timestamp = Date.now();

      const filePathRequest = `${dirToPutRes}/dockerhubRequest-${imageNameFormatted}-${imageTagFormatted}-${timestamp}.json`;
      const filePathRes = `${dirToPutRes}/dockerhub-${imageNameFormatted}-${imageTagFormatted}-${timestamp}.json`;

      // Create the config for the request
      const config = this.createConfig(request, filePathRes);
      fs.writeFileSync(filePathRequest, JSON.stringify(config));

      let command = this.getCommand(filePathRequest);
      command = escapeCharsFromPath(command);

      const msg = {
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "dockerhub-service",
        repoName: repo,
        resultPath: filePathRes,
        timeout: 900000,
        orgDisplayName: process.env["companyName"],
        isMonoRepoChild: false,
        putInQueueTime: new Date().getTime(),
        shouldSkipSSH: isLocalDevelopment(),
        shouldSkipLocalCopy: true,
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(`Docker hub message msg: ${JSON.stringify(msg)}`);

      const reqRes = await this.DockerhubQueue.sendQueueMessage(info);
      if (!reqRes) {
        logger.error(`failed enter item to dockerhub Q, msg: ${JSON.stringify(msg)}`);
        return null;
      }

      if (!(await isDockerHubResponseRequired.isDockerHubResponseRequiredImpl(StatesHelper.Instance.orgName))) {
        return null;
      }

      logger.info(`about to start waiting for dockerhub requests, msg: ${JSON.stringify(msg)}`);

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${filePathRes}.fail`;
      let doneFromDockerhub = false;
      const sleepSeconds = 6;
      let counter = sleepSeconds * 10 * 10; // 600 seconds = 10 minutes
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.error(
            `failed set dockerhub due to timeout, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          StatesHelper.Instance.scanInfoStats.dockerhubNumTimeouts += 1;
          if (atFinalizing) {
            StatesHelper.Instance.scanInfoStats.dockerhubTimeAtFinalizing += new Date().getTime() - startProcessTime;
          }
          return null;
        }

        //Failed from dockerhub
        if (fs.existsSync(failedFilePath)) {
          //setToolInfoFromDoneFile(doneFilePath, this.orgName, this.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.error(
            `failed file discovered from dockerhub service for dockerhub response, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          StatesHelper.Instance.scanInfoStats.dockerhubNumFails += 1;
          if (atFinalizing) {
            StatesHelper.Instance.scanInfoStats.dockerhubTimeAtFinalizing += new Date().getTime() - startProcessTime;
          }
          return null;
        }

        //Done from dockerhub
        if (fs.existsSync(doneFilePath)) {
          //setToolInfoFromDoneFile(doneFilePath, this.orgName, this.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `done file discovered from dockerhub response, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromDockerhub = true;
          break;
        }

        // Sleep seconds
        await this.sleep(sleepSeconds);
        counter -= sleepSeconds;
      }

      if (!fs.existsSync(filePathRes)) {
        let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

        logger.error(
          `response file from dockerhub does not exist on disk, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, done from dockerhub: ${doneFromDockerhub}, dirToPutRes: ${dirToPutRes}`,
        );
        if (atFinalizing) {
          StatesHelper.Instance.scanInfoStats.dockerhubTimeAtFinalizing += new Date().getTime() - startProcessTime;
        }
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      data = fs.readFileSync(filePathRes, "utf8");
      let dockerhubRes = null;
      try {
        dockerhubRes = JSON.parse(data);
      } catch (error) {
        logger.warn(`Failed parsing dockerhub data (maybe the image just wasn't found in dockerhub), data: ${data}, err: ${error}`);
        if (atFinalizing) {
          StatesHelper.Instance.scanInfoStats.dockerhubTimeAtFinalizing += new Date().getTime() - startProcessTime;
        }
        return null;
      }

      logger.info(
        `finished searching in dockerhub, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, counter: ${counter}`,
      );
      // const elapsedTime = timer.timeMe();
      if (atFinalizing) {
        StatesHelper.Instance.scanInfoStats.dockerhubTimeAtFinalizing += new Date().getTime() - startProcessTime;
      }

      return dockerhubRes;
    } catch (err) {
      logger.error(`Failed searching in dockerhub data: ${data}, err: ${err}`);
      StatesHelper.Instance.scanInfoStats.dockerhubNumFails += 1;
      if (atFinalizing) {
        StatesHelper.Instance.scanInfoStats.dockerhubTimeAtFinalizing += new Date().getTime() - startProcessTime;
      }
    }
    return null;
  }

  getCommand(requestPath: string) {
    if (process.env.DEBUG) {
      return `node ${process.env.DOCKERHUB_SERVICE_PATH} ${requestPath} ${process.env.REDIS_HOST} ${process.env.REDIS_PORT}`;
    }
    return `/usr/local/bin/node /app/lib/src/index.js ${requestPath} ${process.env.REDIS_HOST} ${process.env.REDIS_PORT}`;
  }

  async sleep(seconds) {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * seconds);
  }

  createConfig(request: DockerhubRequest, resultPath: string) {
    return {
      resultPath: resultPath,
      records: [request],
      redis: {
        prefix: "dockerhub",
        defaultTtlSeconds: 3600,
      },
    };
  }
}

export const getDockerHubCache = () => {
  const dockerHubMap = new Map<string, string>();
  const TTL = 14 * 60 * 24 * 60;

  const genUniqueKey = (docker: string) => {
    return `dockerhub-service:${docker}`;
  };

  if (isLocalDevelopment()) {
    return {
      get: async (docker: string): Promise<DockerHubInfo | null> => {
        try {
          const found = dockerHubMap.get(genUniqueKey(docker));
          if (!found) return null;
          const parsed = JSON.parse(found) as DockerHubInfo;
          return parsed;
        } catch (err) {
          logger.error(`Failed to get cached DockerHubInfo result for ${docker} err: ${err}`);
        }
      },

      set: async (docker: string, artifact: DockerHubInfo) => {
        try {
          dockerHubMap.set(genUniqueKey(docker), JSON.stringify(artifact));
        } catch (err) {
          logger.error(`Failed to cache DockerHubInfo result for ${docker}, err: ${err}`);
        }
      },
    };
  } else {
    return {
      get: async (docker: string): Promise<DockerHubInfo | null> => {
        try {
          const found = await memoryDB.get.execute(genUniqueKey(docker));
          if (found === null) return null;
          const parsed = JSON.parse(found) as DockerHubInfo;
          return parsed;
        } catch (err) {
          logger.error(`Failed to get cached DockerHubInfo result for ${docker} err: ${err}`);
        }
      },

      set: async (docker: string, artifact: DockerHubInfo) => {
        try {
          await memoryDB.set.execute(genUniqueKey(docker), TTL, JSON.stringify(artifact));
        } catch (err) {
          logger.error(`Failed to cache DockerHubInfo result for ${docker}, err: ${err}`);
        }
      },
    };
  }
};

export default DockerhubHelper;
