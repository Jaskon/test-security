//https://www.npmjs.com/package/node-redis-pubsub

import loggerImport from "../../logger";
import RulesManager from "../../policy/rules/ruleManager";
import { ScanErrorName, sendScannerErrorTelemetry } from "../telemetry-utils";
import IpupSub from "./IpupSub";

const NRP = require("node-redis-pubsub");
const logger = loggerImport.getDebugLogger();

const REDIS_PUPSUB_PORT = process.env.REDIS_PORT || 6379;
const REDIS_PUPSUB_HOST = process.env.REDIS_HOST || "127.0.0.1";

//this parms out of scope so we will be able to use them in setInterval
let callBack: RulesManager;

class RedisPubSub extends IpupSub {
  client: any;
  topic: string;
  connectionOpen: boolean = false;

  constructor(uuid: string, callbackOnMessage: RulesManager, orgName: string, topic: string) {
    super(uuid, orgName);
    callBack = callbackOnMessage;
    this.topic = topic;
  }

  init() {
    logger.info(`init redis pubsub host: ${REDIS_PUPSUB_HOST} scope: ${this.topic}`);

    const url = `redis://${REDIS_PUPSUB_HOST}:${REDIS_PUPSUB_PORT}`;
    const config = {
      url: url,
    };

    this.client = new NRP(config); // This is the NRP client
  }

  async sendPupSubMessage(msg: any) {
    const msgStr = JSON.stringify(msg);

    try {
      const res = await this.client.emit(this.topic, msg);
      return res;
    } catch (err) {
      const errInfo = `scope: ${this.topic}, topic: ${this.topic}, failed to send redis pubsub msg: ${msgStr}, err: ${err}`;
      logger.error(errInfo);
      await sendScannerErrorTelemetry(ScanErrorName.FailedSendRedisMsg, errInfo, this.orgName, this.uuid);
    }
    return null;
  }

  async createPupSubListener() {
    try {
      if (this.connectionOpen) {
        logger.error(`scope: ${this.topic}, cannot open redis pubsub listener, one already open`);
        return;
      }
      this.connectionOpen = true;

      logger.info(`scope: ${this.topic}, open redis pubsub listener`);

      this.client.on(this.topic, function (msg) {
        try {
          const str = JSON.stringify(msg);
          const msgJson = JSON.parse(str);

          callBack.collectorManager.collectors.forEach(i => i.updateToolResults(msgJson));
        } catch (err) {
          logger.error(`got error during distribute redis pubsub msg notification, msg: ${JSON.stringify(msg, null, 4)}, err: ${err}`);
        }
      });
    } catch (err) {
      const errInfo = `scope: ${this.topic}, got error during create redis pubsub listener, err: ${err}`;
      logger.error(errInfo);
      await sendScannerErrorTelemetry(ScanErrorName.FailedCreateRedisPupSub, errInfo, this.orgName, this.uuid);
    }

    this.client.on("error", err => {
      logger.error(`scope: ${this.topic}, got error from redis pubsub, err: ${err.message}`);
    });
  }

  closeConnection() {
    try {
      if (!this.connectionOpen) return;

      logger.info(`scope: ${this.topic}, close redis pubsub listener`);

      this.client.quit();
      this.connectionOpen = false;
    } catch (err) {
      logger.error(`scope: ${this.topic}, failed close redis pubsub connection, err: ${err.message}`);
    }
  }
}

export default RedisPubSub;
