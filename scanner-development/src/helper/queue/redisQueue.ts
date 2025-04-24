//https://pandeysoni.medium.com/how-can-we-use-redis-queue-mechanism-in-node-js-e3304e1f496f
import { createClient, RedisClientType } from "redis";
import loggerImport from "../../logger";
import RulesManager from "../../policy/rules/ruleManager";
import Iqueue from "./Iqueue";

const logger = loggerImport.getDebugLogger();
const REDIS_PUPSUB_PORT = process.env.REDIS_PORT || 6379;
const REDIS_PUPSUB_HOST = process.env.REDIS_HOST || "127.0.0.1";

export class RedisQueue extends Iqueue {
  private static _instance: RedisQueue;
  private _client: RedisClientType;
  private _connectPromise: Promise<void>;

  private constructor(uuid: string, callbackObject: RulesManager, orgName: string) {
    super(uuid, callbackObject, orgName);
    this._client = createClient({ url: `redis://${REDIS_PUPSUB_HOST}:${REDIS_PUPSUB_PORT}`, name: "scanner" });
    logger.info(`[${RedisQueue.name}] Init client with REDIS_PUPSUB_HOST: ${REDIS_PUPSUB_HOST}, REDIS_PUPSUB_PORT: ${REDIS_PUPSUB_PORT}`);
    this._client.on("error", err => {
      logger.error(`[${RedisQueue.name}] Client error`, err);
    });
    this._client.on("connect", err => {
      logger.info(`[${RedisQueue.name}] Client connect`);
    });
    this._client.on("ready", err => {
      logger.info(`[${RedisQueue.name}] Client ready`);
    });
  }

  static getInstance(uuid: string, callbackObject: RulesManager, orgName: string): RedisQueue {
    if (!this._instance) {
      this._instance = new RedisQueue(uuid, callbackObject, orgName);
    }
    return this._instance;
  }

  async init(): Promise<void> {
    if (!this._connectPromise) {
      this._connectPromise = this._client.connect();
    }
    await this._connectPromise;
  }

  async sendQueueMessage(info: any): Promise<boolean> {
    if (this.orgName === "org_SUdqCfsm7ipz8qna") {
      logger.info(`GADY - ${JSON.stringify(info.msg)}`);
    }
    if (process.env.DOCKER_DEBUG) {
      info.msg.shouldSkipActiveScanCheck = true;
      for (const [key, value] of Object.entries(info.msg)) {
        if (typeof value === "string") {
          info.msg[key] = info.msg[key]
            .replaceAll(`${process.env.OX_SHARED_DATA}/scratch`, "/mnt/scratch")
            .replaceAll(process.env.OX_SHARED_DATA, "/var/shared-data");
        }
      }
    }
    const msg = JSON.stringify(info.msg);
    try {
      const qLength = await this._client.rPush(info.url, msg);
      //Debug
      // logger.info(`[${RedisQueue.name}] Push to queue: ${info.url}, Q Length: ${qLength}`);
      return true;
    } catch (err) {
      logger.error(`[${RedisQueue.name}] Failed to push to queue: ${info.url}, msg: ${msg}, err: ${err}`, err);
      const errInfo = `failed to send redis queue msg: ${JSON.stringify(info.msg)}, err: ${err}`;
      return false;
    }
  }
}
