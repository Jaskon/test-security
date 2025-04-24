import RulesManager from "../../policy/rules/ruleManager";
import { isK8Mode } from "../envUtils";
import localToolRunner from "../localToolRunner";
import Iqueue from "./Iqueue";
import { RedisQueue } from "./redisQueue";
import SqsAWSqueue from "./sqsAWSqueue";
import Bull = require("bull");

const redisOnPrem = process.env.redisOnPrem != undefined;
const isK8 = isK8Mode();
const onAWS = process.env.MONGO_CONN === "atlas";
const debug = process.env.DEBUG != undefined;

// eyal: need to change here
class EnvQueueFactory {
  static getQueue(uuid: string, callbackObject: RulesManager | null, orgName: string): Iqueue {
    if (localToolRunner().isConfiguredToRunToolsLocally() || process.env.DOCKER_DEBUG)
      return RedisQueue.getInstance(uuid, callbackObject, orgName);
    if (isK8) return RedisQueue.getInstance(uuid, callbackObject, orgName);
    if (debug) return new Iqueue(uuid, callbackObject, orgName);
    if (onAWS) return new SqsAWSqueue(uuid, callbackObject, orgName);
    if (redisOnPrem) return RedisQueue.getInstance(uuid, callbackObject, orgName);
    return new Iqueue(uuid, callbackObject, orgName);
  }

  static getNewQueue(name: string, heavy = false): Bull.Queue {
    return new Bull(heavy ? `${name}Heavy` : name, {
      redis: {
        host: process.env.REDIS_HOST || "127.0.0.1",
        port: Number(process.env.REDIS_PORT || 6379),
        connectionName: `scanner:${name}`,
      },
      defaultJobOptions: { removeOnComplete: { age: 10 * 60 /* 10 minutes */ }, removeOnFail: { age: 60 * 60 * 24 * 14 /* 14 days */ } },
    });
  }
}

export default EnvQueueFactory;
