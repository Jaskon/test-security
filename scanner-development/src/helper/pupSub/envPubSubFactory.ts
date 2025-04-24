import RulesManager from "../../policy/rules/ruleManager";
import RedisPubSub from "./redisPubSub";
import IpupSub from "./IpupSub";
import { isK8Mode } from "../envUtils";
import { Scope } from "@aws-sdk/client-ecs";

const redisOnPrem = process.env.redisOnPrem != undefined;
const onAWS = process.env.MONGO_CONN === "atlas";
const debug = process.env.DEBUG != undefined;
const isk8 = isK8Mode();

class EnvPubSubFactory {
  static getPubSub(uuid: string, callbackObject: RulesManager, orgName: string, topic: string, scope: string) {
    if (isk8) return new RedisPubSub(uuid, callbackObject, orgName, topic);
    if (debug) return new IpupSub(uuid, orgName);
    if (redisOnPrem) return new RedisPubSub(uuid, callbackObject, orgName, topic);
    return new IpupSub(uuid, orgName);
  }
}

export default EnvPubSubFactory;
