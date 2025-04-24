import AWS from "aws-sdk";
import loggerImport from "../../logger";
import RulesManager from "../../policy/rules/ruleManager";
import Iqueue from "./Iqueue";

const logger = loggerImport.getDebugLogger();
const REGION = process.env.AWS_REGION || "";
const AWS_SQS_ACCESS_KEY_ID = process.env.AWS_SQS_ACCESS_KEY_ID || "";
const AWS_SQS_SECRET_ACCESS_KEY = process.env.AWS_SQS_SECRET_ACCESS_KEY || "";
const AWS_SESSION_TOKEN = process.env.AWS_SESSION_TOKEN || ""; // ask if this breakss other stuff

const localDebug = process.env.DEBUG != undefined;

class SqsAWSqueue extends Iqueue {
  client: any;
  scope: string;

  constructor(uuid: string, callbackObject: RulesManager, orgName: string) {
    super(uuid, callbackObject, orgName);

    this.scope = `tool-runner-${orgName}-${uuid}`;
  }

  async init() {
    logger.info(`init SQS queue with: ${this.scope}`);

    let credentials = null;
    if (localDebug) {
      credentials = {
        accessKeyId: AWS_SQS_ACCESS_KEY_ID,
        secretAccessKey: AWS_SQS_SECRET_ACCESS_KEY,
        sessionToken: AWS_SESSION_TOKEN,
      };
    }

    AWS.config.update({
      credentials,
      region: REGION,
    });

    this.client = new AWS.SQS({ apiVersion: "2012-11-05" });
  }

  async sendQueueMessage(info: any): Promise<boolean> {
    try {
      const url = info.url;
      const msgStr = JSON.stringify(info.msg);

      let sqsPayload = {
        MessageBody: msgStr,
        QueueUrl: url,
      };

      const res = await this.client.sendMessage(sqsPayload).promise();

      try {
        logger.debug(`MSG from insert to SQS ${JSON.stringify(res)}, info: ${JSON.stringify(info)}`);
      } catch (err) {}

      return res.$response != null;
    } catch (err) {
      const errInfo = `failed to send sqs msg: ${JSON.stringify(info.msg)}, err: ${err}`;
      logger.error(errInfo, err);
    }
    return false;
  }
}

export default SqsAWSqueue;
