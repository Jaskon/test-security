import loggerImport from "../../logger";
import RulesManager from "../../policy/rules/ruleManager";
const logger = loggerImport.getDebugLogger();

class Iqueue {
  uuid: string;
  orgName: string;
  callBackObject: RulesManager | null;

  async init() {}

  async sendQueueMessage(info: any): Promise<boolean> {
    logger.info(`pretending to send to Q: ${JSON.stringify(info)}`);
    return null;
  }

  constructor(uuid: string, callbackObject: RulesManager | null, orgName: string) {
    this.uuid = uuid;
    this.callBackObject = callbackObject;
    this.orgName = orgName;
  }
}

export default Iqueue;
