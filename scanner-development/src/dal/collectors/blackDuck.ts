//https://snyk.docs.apiary.io/#reference/reporting-api/latest-issues/get-list-of-latest-issues
import { SecurityEvent } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";

import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import BlackDuckAPI from "./api/BlackDuckAPI";

const logger = loggerImport.getDebugLogger();
const Timeout = require("await-timeout");

class BlackDuck extends ExternalSecurityProviderBase {
  host: string;
  private_token: string;
  uniqueRepos = {};
  private clientApi: BlackDuckAPI;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.host = token.host;
    this.private_token = token.password;
  }

  async initLib() {
    try {
      logger.info(`set ${this.token.name}, host: ${this.host}`);
      this.clientApi = new BlackDuckAPI(this.host, this.private_token);
      await this.clientApi.auth();
    } catch (err) {
      logger.error(`failed to initialize ${this.token.name}, , host: ${this.host}, err: ${err}`);
    }
  }

  async securityEvents() {
    let securityEventList: SecurityEvent[] = [];

    try {
      logger.info(`try collect ${this.token.name} security events`);
      securityEventList = await this.clientApi.getAllSecEvents();
      logger.info(`finish collect ${this.token.name} security events count: ${securityEventList.length}`);
    } catch (err) {
      logger.error(`failed to set all ${this.token.name} security events, err: ${err}`);
    }

    logger.info(`finish collect ${this.token.name} security events, security event list count: ${securityEventList.length}`);
    return securityEventList;
  }
}

export default BlackDuck;
