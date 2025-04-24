import { repoType } from "../entitis/codeRepoTypes";
import { Token } from "../entitis/collectorEntitisTypes";
import { ScannerMessage } from "../entitis/service/connector-message-types";
import { PerformanceTelemetry } from "../helper/decorators/PerformanceTelemetry";
import StatesHelper from "../helper/statesHelper";
import { millisToMinutesAndSeconds, ScanPhaseTime, sendScannerPhaseTimeTelemetry } from "../helper/telemetry-utils";
import loggerImport from "../logger";
import MongoConnect from "../mongo/mongoConnect";
import OrgPolicyParser from "../policy/org/ruleConfigParser";
import JsonApplicationDiscoveryOverview from "../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../policy/rules/ruleManager";
import CollectorBase from "./base/collectorBase";

const logger = loggerImport.getDebugLogger();

class CollectorManager {
  uuid: string;
  orgName: string;
  jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview;
  mongoConnect: MongoConnect;
  body: ScannerMessage;

  constructor(uuid: string, orgName: string, mongoConnect: MongoConnect, body: ScannerMessage) {
    this.uuid = uuid;
    this.orgName = orgName;
    this.mongoConnect = mongoConnect;
    this.body = body;
    this.jsonApplicationDiscoveryOverview = new JsonApplicationDiscoveryOverview(uuid, orgName, mongoConnect);
  }

  collectors: CollectorBase[] = [];

  async setCommunicationChanle(callObj: RulesManager) {
    this.collectors.forEach(i => i.setCommunicationChanel(callObj.securityToolsQueue, callObj.clonerQueue));
  }

  isDemo() {
    const demo = this.collectors.find(i => i.token.name.toLowerCase().includes("democonnector"));
    if (demo == undefined) {
      return false;
    }
    return true;
  }

  async executeCollector(collectors, resourcesMap, callObj) {
    let proms = [];
    for (const collector of collectors) {
      const resourcesToCollect = resourcesMap[collector.resourceType];
      if (resourcesToCollect == undefined) {
        continue;
      }

      const prom = collector.collect(resourcesToCollect, callObj);
      proms.push(prom);
    }
    await Promise.all(proms);
  }

  @PerformanceTelemetry()
  async collectAllResources(resourcesMap, callObj: RulesManager) {
    logger.info(`try collect all resources in collector manager`);

    const firstLevelConnectors = this.collectors.filter(i => i.executionOrder == 0);
    await this.executeCollector(firstLevelConnectors, resourcesMap, callObj);

    const secondLevelConnectors = this.collectors.filter(i => i.executionOrder == 1);
    await this.executeCollector(secondLevelConnectors, resourcesMap, callObj);

    const startTime = new Date().getTime();

    //Update and run policy on all unattached events
    await callObj.applicationsManager.finalizeScan();

    //Update and run policy which should execute at the end on all repos
    await callObj.applicationsManager.runPolicyOnAllApps();

    // copy old issues to prev-issues collection
    await callObj.resultsHandler.mongoDBreport.copyOldIssues();

    //verify resolved issues
    await callObj.applicationsManager.sendToResolvedIssueValidation();

    this.collectors.forEach(i => i.printStatsOfRateLimitInfo());

    let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
    await sendScannerPhaseTimeTelemetry(ScanPhaseTime.ScanSummeryPhaseTime, this.orgName, this.uuid, Number(elapsedTime));

    logger.info(`finish collect all resources from collector manager, elapsedTime: ${elapsedTime}`);
  }

  async setCollector(token: Token, orgPolicyParser: OrgPolicyParser): Promise<any> {
    try {
      logger.info(`try get collector by token type: ${token.type}, name: ${token.name}`);

      StatesHelper.Instance.cicdConnectorsNames.add(token.friendlyName.toLowerCase());

      const uniqueID: string = token.getID();
      if (this.collectors.some(i => i.token.getID() === uniqueID)) {
        return;
      }

      if (token.name.toLowerCase() === "kong" || token.name.toLowerCase() === "solace") {
        return;
      }

      const CollectorModule = await import(`./collectors/${token.name}`);
      const collector: CollectorBase = new CollectorModule.default(
        token,
        this.uuid,
        this.orgName,
        orgPolicyParser,
        this.jsonApplicationDiscoveryOverview,
        this.mongoConnect,
      );

      if (collector != null) {
        this.collectors.push(collector);
      }
    } catch (err) {
      const errInfo = `failed get collector by token type: ${token.type}, name: ${token.name}, err: ${err}`;
      logger.error(errInfo);
      throw err;
    }
  }

  getConnectorByName(connectorsName: repoType[]) {
    try {
      const collectors = [];
      for (const connectorName of connectorsName) {
        const collector = this.collectors.find(c => c.token.name.toLowerCase() === connectorName.toLowerCase());
        if (collector) {
          collectors.push(collector);
        }
      }
      return collectors;
    } catch (e) {
      logger.error(`failed to get connectorByName for fakerepo app ${e}`);
    }
    return [];
  }
}

export default CollectorManager;
