import { isArray, isString } from "lodash";
import { AlertSeverity, CodeRepoTypes, SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { ResourceType, Token } from "../../entitis/collectorEntitisTypes";
import { Resource } from "../../entitis/orgPolicyTypes";
import { isDevelopment, isUploadToS3 } from "../../helper/envUtils";
import { getSharedFolder } from "../../helper/generalUtils";
import StatesHelper from "../../helper/statesHelper";
import { millisToMinutesAndSeconds, ScanPhaseTime, sendScannerPhaseTimeTelemetry } from "../../helper/telemetry-utils";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";
import CollectorBase from "./collectorBase";
import { CloudSecurityEvent } from "../../entitis/cloudTypes";
import Constant from "../../entitis/constant";
import MemoryMonitorHelper from "../../helper/IO/memoryMonitorHelper";

const fs = require("fs");

const logger = loggerImport.getDebugLogger();

abstract class ExternalSecurityProviderBase extends CollectorBase {
  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, ResourceType[ResourceType.external], policyConfiguration, jsonApplicationDiscoveryOverview);
  }

  abstract initLib();

  async collect(resources: Resource[], callObj: RulesManager): Promise<boolean[]> {
    logger.info(`try set external security provider for: ${this.token.name}, url: ${this.token.host}`);

    const startTime = new Date().getTime();

    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      await this.initLib();

      logger.info(`${this.token.name} start promisees poll to collect external security provider for ${resources.length} resources`);

      let externalSecurityObj = {};
      externalSecurityObj["resourceType"] = ResourceType[ResourceType.external];

      StatesHelper.Instance.externalToolsApisRunningTotal++;
      await callObj.resultsHandler.updateScanInfoStateWithDBupdate();

      const apisProms = resources.map(resource => this.addFirstLevelItemToArtifactsObj(externalSecurityObj, resource));
      await Promise.all(apisProms);

      const data = this.jsonHelper.lookupArrayVal(externalSecurityObj, CodeRepoTypes[CodeRepoTypes.securityEvents]);
      let secAlerts: SecurityEvent[] = [];
      let cloudSecAlerts: CloudSecurityEvent[] = [];

      //Need refactor this to return typed value
      const shouldRunForTools = this.token.name === Constant.orca.toLowerCase() || this.token.name === Constant.wiz.toLowerCase();
      if (data.containerEvents || shouldRunForTools) {
        secAlerts = data.containerEvents;
        cloudSecAlerts = data.cloudSecurityEvents;
      } else {
        secAlerts = data;
      }

      const filteredAllEvents: SecurityEvent[] = secAlerts;

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "after external pulling");

      //Code
      let codeSecEvents = secAlerts.filter(
        i =>
          i.securityAlertType === SecurityAlertType.iac ||
          i.securityAlertType === SecurityAlertType.sast ||
          i.securityAlertType === SecurityAlertType.sca ||
          i.securityAlertType === SecurityAlertType.secrets ||
          i.securityAlertType === SecurityAlertType.license,
      );
      externalSecurityObj[CodeRepoTypes[CodeRepoTypes.securityEvents]] = codeSecEvents;

      //Code sec event
      await callObj.applicationsManager.updateAppManagerExternalSecurityItem(externalSecurityObj);

      //Cloud sec event
      if (cloudSecAlerts.length) {
        externalSecurityObj["cloudSecurityEvents"] = cloudSecAlerts;
        await callObj.applicationsManager.updateAppManagerCloudItem(externalSecurityObj);
      }

      //Artifacts sec event
      let artifactsObj = {};
      externalSecurityObj["resourceType"] = ResourceType[ResourceType.artifactory];
      const artifactsEvents = filteredAllEvents.filter(i => i.securityAlertType === SecurityAlertType.container && i?.artifacts);

      artifactsObj[CodeRepoTypes[CodeRepoTypes.securityEvents]] = artifactsEvents;
      await callObj.applicationsManager.updateAppMangerArtifactsItemForExternalTools(artifactsObj);

      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);

      await sendScannerPhaseTimeTelemetry(ScanPhaseTime.ScanArtifactsPhaseTime, this.orgName, this.uuid, Number(elapsedTime));

      logger.info(
        `${this.token.name} promisees poll finish collect all resource for external security provider, execution time in minutes: ${elapsedTime}`,
      );
    } catch (err) {
      const errInfo = `${this.token.name} failed collect all resources for external security provider, err: ${err}`;
      logger.error(errInfo);
    }

    StatesHelper.Instance.externalToolsApisRunningProgress++;
    await callObj.resultsHandler.updateScanInfoStateWithDBupdate();

    return [];
  }

  async addFirstLevelItemToArtifactsObj(externalSecurityObj: any, resource: Resource) {
    let data = [];

    try {
      if (this.funcNames.has(resource.name)) {
        data = await this[resource.name]();
        externalSecurityObj[resource.name] = data;
      }

      return true;
    } catch (err) {
      logger.error(`failed collect resources: ${resource.name}, err: ${err}`);
    }
    return false;
  }

  copyToolResults({ toolName, data, useStream }: { toolName: string; data: string | []; useStream?: boolean }): void {
    if (!isUploadToS3()) return;
    const oxDir = getSharedFolder(this.uuid) + "/ox-security";
    const telemetryDir = oxDir + "/telemetry-" + this.uuid;
    const repoDir = telemetryDir + "/security-report/" + this.resourceType;
    const toolDir = repoDir + "/" + toolName + "/results.json";
    try {
      if (useStream && isArray(data)) {
        this.fileHelper.writeStream(toolDir, data);
        return;
      }
      this.fileHelper.write(toolDir, data as string);
    } catch (err) {
      logger.error(`failed to copy tool ${this.resourceType} result file`);
    }
  }
}

export default ExternalSecurityProviderBase;
