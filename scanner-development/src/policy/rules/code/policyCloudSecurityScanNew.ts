import { ContainerSecurityType } from "../../../entitis/artifactoryTypes";
import { CloudSecurityEvent } from "../../../entitis/cloudTypes";
import { getToolsNames, getUniqueInfoForCloudAggregation } from "../../../entitis/codeRepoTypes";
import { AdditionalTab } from "../../../entitis/issuesTypes";
import { ChangeReason, SeverityChange } from "../../../entitis/service/blameTypes";
import { AggregatedCloudData, AggregatedInfoForExclusion } from "../../../entitis/service/exclusionTypes";
import { ToolNameForUI } from "../../../entitis/tool/toolsTypes";
import { enableByPolicy } from "../../../helper/commonUtils";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { changeSeverityBasedOnCloudEvents, getCloudSecAllInfoForSeverity, getSeverityChanges } from "../../../helper/policy/severityHelper";
import StatesHelper from "../../../helper/statesHelper";
import StringHelper from "../../../helper/stringHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase, { Tool } from "./policyRulesBase";
const logger = loggerImport.getDebugLogger();

class PolicyCloudSecurityScanNew extends PolicyRulesBase {
  async eval(jsonData) {
    if (!Array.isArray(jsonData.cloudSecurityEvents)) {
      return [];
    }

    const oxTool = jsonData.cloudSecurityEvents.find(i => i.oxTool);
    if (oxTool != undefined) {
      if (!enableByPolicy(ToolNameForUI.prowler)) {
        return [];
      }
    }

    const securityEventsInfo: CloudSecurityEvent[] = jsonData.cloudSecurityEvents;
    const withoutSecretsAlerts = securityEventsInfo.filter(i => i.secret == false);
    if (withoutSecretsAlerts.length === 0) {
      return [];
    }

    changeSeverityBasedOnCloudEvents(withoutSecretsAlerts, this.policyRuleMetadata.name);

    const keyValCloudEvents = this.getKeyValueMapByRuleIdAndData(withoutSecretsAlerts);

    let res = [];
    for (const events of Object.values(keyValCloudEvents) as any) {
      const topLevelEventData: CloudSecurityEvent = events.topLevel;
      //logger.info(`This is top level event non secret ${JSON.stringify(topLevelEventData)}`);
      if (!this.shouldIncludeByPolicyEx(topLevelEventData.severity)) {
        continue;
      }

      const securityItems: CloudSecurityEvent[] = (events.aggregated as PolicyCloudSecurityScanAggItem[]).map(i => i.securityAlert);

      let violationInfoTitle = `${events.aggregated.length} ${topLevelEventData.category} violation discovered`;
      if (events.aggregated.length > 1) {
        violationInfoTitle = `${events.aggregated.length} ${topLevelEventData.category} violations discovered`;
      }

      if (topLevelEventData.category.toLowerCase() != topLevelEventData.cloudService.toLowerCase()) {
        violationInfoTitle = `${violationInfoTitle} in ${topLevelEventData.cloudService}`;
      }

      const aggregated = {
        violationInfoTitle,
        aggregatedItems: events.aggregated,
        columns: "policyCloudSecurityScan",
      };

      let vTitle = topLevelEventData.title;
      if (topLevelEventData.accountName && StatesHelper.Instance.aggCloudAlertsBaseOnOrg) {
        vTitle = `${topLevelEventData.title} (${topLevelEventData.accountName})`;
      }

      if (!vTitle.toLowerCase().startsWith(`${topLevelEventData.cloudService.toLowerCase()} `)) {
        const serviceForTittle = this.getServiceNameForTitle(topLevelEventData.cloudService);
        if (serviceForTittle != null) {
          vTitle = `${serviceForTittle} ${vTitle}`;
        }
      }

      const issueOwners = this.getOwnersFromAppOwnersConfig(jsonData);
      const uniqueProviders = this.getUniqueSecurityProviders(
        events.aggregated.map(i => i.securityAlert.securityProviders),
        topLevelEventData.securityProvider,
      );

      const extraInfo = [];
      extraInfo.push({
        key: "Rule name",
        value: topLevelEventData.ruleId,
      });
      let allGroups = new Set();
      (events.aggregated as PolicyCloudSecurityScanAggItem[]).forEach(i => {
        i.securityAlert.cloudAccountGroups.forEach(j => {
          allGroups.add(j);
        });
      });
      if (allGroups.size > 0) {
        extraInfo.push({
          key: "Cloud Account Groups",
          value: `${Array.from(allGroups).join(", ")}`,
        });
      }

      let cloudAccountOwners = new Set();
      (events.aggregated as PolicyCloudSecurityScanAggItem[]).forEach(i => {
        i.securityAlert.cloudAccountOwners.forEach(j => cloudAccountOwners.add(j));
      });
      if (cloudAccountOwners.size > 0) {
        extraInfo.push({
          key: "Cloud Account Owners",
          value: `${Array.from(cloudAccountOwners).join(", ")}`,
        });
      }

      const resInfo = getCloudSecAllInfoForSeverity(securityItems, "cloud");
      const uniqueSeverityChanges = resInfo.uniqueSeverityFromAllAlerts as ChangeReason[];
      const originalSeverity = resInfo.originalSeverity;
      const originalSeverityStr = resInfo.originalSeverityStr;
      const newSeverityForPolicy = resInfo.newSeverityForPolicy;

      const additionalTabs = [];
      if (withoutSecretsAlerts[0].artifacts) {
        //This is a hack we do to additional tabs on top of the agg item key
        const additionalTab: AdditionalTab = new AdditionalTab();
        additionalTab.type = "policySecurityContainerScan";
        additionalTabs.push(additionalTab);
      }

      let item = this.generateItemForReport(
        true,
        vTitle,
        topLevelEventData.violationInfo,
        vTitle,
        topLevelEventData.recommendation,
        violationInfoTitle,
        "Code Repository",
        [],
        `Rule name - ${topLevelEventData.ruleId}`,
        true,
        "",
        aggregated,
        uniqueProviders,
        getToolsNames(topLevelEventData.securityProviders, topLevelEventData.tools),
        extraInfo,
        this.getCustomIssueId(`${topLevelEventData.ruleId}_${topLevelEventData.cloudService}`),
        issueOwners,
        topLevelEventData.moreInfoLink,
        topLevelEventData.ruleId,
        [],
        "",
        [],
        newSeverityForPolicy,
        [],
        "",
        originalSeverityStr,
        [],
        getSeverityChanges(originalSeverity, newSeverityForPolicy),
        uniqueSeverityChanges,
        [],
        this.getOriginalSev(securityItems),
      );
      //logger.info(`This is pushed non secret ${JSON.stringify(item)}`);
      item.eventFromExternalTool = securityItems.filter(i => !i.oxTool).length > 0;

      item.additionalTabs = additionalTabs.length == 0 ? undefined : additionalTabs;

      if (StatesHelper.Instance.isMatchingArtifactToCloud) {
        item.correlatedRegistry = topLevelEventData.securityProvider.toLowerCase();
      }

      res.push(item);
    }

    return res;
  }

  getServiceNameForTitle(service: string) {
    const serviceToLower = service.toLowerCase();
    if (
      serviceToLower === "ec2" ||
      serviceToLower === "iam" ||
      serviceToLower === "s3" ||
      serviceToLower === "kms" ||
      serviceToLower === "vpc" ||
      serviceToLower === "ecr" ||
      serviceToLower === "rds" ||
      serviceToLower === "elb" ||
      serviceToLower === "es" ||
      serviceToLower === "acm" ||
      serviceToLower === "sqs" ||
      serviceToLower === "sns" ||
      serviceToLower === "ecs" ||
      serviceToLower === "eks" ||
      serviceToLower === "ssm" ||
      serviceToLower === "efs"
    ) {
      return service.toUpperCase();
    }

    return null;
  }

  getKeyValueMapByRuleIdAndData(securityEvents: CloudSecurityEvent[]) {
    let aggregatedItems = {};

    for (const securityEvent of securityEvents) {
      const singleItem: PolicyCloudSecurityScanAggItem = new PolicyCloudSecurityScanAggItem();

      singleItem.resource = securityEvent.resource || "";
      singleItem.service = securityEvent.cloudService || "";
      singleItem.cloudEnv = securityEvent?.cloudEnv || "";
      singleItem.region =
        securityEvent.accountName && securityEvent.accountName !== "N/A"
          ? `${securityEvent.region} (${securityEvent.accountName})`
          : securityEvent.region || "";
      singleItem.accountName = securityEvent.accountName || "";
      singleItem.securityAlert = securityEvent;
      singleItem.ruleId = securityEvent.ruleId || "";
      singleItem.accountId = securityEvent.accountId || "";
      singleItem.additionalToolData = securityEvent.additionalToolData || "";
      singleItem.realMatch = `${singleItem.resource}_${singleItem.service}`;
      singleItem.linkToExternalProduct = securityEvent.linkToExternalProduct;

      if (securityEvent.artifacts) {
        singleItem.dockerVer = securityEvent?.artifacts?.dockerVer || "";
        singleItem.imageCreatedAt = securityEvent?.artifacts?.imageCreatedAt || "";
        if (singleItem.imageCreatedAt) {
          if (singleItem.imageCreatedAt.toLowerCase() != "n/a") {
            try {
              singleItem.imageCreatedAt = new Date(singleItem.imageCreatedAt).toLocaleString();
            } catch (err) {}
          }
        }

        singleItem.pkgCount = securityEvent?.artifacts?.pkgCount || 0;
        singleItem.binariesCount = securityEvent?.artifacts?.binariesCount || 0;
        singleItem.sha = securityEvent?.artifacts?.sha || "";
        singleItem.os = securityEvent?.artifacts?.os || "";
        if (singleItem.os) {
          if (securityEvent?.artifacts?.osVersion) {
            singleItem.os = `${singleItem.os}@${securityEvent?.artifacts?.osVersion}`;
          }
        }

        singleItem.image = securityEvent.artifacts.dockerFileInRunTime;
        singleItem.imageLink = securityEvent.artifacts.linkToRegistry || "";
        singleItem.registryName = securityEvent.artifacts.registryName || "";
        singleItem.tag = securityEvent?.artifacts?.tag || "";
        singleItem.layer = "";
      }

      singleItem.setAggId();

      let unique = getUniqueInfoForCloudAggregation(securityEvent);

      if (aggregatedItems.hasOwnProperty(unique)) {
        let info = aggregatedItems[unique];
        info.aggregated.push(singleItem);
      } else {
        const info = {
          topLevel: securityEvent,
          aggregated: [],
        };

        info.aggregated.push(singleItem);
        aggregatedItems[unique] = info;
      }
    }
    return aggregatedItems;
  }
}

export class PolicyCloudSecurityScanAggItem extends AggregatedInfoForExclusion {
  resource: string;
  service: string;
  region: string;
  cloudEnv: string;
  securityAlert: CloudSecurityEvent;
  accountName: string;
  realMatch: string;
  linkToExternalProduct: string;
  ruleId: string;
  additionalToolData: string;
  accountId: string;

  //Artifacts
  dockerVer: string;
  imageCreatedAt: string;
  pkgCount: number;
  binariesCount: number;
  sha: string;
  layer: string;
  baseImage: string;
  os: string;
  image: string;
  tag: string;
  imageLink: string;
  registryName: string;

  getExclusionObj() {
    const i: AggregatedCloudData = new AggregatedCloudData();
    i.resource = this.resource;
    i.service = this.service;
    i.accountId = this.accountId;
    i.secret = "";
    i.ruleId = this.ruleId;
    return i;
  }

  setAggId() {
    this.aggId = StringHelper.combineStrings(this.service, this.resource, this.accountId, this.ruleId);
    this.hashAggId = StringHelper.hashMd5(this.aggId);
  }
}

export default PolicyCloudSecurityScanNew;
