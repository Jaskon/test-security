import { CloudSecurityEvent } from "../../../entitis/cloudTypes";
import PolicyRulesBase, { Tool } from "./policyRulesBase";

import { AggregatedCloudData, AggregatedInfoForExclusion } from "../../../entitis/service/exclusionTypes";
import StringHelper from "../../../helper/stringHelper";
import PasswordHelper from "../../../helper/tools/passwordHelper";

import { ChangeReason } from "../../../entitis/service/blameTypes";
import isCloudSecretEnabledForOrg from "../../../helper/featureFlags/isCloudSecretEnabled";
import jsonParser from "../../../helper/jsonParser";
import { changeSeverityBasedOnCloudEvents, getCloudSecAllInfoForSeverity, getSeverityChanges } from "../../../helper/policy/severityHelper";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
const logger = loggerImport.getDebugLogger();

class PolicyCloudSecuritySecretScanNew extends PolicyRulesBase {
  private passwordHelper: PasswordHelper = new PasswordHelper();

  async eval(jsonData) {
    try {
      const shouldRun = await isCloudSecretEnabledForOrg.isOn(StatesHelper.Instance.orgName);
      if (!shouldRun) {
        return [];
      }

      const securityEventsInfo: CloudSecurityEvent[] = jsonData.cloudSecurityEvents;
      const secretsAlerts = securityEventsInfo.filter(i => i.secretContent != "" && i.secret == true);

      changeSeverityBasedOnCloudEvents(secretsAlerts, this.policyRuleMetadata.name);

      const keyValCloudEvents = this.getKeyValueMapByRuleIdAndData(secretsAlerts);
      let res = [];
      for (const events of Object.values(keyValCloudEvents) as any) {
        const topLevelEventData: CloudSecurityEvent = events.topLevel;

        if (!this.shouldIncludeByPolicyEx(topLevelEventData.severity)) {
          continue;
        }

        const securityItems: CloudSecurityEvent[] = (events.aggregated as PolicyCloudSecuritySecretScanAggItem[]).map(i => i.securityAlert);

        let violationInfoTitle = `${events.aggregated.length} secret discovered`;
        if (events.aggregated.length > 1) {
          violationInfoTitle = `${events.aggregated.length} secrets discovered`;
        }

        const aggregated = {
          violationInfoTitle,
          aggregatedItems: events.aggregated,
          columns: "policyCloudSecuritySecretScan",
        };
        const manaulConfig = jsonParser.getInstance().getIdObject(topLevelEventData.ruleId, "prowler");

        let vTitle;
        if (manaulConfig === undefined) {
          vTitle = topLevelEventData.title.replace(topLevelEventData.resource, "");

          vTitle = `${topLevelEventData.secretType} ${topLevelEventData.title.toLowerCase()}`;

          vTitle = vTitle.replace("potential", "");
        } else {
          vTitle = topLevelEventData.title;
        }
        let issueOwners = [];
        issueOwners = this.getOwnersFromAppOwnersConfig(jsonData);
        if (issueOwners.length == 0) {
          issueOwners = this.getOwnersFromUsers(jsonData);
        }
        if (issueOwners.length == 0) {
          issueOwners = this.getOwnersFromAppCreator(jsonData);
        }

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
        (events.aggregated as PolicyCloudSecuritySecretScanAggItem[]).forEach(i => {
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

        const resInfo = getCloudSecAllInfoForSeverity(securityItems, "cloud");
        const uniqueSeverityChanges = resInfo.uniqueSeverityFromAllAlerts as ChangeReason[];
        const originalSeverity = resInfo.originalSeverity;
        const originalSeverityStr = resInfo.originalSeverityStr;
        const newSeverityForPolicy = resInfo.newSeverityForPolicy;

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
          uniqueProviders.map(i => i.toLowerCase() as Tool),
          extraInfo,
          this.getCustomIssueId(`${topLevelEventData.ruleId}_${topLevelEventData.resource}`),
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

        item.eventFromExternalTool = securityItems.filter(i => !i.oxTool).length > 0;
        res.push(item);
      }
      return res;
    } catch (err) {
      logger.error(`Failed to run eval ${err} `);
      return [];
    }
  }

  getKeyValueMapByRuleIdAndData(securityEvents: CloudSecurityEvent[]) {
    let aggregatedItems = {};

    for (const securityEvent of securityEvents) {
      const singleItem: PolicyCloudSecuritySecretScanAggItem = new PolicyCloudSecuritySecretScanAggItem();

      singleItem.resource = securityEvent.resource || "";
      singleItem.service = securityEvent.cloudService || "";
      singleItem.cloudEnv = securityEvent?.cloudEnv || "";
      singleItem.secret = this.passwordHelper.getObfuscatedPass(
        [securityEvent.secretContent || ""],
        securityEvent.secretContent,
        "cloud-secret",
      );

      singleItem.realMatch = securityEvent.realMatch || "";
      singleItem.region = securityEvent.accountName ? `${securityEvent.region} (${securityEvent.accountName})` : securityEvent.region || "";
      singleItem.accountName = securityEvent.accountName || "";
      singleItem.securityAlert = securityEvent;
      singleItem.ruleId = securityEvent.ruleId || "";
      singleItem.linkToExternalProduct = securityEvent.linkToExternalProduct;
      singleItem.match = singleItem.secret;
      singleItem.accountId = securityEvent.accountId || "";
      singleItem.additionalToolData = securityEvent.additionalToolData || "";
      singleItem.link = securityEvent.link;
      singleItem.setAggId();

      if (!singleItem.realMatch) {
        logger.error(`failed add ${singleItem.ruleId}} for cloud, no match, policy: ${this.policyRuleMetadata.name}`);
        continue;
      }

      let unique = `${securityEvent.ruleId}_${securityEvent.resource}`;

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

export class PolicyCloudSecuritySecretScanAggItem extends AggregatedInfoForExclusion {
  resource: string;
  service: string;
  secret: string;
  region: string;
  cloudEnv: string;
  match: string;
  accountName: string;
  securityAlert: CloudSecurityEvent;
  ruleId: string;
  linkToExternalProduct: string;
  realMatch: string;
  accountId: string;
  additionalToolData: string;
  link: string;

  getExclusionObj() {
    const i: AggregatedCloudData = new AggregatedCloudData();
    i.resource = this.resource;
    i.service = this.service;
    i.accountId = this.accountId;
    i.ruleId = this.ruleId;
    i.secret = this.realMatch;
    return i;
  }

  setAggId() {
    this.aggId = StringHelper.combineStrings(this.service, this.resource, this.accountId, this.ruleId, this.realMatch);
    this.hashAggId = StringHelper.hashMd5(this.aggId);
  }
}

export default PolicyCloudSecuritySecretScanNew;
