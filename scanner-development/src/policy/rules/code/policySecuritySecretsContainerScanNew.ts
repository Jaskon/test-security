import loggerImport from "../../../logger";
import PolicyRulesBase, { Tool } from "./policyRulesBase";
import { IssueOwner, SecurityEvent, getUniqueInfoForAggregation } from "../../../entitis/codeRepoTypes";
import pluralize from "pluralize";
import TimeHelper from "../../../helper/timeHelper";
import { SeverityChange } from "../../../entitis/service/blameTypes";
import { PolicySecuritySecretsContainerScanAggItem } from "./policySecuritySecretsContainerScan";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import StatesHelper from "../../../helper/statesHelper";

const logger = loggerImport.getDebugLogger();

class policySecuritySecretsContainerScanNew extends PolicyRulesBase {
  private timeHelper: TimeHelper = new TimeHelper("");

  async eval(jsonData) {
    return [];

    const shouldRun = StatesHelper.Instance.isContainerEnable;
    if (!shouldRun) {
      return [];
    }

    const scanTypeFromArgs = this.getValueFromRuleArgs("scanType");

    if (Array.isArray(scanTypeFromArgs)) {
      throw `scanType is array and not string type, ${scanTypeFromArgs.toString()}`;
    }

    const aggragatedInfo = this.getKeyValueMapByRuleIdAndData(jsonData.securityEvents);

    let res = [];
    const owners = this.getOwnersFromAppOwnersConfig(jsonData);

    const issueOwners = owners.map(owner => {
      const issueOwner: IssueOwner = {
        name: owner.name,
        email: owner.email,
      };
      return issueOwner;
    });
    for (const events of Object.values(aggragatedInfo) as any) {
      const topLevelEventData = events.topLevel;

      const securityItems: SecurityEvent[] = (events.aggregated as PolicySecuritySecretsContainerScanAggItem[]).map(i => i.securityAlert);

      if (scanTypeFromArgs.toLowerCase() != topLevelEventData.securityAlertTypeStr.toLowerCase()) continue;

      if (!this.shouldIncludeByPolicyEx(topLevelEventData.severity)) {
        continue;
      }

      const violationInfoTitle =
        events.aggregated.length &&
        `${pluralize("occurrence", events.aggregated.length, true)}  discovered in ${pluralize("file", events.uniqueFiles.size, true)}`;

      const aggregated = {
        aggregatedItems: this.sortEvents(events.aggregated),
        columns: "policySecuritySecretsContainerScan",
        violationInfoTitle,
      };

      const recommendation = topLevelEventData.recommendation;
      let newVi = `Secrets in Containers`;
      if (topLevelEventData.secretType) {
        newVi = `Secrets in Containers: ${topLevelEventData.secretType}`;
      }

      const uniqueProviders = this.getUniqueSecurityProviders(
        events.aggregated.map(i => i.securityAlert.securityProviders),
        topLevelEventData.securityProvider,
      );

      let item = this.generateItemForReport(
        true,
        newVi,
        "",
        newVi,
        recommendation,
        topLevelEventData.securityProvider,
        topLevelEventData.securityAlertTypeStr,
        [],
        `Rule name - ${events.topLevel.ruleId}`,
        true,
        "",
        aggregated,
        uniqueProviders,
        uniqueProviders.map(i => i.toLowerCase() as Tool),
        [{ key: "Rule name", value: events.topLevel.ruleId }],
        this.getCustomIssueId(events.topLevel.ruleId),
        issueOwners,
        topLevelEventData.moreInfoLink,
        events.topLevel.ruleId,
        [],
        "",
        [],
        this.policyRuleMetadata.severity,
        [],
        "",
        "",
        [],
        SeverityChange.NotApplicable,
        [],
        [],
        this.getOriginalSev(securityItems),
      );

      item.eventFromExternalTool = securityItems.filter(i => !i.oxTool).length > 0;

      res.push(item);
    }
    return res;
  }

  sortEvents(commits: PolicySecuritySecretsContainerScanAggItem[]) {
    try {
      const res = commits.sort(
        (a, b) => this.timeHelper.getTimeIntervalFronNowInMili(a.image) - this.timeHelper.getTimeIntervalFronNowInMili(b.image),
      );
      return res;
    } catch (err) {
      logger.error(`failed sort ${this.policyRuleMetadata.name}, err: ${err}`);
    }
    return commits;
  }

  getKeyValueMapByRuleIdAndData(securityEvents: SecurityEvent[]) {
    let aggregatedItems = {};
    for (const event of securityEvents) {
      const singleItem: PolicySecuritySecretsContainerScanAggItem = new PolicySecuritySecretsContainerScanAggItem();

      singleItem.dockerVer = event.artifacts.dockerVer;
      singleItem.filePath = event.fileName || "";
      singleItem.imageCreatedAt = event.artifacts.imageCreatedAt || "";
      singleItem.pkgCount = event.artifacts.pkgCount;
      singleItem.binariesCount = event.artifacts.binariesCount;
      singleItem.securityAlert = event;
      singleItem.sha = event.artifacts.sha || "";
      singleItem.os = event.artifacts.os || "";
      singleItem.image = event.artifacts.dockerFileInRunTime || "";
      singleItem.tag = event.artifacts.tag || "";
      singleItem.linkToExternalProduct = event.linkToExternalProduct;

      singleItem.setAggId();

      const unique = getUniqueInfoForAggregation(event);

      if (aggregatedItems.hasOwnProperty(unique)) {
        let info = aggregatedItems[unique];
        info.aggregated.push(singleItem);
        info.uniqueFiles.add(event.fileName);
      } else {
        const info = {
          topLevel: event,
          aggregated: [],
          uniqueFiles: new Set(),
        };
        info.uniqueFiles.add(event.fileName);
        info.aggregated.push(singleItem);
        aggregatedItems[unique] = info;
      }
    }
    return aggregatedItems;
  }
}

export default policySecuritySecretsContainerScanNew;
