import { IssueOwner, repoResourceType, repoType, resourceType, User, UserRole, Webhook } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { SeverityChange } from "../../../entitis/service/blameTypes";
import loggerImport from "../../../logger";
import { ChangeReason } from "../../../package-index";
import PolicyRulesBase from "./policyRulesBase";
import { PolicyWebhookConfigurationAggItem } from "./policyWebhookConfiguration";
import { generateFixes } from "./webhooksReputation";
class policyAnomalousWebhooks extends PolicyRulesBase {
  async eval(jsonData) {
    if (!jsonData.code_repo.realRepo) {
      return [];
    }

    let percentAnomaly = this.getValueFromRuleArgs("MaxRepoPercent");
    if (!percentAnomaly) {
      throw "cannot find MaxRepoPercent";
    }
    percentAnomaly = percentAnomaly / 100;

    const maximumCount = this.getValueFromRuleArgs("MaxRepoCount");
    if (!maximumCount) {
      throw "cannot find MaxRepoPercent";
    }

    const domainExclusions = this.getValueFromRuleArgs("domainExclusions");
    if (!domainExclusions || !Array.isArray(domainExclusions)) {
      throw "bad format domainExclusions";
    }

    const res = [];
    const data = [];
    const webhooksToRemove = [];
    for (const webhook of jsonData.webhooks as Webhook[]) {
      if (webhook.domainAppearAcrossOrgPercentage == 0 || webhook.numberOfReposDomainAppear == 0) {
        continue;
      }

      if (webhook.domainAppearAcrossOrgPercentage < percentAnomaly && webhook.numberOfReposDomainAppear < maximumCount) {
        let excluded = false;
        for (const domainExclusion of domainExclusions as string[]) {
          if (webhook.domain.toLowerCase().match(domainExclusion.toLowerCase()) != null) {
            excluded = true;
            break;
          }
        }
        if (excluded) {
          continue;
        }

        webhooksToRemove.push(webhook);
        const item: PolicyWebhookConfigurationAggItem = new PolicyWebhookConfigurationAggItem();
        item.url = webhook.url || "";
        item.link = webhook.link;
        item.events =
          webhook.events.length > 3 // string
            ? webhook.events.slice(0, 3).join(", ") + "..."
            : webhook.events.join(", ");
        item.allEvents = webhook.events.join(", ");
        item.numberOfReposDomainAppear = webhook.numberOfReposDomainAppear;

        item.setAggId();
        data.push(item);
      }
    }

    if (data.length === 0) {
      return [];
    }

    const newVi = `Webhook URL${data.length > 1 ? "s" : ""} usage is rare: ${data.length} URL${data.length > 1 ? "s" : ""}`;
    const dec: string = `Webhook URL${data.length > 1 ? "s" : ""} were found that are rarely used in the organization. You have ${
      data.length
    } URL${data.length > 1 ? "s" : ""} that are seldom used in your organization’s repositories.`;

    const aggregated = {
      columns: "policyWebhookNoSecrets",
      aggregatedItems: data,
    };

    const issueOwners = this.getOwnersFromUsers(jsonData);

    const item = this.generateItemForReport(
      true,
      newVi,
      dec,
      newVi,
      "Please remove any webhooks that you determine to be not needed. This will reduce the likelihood that your code will be exposed.",
      "",
      "URL",
      "",
      "",
      true,
      "",
      aggregated,
      [Constant.cicdPosture],
      [repoResourceType.webhooks],
      [],
      this.getGeneralIssueId(),
      issueOwners,
    );

    res.push(item);
    if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
      item.fixes = generateFixes(webhooksToRemove, jsonData.code_repo, this.policyRuleMetadata.name);
    }
    return res;
  }
}

export default policyAnomalousWebhooks;
