import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import pluralize from "pluralize";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { IssueOwner, Repo, repoResourceType, repoType, User, UserRole, Webhook } from "../../../entitis/codeRepoTypes";
import { AggregatedWebhook, AggregatedInfoForExclusion } from "../../../entitis/service/exclusionTypes";
import StringHelper from "../../../helper/stringHelper";
import { Input, InputOption, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";

const logger = loggerImport.getDebugLogger();

class PolicyWebhookConfiguration extends PolicyRulesBase {
  async eval(jsonData) {
    if (!jsonData.code_repo.realRepo) {
      return [];
    }
    let webhooksNoSecret = [];
    let columns;
    const data = new Set<PolicyWebhookConfigurationAggItem>();
    const webhookParamFromArgs = this.getValueFromRuleArgs("webhookParam");
    if (Array.isArray(webhookParamFromArgs)) {
      throw `webhookParam is array and not string type, ${webhookParamFromArgs.toString()}`;
    }

    let newVi: string = "";
    let recom: string = "";
    // i think there is a problem for github: webhooks with no secret returns true? investigate further.
    // there an issue with gitlab, current always return true
    if (webhookParamFromArgs.toLowerCase() === "secrets") {
      columns = "policyWebhookNoSecrets";
      webhooksNoSecret = jsonData.webhooks.filter(
        webhook =>
          webhook.secret == false &&
          Constant.secretRegex.exec(webhook.url) &&
          webhook.url.length > 70 &&
          !Constant.trustedWebhooks.some(trustedWebhook => webhook.url.includes(trustedWebhook)),
      );

      newVi = "Insecure webhook: no secret key";
      recom = "Please consider adding a secret for communication between the repo and the URL.";
    }

    if (webhookParamFromArgs.toLowerCase() === "ssl") {
      columns = "policyWebhookNoSSL";
      webhooksNoSecret = jsonData.webhooks.filter(webhook => webhook.ssl == false);
      const webhooksAfterFilter = jsonData.webhooks.filter(webhook => webhook.ssl == true);

      for (const hook of webhooksAfterFilter) {
        if (!hook.url.startsWith("https")) {
          webhooksNoSecret.push(hook);
        }
      }
      newVi = "Insecure webhook: no SSL";
      recom = 'Please "Enable SSL verification" in the settings for communication between the repo and the URL. ';

      if (webhooksNoSecret.some(i => !i.url.startsWith("https"))) {
        recom += "Please consider using https.";
      }
    }

    let res = [];
    let hooksIdNoSSL = [];
    for (const webhookNoSSL of webhooksNoSecret) {
      hooksIdNoSSL.push(webhookNoSSL); // add hookId
      const item: PolicyWebhookConfigurationAggItem = new PolicyWebhookConfigurationAggItem();
      item.url = webhookNoSSL.url || "";
      item.link = webhookNoSSL.link;
      item.events =
        webhookNoSSL.events.length > 3 // string
          ? webhookNoSSL.events.slice(0, 3).join(", ") + "..."
          : webhookNoSSL.events.join(", ");
      item.allEvents = webhookNoSSL.events.join(", ");
      item.numberOfReposDomainAppear = webhookNoSSL.numberOfReposDomainAppear;

      item.setAggId();

      data.add(item);
    }

    if (data.size === 0) {
      return [];
    }

    const replaceInfo = [
      // { replace: "*url_output*", replaceTo: webhookNoSSL.url },
      { replace: "*typeWebhook*", replaceTo: webhookParamFromArgs },
    ];
    const violationInfoTitle = `${pluralize("webhook", data.size, true)} found violating policy`;
    const aggregated = {
      columns: columns,
      violationInfoTitle: violationInfoTitle,
      aggregatedItems: [...data],
    };

    const issueOwners = this.getOwnersFromUsers(jsonData);

    const item = this.generateItemForReport(
      true,
      newVi,
      "",
      newVi,
      recom,
      "",
      "URL",
      replaceInfo,
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

    if (jsonData.code_repo.type.toLowerCase() === repoType.github && webhookParamFromArgs.toLowerCase() === "ssl") {
      item.fixes = this.generateFixes(hooksIdNoSSL, jsonData.code_repo);
    }
    return res;
  }

  generateFixes(data: Webhook[], repo: Repo) {
    try {
      const p: PolicyFix = new PolicyFix();
      p.description = `This action will enable SSL verification in the settings.`;
      p.settingType = SettingType.changeWebhookSSL;
      p.confirmation = "After this fix is implemented, the selected webhook URLs will have SSL verification enabled.";

      if (data.some(i => !i.url.startsWith("https"))) {
        p.description = `This action will require the URL to connect through HTTPS. SSL verification will also be enabled in the settings`;
        p.confirmation = `After this fix is implemented, the selected webhook URLs will have SSL verification enabled and communication will be done through HTTPs.`;
        p.warning = `Do not implement this fix if the URL does not have a valid SSL certificate.`;
      }
      const input: Input = new Input();
      input.type = "select";
      input.name = InputType.hooks;
      input.displayName = "Webhooks by URL";
      input.multiSelect = true;

      let clone = data.slice();
      input.options = clone.map(i => {
        let url = i.url;
        if (!i.url.startsWith("https")) {
          const urlPos = i.url.indexOf(":");
          url = i.url.substring(0, urlPos) + "s" + i.url.substring(urlPos);
        }
        const o: InputOption = new InputOption();
        o.name = i.url;
        o.displayName = i.url;
        o.selected = true;
        o.metadata = JSON.stringify({
          repo: repo.name,
          owner: repo.ownerNameApi,
          hookId: i.id,
          config: { url: url, insecure_ssl: 0 },
          scanId: StatesHelper.Instance.uuid,
          orgId: StatesHelper.Instance.orgName,
        });
        return o;
      });
      p.inputs.push(input);

      return p;
    } catch (e) {
      logger.error(`failed to generate fixes, policy: ${this.policyRuleMetadata.name}, error: ${e}`);
    }
  }
}

export class PolicyWebhookConfigurationAggItem extends AggregatedInfoForExclusion {
  url: string;
  link: string;
  events: string;
  allEvents: string;
  numberOfReposDomainAppear: number;

  getExclusionObj() {
    const i: AggregatedWebhook = new AggregatedWebhook();
    i.url = this.url;
    return i;
  }

  setAggId() {
    this.aggId = StringHelper.combineStrings(this.url);
    this.hashAggId = StringHelper.hashMd5(this.aggId);
  }
}

export default PolicyWebhookConfiguration;
