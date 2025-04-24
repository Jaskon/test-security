import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import vtAPI from "../../../helper/policy/vtHelper";
import pluralize from "pluralize";
import { IssueOwner, Repo, repoType, User, UserRole, Webhook } from "../../../entitis/codeRepoTypes";
import { AggregatedWebhook, AggregatedInfoForExclusion } from "../../../entitis/service/exclusionTypes";
import StringHelper from "../../../helper/stringHelper";
import { Input, InputOption, PolicyFix } from "../../../helper/service/policy-service/types";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import StatesHelper from "../../../helper/statesHelper";

const md5File = require("md5-file");
const logger = loggerImport.getDebugLogger();

class WebhooksReputation extends PolicyRulesBase {
  async eval(jsonData) {
    return [];

    if (!jsonData.code_repo.realRepo) {
      return [];
    }
    const data: WebhooksReputationAggItem[] = [];
    const webhooksReputationFromArgs = this.getValueFromRuleArgs("reputation");
    if (!Array.isArray(webhooksReputationFromArgs)) {
      throw `reputation is not array type, ${webhooksReputationFromArgs.toString()}`;
    }

    let res = [];
    const webhooksToRemove = [];
    //for each webhook
    for (const webhookRepInfo of jsonData.webhooks) {
      if (webhookRepInfo.reputationSkip) {
        continue;
      }
      // rep data is an array that has ma 3 obj - urlRep, domainRep ipRep
      // usually theres only one.
      for (const webhookRep of webhookRepInfo.reputationData) {
        if (webhookRep == null) {
          continue;
        }

        // if one of the 3 (urlRep, domainRep ipRep) matchess the policy - violation
        const rep = vtAPI.getInstance().getCalssification(webhookRep);
        if (webhooksReputationFromArgs.some(i => rep.toLowerCase() == i.toLowerCase())) {
          logger.info(`find rep: ${rep} for webhook url: ${webhookRepInfo.url}`);
          webhooksToRemove.push(webhookRep);
          const item: WebhooksReputationAggItem = new WebhooksReputationAggItem();
          item.url = webhookRepInfo.url || "";
          item.link = webhookRepInfo.link;
          item.reputation = this.getAdditionalInfo(webhookRep, webhookRepInfo.url, rep);
          item.events =
            webhookRepInfo.events.length > 3 ? webhookRepInfo.events.slice(0, 3).join(", ") + "..." : webhookRepInfo.events.join(", ");
          item.allEvents = webhookRepInfo.events.join(", ");
          item.vtLink = vtAPI.getInstance().getVtWebLink(webhookRepInfo.url);
          item.numberOfReposDomainAppear = webhookRepInfo.numberOfReposDomainAppear;

          item.setAggId();

          data.push(item);

          continue;
        }
      }
      continue;
    }

    const violationInfoTitle = `${pluralize("webhook", data.length, true)} found violating policy`;
    const aggregated = {
      violationInfoTitle,
      aggregatedItems: data,
      columns: "webhooksReputation",
    };

    const replaceInfo = [{ replace: "*rep*", replaceTo: webhooksReputationFromArgs[0] }];
    const newVi = `Webhook accessing *repo* URL`;

    const issueOwners = this.getOwnersFromUsers(jsonData);

    const item = this.generateItemForReport(
      true,
      newVi,
      "",
      newVi,
      `Please consider removing the ${pluralize(
        "webhook",
        data.length,
      )}. Analyze your repo to ensure that permissions are set for only those who really need access to the repo.`,
      "",
      "URL",
      replaceInfo,
      [],
      true,
      "",
      aggregated,
      [Constant.cicdPosture],
      ["UNKNOWN"], // dor fill
      [],
      this.getGeneralIssueId(),
      issueOwners,
    );

    if (data.length) {
      res.push(item);
    }

    if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
      item.fixes = generateFixes(webhooksToRemove, jsonData.code_repo, this.policyRuleMetadata.name);
    }
    return res;
  }

  getAdditionalInfo(webhookRep, url, rep) {
    try {
      return `${
        webhookRep.data.attributes.last_analysis_stats[rep.toLowerCase()]
      } VirusTotal vendors classify ${url} as ${rep.toLowerCase()}`;
    } catch (err) {
      logger.error(`getAdditionalInfo err: ${err}. rep: ${JSON.stringify(webhookRep, null, 4)}`);
      return "";
    }
  }
}

export function generateFixes(data: Webhook[], repo: Repo, policyName: string) {
  try {
    const p: PolicyFix = new PolicyFix();
    p.description = `This action will delete the selected webhooks.`;
    p.settingType = SettingType.deleteWebhook;
    p.confirmation = "After this fix, the selected webhooks will be deleted";

    const input: Input = new Input();
    input.type = "select";
    input.name = InputType.hooks;
    input.displayName = "Webhooks by URL";
    input.multiSelect = true;

    let clone = data.slice();
    input.options = clone.map(i => {
      const o: InputOption = new InputOption();
      o.name = i.url;
      o.displayName = i.url;
      o.selected = true;
      o.metadata = JSON.stringify({
        repo: repo.name,
        owner: repo.ownerNameApi,
        hookId: i.id,
        scanId: StatesHelper.Instance.uuid,
        orgId: StatesHelper.Instance.orgName,
      });
      return o;
    });
    p.inputs.push(input);

    return p;
  } catch (e) {
    logger.error(`failed to generate fixes, policy: ${policyName}, error: ${e}`);
  }
}
export class WebhooksReputationAggItem extends AggregatedInfoForExclusion {
  url: string;
  link: string;
  reputation: string;
  events: string;
  allEvents: string;
  vtLink: string;
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

export default WebhooksReputation;
