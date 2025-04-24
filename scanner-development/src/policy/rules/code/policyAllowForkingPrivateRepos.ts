import pluralize from "pluralize";
import { AlertSeverity, DevLanguages, IssueOwner, Repo, repoType, User, UserRole } from "../../../entitis/codeRepoTypes";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { ToolConfig } from "../../../entitis/tool/secuirtyToolsConfig";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import AutoFix from "../../../helper/service/auto-fix-service/auto-fix";
import { Input, InputOption, Policy, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { ChangeReason } from "../../../package-index";
import PolicyRulesBase from "./policyRulesBase";
const { Octokit } = require("@octokit/core");

const logger = loggerImport.getDebugLogger();

class PolicyAllowForkingPrivateRepos extends PolicyRulesBase {
  async eval(jsonData) {
    const repo: Repo = jsonData.code_repo;

    if (!repo.realRepo) {
      return [];
    }

    if (!repo.privateVisability) {
      return [];
    }
    if (!repo.allowForking) {
      return [];
    }

    const bpAllowed = this.getValueFromRuleArgs("bp");
    if (repo.repoImportance.total < bpAllowed) {
      return [];
    }

    const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);
    const orgFix = `https://github.com/organizations/${repo.organization}/settings/member_privileges`;
    const repoFix = `https://github.com/${repo.fullName}/settings`;
    const mainTitle = "Private repo can be forked";
    const recommendation = `You can either disable private forking for the entire organization (safer option) or disable private forking for specific repos.<br><br>To disable private forking for the entire org:<br><br>${orgFix}<br><br>To disable private forking only for this repo:<br><br>${repoFix}<br><br>Note: These settings do not disable forking of public repos.`;
    const description = `Your repo ${
      repo.fullName
    } can be privately forked into a user’s personal account, and this can lead to data leakage. Forking is allowed because the settings for private repo forking are enabled for the organization and the repo.<br><br>Note: Users no longer in your organization will have access to private forked repos for up to 24 hours. <br>
    The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

    const issueOwners = this.getOwnersFromUsers(jsonData);
    const item = this.generateItemForReport(
      true,
      mainTitle,
      description,
      "",
      recommendation,
      "N/A",
      "N/A",
      [],
      "",
      true,
      "",
      [],
      [Constant.gitPosture],
      [],
      [],
      this.getGeneralIssueId(),
      issueOwners,
    );
    let res = [];

    if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
      item.fixes = generateFixesForAllowForking(repo, this.policyRuleMetadata.name);
    }

    res.push(item);
    return res;
  }
}

export function generateFixesForAllowForking(repo: Repo, policyName: string) {
  try {
    const p: PolicyFix = new PolicyFix();
    p.description = "This action will prevent private repo forking.";
    p.settingType = SettingType.changeForkSettings;
    p.confirmation = "After this fix, the private repo will not be forkable";
    p.tooltip = "disable the option to fork the repo";

    const input: Input = new Input();
    input.type = "radio";
    input.name = InputType.settingsOption;
    input.displayName = "Fix Options";

    const o1: InputOption = new InputOption();
    o1.name = "Repo settings";
    o1.displayName = `'${repo.name}' repo only`;
    o1.info = "This will prevent forking for this repo only. Existing forks will continue to work.";
    o1.metadata = JSON.stringify({
      repo: repo.name,
      owner: repo.ownerNameApi,
      org: repo.organization,
      policyName: policyName,
      scanId: StatesHelper.Instance.uuid,
      orgId: StatesHelper.Instance.orgName,
    });
    const o2: InputOption = new InputOption();
    o2.name = "Organization settings";
    o2.selected = true;
    o2.displayName = `All repos in '${repo.organization}' org`;
    o2.info = "This will prevent forking for all private repos in the organization. Existing forks will continue to work.";
    o2.metadata = JSON.stringify({
      repo: repo.name,
      owner: repo.ownerNameApi,
      org: repo.organization,
      policyName: policyName,
      scanId: StatesHelper.Instance.uuid,
      orgId: StatesHelper.Instance.orgName,
    });
    input.options.push(o1);
    input.options.push(o2);
    p.inputs.push(input);

    return p;
  } catch (e) {
    logger.error(`failed to generate fixes, policy: ${policyName}, error: ${e}`);
  }
}

export default PolicyAllowForkingPrivateRepos;
