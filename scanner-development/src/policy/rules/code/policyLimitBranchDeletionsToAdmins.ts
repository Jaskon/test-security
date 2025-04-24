import pluralize from "pluralize";
import { Repo, repoResourceType, repoType, User } from "../../../entitis/codeRepoTypes";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { BranchProtectionRule, changedValues } from "../../../helper/service/auto-fix-service/updateBranchProtectionRule";
import { Input, InputOption, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
const logger = loggerImport.getDebugLogger();

class policyLimitBranchDeletionsToAdmins extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const repo: Repo = jsonData.code_repo;
      if (!repo.realRepo) {
        return [];
      }
      const gitType = jsonData.code_repo.type.toLowerCase();
      let shouldRunPolicy = false;

      switch (gitType) {
        case repoType.github:
          shouldRunPolicy = true;
          break;

        case repoType.gitlab:
          shouldRunPolicy = true;
          break;

        case repoType.bitbucket:
          shouldRunPolicy = true;
          break;
      }

      if (!shouldRunPolicy) {
        return [];
      }

      const users = jsonData.users;
      const privateVisability = repo.privateVisability;
      const reposType = this.getValueFromRuleArgs("RepoType");
      if ((reposType === "Private" && !privateVisability) || (reposType === "Public" && privateVisability)) {
        return [];
      }
      const defaultBranchName = repo.defaultBranch;
      const branchSettings = jsonData.branchSettings;
      const rule = branchSettings.rule;
      const isDeletionAllowed = branchSettings.forceDeleteAllowed;
      if (!isDeletionAllowed) {
        return [];
      }
      let fixLink = ``;
      const issueName = `The ${defaultBranchName} branch can be deleted by non-admins`;
      const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);
      let issueDesc;
      switch (gitType) {
        case repoType.github:
        case repoType.bitbucket:
          issueDesc = `The branch ${defaultBranchName} has a setting that allows anyone with “write” access to delete the branch. <br>
           The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;
          break;

        case repoType.gitlab:
          issueDesc = `The branch ${defaultBranchName} is not protected, and therefore any member can delete it. <br>
           The project was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;
      }
      let recommendation = "";

      const adminRole = repo.gitRoles.repo.admin.toLowerCase();
      const orgAdminRole = repo.gitRoles.org.admin.toLowerCase();
      let userIssueOwner = this.getAdminWithMaxOperations(users as User[], adminRole, true);
      if (!userIssueOwner) {
        userIssueOwner = this.getAdminWithMaxOperations(jsonData.allUsers as User[], orgAdminRole);
      }
      if (!userIssueOwner) {
        userIssueOwner = { name: repo.ownerName, email: repo.ownerEmail || "" };
      }

      switch (gitType) {
        case repoType.github:
          fixLink = repo.settingLink.concat("/branches");
          recommendation = `Ensure your repository is configured to not allow any deletions of the ${defaultBranchName} branch by users with write permissions by <br>
            1. Enter the [link](${fixLink}) <br>
            2. Click on "Edit" for the rule applied to ${defaultBranchName} <br>
            3. Uncheck the box "Allow deletions" <br>
            4. Click "Save changes"`;
          break;

        case repoType.gitlab:
          fixLink = `${repo.link}/-/settings/repository`;
          recommendation = `Ensure your project is configured to not allow any deletions of the ${defaultBranchName} branch by users with lower roles than "Maintainer"<br>
              1. Enter the [link](${fixLink}) <br>
              2. Click on "Protected branches"<br>
              3. Make ${defaultBranchName} branch protected <br>`;
          break;

        case repoType.bitbucket:
          fixLink = repo.settingLink.concat("/branch-restrictions");
          recommendation = `Ensure your repository is configured to not allow any deletions of the ${defaultBranchName} branch by users with write permissions by <br>
              1. Enter the [link](${fixLink}) <br>
              2. Click on "Edit" for the restriction applied to ${defaultBranchName} <br>
              3. Uncheck the box "Allow deleting this branch" <br>
              4. Click "Save"`;
          break;
      }

      const item = this.generateItemForReport(
        true,
        issueName,
        issueDesc,
        issueName,
        recommendation,
        "N/A",
        "N/A",
        "",
        "",
        true,
        fixLink,
        [],
        [Constant.gitPosture],
        [repoResourceType.branchSettings],
        [],
        this.getGeneralIssueId(),
        [userIssueOwner],
      );

      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        let fixedRule = creatingFixedRule(rule, this.policyRuleMetadata.name);

        //If fixed rule is defined properly
        if (fixedRule) {
          fixedRule.allowDeletions = false;
        }

        item.fixes = this.generateFixes(repo, defaultBranchName, fixedRule, branchSettings.branchProtection);
      }

      return [item];
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
    return [];
  }

  generateFixes(repo: Repo, branch: string, fixedRule: BranchProtectionRule, hasRule: boolean) {
    try {
      // in case we couldn't create a fixed rule to send
      if (!fixedRule || (!fixedRule.requiredPullRequestReviews && fixedRule.requiredPullRequestReviews != null)) {
        return;
      }
      //in case we couldn't create lists to send / couldn't determine if the lists are valid
      if (!checkingListsValidForUpdate(fixedRule, this.policyRuleMetadata.name, repo.name)) {
        return;
      }

      const p: PolicyFix = new PolicyFix();
      p.description = "This action will prevent the branch from being deleted by users with write access.";
      p.settingType = SettingType.setRepoBranchProtectionForDeletionOnBranch;
      p.confirmation = "After this fix only admins will be able to delete the branch.";
      p.tooltip = "Prevent protected branch from being deleted";

      const input: Input = new Input();
      input.type = "select";
      input.name = InputType.branch;
      input.displayName = "Branch";
      const o: InputOption = new InputOption();
      o.name = branch;
      o.displayName = branch;
      o.selected = true;
      o.metadata = JSON.stringify({
        owner: repo.ownerNameApi,
        repo: repo.name,
        branch: branch,
        fixedRule: fixedRule,
        changedValues: [changedValues.AllowDeletions],
        hasRule: hasRule,
        scanId: StatesHelper.Instance.uuid,
        orgId: StatesHelper.Instance.orgName,
      });

      input.options.push(o);
      p.inputs.push(input);

      return p;
    } catch (e) {
      logger.error(`failed to generate fixes, policy: ${this.policyRuleMetadata.name}, error: ${e}`);
    }
  }
}

export function gettingListUsers(list) {
  try {
    return list.map(i => i.login);
  } catch (e) {
    logger.error(`failed to get list of users, err:${e}`);
    return undefined;
  }
}
export function gettingListTeamsOrApps(list) {
  try {
    return list.map(i => i.slug);
  } catch (e) {
    logger.error(`failed to get list of teams or apps, err:${e}`);
    return undefined;
  }
}
export function creatingFixedRule(rule, policyName) {
  try {
    let setRequiredPullRequestReviews;
    if (!rule.hasOwnProperty("required_pull_request_reviews")) {
      setRequiredPullRequestReviews = null;
    } else {
      const dismissStaleReviews = rule.hasOwnProperty("required_pull_request_reviews")
        ? rule["required_pull_request_reviews"]["dismiss_stale_reviews"]
        : false;
      const requireCodeOwnerReviews = rule.hasOwnProperty("required_pull_request_reviews")
        ? rule["required_pull_request_reviews"]["require_code_owner_reviews"]
        : false;
      const requireLastPushApproval = rule.hasOwnProperty("required_pull_request_reviews")
        ? rule["required_pull_request_reviews"]["require_last_push_approval"]
        : false;
      const requiredApprovingReviewCount = rule.hasOwnProperty("required_pull_request_reviews")
        ? rule["required_pull_request_reviews"]["required_approving_review_count"]
        : 0;
      let bypassPullRequestAllowances = { users: [], teams: [], apps: [] };
      let dismissalRestrictions = {};

      if (!rule["required_pull_request_reviews"]["dismissal_restrictions"]) {
        dismissalRestrictions = {};
      } else {
        const list = rule["required_pull_request_reviews"]["dismissal_restrictions"];
        const usersListDismissal = gettingListUsers(list.users);
        const teamsListDismissal = gettingListTeamsOrApps(list.teams);
        const appsListDismissal = gettingListTeamsOrApps(list.apps);
        dismissalRestrictions = { users: usersListDismissal, teams: teamsListDismissal, apps: appsListDismissal };
      }
      if (!rule["required_pull_request_reviews"]["bypass_pull_request_allowances"]) {
        bypassPullRequestAllowances = { users: [], teams: [], apps: [] };
      } else {
        const list = rule["required_pull_request_reviews"]["bypass_pull_request_allowances"];
        bypassPullRequestAllowances = { users: [], teams: [], apps: [] };
        const usersList = gettingListUsers(list.users);
        const teamsList = gettingListTeamsOrApps(list.teams);
        const appsList = gettingListTeamsOrApps(list.apps);
        bypassPullRequestAllowances = { users: usersList, teams: teamsList, apps: appsList };
      }

      setRequiredPullRequestReviews = {
        dismiss_stale_reviews: dismissStaleReviews,
        require_code_owner_reviews: requireCodeOwnerReviews,
        required_approving_review_count: requiredApprovingReviewCount,
        require_last_push_approval: requireLastPushApproval,
        bypass_pull_request_allowances: bypassPullRequestAllowances,
        dismissal_restrictions: dismissalRestrictions,
      };
    }

    //Setting required field "required_status_checks" for the autofix
    const requiredStatusChecks = rule["required_status_checks"];
    let setRequiredStatusChecks;
    if (!requiredStatusChecks) {
      setRequiredStatusChecks = null;
    } else {
      setRequiredStatusChecks =
        requiredStatusChecks["contexts"].length > 0 || requiredStatusChecks["checks"].length > 0 ? requiredStatusChecks : null;
    }

    const enforceAdmins = rule.enforce_admins ? rule.enforce_admins.enabled : false;
    let restrictions;
    if (!rule.restrictions) {
      restrictions = null;
    } else {
      const list = rule["restrictions"];
      const usersList = gettingListUsers(list.users);
      const teamsList = gettingListTeamsOrApps(list.teams);
      const appsList = gettingListTeamsOrApps(list.apps);
      restrictions = { users: usersList, teams: teamsList, apps: appsList };
    }
    let allowDeletions = rule["allow_deletions"];
    let allowForcePushes = rule["allow_force_pushes"];
    if (!allowDeletions) {
      allowDeletions = false;
    } else {
      allowDeletions = allowDeletions.enabled;
    }
    if (!allowForcePushes) {
      allowForcePushes = false;
    } else {
      allowForcePushes = allowForcePushes.enabled;
    }

    return new BranchProtectionRule(
      setRequiredPullRequestReviews,
      enforceAdmins,
      setRequiredStatusChecks,
      restrictions,
      allowDeletions,
      allowForcePushes,
    );
  } catch (e) {
    logger.error(`failed to create fixed rule for policy:${policyName}, err:${e}`);
  }
}

export function checkingListsValidForUpdate(fixedRule: BranchProtectionRule, policyName: string, repoName: string) {
  try {
    let isValidListsRestrictions = true;
    let isValidListsDismissal = true;
    let isValidListsBypassed = true;
    const restrictions = fixedRule.restrictions;
    if (!(restrictions === null)) {
      isValidListsRestrictions = restrictions["users"] && restrictions["teams"] && restrictions["apps"];
    }
    if (!(fixedRule.requiredPullRequestReviews === null)) {
      const dismissal = fixedRule.requiredPullRequestReviews[`dismissal_restrictions`];
      if (!(Object.keys(dismissal).length == 0)) {
        isValidListsDismissal = dismissal["users"] && dismissal["teams"] && dismissal["apps"];
      }
      const bypassed = fixedRule.requiredPullRequestReviews["bypass_pull_request_allowances"];
      isValidListsBypassed = bypassed["users"] && bypassed["teams"] && bypassed["apps"];
    }
    return isValidListsRestrictions && isValidListsDismissal && isValidListsBypassed;
  } catch (e) {
    logger.error(`Could not check if the lists of the fixed rule are valid, policy: ${policyName}, repo: ${repoName}`);
  }
}

export default policyLimitBranchDeletionsToAdmins;
