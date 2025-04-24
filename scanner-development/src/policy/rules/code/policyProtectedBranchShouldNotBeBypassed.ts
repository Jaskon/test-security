import pluralize from "pluralize";
import { AffiliationType, Repo, repoResourceType, repoType, User } from "../../../entitis/codeRepoTypes";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { BranchProtectionRule, changedValues, updateOption } from "../../../helper/service/auto-fix-service/updateBranchProtectionRule";
import { Input, InputOption, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { AdminsAggItem } from "./policyDspmMaxAdmins";
import { gettingListTeamsOrApps, gettingListUsers } from "./policyMainBranchDoesntRequireCodeReview";
import PolicyRulesBase from "./policyRulesBase";
const logger = loggerImport.getDebugLogger();

class policyProtectedBranchShouldNotBeBypassed extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      // run policy only if git type is supported
      if (!jsonData.code_repo.realRepo || jsonData.code_repo.type.toLowerCase() !== repoType.github) {
        return [];
      }

      const repo = jsonData.code_repo;
      const users = jsonData.users;
      const admins = users.filter(i => i.repoRolesRaw.includes("admin"));
      const branchSettings = jsonData.branchSettings;
      const isBranchProtection = branchSettings.branchProtection;
      const selectedOptionForAutoFix = this.getValueFromRuleArgs("UncheckBothOrOne");
      let rule = branchSettings.rule;
      const orgName = jsonData.code_repo.organization;
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);

      // if there was no branch protection rule at all or no rule regarding code reviews , we are not violating
      if (!isBranchProtection || branchSettings.MRWithoutReviewEnabled) {
        return [];
      }

      const dissmisalRestrictions = branchSettings.dissmisalRestrictions;
      const bypassPullReqAllowances = branchSettings.bypassPullReqAllowances;
      const bypassUsers = bypassPullReqAllowances.users ? bypassPullReqAllowances.users : [];

      const dismissalUsers = dissmisalRestrictions.users ? dissmisalRestrictions.users : [];

      // filtering the admins since they can bypass
      const adminNames = admins.map(i => i.name);
      const filteredBypassUsers = bypassUsers.filter(i => !adminNames.includes(i.login));

      const commonUserPrefixSuffix = Object.keys(StatesHelper.Instance.commonUserPrefixSuffix);

      // filtering the outside collaborators
      const bypassUsersWithoutOC = [];
      for (const bypassedUser of filteredBypassUsers) {
        const user = users.filter(i => i.name === bypassedUser.login)[0];
        if (!user) {
          continue;
        }
        if (user.affiliation.has(AffiliationType.outside)) {
          const partOfCommon = commonUserPrefixSuffix.find(i => user.username.startsWith(i) || user.username.endsWith(i));
          if (!partOfCommon) {
            continue;
          }
        }
        bypassUsersWithoutOC.push(user);
      }

      const filteredBypassLength = bypassUsersWithoutOC.length;
      const filteredDismissalUsers = dismissalUsers.filter(i => !adminNames.includes(i.login));

      const dismissalWithoutOC = [];
      for (const dismissalUser of filteredDismissalUsers) {
        const user = users.filter(i => i.name === dismissalUser.login)[0];
        if (!user) {
          continue;
        }
        if (user.affiliation.has(AffiliationType.outside)) {
          const partOfCommon = commonUserPrefixSuffix.find(i => user.username.startsWith(i) || user.username.endsWith(i));
          if (!partOfCommon) {
            continue;
          }
        }
        dismissalWithoutOC.push(user);
      }
      const filteredDismissalLength = dismissalWithoutOC.length;

      const combinedBypassedUsers = [...bypassUsersWithoutOC, ...dismissalWithoutOC];

      // if there is no bypass violations at all
      if (combinedBypassedUsers.length == 0) {
        return [];
      }

      const data = [];
      const usersWithoutDup = [];
      for (const user of combinedBypassedUsers) {
        // pass duplicates
        if (usersWithoutDup.includes(user.name)) {
          continue;
        }
        usersWithoutDup.push(user.name);

        const item: AdminsAggItem = new AdminsAggItem();
        item.user = user.name;
        item.userInfo = user;
        item.userAvatar = user.avatarUrl;
        item.userLink = user.htmlLink;
        item.orgRole = Array.from(user.orgRole).join(", ");
        item.repoPermissions = this.handlePermissionsDisplay(user.repoRolesRaw);
        item.earliestActivityDate = user.createdAtDate ? user.createdAtDate.toString() : "";
        if (auditLogsAvailable) {
          if (user.foundAdminDataRepo) {
            item.adminOperation = this.getUserActivityBasedPretty(user.adminOperationRepo, user.adminOperationDateRepo);
            item.adminLocation = user.adminLocationRepo;
            item.adminOperationDate = user.adminOperationDateRepo.toString();
          } else {
            item.adminOperation = "No Activity";
            item.lastAdminOperation = "No Activity";
          }
        }
        if (user.foundDevDataRepo) {
          item.devOperation = this.getUserActivityBasedPretty(user.devOperationRepo, user.devOperationDateRepo);
          item.devOperationDate = user.devOperationDateRepo.toString();
        }

        if (user.foundReviewDataRepo) {
          item.reviewOperation = this.getUserActivityBasedPretty(user.reviewOperationRepo, user.reviewOperationDateRepo);
          item.reviewOperationDate = user.reviewOperationDateRepo.toString();
        }

        item.earliestActivityDate = user.lastActivityData ? user.lastActivityData.toString() : "";

        item.setAggId();
        data.push(item);
      }

      if (data.length == 0) {
        return [];
      }

      const aggregated = {
        columns: "policyProtectedBranchShouldNotBeBypassed",
        aggregatedItems: data,
      };

      const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);
      let issueDesc = `The following bypass settings have ${data.length} ${
        data.length == 1 ? "user" : "users"
      } attached to them: <br> <br>`;

      issueDesc = filteredBypassLength == 0 ? issueDesc : issueDesc + `&bull; Allow specified actors to bypass required pull requests <br>`;
      issueDesc =
        filteredDismissalLength == 0
          ? issueDesc
          : issueDesc + `&bull; Specify people, teams, or apps allowed to dismiss pull request reviews <br>`;

      issueDesc = issueDesc + `<br` + `The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

      const defaultBranchName = repo.defaultBranch;
      const fixLink = repo.settingLink.concat("/branches");
      const adminRole = repo.gitRoles.repo.admin.toLowerCase();
      const orgAdminRole = repo.gitRoles.org.admin.toLowerCase();
      let userIssueOwner = this.getAdminWithMaxOperations(users as User[], adminRole, true);
      if (!userIssueOwner) {
        userIssueOwner = this.getAdminWithMaxOperations(jsonData.allUsers as User[], orgAdminRole);
      }
      if (!userIssueOwner) {
        userIssueOwner = { name: repo.ownerName, email: repo.ownerEmail || "" };
      }

      const issueName = `Users can bypass branch protection reviews: ${data.length} ${data.length == 1 ? "user" : "users"}`;

      let recommendation = `It is highly recommended that the repo branch protection code reviews not be bypassed by users. Please remove the users from the following settings: <br>
      1. Enter the [link](${fixLink}) <br>
      2. Click on 'Edit' for the rule applied to ${defaultBranchName} <br>
`;
      recommendation =
        filteredBypassLength == 0
          ? recommendation
          : recommendation +
            `       3. Under "Require a pull request before merging" box, remove the users specified under "Allow specified actors to bypass required pull requests" box <br>`;
      if (filteredBypassLength == 0) {
        recommendation =
          filteredDismissalLength == 0
            ? recommendation
            : recommendation +
              `      3. Under "Require a pull request before merging" box, remove the users specified under "Restrict who can dismiss pull request reviews" box`;
      } else {
        recommendation =
          filteredDismissalLength == 0
            ? recommendation
            : recommendation +
              `<br>      4. Under the "Require a pull request before merging" box, remove the users specified under "Restrict who can dismiss pull request reviews" box`;
      }

      const item = this.generateItemForReport(
        true,
        issueName,
        issueDesc,
        issueDesc,
        recommendation,
        "N/A",
        "N/A",
        "",
        "",
        true,
        fixLink,
        aggregated,
        [Constant.gitPosture],
        [repoResourceType.branchSettings, repoResourceType.users],
        [],
        this.getCustomIssueId(`${repo.type}_${repo.name}`),
        [userIssueOwner],
      );
      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        const fixedRule = creatingFixedRule(rule, this.policyRuleMetadata.name, selectedOptionForAutoFix);

        item.fixes = generateFixes(
          repo,
          defaultBranchName,
          fixedRule,
          this.policyRuleMetadata.name,
          selectedOptionForAutoFix,
          isBranchProtection,
        );
      }
      return [item];
    } catch (e) {
      const repoName = jsonData.code_repo.fullName;
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}, repo: ${repoName}`);
    }
    return [];
  }
}

export function generateFixes(
  repo: Repo,
  branch: string,
  fixedRule: BranchProtectionRule,
  policyName: string,
  additionalArg: string,
  hasRule: boolean,
) {
  try {
    let changedVals = [];

    if (!fixedRule || !fixedRule.requiredPullRequestReviews) {
      return;
    }
    if (!checkingListsValidForUpdate(fixedRule, policyName)) {
      return;
    }

    if (additionalArg === updateOption.RemovingBoth)
      changedVals = [changedValues.DismissalRestrictions, changedValues.BypassPullRequestAllowances];
    else if (additionalArg === updateOption.RemovingDismissal) changedVals = [changedValues.DismissalRestrictions];
    else changedVals = [changedValues.BypassPullRequestAllowances];

    const p: PolicyFix = new PolicyFix();
    p.description = "This action will not allow the review requirement in the protected branch to be bypassed";
    p.settingType = SettingType.setRepoBranchProtectionUnReviewedCode;
    p.confirmation = "After the fix, review requirements will not have the bypass option selected.";
    p.tooltip = "disable reviews bypassing options";

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
      changedValues: changedVals,
      hasRule: hasRule,
      policyName: policyName,
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

export function creatingFixedRule(rule, policyName, selectedOptionForAutoFix) {
  try {
    let setRequiredPullRequestReviews;
    let dismissalRestrictions = {};
    let bypassPullRequestAllowances = { users: [], teams: [], apps: [] };
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
      const usersList = gettingListUsers(rule["restrictions"].users);
      const teamsList = gettingListTeamsOrApps(rule["restrictions"].teams);
      const appsList = gettingListTeamsOrApps(rule["restrictions"].apps);
      restrictions = { users: usersList, teams: teamsList, apps: appsList };
    }

    if (selectedOptionForAutoFix === updateOption.RemovingBoth) {
      dismissalRestrictions = {};
      bypassPullRequestAllowances = { users: [], teams: [], apps: [] };
    } else if (selectedOptionForAutoFix === updateOption.RemovingDismissal) {
      dismissalRestrictions = {};
      if (!rule["required_pull_request_reviews"]["bypass_pull_request_allowances"]) {
        bypassPullRequestAllowances = { users: [], teams: [], apps: [] };
      } else {
        const list = rule["required_pull_request_reviews"]["bypass_pull_request_allowances"];
        const usersList = gettingListUsers(list.users);
        const teamsList = gettingListTeamsOrApps(list.teams);
        const appsList = gettingListTeamsOrApps(list.apps);
        bypassPullRequestAllowances = {
          users: usersList,
          teams: teamsList,
          apps: appsList,
        };
      }
    } else {
      bypassPullRequestAllowances = { users: [], teams: [], apps: [] };
      if (!rule["required_pull_request_reviews"]["dismissal_restrictions"]) {
        dismissalRestrictions = {};
      } else {
        const list = rule["required_pull_request_reviews"]["dismissal_restrictions"];
        const usersListDismissal = gettingListUsers(list.users);
        const teamsListDismissal = gettingListTeamsOrApps(list.teams);
        const appsListDismissal = gettingListTeamsOrApps(list.apps);
        dismissalRestrictions = {
          users: usersListDismissal,
          teams: teamsListDismissal,
          apps: appsListDismissal,
        };
      }
    }

    setRequiredPullRequestReviews = {
      dismiss_stale_reviews: dismissStaleReviews,
      require_code_owner_reviews: requireCodeOwnerReviews,
      required_approving_review_count: requiredApprovingReviewCount,
      require_last_push_approval: requireLastPushApproval,
      bypass_pull_request_allowances: bypassPullRequestAllowances,
      dismissal_restrictions: dismissalRestrictions,
    };

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

export function checkingListsValidForUpdate(fixedRule: BranchProtectionRule, policyName: string) {
  try {
    let isValidListsRestrictions = true;
    let isValidListsDismissal = true;
    let isValidListsBypassed = true;
    const restrictions = fixedRule.restrictions;
    if (!(restrictions === null)) {
      isValidListsRestrictions = restrictions["users"] && restrictions["teams"] && restrictions["apps"];
    }
    if (fixedRule.requiredPullRequestReviews) {
      const dismissal = fixedRule.requiredPullRequestReviews["dismissal_restrictions"];
      if (!(Object.keys(dismissal).length == 0)) {
        isValidListsDismissal = dismissal["users"] && dismissal["teams"] && dismissal["apps"];
      }
      const bypassed = fixedRule.requiredPullRequestReviews["bypass_pull_request_allowances"];
      isValidListsBypassed = bypassed["users"] && bypassed["teams"] && bypassed["apps"];
    }
    return isValidListsRestrictions && isValidListsDismissal && isValidListsBypassed;
  } catch (e) {
    logger.error(`Could not check if the lists of the fixed rule are valid, policy: ${policyName}`);
  }
}
export default policyProtectedBranchShouldNotBeBypassed;
