import pluralize from "pluralize";
import { PushRole, Repo, repoResourceType, repoType, User } from "../../../entitis/codeRepoTypes";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { BranchProtectionRule, changedValues } from "../../../helper/service/auto-fix-service/updateBranchProtectionRule";
import { Input, InputOption, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { AdminsAggItem } from "./policyDspmMaxAdmins";
import { checkingListsValidForUpdate, gettingListTeamsOrApps, gettingListUsers } from "./policyMainBranchDoesntRequireCodeReview";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class policyProtectedBranchPushEventsNotBypassed extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      if (!jsonData.code_repo.realRepo) {
        return [];
      }

      const gitType = jsonData.code_repo.type.toLowerCase();
      const repo = jsonData.code_repo;

      let shouldRunPolicy = false;
      let fixLink;
      if (gitType === repoType.github) {
        fixLink = repo.settingLink.concat("/branches");
        shouldRunPolicy = true;
      }

      if (gitType === repoType.gitlab) {
        fixLink = `${repo.link}/-/settings/repository`;
        shouldRunPolicy = true;
      }

      if (!shouldRunPolicy) {
        return [];
      }

      const users = jsonData.users;
      const branchSettings = jsonData.branchSettings;
      const branchProtection = branchSettings.branchProtection;
      const pushEventsEnabled = branchSettings.pushEventEnabled;
      const pushRole = branchSettings.pushRole;

      if (!branchProtection) {
        return [];
      }

      const restrictions = branchSettings.restrictions;
      const admins = users.filter(i => i.repoRolesRaw.includes(jsonData.code_repo.gitRoles.repo.admin.toLowerCase()));
      const adminNames = admins.map(i => i.name);

      const orgName = jsonData.code_repo.organization;
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);

      let restrictionUsers = [];
      let relevantUsers = [];

      switch (gitType) {
        case repoType.github:
          if (pushEventsEnabled) {
            return [];
          }
          restrictionUsers = restrictions.users ? restrictions.users : [];
          relevantUsers = restrictionUsers.filter(i => !adminNames.includes(i.login));
          break;

        case repoType.gitlab:
          if (pushRole != PushRole.NONE) {
            return [];
          }
          relevantUsers = restrictions;
          break;
      }

      if (relevantUsers.length == 0) {
        return [];
      }

      const commonUserPrefixSuffix = Object.keys(StatesHelper.Instance.commonUserPrefixSuffix);

      const data = [];

      for (const bypassedUser of relevantUsers) {
        const user = this.getUserJson(bypassedUser, gitType, users);
        if (!user) {
          continue;
        }
        // if outside collaborator can bypass the rule, will pass

        const isOutsideCollaborator = this.checkOutsideCollaborator(user, gitType, commonUserPrefixSuffix);

        if (isOutsideCollaborator === undefined || isOutsideCollaborator) {
          continue;
        }

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

      const adminRole = repo.gitRoles.repo.admin.toLowerCase();
      const orgAdminRole = repo.gitRoles.org.admin.toLowerCase();
      let userIssueOwner = this.getAdminWithMaxOperations(users as User[], adminRole, true);
      if (!userIssueOwner) {
        userIssueOwner = this.getAdminWithMaxOperations(jsonData.allUsers as User[], orgAdminRole);
      }

      if (!userIssueOwner) {
        userIssueOwner = { name: repo.ownerName, email: repo.ownerEmail || "" };
      }

      const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);
      let issueName, recommendation, issueDesc;
      const defaultBranchName = repo.defaultBranch;
      switch (gitType) {
        case repoType.github:
          issueName = `Users can bypass branch protection push restrictions: ${data.length} ${pluralize("user", data.length)}`;
          recommendation = `It is highly recommended that the push event restriction not be bypassed by users. Please remove the users from the following settings: <br>
              1. Enter the [link](${fixLink}) <br>
              2. Click on 'Edit' for the rule applied to ${defaultBranchName} <br>
              3. Remove the users specified under "Restrict who can push to matching branches" box <br>`;

          issueDesc = `Branch protection in this repository is set to prevent direct pushes of code. However, there ${pluralize(
            "is",
            data.length,
          )} ${data.length} ${pluralize("user", data.length)} that can bypass this via the following setting:<br> <br>
              &bull; Restrict who can push to matching branches <br>
              The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;
          break;

        case repoType.gitlab:
          issueName = `Users can bypass branch protection push restrictions: ${data.length} ${pluralize("user", data.length)}`;
          recommendation = `It is highly recommended that push events will be disabled by any user. Please remove the users from the following settings: <br>
              1. Enter the [link](${fixLink}) <br>
              2. Under 'Protected branches' find ${defaultBranchName} branch <br>
              3. Change 'Allowed to push' to 'No one' without any additional users<br>`;

          issueDesc = `Branch protection in this project is set to prevent direct pushes of code. However, there ${pluralize(
            "is",
            data.length,
          )} ${data.length} ${pluralize("user", data.length)} that can bypass this via the following setting:<br> <br>
              &bull; Restrict who can push to the protected branch <br>
              The project was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;
          break;
      }

      const rule = branchSettings.rule;

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
        const fixedRule = creatingFixedRule(rule, this.policyRuleMetadata.name);

        item.fixes = generateFixes(repo, defaultBranchName, fixedRule, this.policyRuleMetadata.name, branchProtection);
      }
      return [item];
    } catch (e) {
      const repoName = jsonData.code_repo.fullName;
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}, repo: ${repoName}`);
    }
    return [];
  }
}

export function generateFixes(repo: Repo, branch: string, fixedRule: BranchProtectionRule, policyName: string, hasRule: boolean) {
  try {
    if (!fixedRule) {
      return;
    }

    if (!checkingListsValidForUpdate(fixedRule, policyName, repo.fullName)) {
      return;
    }

    const p: PolicyFix = new PolicyFix();
    p.description = "This action will not allow any users to directly push to the protected branch.";
    p.settingType = SettingType.setRepoBranchProtectionUnReviewedCode;
    p.tooltip = "Remove restrictions for pushing to the default branch";
    p.confirmation = "After this fix, direct pushes to the protected branch will be disabled for everyone";

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
      changedValues: [changedValues.Restrictions],
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
      null,
      allowDeletions,
      allowForcePushes,
    );
  } catch (e) {
    logger.error(`failed to create fixed rule for policy:${policyName}, err:${e}`);
  }
}

export default policyProtectedBranchPushEventsNotBypassed;
