import pluralize from "pluralize";
import { Repo, repoResourceType, repoType, User } from "../../../entitis/codeRepoTypes";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { BranchProtectionRule, changedValues } from "../../../helper/service/auto-fix-service/updateBranchProtectionRule";
import { Input, InputOption, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
const logger = loggerImport.getDebugLogger();

export function isPolicyMainBranchDoesntRequireCodeReviewViolation(branchSettings: any) {
  try {
    const MRWithoutReviewEnabled = branchSettings.MRWithoutReviewEnabled;
    const pushEventsEnabled = branchSettings.pushEventEnabled;

    //False
    if (!MRWithoutReviewEnabled && !pushEventsEnabled) {
      return false;
    }
    //True
    if (MRWithoutReviewEnabled && pushEventsEnabled) {
      return true;
    }
    if (MRWithoutReviewEnabled && !pushEventsEnabled) {
      return true;
    }
    if (!MRWithoutReviewEnabled && pushEventsEnabled) {
      return true;
    }
  } catch (err) {
    logger.error(`failed isPolicyMainBranchDoesntRequireCodeReviewViolation, err: ${err}`);
  }
  return false;
}

class policyMainBranchDoesntRequireCodeReview extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      if (!jsonData.code_repo.realRepo) {
        return [];
      }

      const users = jsonData.users;
      const branchSettings = jsonData.branchSettings;
      const MRWithoutReviewEnabled = branchSettings.MRWithoutReviewEnabled;
      const pushEventsEnabled = branchSettings.pushEventEnabled;
      const branchProtection = branchSettings.branchProtection;
      const rule = branchSettings.rule;
      let pullOrMergeReq = "";
      const repo = jsonData.code_repo;
      const defaultBranchName = repo.defaultBranch;
      let fixLink = "";
      let pushFixLink = "";
      let mergeFixLink = "";

      const minBP = this.getValueFromRuleArgs("minBP");
      if (!minBP) {
        throw `minbp is not exist`;
      }

      if (!jsonData.code_repo.realRepo) {
        return [];
      }

      const gitType = jsonData.code_repo.type.toLowerCase();

      let shouldRunPolicy = false;

      switch (gitType) {
        case repoType.github:
          shouldRunPolicy = true;
          pullOrMergeReq = "pull";
          fixLink = repo.settingLink.concat("/branches");
          break;

        case repoType.gitlab:
          shouldRunPolicy = true;
          pullOrMergeReq = "merge";
          pushFixLink = `${repo.link}/-/settings/repository`;
          mergeFixLink = `${repo.link}/-/settings/merge_requests`;
          break;

        case repoType.bitbucket:
          pullOrMergeReq = "pull";
          shouldRunPolicy = true;
          fixLink = `${repo.link}/admin/branch-restrictions`;
          break;
      }

      if (!shouldRunPolicy) {
        return [];
      }

      //low BP - bail
      if (repo.repoImportance.total < minBP) {
        // if (isDevelopment()) {
        //   logger.info(`exit policy enforced branch due to min bp repo ${jsonData.code_repo.fullName} bp ${repo.repoImportance.total}`);
        // }

        return [];
      }

      if (!MRWithoutReviewEnabled && !pushEventsEnabled) {
        return [];
      }

      const adminRole = repo.gitRoles.repo.admin.toLowerCase();
      const orgAdminRole = repo.gitRoles.org.admin.toLowerCase();
      let userIssueOwner = this.getAdminWithMaxOperations(users as User[], adminRole, true);
      if (!userIssueOwner) {
        userIssueOwner = this.getAdminWithMaxOperations(jsonData.allUsers as User[], orgAdminRole);
      }
      if (!userIssueOwner) {
        userIssueOwner = { name: repo.ownerName, email: repo.ownerEmail || "" };
      }

      let issueName = "";
      let recommendation = "";
      let info = "";
      const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);

      if (MRWithoutReviewEnabled && pushEventsEnabled) {
        switch (gitType) {
          case repoType.github:
            issueName = `Code reviews may be bypassed via Push Events or ${this.capFirstLetter(
              pullOrMergeReq,
            )} Requests with no review enforcement`;

            info = `Code reviews for the ${defaultBranchName} branch may be bypassed via <br> <br>
                      &bull; Push Eventss (direct changes to the branch) <br>
                      &bull; ${this.capFirstLetter(pullOrMergeReq)} Requests with nso review or approval enforcement <br> <br>
             The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

            recommendation = `Ensure your repository is configured to block any push request to the ${defaultBranchName} branch. In addition, ensure that ${this.capFirstLetter(
              pullOrMergeReq,
            )} Requests require reviews. Follow the instructions below:<br>
              1. Enter the [link](${fixLink})<br>
              2. If you don't have any rule for ${defaultBranchName}<br>
                &bull; Click 'Add rule' and under 'Branch name pattern' type ${defaultBranchName} . Otherwise: <br>
                &bull; Click on 'Edit' for the rule applied to ${defaultBranchName} <br>
              3. Check the 'Require a pull request before merging' box <br>
              4. Under 'Require approvals' choose a number which is bigger than 0 <br>
              5. Check the box of 'Do not allow bypassing the above settings' <br>
              6. Do not check the box of 'Allow force pushes'`;
            break;

          case repoType.gitlab:
            issueName = `Code reviews may be bypassed via Push Events or ${this.capFirstLetter(
              pullOrMergeReq,
            )} Requests with no review enforcement`;

            info = `Code reviews for the ${defaultBranchName} branch may be bypassed via <br> <br>
                      &bull; Push Events (direct changes to the branch) <br>
                      &bull; ${this.capFirstLetter(pullOrMergeReq)} Requests with no review or approval enforcement <br> <br>
             The project was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

            let branchRecommendation = branchSettings.branchProtection
              ? `Under 'Protected branches':<br>
                  &bull; Find ${defaultBranchName} branch<br>
                  &bull; Change 'Allowed to push' to 'No one'`
              : `Under 'Protected branches':<br>
                  &bull; please protect ${defaultBranchName} branch<br>
                  &bull; Change 'Allowed to push' to 'No one'`;

            recommendation = `Ensure your project is configured to block any push request to the ${defaultBranchName} branch. In addition, ensure that ${this.capFirstLetter(
              pullOrMergeReq,
            )} Requests require reviews. Follow the instructions below:<br>
              1. Enter the [link](${pushFixLink})<br>
              2. ${branchRecommendation}<br>
              3. Enter the [link](${mergeFixLink})<br>
              4. Under 'Merge request approvals' change 'Approvals required' to a number greater than 0 <br>`;
            break;

          case repoType.bitbucket:
            issueName = `Code reviews may be bypassed via Push Events or ${this.capFirstLetter(
              pullOrMergeReq,
            )} Requests with no review enforcement`;

            info = `Code reviews for the ${defaultBranchName} branch may be bypassed via <br> <br>
                      &bull; Push Eventss (direct changes to the branch) <br>
                      &bull; ${this.capFirstLetter(pullOrMergeReq)} Requests with nso review or approval enforcement <br> <br>
             The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

            recommendation = `Ensure your repository is configured to block any push request to the ${defaultBranchName} branch. In addition, ensure that ${this.capFirstLetter(
              pullOrMergeReq,
            )} Requests require reviews. Follow the instructions below:<br>
              1. Enter the [link](${fixLink})<br>
              2. If you don't have any branch restriction for ${defaultBranchName}<br>
                &bull; Click 'Add branch restriction' and under 'By branch name or pattern' type ${defaultBranchName} . Otherwise: <br>
                &bull; Click on 'Edit' for the branch resrtiction applied to ${defaultBranchName} <br>
              3. Check the 'Only specific people or groups have write access' box and keep it on "Nobody has write access"<br>
              4. Under 'Merge settings' check the 'Minimum number of approvals' box and choose number of approvals required. <br>`;
            break;
        }
      }

      if (MRWithoutReviewEnabled && !pushEventsEnabled) {
        switch (gitType) {
          case repoType.github:
            issueName = `Code reviews may be bypassed via ${pullOrMergeReq} requests with no review enforcement`;
            info = `Code reviews for the ${defaultBranchName} branch may be bypassed via ${this.capFirstLetter(
              pullOrMergeReq,
            )} Requests with no review or approval enforcement <br> <br>
            The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

            recommendation = `Ensure your repository is configured to require reviews for ${this.capFirstLetter(
              pullOrMergeReq,
            )} Requests. Follow the instructions below: <br>
                1. Enter the [link](${fixLink}) <br>
                2. If you don't have any rule for ${defaultBranchName} <br>
                  &bull; click 'Add rule' and under 'Branch name pattern' type ${defaultBranchName} . Otherwise: <br>
                  &bull; Click on 'Edit' for the rule applied to ${defaultBranchName} <br>
                3. Check the 'Require a pull request before merging' box <br>
                4. Under 'Require approvals' fix the number to be greater than 0 <br>
                5. Check the box of 'Do not allow bypassing the above settings' <br>
                6. Do not check the box of 'Allow force pushes' <br>`;
            break;

          case repoType.gitlab:
            issueName = `Code reviews may be bypassed via ${this.capFirstLetter(pullOrMergeReq)} Requests with no review enforcement`;
            info = `Code reviews for the ${defaultBranchName} branch may be bypassed via ${this.capFirstLetter(
              pullOrMergeReq,
            )} Requests with no review or approval enforcement <br> <br>
            The project was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago `;

            recommendation = `Ensure your project is configured to require reviews for ${this.capFirstLetter(
              pullOrMergeReq,
            )} Requests. Follow the instructions below: <br>
                  1. Enter the [link](${mergeFixLink}) <br>
                  2. Under 'Merge request approvals': <br>
                    &bull; Find 'Approvals required' <br>
                    &bull; Change to a number greater than 0`;
            break;

          case repoType.bitbucket:
            issueName = `Code reviews may be bypassed via ${pullOrMergeReq} requests with no review enforcement`;
            info = `Code reviews for the ${defaultBranchName} branch may be bypassed via ${this.capFirstLetter(
              pullOrMergeReq,
            )} Requests with no review or approval enforcement <br> <br>
            The repository was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

            recommendation = `Ensure your repository is configured to require reviews for ${this.capFirstLetter(
              pullOrMergeReq,
            )} Requests. Follow the instructions below: <br>
                1. Enter the [link](${fixLink}) <br>
                2. If you don't have any rule for ${defaultBranchName} <br>
                  &bull; click 'Add branch restriction' and under 'Branch name pattern' type ${defaultBranchName}. Otherwise: <br>
                  &bull; Click on 'Edit' for the rule applied to ${defaultBranchName} <br>
                3. Under 'Merge settings' check the 'Minimum number of approvals' box and choose number of approvals required. <br>`;

            // replacing spaces for html fixes
            recommendation = recommendation.replaceAll("                ", "");
            break;
        }
      }

      if (!MRWithoutReviewEnabled && pushEventsEnabled) {
        switch (gitType) {
          case repoType.github:
            issueName = "Code reviews may be bypassed via push events";
            info = `Code reviews for the ${defaultBranchName} branch may be bypassed via push Events (direct changes to the branch) <br> <br>
             The repository was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago`;
            recommendation = `Ensure your repository is configured to block any push request to the ${defaultBranchName} branch. Follow the instructions below: <br>
            1. Enter the [link](${fixLink}) <br>
            2. If you don't have any rules for ${defaultBranchName} <br>
              &bull; Click 'Add rule' and under 'Branch name pattern' type ${defaultBranchName} . Otherwise: <br>
              &bull; Click on 'Edit' for the rule applied to ${defaultBranchName} <br>
            3. Check the box of 'Do not allow bypassing the above settings' <br>
            4. Do not check the box of 'Allow force pushes' <br>`;
            break;

          case repoType.gitlab:
            issueName = "Code reviews may be bypassed via push events";
            info = `Code reviews for the ${defaultBranchName} branch may be bypassed via push Events (direct changes to the branch) <br> <br>
             The project was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

            recommendation = `Ensure your project is configured to block any push request to the ${defaultBranchName} branch. Follow the instructions below: <br>
              1. Enter the [link](${pushFixLink}) <br>
              2. ${
                branchSettings.branchProtection
                  ? `Under 'Protected branches':<br>
                      &bull; Find ${defaultBranchName} branch<br>
                      &bull; Change 'Allowed to push' to 'No one'`
                  : `Under 'Protected branches':<br>
                      &bull; please protect ${defaultBranchName} branch<br>
                      &bull; Change 'Allowed to push' to 'No one' <br>`
              }`;
            break;

          case repoType.bitbucket:
            issueName = "Code reviews may be bypassed via push events";
            info = `Code reviews for the ${defaultBranchName} branch may be bypassed via push Events (direct changes to the branch) <br> <br>
              The repository was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago`;
            recommendation = `Ensure your repository is configured to block any push request to the ${defaultBranchName} branch. Follow the instructions below: <br>
            1. Enter the [link](${fixLink}) <br>
            2. If you don't have any rules for ${defaultBranchName} <br>
              &bull; Click 'Add branch restriction' and under 'Branch name pattern' type ${defaultBranchName} . Otherwise: <br>
              &bull; Click on 'Edit' for the rule applied to ${defaultBranchName} <br>
            3. Check the 'Only specific people or groups have write access' box and keep it on "Nobody has write access"<br>`;
            break;
        }
      }

      switch (gitType) {
        case repoType.github:
        case repoType.bitbucket:
          info = `${info}
          Repositories without protected branches: ${StatesHelper.Instance.reposMainBranchDoesntRequireCodeReviewViolationCount} <br>
          Repositories with protected branches: ${StatesHelper.Instance.noReposMainBranchDoesntRequireCodeReviewViolationCount}`;
          break;

        case repoType.gitlab:
          info = `${info}
          Projects without protected branches: ${StatesHelper.Instance.reposMainBranchDoesntRequireCodeReviewViolationCount} <br>
          Projects with protected branches: ${StatesHelper.Instance.noReposMainBranchDoesntRequireCodeReviewViolationCount}`;
          break;
      }

      recommendation;

      const item = this.generateItemForReport(
        true,
        issueName,
        info,
        `${issueName} This check applies to the ${defaultBranchName} branch only`,
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
        const fixedRule = createFixedRule(rule, branchProtection);

        item.fixes = this.generateFixes(repo, defaultBranchName, fixedRule, this.policyRuleMetadata.name, branchProtection);
      }

      return [item];
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
    return [];
  }

  capFirstLetter(word) {
    try {
      return word[0].toUpperCase() + word.slice(1);
    } catch (err) {
      logger.error(`function 'capFirstLetter' failed with word: ${word}, err: ${err}`);
    }
  }

  generateFixes(repo: Repo, branch: string, fixedRule: BranchProtectionRule, policyName: string, hasRule: boolean) {
    try {
      if (!fixedRule || !fixedRule.requiredPullRequestReviews) {
        return;
      }

      if (!checkingListsValidForUpdate(fixedRule, this.policyRuleMetadata.name, repo.fullName)) {
        return;
      }

      const p: PolicyFix = new PolicyFix();
      p.description = "This action will enable branch protection with code review requirements (reviewers required and no push events).";
      p.settingType = SettingType.setRepoBranchProtectionUnReviewedCode;
      p.confirmation =
        "After this fix, the branch protection rule will require at least 1 reviewer and will prevent direct pushes to the branch";
      p.tooltip = "Enable or update branch protection";

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
        changedValues: [changedValues.RequiredApprovingReviewCount],
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
}
function createFixedRule(rule, branchProtection: boolean) {
  try {
    if (!branchProtection) {
      const requiredPullRequestReviews = {
        dismiss_stale_reviews: false,
        require_code_owner_reviews: false,
        required_approving_review_count: 1,
        require_last_push_approval: false,
        bypass_pull_request_allowances: { users: [], teams: [], apps: [] },
        dismissal_restrictions: {},
      };
      return new BranchProtectionRule(requiredPullRequestReviews, null, null, null, false, null);
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
      const requiredApprovingReviewCount =
        rule.hasOwnProperty("required_pull_request_reviews") && rule["required_pull_request_reviews"]["required_approving_review_count"] > 0
          ? rule["required_pull_request_reviews"]["required_approving_review_count"]
          : 1;
      let bypassPullRequestAllowances = { users: [], teams: [], apps: [] };
      let dismissalRestrictions = {};

      if (!rule.hasOwnProperty("required_pull_request_reviews")) {
        dismissalRestrictions = {};
        bypassPullRequestAllowances = { users: [], teams: [], apps: [] };
      } else {
        if (rule["required_pull_request_reviews"]["dismissal_restrictions"]) {
          const usersList = gettingListUsers(rule["required_pull_request_reviews"]["dismissal_restrictions"].users);
          const teamsList = gettingListUsers(rule["required_pull_request_reviews"]["dismissal_restrictions"].teams);
          const appsList = gettingListUsers(rule["required_pull_request_reviews"]["dismissal_restrictions"].apps);
          dismissalRestrictions = {
            users: usersList,
            teams: teamsList,
            apps: appsList,
          };
        }
        if (rule["required_pull_request_reviews"]["bypass_pull_request_allowances"]) {
          const usersList = gettingListUsers(rule["required_pull_request_reviews"]["bypass_pull_request_allowances"].users);
          const teamsList = gettingListTeamsOrApps(rule["required_pull_request_reviews"]["bypass_pull_request_allowances"].teams);
          const appsList = gettingListTeamsOrApps(rule["required_pull_request_reviews"]["bypass_pull_request_allowances"].apps);
          bypassPullRequestAllowances = {
            users: usersList,
            teams: teamsList,
            apps: appsList,
          };
        }
      }

      const setRequiredPullRequestReviews = {
        dismiss_stale_reviews: dismissStaleReviews,
        require_code_owner_reviews: requireCodeOwnerReviews,
        required_approving_review_count: requiredApprovingReviewCount,
        require_last_push_approval: requireLastPushApproval,
        bypass_pull_request_allowances: bypassPullRequestAllowances,
        dismissal_restrictions: dismissalRestrictions,
      };

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
        const usersList = gettingListUsers(rule["restrictions"].users);
        const teamsList = gettingListTeamsOrApps(rule["restrictions"].teams);
        const appsList = gettingListTeamsOrApps(rule["restrictions"].apps);
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
    }
  } catch (e) {
    logger.error(`failed to create fixed rule for policy:${this.policyRuleMetadata.name}, err:${e}`);
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

export function checkingListsValidForUpdate(fixedRule: BranchProtectionRule, policyName: string, repoName: string) {
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
    logger.error(`Could not check if the lists of the fixed rule are valid, policy: ${policyName}, repo: ${repoName}`);
  }
}
export default policyMainBranchDoesntRequireCodeReview;
