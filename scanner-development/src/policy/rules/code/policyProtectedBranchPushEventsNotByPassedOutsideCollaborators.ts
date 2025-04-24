import { AffiliationType, OrgRoles, PushRole, Repo, repoResourceType, repoType, User } from "../../../entitis/codeRepoTypes";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import { AdminsAggItem } from "./policyDspmMaxAdmins";
import StatesHelper from "../../../helper/statesHelper";
import { creatingFixedRule, generateFixes } from "./policyProtectedBranchPushEventsNotBypassed";
import AutoFix from "../../../helper/service/auto-fix-service/auto-fix";
import pluralize from "pluralize";
import { isDevelopment } from "../../../helper/envUtils";
import Constant from "../../../entitis/constant";

const logger = loggerImport.getDebugLogger();

class policyProtectedBranchPushEventsNotBypassedOutsideCollaborators extends PolicyRulesBase {
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
      const orgName = jsonData.code_repo.organization;
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);

      const pushRole = branchSettings.pushRole;

      if (!branchProtection) {
        return [];
      }

      const restrictions = branchSettings.restrictions;
      const admins = users.filter(i => i.repoRolesRaw.includes(jsonData.code_repo.gitRoles.repo.admin.toLowerCase()));
      const adminNames = admins.map(i => i.name);
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
        // process only outside collaborators

        if (!this.checkOutsideCollaborator(user, gitType, commonUserPrefixSuffix)) {
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
        columns: "policyProtectedBranchPushEventsNotBypassedOutsideCollaborators",
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

      let issueName, recommendation, issueDesc;
      const defaultBranchName = repo.defaultBranch;
      const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);

      switch (gitType) {
        case repoType.github:
          issueName = `Outside collaborators can bypass branch protection push restrictions: ${data.length} ${pluralize(
            "user",
            data.length,
          )}`;
          recommendation = `It is highly recommended that the push event restriction not be bypassed by outside collaborators. Please remove the users from the following settings: <br>
              1. Enter the [link](${fixLink}) <br>
              2. Click on 'Edit' for the rule applied to ${defaultBranchName} <br>
              3. Remove the users specified under "Restrict who can push to matching branches" box <br>`;

          issueDesc = `Branch protection in this repository is set to prevent direct pushes of code. However, there ${pluralize(
            "is",
            data.length,
          )} ${data.length} ${pluralize("outside collaborator", data.length)} that can bypass this via the following setting:<br> <br>
              &bull; Restrict who can push to matching branches <br> <br>
              The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;
          break;

        case repoType.gitlab:
          issueName = `Outside collaborators can bypass branch protection push restrictions: ${data.length} ${pluralize(
            "user",
            data.length,
          )}`;
          recommendation = `It is highly recommended that push events will be disabled for outside collaborators. Please remove the users from the following settings: <br>
              1. Enter the [link](${fixLink}) <br>
              2. Under 'Protected branches' find ${defaultBranchName} branch <br>
              3. Change 'Allowed to push' to 'No one' without any additional users<br>`;

          issueDesc = `Branch protection in this project is set to prevent direct pushes of code. However, there ${pluralize(
            "is",
            data.length,
          )} ${data.length} ${pluralize("outside collaborator", data.length)} that can bypass this via the following setting:<br> <br>
              &bull; Restrict who can push to the protected branch <br> <br>
              The project was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.
              `;
          break;
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
      const rule = branchSettings.rule;
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

export default policyProtectedBranchPushEventsNotBypassedOutsideCollaborators;
