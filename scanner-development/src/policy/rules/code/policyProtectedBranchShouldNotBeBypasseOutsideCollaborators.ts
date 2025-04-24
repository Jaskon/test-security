import { AffiliationType, repoResourceType, repoType, User } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { AdminsAggItem } from "./policyDspmMaxAdmins";
import { creatingFixedRule, generateFixes } from "./policyProtectedBranchShouldNotBeBypassed";
import PolicyRulesBase from "./policyRulesBase";
import pluralize from "pluralize";
const logger = loggerImport.getDebugLogger();

class policyProtectedBranchShouldNotBeBypassedOutsideCollaborators extends PolicyRulesBase {
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
      const orgName = jsonData.code_repo.organization;
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);

      // if there was no branch protection rule at all or no rule regarding code reviews , we are not violating
      if (!isBranchProtection || branchSettings.MRWithoutReviewEnabled) {
        return [];
      }

      const commonUserPrefixSuffix = Object.keys(StatesHelper.Instance.commonUserPrefixSuffix);

      const dissmisalRestrictions = branchSettings.dissmisalRestrictions;
      const bypassPullReqAllowances = branchSettings.bypassPullReqAllowances;
      const bypassUsers = bypassPullReqAllowances.users ? bypassPullReqAllowances.users : [];

      const dismissalUsers = dissmisalRestrictions.users ? dissmisalRestrictions.users : [];

      // filtering the admins since they can bypass
      const adminNames = admins.map(i => i.name);
      const filteredBypassUsers = bypassUsers.filter(i => !adminNames.includes(i.login));
      const bypassOutsideCollaborators = [];
      for (const bypassedUser of filteredBypassUsers) {
        const user = users.filter(i => i.name === bypassedUser.login)[0];
        if (!user) {
          continue;
        }
        if (!user.affiliation.has(AffiliationType.outside)) {
          continue;
        }
        if (user.affiliation.has(AffiliationType.outside)) {
          const partOfCommon = commonUserPrefixSuffix.find(i => user.username.startsWith(i) || user.username.endsWith(i));
          if (partOfCommon) {
            continue;
          }
        }
        bypassOutsideCollaborators.push(user);
      }
      const filteredBypassLength = bypassOutsideCollaborators.length;

      const filteredDismissalUsers = dismissalUsers.filter(i => !adminNames.includes(i.login));

      const dismissalOutsideCollaborators = [];
      for (const dismissalUser of filteredDismissalUsers) {
        const user = users.filter(i => i.name === dismissalUser.login)[0];
        if (!user) {
          continue;
        }
        if (!user.affiliation.has(AffiliationType.outside)) {
          continue;
        }
        if (user.affiliation.has(AffiliationType.outside)) {
          const partOfCommon = commonUserPrefixSuffix.find(i => user.username.startsWith(i) || user.username.endsWith(i));
          if (partOfCommon) {
            continue;
          }
        }
        dismissalOutsideCollaborators.push(user);
      }

      const filteredDismissalLength = dismissalOutsideCollaborators.length;

      const combinedBypassedUsers = [...bypassOutsideCollaborators, ...dismissalOutsideCollaborators];

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
        columns: "policyProtectedBranchShouldNotBeBypassedOutsideCollaborators",
        aggregatedItems: data,
      };

      const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);
      let issueDesc = `The following bypass settings have ${data.length} ${
        data.length == 1 ? "outside collaborator" : "outside collaborators"
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

      const issueName = `Outside collaborators can bypass branch protection reviews: ${data.length} ${data.length == 1 ? "user" : "users"}`;

      let recommendation = `It is highly recommended that the repo branch protection code reviews not be bypassed by outside collaborators. Please remove the users from the following settings: <br>
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
              `<br>       4. Under the "Require a pull request before merging" box, remove the users specified under "Restrict who can dismiss pull request reviews" box`;
      }
      const selectedOptionForAutoFix = this.getValueFromRuleArgs("UncheckBothOrOne");
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
export default policyProtectedBranchShouldNotBeBypassedOutsideCollaborators;
