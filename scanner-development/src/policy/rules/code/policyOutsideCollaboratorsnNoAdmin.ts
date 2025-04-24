import pluralize from "pluralize";
import { AffiliationType, OrgRoles, Repo, repoResourceType, repoType, User } from "../../../entitis/codeRepoTypes";
import Constant, { SettingType } from "../../../entitis/constant";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { AdminsAggItem, generateFixesForUserRepoPermissions } from "./policyDspmMaxAdmins";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class PolicyOutsideCollaboratorsnNoAdmin extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      if (!jsonData.code_repo.realRepo) {
        return [];
      }

      const gitType = jsonData.code_repo.type.toLowerCase();
      const supportedGitTypes = ["github", "gitlab"];
      // run policy only if git type is supported
      if (!supportedGitTypes.includes(gitType)) {
        return [];
      }

      let type = "";
      const typeInfo = this.getValueFromRuleArgs("type")[0];
      if (typeInfo === undefined) {
        throw `typeInfo is not exist`;
      }

      // get correct role names for github org and repo level

      const orgAdminRole = jsonData.code_repo.gitRoles.org.admin.toLowerCase();
      const orgMaintainerRole = jsonData.code_repo.gitRoles.org.maintainer.toLowerCase();
      const repoAdminRole = jsonData.code_repo.gitRoles.repo.admin.toLowerCase();

      const isAdmin = typeInfo.toLowerCase() === "admin";

      if (typeInfo.toLowerCase() === "admin") {
        if (gitType === repoType.github) type = repoAdminRole;
        else if (gitType === repoType.gitlab) type = orgAdminRole;
      } else if (typeInfo.toLowerCase() === "maintainer") {
        type = orgMaintainerRole;
      }

      const repo: Repo = jsonData.code_repo;

      const commonUserPrefixSuffix = Object.keys(StatesHelper.Instance.commonUserPrefixSuffix);
      const orgName = jsonData.code_repo.organization;
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);
      let items: AdminsAggItem[] = [];
      for (const user of jsonData.users as User[]) {
        if (
          (gitType === repoType.github && user.affiliation.has(AffiliationType.outside) && user.repoRoleName.toLowerCase() === type) ||
          (gitType === repoType.gitlab &&
            (user.orgRole.size == 0 || user.orgRole.has(OrgRoles.COLLABORATORS)) &&
            user.repoRoleName.toLowerCase() === type)
        ) {
          const partOfCommon = commonUserPrefixSuffix.find(i => user.username.startsWith(i) || user.username.endsWith(i));
          if (partOfCommon) {
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
            if (user.foundAdminData) {
              item.adminOperation = this.getUserActivityBasedPretty(user.adminOperation, user.adminOperationDate);
              item.adminLocation = user.adminLocation;
              item.adminOperationDate = user.adminOperationDate.toString();
              item.lastAdminOperation = user.lastAdminOperation;
            } else {
              item.adminOperation = "No Activity";
              item.lastAdminOperation = "No Activity";
            }
          }

          if (user.foundDevData) {
            item.devOperation = this.getUserActivityBasedPretty(user.devOperation, user.devOperationDate);
            item.devOperationDate = user.devOperationDate.toString();
          }

          if (user.foundReviewData) {
            item.reviewOperation = this.getUserActivityBasedPretty(user.reviewOperation, user.reviewOperationDate);
            item.reviewOperationDate = user.reviewOperationDate.toString();
          }

          item.earliestActivityDate = user.lastActivityData ? user.lastActivityData.toString() : "";

          item.setAggId();
          items.push(item);
        }
      }

      if (items.length == 0) {
        return [];
      }

      const org = repo.isOrgRepo ? repo.organization : "";

      //Default
      let issueOwner;

      let userIssueOwner = this.getAdminWithMaxOperations(jsonData.users as User[], repoAdminRole, true);

      if (!userIssueOwner) {
        userIssueOwner = this.getAdminWithMaxOperations(jsonData.allUsers as User[], orgAdminRole);
      }

      if (!userIssueOwner) {
        issueOwner = { name: repo.ownerName, email: repo.ownerEmail || "" };
      } else {
        issueOwner = {
          name: userIssueOwner.name,
          email: userIssueOwner.email || "",
        };
      }
      //Sort alerts based on last activity
      const withLastActivity = items.filter(i => i.userInfo.lastActivityData);
      const withoutLastActivity = items.filter(i => !i.userInfo.lastActivityData);
      const withLastActivitySorted = withLastActivity.sort(
        (a, b) => b.userInfo.lastActivityData.getTime() - a.userInfo.lastActivityData.getTime(),
      );
      items = [...withLastActivitySorted, ...withoutLastActivity];

      const aggregated = {
        columns: "policyOutsideCollaboratorsnNoAdmin",
        aggregatedItems: items,
      };

      let fixLink = "";
      let newVi = "";
      let recommendation = "";
      let issueName = "";
      const outsideColNames = [];
      items.forEach(item => {
        outsideColNames.push(item.user);
      });

      const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);
      switch (gitType) {
        case "github":
          fixLink = `${repo.settingLink}/access?guidance_task=`;
          newVi = `There ${pluralize("is", items.length)} ${items.length} ${pluralize("oustide collaborator", items.length)}
           with ${typeInfo} access to this repository. Outside collaborators are not direct members ${
            org ? `of your: ${org} organization` : ""
          }. Please consider reducing their repository permissions to "write" at most. <br>
          The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

          recommendation = `Please downgrade outside collaborator repository permissions to "write"`;

          issueName = `Outside collaborators were found with repo ${typeInfo.toLowerCase()} permissions: ${items.length} ${pluralize(
            "user",
            items.length,
          )}`;

          break;

        case "gitlab":
          fixLink = `${repo.link}/-/project_members`;
          newVi = `There ${pluralize("is", items.length)} ${items.length} ${pluralize("oustide collaborator", items.length)}
           with ${type} access to this project. Outside collaborators are not direct members of
           your: ${org} top-level group. Please consider reducing their project role to Developer at most.
           The project was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

          recommendation = `Please downgrade ${outsideColNames.join(", ")} from ${type} to at most developer role`;

          issueName = `Outside collaborators were found with project ${type} permissions: ${items.length} ${pluralize(
            "user",
            items.length,
          )}`;

          break;
      }

      const res = [];
      const extraInfo = [];
      const item = this.generateItemForReport(
        true,
        issueName,
        newVi,
        newVi,
        recommendation,
        "Code Change",
        "Code Repository",
        "",
        [],
        true,
        fixLink,
        aggregated,
        [Constant.gitPosture],
        [repoResourceType.users],
        extraInfo,
        this.getCustomIssueId(`${jsonData.code_repo.type}`),
        [issueOwner],
      );

      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        item.fixes = generateFixesForUserRepoPermissions(
          items,
          repo,
          this.policyRuleMetadata,
          SettingType.changeRepoCollaboratorStatus,
          "",
          isAdmin
            ? "There are Outside Collaborators who are repository admins. Please consider downgrading or removing the users from the list below."
            : "There are Outside Collaborators who are repository maintainers. Please consider downgrading or removing the users from the list below.",
          -1,
          -1,
          jsonData.code_repo.type.toLowerCase(),
          auditLogsAvailable,
          type,
        );
      }

      res.push(item);
      return res;
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e},policy: ${this.policyRuleMetadata.functionName}`);
    }
    return [];
  }
}

export default PolicyOutsideCollaboratorsnNoAdmin;
