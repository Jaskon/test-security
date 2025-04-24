import pluralize from "pluralize";
import { Repo, repoType, resourceType, User } from "../../../entitis/codeRepoTypes";
import Constant, { SettingType } from "../../../entitis/constant";
import { Severity } from "../../../entitis/reportTypes";
import { ChangeReason, severityReasons } from "../../../entitis/service/blameTypes";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { AdminsAggItem, generateFixesForUserRepoPermissions } from "./policyDspmMaxAdmins";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class policyDspmRepoMaxAdmins extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      if (!jsonData.code_repo.realRepo) {
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

        case repoType.azureGit:
          shouldRunPolicy = true;
          break;
      }

      if (!shouldRunPolicy) {
        return [];
      }

      // get correct role names for github org and repo level
      const orgAdminRole = jsonData.code_repo.gitRoles.org.admin.toLowerCase();
      const repoAdminRole = jsonData.code_repo.gitRoles.repo.admin.toLowerCase();

      const res = [];
      const extraInfo = [];
      const minAdmins = this.getValueFromRuleArgs("minAdmins");
      const minAdminsPercentage = this.getValueFromRuleArgs("minAdminsPercentage");
      const ignoreInherited = this.getValueFromRuleArgs("ignoreOwners");
      // const ignoreInherited = false;

      let changedSeverity = this.policyRuleMetadata.severity;
      const changeReasons: ChangeReason[] = [];

      let directAdminsCount = 0;
      let adminsPlusInheritedCount = 0;
      let data = [];
      let inheritedAdmins = 0;

      const owners = jsonData.allUsers.filter(user => {
        const userOrgRoles = Array.from(user.orgRole) as string[];
        return userOrgRoles.find(i => i.toLowerCase() === orgAdminRole);
      });

      const orgName = jsonData.code_repo.organization;
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);

      if (!owners.length || !owners) {
        return [];
      }

      const admins: User[] = [];
      jsonData.users.forEach(user => {
        let repoRolesRaw = user.repoRolesRaw?.map(role => {
          return role?.toLowerCase();
        });
        if (repoRolesRaw?.includes(repoAdminRole)) {
          admins.push(user);
        }
      });

      let adminsNoOwners;

      switch (gitType) {
        case repoType.azureGit:
        case "github":
          adminsNoOwners = admins.filter(user => !user.orgRole.has("Owner"));
          if ((adminsNoOwners.length < 3 && ignoreInherited) || (!ignoreInherited && admins.length < 3)) {
            return [];
          }
          break;

        case "gitlab":
          const directAdmins = jsonData.users.filter(user => user.repoRoleName.toLowerCase() === repoAdminRole && !user.isOwnerInherited);
          if ((directAdmins < 3 && ignoreInherited) || (!ignoreInherited && admins.length < 3)) {
            return [];
          }

        case "bitbucket":
          adminsNoOwners = admins.filter(user => !user.orgRole.has("owner"));
          if ((adminsNoOwners.length < 3 && ignoreInherited) || (!ignoreInherited && admins.length < 3)) {
            return [];
          }
          break;
      }

      for (const user of jsonData.users as User[]) {
        const userOrgRoles = Array.from(user.orgRole) as string[];

        const isUserRepoAdmin = user.repoRoleName?.toLowerCase() === repoAdminRole;
        const isUserOrgAdmin = userOrgRoles.find(i => i.toLowerCase() === orgAdminRole);

        if (isUserRepoAdmin) {
          adminsPlusInheritedCount++;

          switch (gitType) {
            case repoType.azureGit:
            case "github":
            case "bitbucket":
              if (isUserOrgAdmin) {
                inheritedAdmins++;
                if (ignoreInherited) {
                  continue;
                }
              } else {
                directAdminsCount++;
              }
              break;

            case "gitlab":
              if (user.isOwnerInherited) {
                inheritedAdmins++;
                if (ignoreInherited) {
                  continue;
                }
              } else {
                directAdminsCount++;
              }
              break;

            // case "bitbucket":
            //   directAdminsCount++;
            //   break;
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
          data.push(item);
        }
      }

      const adminsCountForPolicy = ignoreInherited ? directAdminsCount : adminsPlusInheritedCount;
      const usersCountForPolicty = ignoreInherited ? jsonData.users.length - inheritedAdmins : jsonData.users.length;

      const ownersPercentage = Number(this.adminPercentageFromTotal(adminsCountForPolicy, usersCountForPolicty));

      const ownersPercaentageLimit = Number(this.limitPercentage(minAdminsPercentage, usersCountForPolicty).toFixed());

      const greaterMin = Math.max(minAdmins, ownersPercaentageLimit);

      if (adminsCountForPolicy <= greaterMin || directAdminsCount == 0) {
        return [];
      }

      if (ownersPercentage > 75) {
        changedSeverity = changedSeverity + 1;
        changeReasons.push(severityReasons.WayTooManyAdmins);
      }

      if (gitType === repoType.github) {
        if (jsonData.code_repo.isOrg2faEnabled === true) {
          changedSeverity = changedSeverity - 1;
          changeReasons.push(severityReasons.twoFactorOn);
        } else if (jsonData.code_repo.isOrg2faEnabled === false) {
          changeReasons.push(severityReasons.twoFactorOff);
        }
      }

      extraInfo.push({
        key: "Total Admins",
        value: `${adminsCountForPolicy}`,
      });
      extraInfo.push({
        key: "Total Users",
        value: `${usersCountForPolicty}`,
      });

      let issueOwner;

      let userIssueOwner = this.getAdminWithMaxOperations(jsonData.users as User[], repoAdminRole, true);

      if (!userIssueOwner) {
        userIssueOwner = this.getAdminWithMaxOperations(jsonData.allUsers as User[], orgAdminRole);
      }
      const repo: Repo = jsonData.code_repo;
      if (!userIssueOwner) {
        issueOwner = { name: repo.ownerName, email: repo.ownerEmail || "" };
      } else {
        issueOwner = {
          name: userIssueOwner.name,
          email: userIssueOwner.email || "",
        };
      }

      const withLastActivity = data.filter(i => i.userInfo.lastActivityData);
      const withoutLastActivity = data.filter(i => !i.userInfo.lastActivityData);
      const withLastActivitySorted = withLastActivity.sort(
        (a, b) => b.userInfo.lastActivityData.getTime() - a.userInfo.lastActivityData.getTime(),
      );
      data = [...withLastActivitySorted, ...withoutLastActivity];

      const aggregated = {
        columns: "policyDspmMaxAdmins",
        aggregatedItems: data,
      };

      let adminsAmountToRemove = directAdminsCount - greaterMin;
      if (!ignoreInherited) {
        adminsAmountToRemove = adminsPlusInheritedCount - greaterMin;
      }

      if (adminsAmountToRemove > directAdminsCount) {
        adminsAmountToRemove = directAdminsCount;
      }
      const repoName = jsonData.code_repo.name;
      const nonAdminUsersCount = usersCountForPolicty - adminsCountForPolicy;
      let issueName = "";
      let fixLink = "";
      let secondTitle = "";
      let recommendation = "";

      let note = "";

      switch (gitType) {
        case repoType.azureGit:
        case "github":
          const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);
          issueName = `Too many admins for repo: ${adminsCountForPolicy} admins (${ownersPercentage.toFixed()}% of all users)`;

          note = `Note: ${inheritedAdmins} organziation ${pluralize("owner", inheritedAdmins)} inherited admin rights to the repo and were${
            ignoreInherited ? " not " : " "
          }included in the calculation.`;

          fixLink = `${repo.link}/settings/access`;
          secondTitle = `There are too many admins assigned to manage repo ${repoName}.
             There are a total of ${adminsCountForPolicy} admins and ${nonAdminUsersCount} users who are not admins.
             Based on your policy settings you should have at most ${greaterMin} ${pluralize("admin", greaterMin)}. <br><br>
             ${note} <br>
             The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

          recommendation = `Ensure only relevant designated users are defined as an admin in your repo. In order to be in compliance of the policy you need to remove admin rights from ${adminsAmountToRemove} existing ${pluralize(
            "admin",
            adminsAmountToRemove,
          )} ${
            directAdminsCount == adminsAmountToRemove && adminsCountForPolicy - greaterMin != directAdminsCount
              ? `(we recommend to remove only ${directAdminsCount} ${pluralize("admin", directAdminsCount)} and not ${
                  adminsCountForPolicy - greaterMin
                } beacause there ${pluralize("is", directAdminsCount)} ${directAdminsCount} direct ${pluralize(
                  "admin",
                  directAdminsCount,
                )} and ${inheritedAdmins} owners that inherited their admin rights)`
              : ""
          }: <br> <br><pre>
          1. Enter the [link](${fixLink}) <br>
          2. Click the setting (cog) button and choose 'Change Role...' <br>
          3. Select the 'Member' option <br>
          4. Click the 'Change Role' button </pre>`;
          break;

        case "gitlab":
          issueName = `Too many owners for project: ${adminsCountForPolicy} owners (${ownersPercentage.toFixed()}% of all users)`;

          note = `Note: ${inheritedAdmins} upper level group ${pluralize(
            "owner",
            inheritedAdmins,
          )} inherited owner rights to the project and were${ignoreInherited ? " not " : " "}included in the calculation.`;

          fixLink = `${repo.link}/-/project_members`;

          secondTitle = `There are too many owners assigned to manage project ${repoName}.
             There are a total of ${adminsCountForPolicy} owners and ${nonAdminUsersCount} users who are not owners.
             Based on your policy settings you should have at most ${greaterMin} ${pluralize("owner", greaterMin)}. <br><br>
             ${note} <br>
             <br>
             The project was created at: ${repo.createdAt}.`;

          recommendation = `Ensure only relevant designated users are defined as an owner in your project. In order to be in compliance of the policy you need to remove owner rights from ${adminsAmountToRemove} existing ${pluralize(
            "owner",
            adminsAmountToRemove,
          )} ${
            directAdminsCount == adminsAmountToRemove && adminsCountForPolicy - greaterMin != directAdminsCount
              ? `(we recommend to remove only ${directAdminsCount} ${pluralize("owner", directAdminsCount)} and not ${
                  adminsCountForPolicy - greaterMin
                } beacause there ${pluralize("is", directAdminsCount)} ${directAdminsCount} direct ${directAdminsCount} ${pluralize(
                  "owner",
                  directAdminsCount,
                )} and ${inheritedAdmins} owners that inherited their role)`
              : ""
          }: <br> <br><pre>
          1. Enter the [link](${fixLink}) <br>
          2. Scroll down and find a 'Direct Member' that is an owner <br>
          3. Click the dropdown icon <br>
          4. Select a new role </pre>>`;
          break;

        case "bitbucket":
          issueName = `Too many admins for repository: ${adminsCountForPolicy} admins (${ownersPercentage.toFixed()}% of all users)`;

          note = `Note: ${inheritedAdmins} workspace ${pluralize("owner", inheritedAdmins)} inherited admin rights to the repo and were${
            ignoreInherited ? " not " : " "
          }included in the calculation.`;

          fixLink = `${repo.link}/admin/access`;

          secondTitle = `There are too many admins assigned to manage repository ${repoName}.
               There are a total of ${adminsCountForPolicy} admins and ${nonAdminUsersCount} users who are not admins.
               Based on your policy settings you should have at most ${greaterMin} ${pluralize("admin", greaterMin)}. <br><br>
               ${note} <br>
               <br>
               The repository was created at: ${repo.createdAt}.`;

          recommendation = `Ensure only relevant designated users are defined as an admin in your repo. In order to be in compliance of the policy you need to remove admin rights from ${adminsAmountToRemove} existing ${pluralize(
            "admin",
            adminsAmountToRemove,
          )} ${
            directAdminsCount == adminsAmountToRemove && adminsCountForPolicy - greaterMin != directAdminsCount
              ? `(we recommend to remove only ${directAdminsCount} ${pluralize("admin", directAdminsCount)} and not ${
                  adminsCountForPolicy - greaterMin
                } beacause there ${pluralize("is", directAdminsCount)} ${directAdminsCount} direct ${pluralize(
                  "admin",
                  directAdminsCount,
                )} and ${inheritedAdmins} admins that inherited their admin rights)`
              : ""
          }: <br> <br><pre>
          1. Enter the [link](${fixLink}) <br>
          2. Select permission groups with permission = Admin <br>
          3. Select users to remove (in order to keep them read/write permissions, make sure these users still members of other permission groups)</pre>`;
          break;
      }

      const item = this.generateItemForReport(
        true,
        issueName,
        secondTitle,
        "",
        recommendation,
        "Code Change",
        "Code Repository",
        "",
        [],
        true,
        fixLink,
        aggregated,
        [Constant.gitPosture],
        [resourceType.allUsers],
        extraInfo,
        this.getGeneralIssueId(),
        [issueOwner],
        "",
        "",
        [],
        "",
        [],
        changedSeverity,
        [],
        "",
        Severity[this.policyRuleMetadata.severity],
        ["Way too many admins", "75% of all users are admins"],
        getSeverityChanges(this.policyRuleMetadata.severity, changedSeverity),
        changeReasons,
      );

      let max = adminsCountForPolicy - greaterMin;

      if (data.length - max === 1) {
        max--;
      }

      const warning = `You must select at least ${max} admin${max == 1 ? "" : "s"} to be in compliance.`;
      const dataSortedByMinimalActivity = data.reverse();

      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        item.fixes = generateFixesForUserRepoPermissions(
          dataSortedByMinimalActivity,
          repo,
          this.policyRuleMetadata,
          SettingType.changeRepoCollaboratorStatus,
          warning,
          "There are too many admins for the repository. Please select admins to remove or downgrade from the list below.",
          max,
          1,
          jsonData.code_repo.type.toLowerCase(),
          auditLogsAvailable,
        );
      }

      res.push(item);

      return res;
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
    return [];
  }
}

export default policyDspmRepoMaxAdmins;
