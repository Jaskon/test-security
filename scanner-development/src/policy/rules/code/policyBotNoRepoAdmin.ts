import pluralize from "pluralize";
import { Repo, repoResourceType, repoType, User } from "../../../entitis/codeRepoTypes";
import Constant, { SettingType } from "../../../entitis/constant";
import { Severity } from "../../../entitis/reportTypes";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { AdminsAggItem, generateFixesForUserRepoPermissions } from "./policyDspmMaxAdmins";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class policyBotNoRepoAdmin extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      if (!jsonData.code_repo.realRepo || !jsonData.users.length) {
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
      const repo: Repo = jsonData.code_repo;
      const orgName = jsonData.code_repo.organization;
      const repoAdminRole = repo.gitRoles.repo.admin.toLowerCase();
      const orgAdminRole = repo.gitRoles.org.admin.toLowerCase();

      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);
      const baselineCount = this.getValueFromRuleArgs("baselineCount");
      if (!baselineCount) {
        throw "cannot find baselineCount";
      }

      const botStrings = this.getValueFromRuleArgs("botSubStrings");
      const ignoreIfAdminActivity = this.getValueFromRuleArgs("ignoreIfAdminActivity");

      let data = [];
      const botIds = [];
      const extraInfo = [];

      let changedSeverity = this.policyRuleMetadata.severity;
      let changeReason = null;
      let admins = 0;

      for (const user of jsonData.users as User[]) {
        if (baselineCount <= user.repoThatTheUserIsAdmin) {
          continue;
        }

        let userOrgRoles = Array.from(user.orgRole) as string[];
        userOrgRoles = userOrgRoles.map(i => i.toLowerCase());

        let isInherited = false;
        if (user.repoRolesRaw.find(i => i?.toLowerCase() === repoAdminRole)) {
          switch (gitType) {
            case repoType.azureGit:
            case repoType.bitbucket:
            case repoType.github:
              isInherited = userOrgRoles.includes(orgAdminRole);
              break;

            case repoType.gitlab:
              isInherited = user.isOwnerInherited;
              break;
          }

          if (!isInherited) {
            admins++;
            if (!this.isPossibleBot(user, botStrings)) {
              continue;
            }

            if (ignoreIfAdminActivity && user.foundAdminData) {
              continue;
            }

            botIds.push(user.id);
            const item: AdminsAggItem = new AdminsAggItem();
            item.user = user.name;
            item.userInfo = user;
            item.userAvatar = user.avatarUrl;
            item.userLink = user.htmlLink;
            if (user.orgRole.size == 0) {
              userOrgRoles.push("Outside Collaborator");
            }
            item.orgRole = Array.from(userOrgRoles).join(", ");
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

            item.earliestActivityDate = user.lastActivityData ? user.lastActivityData.toString() : "";

            item.setAggId();
            data.push(item);
          }
        }
      }

      if (data.length === 0) {
        return [];
      }

      extraInfo.push({
        key: "Total Admins",
        value: `${admins}`,
      });
      extraInfo.push({
        key: "Total Users",
        value: `${jsonData.users.length}`,
      });
      extraInfo.push({
        key: "Bot Admins",
        value: `${data.length}`,
      });

      const allRepoUsersWithouotBots = jsonData.users.filter(u => !botIds.includes(u.id));
      const allOrgUsersWithouotBots = jsonData.allUsers.filter(u => !botIds.includes(u.id));
      let issueOwner;
      let userIssueOwner = this.getAdminWithMaxOperations(allRepoUsersWithouotBots as User[], repoAdminRole, true);

      if (!userIssueOwner) {
        userIssueOwner = this.getAdminWithMaxOperations(allOrgUsersWithouotBots as User[], orgAdminRole);
      }

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
        columns: "policyBotNoRepoAdmin",
        aggregatedItems: data,
      };

      let issueName = "";
      let fixLink = "";
      let secondTitle = "";
      let recommendation = "";
      switch (gitType) {
        case repoType.github:
          issueName = `Bot users were found with repo admin permissions: ${data.length} bot ${pluralize("user", data.length)}`;

          fixLink = `${repo.link}/settings/access`;

          secondTitle = `There ${pluralize("is", data.length)} ${data.length} ${pluralize("bot users", data.length)}
          with admin access to this repository. Bot users are not real users of your organization.
          Please consider reducing their repository permissions to “write” at most. <br>
          The repository was created at: ${repo.createdAt}.`;

          recommendation = `Please downgrade ${pluralize("bot users", data.length)} repository permissions to “write”: <br>
             1. Enter the [link](${fixLink}) <br>
             2. Click the setting (cog) button and choose 'Change Role...' <br>
             3. Select the 'Member' option <br>
             4. Click the 'Change Role' button <br> <br>`;
          break;

        case repoType.gitlab:
          issueName = `Bot users were found with project owner permissions: ${data.length} bot ${pluralize("user", data.length)}`;

          fixLink = `${repo.link}/-/project_members`;

          secondTitle = `There ${pluralize("is", data.length)} ${data.length} ${pluralize("bot users", data.length)}
          with owner access to this project. Bot users are not real users of your top-level group.
          Please consider reducing their project role to "developer" at most. <br>
          The project was created at: ${repo.createdAt}`;

          recommendation = `Please downgrade ${pluralize("bot users", data.length)} project role to "developer" at most: <br>
            1. Enter the [link](${fixLink}) <br>
            2. Scroll down and find the bot ${pluralize("user", data.length)} with owner permissions<br>
            3. Click the dropdown icon <br>
            4. Select a new role <br> <br>`;
          break;

        case repoType.bitbucket:
          issueName = `Bot users were found with repo admin permissions: ${data.length} bot ${pluralize("user", data.length)}`;

          fixLink = `${repo.settingLink}/access`;

          secondTitle = `There ${pluralize("is", data.length)} ${data.length} ${pluralize("bot users", data.length)}
            with admin access to this repository. Bot users are not real users of your workspace.
            Please consider reducing their repository permissions to “write” at most. <br>
            The repository was created at: ${repo.createdAt}.`;

          recommendation = `Please downgrade ${pluralize(
            "bot users",
            data.length,
          )} repository permissions to “write”: <br>1. Enter the [link](${fixLink}) <br>2. Find the permission groups with permission = "Admin" <br>3. Remove the bot users from all admin permission groups, and add them to groups with write permission <br>`;
          break;

        case repoType.azureGit:
          issueName = `Bot users were found with repo admin permissions: ${data.length} bot ${pluralize("user", data.length)}`;

          fixLink = `${repo.link}/settings/access`;

          secondTitle = `There ${pluralize("is", data.length)} ${data.length} ${pluralize("bot users", data.length)}
            with admin access to this repository. Bot users are not real users of your organization.
            Please consider reducing their repository permissions to “write” at most. <br>
            The repository was created at: ${repo.createdAt}.`;

          recommendation = `Please downgrade ${pluralize("bot users", data.length)} repository permissions to “write”: <br>
               1. Enter the [link](${fixLink}) <br>
               2. Click the setting (cog) button and choose 'Change Role...' <br>
               3. Select the 'Member' option <br>
               4. Click the 'Change Role' button <br> <br>`;
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
        [repoResourceType.users],
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
        [],
        getSeverityChanges(this.policyRuleMetadata.severity, changedSeverity),
        changeReason ? [changeReason] : [],
      );

      const repoAdmins = jsonData.users.filter((u: User) => u.repoRolesRaw.find(i => i?.toLowerCase() === repoAdminRole));

      const adminsNotBots = repoAdmins.filter(u => !botIds.includes(u.id));

      const adminsBots = repoAdmins.filter(u => botIds.includes(u.id));
      let max;
      let warning;
      if (adminsNotBots.length === 1 && adminsBots.length) {
        max = 1;
      }
      if (adminsNotBots.length === 2 && adminsBots.length) {
        max = adminsBots.length;
      }
      if (max > 0) {
        warning = `You must select up to ${max} owners.`;
      }
      if (adminsBots.length === max) {
        warning = "";
      }

      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        item.fixes = generateFixesForUserRepoPermissions(
          data,
          repo,
          this.policyRuleMetadata,
          SettingType.changeRepoCollaboratorStatus,
          warning,
          "There are repository admins who may be bots. Please select the bots to remove or downgrade from the list below.",
          max,
          -1,
          jsonData.code_repo.type.toLowerCase(),
          auditLogsAvailable,
        );
      }

      return [item];
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
    return [];
  }

  isPossibleBot = (user: User, botStrings: string[]) => {
    try {
      const hasSubString = botStrings?.find(sub => {
        return user.name.toLowerCase().includes(sub);
      });

      return hasSubString ? true : false;
    } catch (e) {
      logger.error(`isPossibleBot error: ${e}`, e);
    }
    return false;
  };
}

export default policyBotNoRepoAdmin;
