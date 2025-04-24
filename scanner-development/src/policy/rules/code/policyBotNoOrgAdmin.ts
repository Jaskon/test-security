import pluralize from "pluralize";
import { repoType, resourceType, User } from "../../../entitis/codeRepoTypes";
import Constant, { SettingType } from "../../../entitis/constant";
import { Severity } from "../../../entitis/reportTypes";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { AdminsAggItem, generateFixesForUserOrgRoles } from "./policyDspmMaxAdmins";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class policyBotNoOrgAdmin extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      if (jsonData.code_repo.realRepo || !Object.keys(jsonData.allUsers).length) {
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

      // get substrings from config
      const botStrings = this.getValueFromRuleArgs("botSubStrings");

      let data = [];
      const botIds = [];
      const extraInfo = [];

      let changedSeverity = this.policyRuleMetadata.severity;
      let changeReason = null;
      let admins = 0;
      const orgName = jsonData.code_repo.org;

      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);

      for (const user of jsonData.allUsers as User[]) {
        const userOrgRoles = Array.from(user.orgRole) as string[];

        if (userOrgRoles.find(i => i.toLowerCase() === orgAdminRole)) {
          admins++;
          if (!this.isPossibleBot(user, botStrings)) {
            continue;
          }
          botIds.push(user.id);
          const item: AdminsAggItem = new AdminsAggItem();
          item.user = user.name;
          item.userInfo = user;
          item.userAvatar = user.avatarUrl;
          item.userLink = user.htmlLink;
          item.orgRole = Array.from(user.orgRole).join(", ");
          item.repoPermissions = ""; //this for repo only
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

      if (data.length === 0) {
        return [];
      }

      extraInfo.push({
        key: "Total Users",
        value: `${jsonData.allUsers.length}`,
      });
      extraInfo.push({
        key: "Total Admins",
        value: `${admins}`,
      });
      extraInfo.push({
        key: "Bot Admins",
        value: `${data.length}`,
      });

      const allUsersWithouotBots = jsonData.allUsers.filter(u => !botIds.includes(u.id));
      let issueOwner;
      issueOwner = this.getAdminWithMaxOperations(allUsersWithouotBots, orgAdminRole);
      if (!issueOwner) {
        issueOwner = this.getAdminWithMaxOperations(jsonData.allUsers, orgAdminRole);
      }

      const withLastActivity = data.filter(i => i.userInfo.lastActivityData);
      const withoutLastActivity = data.filter(i => !i.userInfo.lastActivityData);
      const withLastActivitySorted = withLastActivity.sort(
        (a, b) => b.userInfo.lastActivityData.getTime() - a.userInfo.lastActivityData.getTime(),
      );
      data = [...withLastActivitySorted, ...withoutLastActivity];

      const aggregated = {
        columns: "policyBotNoOrgAdmin",
        aggregatedItems: data,
      };

      const org = jsonData.code_repo.org;
      let issueName = "";
      let fixLink = "";
      let secondTitle = "";
      let recommendation = "";
      switch (gitType) {
        case repoType.github:
          issueName = `Bot users were found with org owner permissions: ${data.length} bot ${pluralize("user", data.length)}`;

          fixLink = `https://github.com/orgs/${org}/people`;

          secondTitle = `There ${pluralize("is", data.length)} ${data.length} ${pluralize("bot users", data.length)}
          that ${pluralize(
            "has",
            data.length,
          )} owner permissions in organization ${org}. Bot users having admin permissions to a workspace is a significant security risk, as changes can be made to the environment without any restrictions.`;

          recommendation = `Please downgrade ${pluralize("bot users", data.length)} repository permissions to “write”: <br>
            1. Enter the [link](${fixLink}) <br>
            2. Click the setting (cog) button and choose 'Change Role...' <br>
            3. Select the 'Member' option <br>
            4. Click the 'Change Role' button`;
          break;

        case repoType.gitlab:
          issueName = `Bot users were found with first-level group owner permissions: ${data.length} bot ${pluralize("user", data.length)}`;

          fixLink = `https://gitlab.com/groups/${org}/-/group_members`;

          secondTitle = `There ${pluralize("is", data.length)} ${data.length} ${pluralize("bot users", data.length)}
          with owner access to this first-level group. Bot users having admin permissions to a workspace is a significant security risk, as changes can be made to the environment without any restrictions.`;

          recommendation = `Ensure only relevant designated users are defined as an owner in your ${
            jsonData.code_repo.type
          } first-level group : <br>
            Please downgrade ${org} group ${pluralize("bot user", data.length)} role to "developer" at most: <br>
              1. Enter the [link](${fixLink}) <br>
              2. Scroll down and find the bot ${pluralize("user", data.length)} with owner permissions<br>
              3. Click the dropdown icon <br>
              4. Select a new role <br> <br>`;
          break;

        case repoType.bitbucket:
          issueName = `Bot users were found with workspace owner permissions: ${data.length} bot ${pluralize("user", data.length)}`;

          fixLink = `https://bitbucket.org/${org}/workspace/settings/groups`;

          secondTitle = `There ${pluralize("is", data.length)} ${data.length} ${pluralize("bot users", data.length)}
            that ${pluralize(
              "has",
              data.length,
            )} owner permissions in workspace ${org}. Bot users having admin permissions to a workspace is a significant security risk, as changes can be made to the environment without any restrictions.`;

          recommendation = `Please downgrade ${pluralize(
            "bot users",
            data.length,
          )} repository permissions to “write”: <br>1. Enter the [link](${fixLink}) <br>2. Find the permission groups with ADMIN tag <br>3. Remove the bot users from the admin permission groups, and add them to groups with write permission <br>`;
          break;

        case repoType.azureGit:
          issueName = `Bot users were found with org owner permissions: ${data.length} bot ${pluralize("user", data.length)}`;

          fixLink = `https://dev.azure.com/${org}/_settings/groups`;

          secondTitle = `There ${pluralize("is", data.length)} ${data.length} ${pluralize("bot users", data.length)}
          that ${pluralize(
            "has",
            data.length,
          )} owner permissions in organization ${org}. Bot users having admin permissions to a workspace is a significant security risk, as changes can be made to the environment without any restrictions.`;

          recommendation = `Ensure only relevant designated users are defined as an owner in your ${jsonData.code_repo.type} organization: <br>
          1. Enter the [link](${fixLink}) <br>
          2. Click on "Project Collection Administrators" group <br>
          3. Select the 'Members' tab <br>
          4. Remove Owners`;

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
        [],
        getSeverityChanges(this.policyRuleMetadata.severity, changedSeverity),
        changeReason ? [changeReason] : [],
      );

      const orgOwners = jsonData.allUsers.filter(u => [...u.orgRole].some(i => i.toLowerCase() === orgAdminRole));

      const ownersNotBots = orgOwners.filter(u => !botIds.includes(u.id));

      const ownersBots = orgOwners.filter(u => botIds.includes(u.id));

      let max;
      let warning;
      let isOnlyOwner = false;
      if (orgOwners.length === 1 && ownersBots.length === 1) {
        isOnlyOwner = true;
      }
      if (ownersNotBots.length === 1 && ownersBots.length) {
        max = 1;
      }
      if (ownersNotBots.length === 2 && ownersBots.length) {
        max = ownersBots.length;
      }
      if (max > 0) {
        warning = `You must select up to ${max} owners.`;
      }
      if (ownersBots.length === max) {
        warning = "";
      }

      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        const description =
          "There are bots in the organization with owner roles. Please select owners to remove or downgrade from the below list.";
        item.fixes = generateFixesForUserOrgRoles(
          data,
          org,
          this.policyRuleMetadata,
          SettingType.changeOrgUserStatus,
          warning,
          description,
          max,
          1,
          jsonData.code_repo.type.toLowerCase(),
          auditLogsAvailable,
          isOnlyOwner,
        );
      }

      return [item];
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
    return [];
  }
}

export default policyBotNoOrgAdmin;
