import { repoType, resourceType, User } from "../../../entitis/codeRepoTypes";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import StatesHelper from "../../../helper/statesHelper";
import { AdminsAggItem, generateFixesForUserOrgRoles } from "./policyDspmMaxAdmins";
import pluralize from "pluralize";
import { repoAdminRole } from "../../../dal/GolobalCollectorData/globalCodeRepoData";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import Constant, { SettingType } from "../../../entitis/constant";
const logger = loggerImport.getDebugLogger();

class policyOrgOwnersWithNoActivity extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const orgName = jsonData?.code_repo?.org;
      if (!orgName) {
        return [];
      }

      const orgUsers = jsonData.allUsers;
      const orgId = jsonData.code_repo.orgId;
      const orgAdminRole = jsonData.code_repo.gitRoles.org.admin.toLowerCase();
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);

      // in case we can't get auditlogs for our org, we will not run the policy

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

      if (jsonData.code_repo.realRepo || orgUsers.length === 0 || !auditLogsAvailable) {
        return [];
      }

      let data = [];
      const auditLogs = jsonData.auditLog;
      const monthsTillVi = this.getValueFromRuleArgs("monthsSinceActivity");

      const orgOwners = orgUsers.filter(i => i.orgRole.has(orgAdminRole));

      const days = monthsTillVi * 30;
      let latestActivity = 0;
      let chosenOwner;
      let issueOwner;
      let violatedOwnersArr = [];

      // will not run the policy if we have less than 3 owners

      if (orgOwners.length < 3) {
        return [];
      }

      const currDate = new Date().getTime();
      let violated = false;

      for (const owner of orgOwners) {
        // In case the owner does not appear in the audit logs

        if (!auditLogs.hasOwnProperty(owner.name)) violated = true;
        else if (auditLogs[owner.name].length == 0) violated = true;
        // In case the owner appears in the audit logs and has activities
        else {
          const lastAdminOperationDate = owner.adminOperationDate.getTime();
          const calcDays = (currDate - lastAdminOperationDate) / (1000 * 60 * 60 * 24);
          const monthsCalc = Math.round(Math.abs(calcDays)) > days;

          // there was not activity in the time configured by the user

          if (monthsCalc) {
            violated = true;
          }
        }

        // Violation happens

        if (violated) {
          violatedOwnersArr.push(owner);
          const item: AdminsAggItem = new AdminsAggItem();
          item.user = owner.name;
          item.userInfo = owner;
          item.userAvatar = owner.avatarUrl;
          item.userLink = owner.htmlLink;
          item.orgRole = Array.from(owner.orgRole).join(", ");
          item.repoPermissions = ""; //this for repo only
          item.earliestActivityDate = owner.createdAtDate ? owner.createdAtDate.toString() : "";
          if (owner.foundAdminData) {
            item.adminOperation = this.getUserActivityBasedPretty(owner.adminOperation, owner.adminOperationDate);
            item.adminLocation = owner.adminLocation;
            item.adminOperationDate = owner.adminOperationDate.toString();
            item.lastAdminOperation = owner.lastAdminOperation;

            const itemDate = owner.adminOperationDate.getTime();
            if (itemDate > latestActivity) {
              chosenOwner = item.userInfo;
              latestActivity = itemDate;
            }
          } else {
            item.adminOperation = "No Activity";
            item.lastAdminOperation = "No Activity";
          }

          if (owner.foundDevData) {
            item.devOperation = this.getUserActivityBasedPretty(owner.devOperation, owner.devOperationDate);
            item.devOperationDate = owner.devOperationDate.toString();
          }

          if (owner.foundReviewData) {
            item.reviewOperation = this.getUserActivityBasedPretty(owner.reviewOperation, owner.reviewOperationDate);
            item.reviewOperationDate = owner.reviewOperationDate.toString();
          }

          item.earliestActivityDate = owner.lastActivityData ? owner.lastActivityData.toString() : "";

          item.setAggId();
          data.push(item);
        }
        violated = false;
      }

      // In case the number of owners is equal to the number of the violated owners, we will remove the owner with the latest activity

      if (data.length == orgOwners.length) {
        data = data.filter(i => !(i.userInfo === chosenOwner));
        violatedOwnersArr = violatedOwnersArr.filter(i => !(i === chosenOwner));
      }

      if (data.length == 0) {
        return [];
      }

      // Sorting based last activity

      const withLastActivity = data.filter(i => i.userInfo.adminOperationDate);
      const withoutLastActivity = data.filter(i => !i.userInfo.adminOperationDate);
      const withLastActivitySorted = withLastActivity.sort(
        (a, b) => b.userInfo.adminOperationDate.getTime() - a.userInfo.adminOperationDate.getTime(),
      );
      data = [...withLastActivitySorted, ...withoutLastActivity];

      const aggregated = {
        columns: "policyOrgOwnersWithNoActivity",
        aggregatedItems: data,
      };

      const monthsPluralized = pluralize("month", monthsTillVi);
      const violatedOwners = data.length;
      const ownersPluralized = pluralize("owner", violatedOwners);
      const totalOwnersPluralized = pluralize("owner", orgOwners.length);

      // calculating issue owner - the most veteran owner among those who are not violated

      const possibleIssueOwner = orgOwners.filter(i => !violatedOwnersArr.includes(i));

      if (possibleIssueOwner.length === 1) {
        issueOwner = possibleIssueOwner[0];
      } else {
        let mostVeteranDate = possibleIssueOwner[0].createdAt;
        issueOwner = possibleIssueOwner[0];
        for (const owner of possibleIssueOwner) {
          const createdDate = new Date(owner.createdAt).getTime();
          if (createdDate < mostVeteranDate) {
            issueOwner = owner;
            mostVeteranDate = createdDate;
          }
        }
      }

      let issueName = "";
      let issueDescription = "";
      let fixLink = "";
      let recommendation = "";

      switch (gitType) {
        case repoType.azureGit:
          issueName = `Org owners found with no admin activity for ${monthsTillVi} ${monthsPluralized}: ${data.length} ${ownersPluralized}`;
          issueDescription = `There ${pluralize(
            "is",
            violatedOwners,
          )} ${violatedOwners} org(${orgName}) ${ownersPluralized} with no admin activity for at least ${monthsTillVi} ${monthsPluralized}.  From the total of ${
            orgOwners.length
          } ${totalOwnersPluralized}, ${violatedOwners} ${ownersPluralized} ${pluralize(
            "have",
            data.length,
          )} not made any changes in the last ${monthsTillVi} ${monthsPluralized}.`;
          fixLink = `https://dev.azure.com/${orgName}/_settings/groups`;
          recommendation = `Ensure only relevant designated users are defined as an owner in your ${jsonData.code_repo.type} organization: <br>
          1. Enter the [link](${fixLink}) <br>
          2. Click on "Project Collection Administrators" group <br>
          3. Select the 'Members' tab <br>
          4. Remove Owners`;
          break;

        case repoType.github:
          issueName = `Org owners found with no admin activity for ${monthsTillVi} ${monthsPluralized}: ${data.length} ${ownersPluralized}`;
          issueDescription = `There ${pluralize(
            "is",
            violatedOwners,
          )} ${violatedOwners} org(${orgName}) ${ownersPluralized} with no admin activity for at least ${monthsTillVi} ${monthsPluralized}.  From the total of ${
            orgOwners.length
          } ${totalOwnersPluralized}, ${violatedOwners} ${ownersPluralized} ${pluralize(
            "have",
            data.length,
          )} not made any changes in the last ${monthsTillVi} ${monthsPluralized}.`;
          fixLink = `https://github.com/orgs/${orgName}/people`;
          recommendation = `Ensure only relevant designated users are defined as an owner in your organization. In order to be in compliance of the policy you need to remove owner rights from ${violatedOwners} existing owners: <br>
            1. Enter the [link](${fixLink}) <br>
            2. Click the setting (cog) button and choose 'Change Role...' <br>
            3. Select the 'Member' option <br>
            4. Click the 'Change Role' button`;
          break;

        case repoType.gitlab:
          issueName = `Top-level group owners found with no admin activity for ${monthsTillVi} ${monthsPluralized}: ${data.length} ${ownersPluralized}`;
          issueDescription = `There ${pluralize(
            "is",
            violatedOwners,
          )} ${violatedOwners} top-level group(${orgName}) ${ownersPluralized} with no admin activity for at least ${monthsTillVi} ${monthsPluralized}.  From the total of ${
            orgOwners.length
          } ${totalOwnersPluralized}, ${violatedOwners} ${ownersPluralized} ${pluralize(
            "have",
            data.length,
          )} not made any changes in the last ${monthsTillVi} ${monthsPluralized}.`;
          fixLink = `https://gitlab.com/groups/${orgName}/-/group_members`;
          recommendation = `Ensure only relevant designated users are defined as an owner in your top-level group. In order to be in compliance of the policy you need to remove owner rights from ${violatedOwners} existing owners: <br>
            1. Enter the [link](${fixLink}) <br>
            2. Scroll down and find the aggregated owners <br>
            3. Click the dropdown icon <br>
            4. Select a new role`;
          break;

        case repoType.bitbucket:
          issueName = `Workspace owners found with no admin activity for ${monthsTillVi} ${monthsPluralized}: ${data.length} ${ownersPluralized}`;
          issueDescription = `There ${pluralize(
            "is",
            violatedOwners,
          )} ${violatedOwners} workspace(${orgName}) ${ownersPluralized} with no admin activity for at least ${monthsTillVi} ${monthsPluralized}.  From the total of ${
            orgOwners.length
          } ${totalOwnersPluralized}, ${violatedOwners} ${ownersPluralized} ${pluralize(
            "have",
            data.length,
          )} not made any changes in the last ${monthsTillVi} ${monthsPluralized}.`;
          fixLink = `https://bitbucket.org/${orgName}/workspace/settings/groups`;
          recommendation = `Ensure only relevant designated users are defined as an owner in your workspace. In order to be in compliance of the policy you need to remove owner rights from ${violatedOwners} existing owners: <br>1. Enter the [link](${fixLink}) <br>2. Find the permission groups with ADMIN tag <br>3. Remove the aggregated owners from the admin permission groups (in order to keep them write/read permissions, add them to other permission groups)<br>`;
          break;
      }
      const extraInfo = [];
      extraInfo.push({
        key: "Total Owners",
        value: `${orgOwners.length}`,
      });
      extraInfo.push({
        key: "Total Users",
        value: `${orgUsers.length}`,
      });
      const res = [];

      const item = this.generateItemForReport(
        true,
        issueName,
        issueDescription,
        issueDescription,
        recommendation,
        "N/A",
        "N/A",
        "",
        [],
        true,
        fixLink,
        aggregated,
        [Constant.gitPosture],
        [resourceType.allPulls, resourceType.auditLog],
        extraInfo,
        this.getCustomIssueId(`${jsonData.code_repo.type}-${orgName}-${orgId}`),
        [issueOwner],
      );

      let warning = "";
      let max = orgOwners.length - data.length === 0 ? orgOwners.length - 2 : data.length;
      if (orgOwners.length - data.length === 1) {
        max = data.length - 1;
      }

      if (max > 0 && max != data.length) {
        warning = `You must select up to ${max} owners.`;
      }

      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        const description = `There are owners in the organization with no activity. Please select owners to remove or downgrade from the list below.`;
        // const confirmation = `After the fix the chosen users will no longer be owners in ${orgName} organization`
        item.fixes = generateFixesForUserOrgRoles(
          data,
          orgName,
          this.policyRuleMetadata,
          SettingType.changeOrgUserStatus,
          warning,
          description,
          max,
          -1,
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

export default policyOrgOwnersWithNoActivity;
