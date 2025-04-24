import { Repo, repoResourceType, repoType, resourceType, User } from "../../../entitis/codeRepoTypes";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { AdminsAggItem, generateFixesForUserRepoPermissions } from "./policyDspmMaxAdmins";
import PolicyRulesBase from "./policyRulesBase";
import pluralize from "pluralize";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import Constant, { SettingType } from "../../../entitis/constant";
import { capitalizeFirstLetter } from "../../../helper/commonUtils";
const logger = loggerImport.getDebugLogger();

class policyRepoAdminsWithNoActivity extends PolicyRulesBase {
  async eval(jsonData) {
    const repo: Repo = jsonData.code_repo;

    if (!jsonData.code_repo.realRepo || jsonData.users.length == 0) {
      return [];
    }

    try {
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

      const orgName = jsonData.code_repo.organization;
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);

      if (!auditLogsAvailable) {
        return [];
      }

      const users = jsonData.users;
      const repoAdminRole = repo.gitRoles.repo.admin.toLowerCase();
      const orgAdminRole = repo.gitRoles.org.admin.toLowerCase();

      let admins: User[] = [];
      users.forEach(user => {
        let repoRolesRaw = user.repoRolesRaw.map(role => {
          return role?.toLowerCase();
        });
        if (repoRolesRaw.includes(repoAdminRole)) {
          admins.push(user);
        }
      });

      let relevantAdmins;
      switch (gitType) {
        case repoType.bitbucket:
        case repoType.azureGit:
        case repoType.github:
          relevantAdmins = admins.filter(i => !i.orgRole.has(capitalizeFirstLetter(orgAdminRole)));
          break;

        case repoType.gitlab:
          relevantAdmins = admins.filter(i => !i.isOwnerInherited);
          break;
      }

      // in case all the admins are also org owners
      if (relevantAdmins.length == 0) {
        return [];
      }

      const repoName = repo.fullName;

      const monthsTillVi = this.getValueFromRuleArgs("monthsSinceActivity");
      const days = monthsTillVi * 30;
      const currDate = new Date().getTime();

      // checking if the repo is existing more time than activity period that was configured

      const repoCreationDate = new Date(repo.createdAt).getTime();
      let requiredTimeFromCreation;
      if (!repoCreationDate) {
        requiredTimeFromCreation = false;
      } else {
        const daysSinceCreation = (currDate - repoCreationDate) / (1000 * 60 * 60 * 24);

        requiredTimeFromCreation = !(daysSinceCreation > days);
      }
      if (requiredTimeFromCreation) {
        return [];
      }

      let violated = false;

      let data = [];
      const violatedAdmins = [];
      const violatedWithoutDev = [];

      // admins that joined before the months required

      const relevantAdminsByJoinDate = relevantAdmins.filter(
        i => !i.createdAtDate || i.createdAt === "" || (currDate - i.createdAtDate.getTime()) / (1000 * 60 * 60 * 24) > days,
      );

      // all the admins are added after the time configured
      if (relevantAdminsByJoinDate.length == 0) {
        return [];
      }

      for (const admin of relevantAdminsByJoinDate) {
        // In case the admin does not appear in the audit logs

        if (!admin.adminOperationDateRepo) violated = true;
        // Calculating time from last activity in repo
        else {
          const lastAdminOperationDate = admin.adminOperationDateRepo.getTime();
          const calcDays = (currDate - lastAdminOperationDate) / (1000 * 60 * 60 * 24);
          const monthsCalc = Math.round(Math.abs(calcDays)) > days;

          if (monthsCalc) violated = true;
        }

        if (violated) {
          // Checking if there was no repo dev activity as well for relevant admins

          violatedAdmins.push(admin.name);
          if (!admin.devOperationDateRepo) violatedWithoutDev.push(admin.name);
          else {
            const lastdevOperationDate = admin.devOperationDateRepo.getTime();
            const calcDays = (currDate - lastdevOperationDate) / (1000 * 60 * 60 * 24);
            const monthsCalc = Math.round(Math.abs(calcDays)) > days;

            if (monthsCalc) violatedWithoutDev.push(admin.name);
          }

          const item: AdminsAggItem = new AdminsAggItem();
          item.user = admin.name;
          item.userInfo = admin;
          item.userAvatar = admin.avatarUrl;
          item.userLink = admin.htmlLink;
          item.orgRole = Array.from(admin.orgRole).join(", ");
          item.repoPermissions = this.handlePermissionsDisplay(admin.repoRolesRaw);
          item.earliestActivityDate = admin.createdAtDate ? admin.createdAtDate.toString() : "";
          if (auditLogsAvailable) {
            if (admin.foundAdminDataRepo) {
              item.adminOperation = this.getUserActivityBasedPretty(admin.adminOperationRepo, admin.adminOperationDateRepo);
              item.adminLocation = admin.adminLocationRepo;
              item.adminOperationDate = admin.adminOperationDateRepo.toString();
              if (item.adminOperationDate) {
                item.lastAdminOperation = item.adminOperationDate;
              }
            } else {
              item.adminOperation = "No Activity";
              item.lastAdminOperation = "No Activity";
            }
          }

          if (admin.foundDevDataRepo) {
            item.devOperation = this.getUserActivityBasedPretty(admin.devOperationRepo, admin.devOperationDateRepo);
            item.devOperationDate = admin.devOperationDateRepo.toString();
          }

          if (admin.foundReviewDataRepo) {
            item.reviewOperation = this.getUserActivityBasedPretty(admin.reviewOperationRepo, admin.reviewOperationDateRepo);
            item.reviewOperationDate = admin.reviewOperationDateRepo.toString();
          }

          item.earliestActivityDate = admin.lastActivityData ? admin.lastActivityData.toString() : "";

          item.setAggId();
          data.push(item);
        }
        violated = false;
      }

      //In case no violations for relevant admins (data includes all the admins which are no owners with violation)

      if (data.length == 0) {
        return [];
      }

      let issueName = "";
      let newAdminsNotIncluded = "";
      let boldRes = "";
      let issueDescription = "";
      let fixLink = "";
      let baseRecommendation = "";
      const typeOfResource = repo.type;
      let recommendForWithDev = "";
      let withoutDevRecommendation = "";

      const violatedWithDev = violatedAdmins.filter(i => !violatedWithoutDev.includes(i));

      switch (gitType) {
        case repoType.azureGit:
          fixLink = `https://dev.azure.com/${repo.organization}/${repo.projectName}/_settings/permissions`;

          newAdminsNotIncluded =
            relevantAdmins - relevantAdminsByJoinDate.length == 0 ? "" : "We did not include new admins in this issue.";
          issueName = `Repo admins found with no admin activity for ${monthsTillVi} ${pluralize("month", monthsTillVi)}: ${
            data.length
          } ${pluralize("admin", data.length)}`;

          boldRes = `**Older Admins with No Admin Activity**`;

          issueDescription = `There ${pluralize("is", data.length)} ${data.length} repository ${pluralize(
            "admin",
            data.length,
          )} with no activity for at least ${monthsTillVi} ${pluralize("month", monthsTillVi)}.${newAdminsNotIncluded} <br> <br>
            &bull; Total Repo Admins (including org owners): ${admins.length} <br> <br>
            &bull; Admins with Admin Activity: ${relevantAdmins.length - data.length} <br> <br>
            &bull; ${boldRes}: ${data.length} <br> <br>
            The repo was created at: ${repo.createdAt}.`;

          baseRecommendation = `Ensure only relevant designated users are defined as an admin in your ${typeOfResource} organization. In order to be in compliance of the policy you need to remove admin rights from ${
            data.length
          } existing ${pluralize("admin", data.length)} by the next steps: <br>
              1. Enter the [link](${fixLink})<br>
              2. Under 'Manage access' table go to the row of the required admin <br>
              3. Click on the Role box and change to 'Write', 'Triage' or 'Read' <br>`;

          //addition to recommendation in case we have both admins with no dev activity, and admins with dev activity

          recommendForWithDev =
            violatedWithDev.length > 0
              ? `4. For the ${violatedWithDev.length} ${pluralize(
                  "admin",
                  violatedWithDev.length,
                )} with dev activity -  click on the Role box and change to 'Write', 'Triage' or 'Read'`
              : "";

          withoutDevRecommendation =
            `Ensure only relevant designated users are defined as an admin in your repo. In order to be in compliance of the policy you need to remove admin rights from ${
              data.length
            } existing ${pluralize("admin", data.length)}.` +
            `There ${pluralize("is", violatedWithoutDev.length)} ${violatedWithoutDev.length} ${pluralize(
              "admin",
              violatedWithoutDev.length,
            )} that ${pluralize("has", violatedWithoutDev.length)} no dev operations, consider changing ${
              violatedWithoutDev.length == 1 ? "it" : "their"
            } role accordingly by the next steps: <br>
               1. Enter the [link](${fixLink})<br>
               2. Under 'Manage access' table go to the row of the required admin <br>
               3. Click on the Role box and change to 'Triage' or 'Read' <br>` +
            recommendForWithDev;

          break;
        case repoType.github:
          newAdminsNotIncluded =
            relevantAdmins - relevantAdminsByJoinDate.length == 0 ? "" : "We did not include new admins in this issue.";
          issueName = `Repo admins found with no admin activity for ${monthsTillVi} ${pluralize("month", monthsTillVi)}: ${
            data.length
          } ${pluralize("admin", data.length)}`;

          boldRes = `**Older Admins with No Admin Activity**`;

          issueDescription = `There ${pluralize("is", data.length)} ${data.length} repository ${pluralize(
            "admin",
            data.length,
          )} with no activity for at least ${monthsTillVi} ${pluralize("month", monthsTillVi)}.${newAdminsNotIncluded} <br> <br>
            &bull; Total Repo Admins (including org owners): ${admins.length} <br> <br>
            &bull; Admins with Admin Activity: ${relevantAdmins.length - data.length} <br> <br>
            &bull; ${boldRes}: ${data.length} <br> <br>
            The repository was created at: ${repo.createdAt}.`;

          fixLink = `${repo.settingLink}/access`;

          //base recommendation in case there is dev activity for all the violated admins

          baseRecommendation = `Ensure only relevant designated users are defined as an admin in your ${typeOfResource} organization. In order to be in compliance of the policy you need to remove admin rights from ${
            data.length
          } existing ${pluralize("admin", data.length)} by the next steps: <br>
            1. Enter the [link](${fixLink})<br>
            2. Under 'Manage access' table go to the row of the required admin <br>
            3. Click on the Role box and change to 'Write', 'Triage' or 'Read' <br>`;

          //addition to recommendation in case we have both admins with no dev activity, and admins with dev activity

          recommendForWithDev =
            violatedWithDev.length > 0
              ? `4. For the ${violatedWithDev.length} ${pluralize(
                  "admin",
                  violatedWithDev.length,
                )} with dev activity -  click on the Role box and change to 'Write', 'Triage' or 'Read'`
              : "";

          withoutDevRecommendation =
            `Ensure only relevant designated users are defined as an admin in your repo. In order to be in compliance of the policy you need to remove admin rights from ${
              data.length
            } existing ${pluralize("admin", data.length)}.` +
            `There ${pluralize("is", violatedWithoutDev.length)} ${violatedWithoutDev.length} ${pluralize(
              "admin",
              violatedWithoutDev.length,
            )} that ${pluralize("has", violatedWithoutDev.length)} no dev operations, consider changing ${
              violatedWithoutDev.length == 1 ? "it" : "their"
            } role accordingly by the next steps: <br>
             1. Enter the [link](${fixLink})<br>
             2. Under 'Manage access' table go to the row of the required admin <br>
             3. Click on the Role box and change to 'Triage' or 'Read' <br>` +
            recommendForWithDev;

          break;

        case repoType.gitlab:
          newAdminsNotIncluded =
            relevantAdmins - relevantAdminsByJoinDate.length == 0 ? "" : "We did not include new owners in this issue.";
          issueName = `Repo admins found with no admin activity for ${monthsTillVi} ${pluralize("month", monthsTillVi)}: ${
            data.length
          } ${pluralize("owner", data.length)}`;

          boldRes = `**Older Owners with No Admin Activity**`;

          issueDescription = `There ${pluralize("is", data.length)} ${data.length} project ${pluralize(
            "owner",
            data.length,
          )} with no activity for at least ${monthsTillVi} ${pluralize("month", monthsTillVi)}. ${newAdminsNotIncluded} <br> <br>
            &bull; Total Project Owners (including top-level group owners): ${admins.length} <br> <br>
            &bull; Owners with Admin Activity: ${relevantAdmins.length - data.length} <br> <br>
            &bull; ${boldRes}: ${data.length} <br> <br>
            The project was created at: ${repo.createdAt}.`;

          fixLink = `${repo.link}/-/project_members`;

          //base recommendation in case there is dev activity for all the violated admins

          baseRecommendation = `Ensure only relevant designated users are defined as an owner in your project. In order to be in compliance of the policy you need to remove admin rights from ${
            data.length
          } existing ${pluralize("owner", data.length)} by the next steps: <br>
              1. Enter the [link](${fixLink}) <br>
              2. Scroll down and find the aggregated owners <br>
              3. Click on the Role box and change to 'Developer' <br>`;

          //addition to recommendation in case we have both admins with no dev activity, and admins with dev activity

          recommendForWithDev =
            violatedWithDev.length > 0
              ? `4. For the ${violatedWithDev.length} ${pluralize(
                  "owner",
                  violatedWithDev.length,
                )} with dev activity -  change role to 'Developer'`
              : "";

          withoutDevRecommendation =
            `Ensure only relevant designated users are defined as an owner in your project. In order to be in compliance of the policy you need to remove admin rights from ${
              data.length
            } existing ${pluralize("owner", data.length)}.` +
            `There ${pluralize("is", violatedWithoutDev.length)} ${violatedWithoutDev.length} ${pluralize(
              "owner",
              violatedWithoutDev.length,
            )} that ${pluralize("has", violatedWithoutDev.length)} no dev operations, consider changing ${
              violatedWithoutDev.length == 1 ? "it" : "their"
            } role accordingly by the next steps: <br>
               1. Enter the [link](${fixLink})<br>
               2. Scroll down and find the aggregated owners that are without dev activity<br>
               3. Click on the Role box and change to 'Reporter' <br>` +
            recommendForWithDev;

          break;

        case repoType.bitbucket:
          newAdminsNotIncluded =
            relevantAdmins - relevantAdminsByJoinDate.length == 0 ? "" : "We did not include new admins in this issue.";
          issueName = `Repo admins found with no admin activity for ${monthsTillVi} ${pluralize("month", monthsTillVi)}: ${
            data.length
          } ${pluralize("admin", data.length)}`;

          boldRes = `**Older Admins with No Admin Activity**`;

          issueDescription = `There ${pluralize("is", data.length)} ${data.length} repository ${pluralize(
            "admin",
            data.length,
          )} with no activity for at least ${monthsTillVi} ${pluralize("month", monthsTillVi)}.${newAdminsNotIncluded} <br> <br>
              &bull; Total Repo Admins (including org owners): ${admins.length} <br> <br>
              &bull; Admins with Admin Activity: ${relevantAdmins.length - data.length} <br> <br>
              &bull; ${boldRes}: ${data.length} <br> <br>
              The repository was created at: ${repo.createdAt}.`;

          fixLink = `${repo.settingLink}/access`;

          //base recommendation in case there is dev activity for all the violated admins

          baseRecommendation = `Ensure only relevant designated users are defined as an admin in your ${typeOfResource} organization. In order to be in compliance of the policy you need to remove admin rights from ${
            data.length
          } existing ${pluralize(
            "admin",
            data.length,
          )} by the next steps: <br>1. Enter the [link](${fixLink})<br>2. Select permission groups with permission = Admin <br>3. Select users to remove<br>`;

          //addition to recommendation in case we have both admins with no dev activity, and admins with dev activity

          recommendForWithDev =
            violatedWithDev.length > 0
              ? `4. For the ${violatedWithDev.length} ${pluralize(
                  "admin",
                  violatedWithDev.length,
                )} with dev activity -  add them to a group with write permission before removing their admin access'`
              : "";

          withoutDevRecommendation =
            `Ensure only relevant designated users are defined as an admin in your repo. In order to be in compliance of the policy you need to remove admin rights from ${
              data.length
            } existing ${pluralize("admin", data.length)}.` +
            `There ${pluralize("is", violatedWithoutDev.length)} ${violatedWithoutDev.length} ${pluralize(
              "admin",
              violatedWithoutDev.length,
            )} that ${pluralize("has", violatedWithoutDev.length)} no dev operations, consider changing ${
              violatedWithoutDev.length == 1 ? "it" : "their"
            } role accordingly by the next steps: <br><br>1. Enter the [link](${fixLink})<br><br>2. Select permission groups with permission = Admin <br><br>3. Select users to remove them from admin permission groups, and add them to a read permission group<br>` +
            recommendForWithDev;

          break;
      }

      const recommendation = violatedWithoutDev.length == 0 ? baseRecommendation : withoutDevRecommendation;

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
      const withLastActivity = data.filter(i => i.userInfo.lastActivityData);
      const withoutLastActivity = data.filter(i => !i.userInfo.lastActivityData);
      const withLastActivitySorted = withLastActivity.sort(
        (a, b) => b.userInfo.lastActivityData.getTime() - a.userInfo.lastActivityData.getTime(),
      );
      data = [...withoutLastActivity, ...withLastActivitySorted];

      const aggregated = {
        columns: "policyRepoAdminsWithNoActivity",
        aggregatedItems: data,
      };

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
        [repoResourceType.users, resourceType.auditLog],
        [],
        this.getCustomIssueId(`${repo.type}_${repoName}`),
        [issueOwner],
      );

      let max = admins.length - data.length === 0 ? admins.length - 1 : data.length;

      const warning = `You must select up to ${max} users`;

      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        item.fixes = generateFixesForUserRepoPermissions(
          data,
          repo,
          this.policyRuleMetadata,
          SettingType.changeRepoCollaboratorStatus,
          warning,
          "There are repository admins with no admin activity. Please select the admins to remove or downgrade from the list below.",
          max,
          -1,
          jsonData.code_repo.type.toLowerCase(),
          auditLogsAvailable,
        );
      }
      res.push(item);
      return res;
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}, repo: ${repo.fullName}`);
    }
    return [];
  }
}

export default policyRepoAdminsWithNoActivity;
