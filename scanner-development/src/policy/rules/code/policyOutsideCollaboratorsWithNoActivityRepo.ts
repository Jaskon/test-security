import { AffiliationType, Repo, repoResourceType, repoType, User } from "../../../entitis/codeRepoTypes";
import Constant, { SettingType } from "../../../entitis/constant";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { AdminsAggItem, generateFixesForUserRepoPermissions } from "./policyDspmMaxAdmins";
import PolicyRulesBase from "./policyRulesBase";
import pluralize from "pluralize";
const logger = loggerImport.getDebugLogger();

class policyOutsideCollaboratorsWithNoActivityRepo extends PolicyRulesBase {
  async eval(jsonData) {
    const repo: Repo = jsonData.code_repo;

    try {
      if (!repo.realRepo) {
        return [];
      }

      if (repo?.gitRoles?.org == undefined || repo?.gitRoles?.repo?.admin == undefined) {
        return [];
      }

      const orgAdminRole = repo.gitRoles.org.admin;
      const repoAdminRole = repo.gitRoles.repo.admin;

      const gitType = jsonData.code_repo.type.toLowerCase();
      const supportedGitTypes = ["github", "gitlab"];
      // run policy only if git type is supported
      if (!supportedGitTypes.includes(gitType)) {
        return [];
      }

      let shouldRunPolicy = false;
      if (gitType === repoType.github) {
        shouldRunPolicy = true;
      }

      if (gitType === repoType.gitlab) {
        shouldRunPolicy = true;
      }

      if (jsonData.users.length == 0 || !shouldRunPolicy) {
        return [];
      }

      const orgName = jsonData.code_repo.organization;
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);

      if (!auditLogsAvailable) {
        return [];
      }

      const users = jsonData.users;
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

      let data = [];
      let outsideCollaboratorAdmin = false;

      // users that joined before the months required
      const relevantUsersByJoinDate = users.filter(
        i => !i.createdAtDate || i.createdAt === "" || (currDate - i.createdAtDate.getTime()) / (1000 * 60 * 60 * 24) > days,
      );

      // all the users are added after the time configured
      if (relevantUsersByJoinDate.length == 0) {
        return [];
      }

      const commonUserPrefixSuffix = Object.keys(StatesHelper.Instance.commonUserPrefixSuffix);

      // if the only admin is an outside collaborator - will not violate on him
      const admins = users.filter(i => i.repoRolesRaw.includes(repoAdminRole));
      if (admins.length === 1) {
        if (this.checkOutsideCollaborator(admins[0], gitType, commonUserPrefixSuffix)) {
          outsideCollaboratorAdmin = true;
        }
      }

      let outsideCollaboratorsCount = 0;

      let violatedDev = false;
      let violatedAdmin = false;
      let violatedReview = false;

      for (const user of relevantUsersByJoinDate) {
        if (this.checkOutsideCollaborator(user, gitType, commonUserPrefixSuffix)) {
          outsideCollaboratorsCount++;

          // not violating in case the outside collaborator doesn't have write permissions

          switch (gitType) {
            case repoType.github:
              if (!user.repoRolesRaw.includes("push")) {
                continue;
              }
              break;

            case repoType.gitlab:
              if (
                !user.repoRolesRaw.includes("Developer") &&
                !user.repoRolesRaw.includes("Owner") &&
                !user.repoRoleRaw.includes("Maintainer")
              ) {
                continue;
              }
              break;
          }

          // not violating in case of the only admin is outside collaborator
          if (outsideCollaboratorAdmin && user.repoRolesRaw.includes(repoAdminRole)) {
            continue;
          }

          const lastdevOperationDate = user.devOperationDateRepo ? user.devOperationDateRepo.getTime() : user.devOperationDateRepo;
          if (!lastdevOperationDate) {
            violatedDev = true;
          } else {
            const calcDays = (currDate - lastdevOperationDate) / (1000 * 60 * 60 * 24);
            const monthsCalc = Math.round(Math.abs(calcDays)) > days;
            if (monthsCalc) {
              violatedDev = true;
            }
          }
          const lastAdminOperationDate = user.adminOperationDateRepo ? user.adminOperationDateRepo.getTime() : user.adminOperationDateRepo;
          if (!lastAdminOperationDate) {
            violatedAdmin = true;
          } else {
            const calcDays = (currDate - lastAdminOperationDate) / (1000 * 60 * 60 * 24);
            const monthsCalc = Math.round(Math.abs(calcDays)) > days;
            if (monthsCalc) {
              violatedAdmin = true;
            }
          }

          const lastReviewOperationDate = user.reviewOperationDateRepo
            ? user.reviewOperationDateRepo.getTime()
            : user.reviewOperationDateRepo;
          if (!lastReviewOperationDate) {
            violatedReview = true;
          } else {
            const calcDays = (currDate - lastReviewOperationDate) / (1000 * 60 * 60 * 24);
            const monthsCalc = Math.round(Math.abs(calcDays)) > days;
            if (monthsCalc) {
              violatedReview = true;
            }
          }

          if (violatedDev && violatedAdmin && violatedReview) {
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
        }
      }

      if (data.length == 0) {
        return [];
      }

      const aggregated = {
        columns: "policyOutsideCollaboratorsWithNoActivityRepo",
        aggregatedItems: data,
      };

      let issueName, issueDescription, fixLink, recommendation;

      const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);
      switch (gitType) {
        case repoType.github:
          issueName = `${data.length} outside ${pluralize("collaborator", data.length)} ${pluralize(
            "has",
            data.length,
          )} had no activity for at least ${monthsTillVi} ${pluralize("month", monthsTillVi)}`;

          issueDescription = `There ${pluralize("is", data.length)} ${data.length} outside ${pluralize(
            "collaborator",
            data.length,
          )} with no activity for at least ${monthsTillVi} ${pluralize(
            "month",
            monthsTillVi,
          )}. From the total of ${outsideCollaboratorsCount} outside ${pluralize(
            "collaborator",
            outsideCollaboratorsCount,
          )} in the repository, ${data.length} ${pluralize(
            "has",
            data.length,
          )} not made any changes in the last ${monthsTillVi} ${pluralize("month", monthsTillVi)}. <br>
          The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

          fixLink = `${repo.settingLink}/access`;

          recommendation = `Please consider removing the outside ${pluralize(
            "collaborator",
            data.length,
          )} from your repository by the next steps: <br>
            1. Enter the [link](${fixLink})<br>
            2. Under 'Manage access' table go to the row of the required outside collaborator <br>
            3. Click on the Remove option <br>
          `;
          break;

        case repoType.gitlab:
          issueName = `${data.length} outside ${pluralize("collaborator", data.length)} ${pluralize(
            "has",
            data.length,
          )} had no activity for at least ${monthsTillVi} ${pluralize("month", monthsTillVi)}`;

          issueDescription = `There ${pluralize("is", data.length)} ${data.length} outside ${pluralize(
            "collaborator",
            data.length,
          )} with no activity for at least ${monthsTillVi} ${pluralize(
            "month",
            monthsTillVi,
          )}. From the total of ${outsideCollaboratorsCount} outside ${pluralize(
            "collaborator",
            outsideCollaboratorsCount,
          )} in the project, ${data.length} ${pluralize("has", data.length)} not made any changes in the last ${monthsTillVi} ${pluralize(
            "month",
            monthsTillVi,
          )}. <br>
          The project created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

          fixLink = `${repo.link}/-/project_members`;

          recommendation = `Please consider removing the outside ${pluralize(
            "collaborator",
            data.length,
          )} from your project by the next steps: <br>
            1. Enter the [link](${fixLink})<br>
            2. Search for the ${pluralize("member", data.length)} to remove<br>
            3. Press the three dots icon on the right side<br>
            3. Click on Remove member <br>
          `;
          break;
      }

      const extraInfo = [];
      extraInfo.push({
        key: "Total Admins",
        value: `${admins.length}`,
      });
      extraInfo.push({
        key: "Total Users",
        value: `${users.length}`,
      });
      extraInfo.push({
        key: "Total Outside Collaborators",
        value: `${outsideCollaboratorsCount}`,
      });

      let issueOwner;
      let userIssueOwner = this.getAdminWithMaxOperations(jsonData.users as User[], repoAdminRole.toLowerCase(), true);

      if (!userIssueOwner) {
        userIssueOwner = this.getAdminWithMaxOperations(jsonData.allUsers as User[], orgAdminRole.toLowerCase());
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
        [repoResourceType.users],
        extraInfo,
        this.getCustomIssueId(`${repo.type}_${repoName}`),
        [issueOwner],
      );

      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        item.fixes = generateFixesForUserRepoPermissions(
          data,
          repo,
          this.policyRuleMetadata,
          SettingType.changeRepoCollaboratorStatus,
          "",
          "There are Outside collaborators with no activity. Please select the Outside collaborators to remove from the list below.",
          data.length,
          -1,
          jsonData.code_repo.type.toLowerCase(),
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

export default policyOutsideCollaboratorsWithNoActivityRepo;
