import { Repo, repoType, resourceType, User } from "../../../entitis/codeRepoTypes";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { Severity } from "../../../entitis/reportTypes";
import { ChangeReason, severityReasons } from "../../../entitis/service/blameTypes";
import { AggregatedInfoForExclusion, AggregatedUser } from "../../../entitis/service/exclusionTypes";
import { capitalizeFirstLetter } from "../../../helper/commonUtils";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import { Input, InputOption, Policy, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import StringHelper from "../../../helper/stringHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import pluralize from "pluralize";

const logger = loggerImport.getDebugLogger();

class policyDspmMaxAdmins extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      if (jsonData.code_repo.realRepo) {
        return [];
      }

      if (jsonData.allUsers.length == 0) {
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
      const owners = jsonData.allUsers.filter(i => i.orgRole.has(capitalizeFirstLetter(orgAdminRole)) || i.orgRole.has(orgAdminRole));
      if (owners.length < 3) {
        return [];
      }
      const res = [];
      const extraInfo = [];
      const minAdmins = this.getValueFromRuleArgs("minAdmins");
      const minAdminsPercentage = this.getValueFromRuleArgs("minAdminsPercentage");

      let changedSeverity = this.policyRuleMetadata.severity;
      let changeReasons: ChangeReason[] = [];

      let admins = 0;
      let data = [];

      const orgName = jsonData.code_repo.org;
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);

      for (const user of jsonData.allUsers as User[]) {
        const userOrgRoles = Array.from(user.orgRole) as string[];

        if (userOrgRoles.find(i => i.toLowerCase() === orgAdminRole)) {
          admins++;

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

          if (user.foundReviewData) {
            item.reviewOperation = this.getUserActivityBasedPretty(user.reviewOperation, user.reviewOperationDate);
            item.reviewOperationDate = user.reviewOperationDate.toString();
          }

          item.earliestActivityDate = user.lastActivityData ? user.lastActivityData.toString() : "";

          item.setAggId();
          data.push(item);
        }
      }

      if (data.length === 0) {
        return [];
      }

      const ownersPercentage = Number(this.adminPercentageFromTotal(admins, jsonData.allUsers.length));

      const ownersPercaentageLimit = Number(this.limitPercentage(minAdminsPercentage, jsonData.allUsers.length).toFixed());

      const greaterMin = Math.max(minAdmins, ownersPercaentageLimit);

      if (admins <= greaterMin) {
        return [];
      }

      if (ownersPercentage > 75) {
        changedSeverity = changedSeverity + 1;
        changeReasons.push(severityReasons.WayTooManyOwners);
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
        key: "Total Owners",
        value: `${admins}`,
      });
      extraInfo.push({
        key: "Total Users",
        value: `${jsonData.allUsers.length}`,
      });

      const issueOwner = this.getAdminWithMaxOperations(jsonData.allUsers, orgAdminRole);

      const withLastActivity = data.filter(i => i.userInfo.lastActivityData);
      const withoutLastActivity = data.filter(i => !i.userInfo.lastActivityData);
      const withLastActivitySorted = withLastActivity.sort(
        (a, b) => b.userInfo.lastActivityData.getTime() - a.userInfo.lastActivityData.getTime(),
      );
      data = [...withLastActivitySorted, ...withoutLastActivity];

      const org = jsonData.code_repo.org;
      const orgId = jsonData.code_repo.orgId;

      const aggregated = {
        columns: "policyDspmMaxAdmins",
        aggregatedItems: data,
      };
      let fixLink = "";
      let newVi = "";
      const W = admins - greaterMin;
      let recommendation = "";
      switch (gitType) {
        case repoType.azureGit:
          fixLink = `https://dev.azure.com/${org}/_settings/groups`;
          newVi = `There are too many owners assigned to manage the ${jsonData.code_repo.type} organization.`;

          recommendation = `Ensure only relevant designated users are defined as an owner in your ${jsonData.code_repo.type} organization. In order to be in compliance of the policy you need to remove owner rights from ${W} existing owners by : <br>
            1. Enter the [link](${fixLink}) <br>
            2. Click on "Project Collection Administrators" group <br>
            3. Select the 'Members' tab <br>
            4. Remove Owners`;

          break;
        case "github":
          fixLink = `https://github.com/orgs/${org}/people`;
          newVi = `There are too many owners assigned to manage the ${jsonData.code_repo.type} organization.`;

          recommendation = `Ensure only relevant designated users are defined as an owner in your ${jsonData.code_repo.type} organization. In order to be in compliance of the policy you need to remove owner rights from ${W} existing owners by : <br>
            1. Enter the [link](${fixLink}) <br>
            2. Click the setting (cog) button and choose 'Change Role...' <br>
            3. Select the 'Member' option <br>
            4. Click the 'Change Role' button`;

          break;
        case "gitlab":
          fixLink = `https://gitlab.com/groups/${org}/-/group_members`;
          newVi = `There are too many owners assigned to manage the ${jsonData.code_repo.type} first-level group.`;

          recommendation = `Ensure only relevant designated users are defined as an owner in your ${jsonData.code_repo.type} first-level group. In order to be in compliance of the policy you need to remove owner rights from ${W} existing owners by : <br>
          1. Enter the [link](${fixLink}) <br>
          2. Scroll down and find an owner <br>
          3. Click the dropdown icon <br>
          4. Select a new role <br> <br>`;

          break;

        case "bitbucket":
          fixLink = `https://bitbucket.org/${org}/workspace/settings/groups`;
          newVi = `There are too many owners assigned to manage the ${jsonData.code_repo.type} workspace.`;

          recommendation = `Ensure only relevant designated users are defined as an owner in your ${
            jsonData.code_repo.type
          } workspace. In order to be in compliance of the policy you need to remove owner rights from ${W} existing ${pluralize(
            "owner",
            W,
          )} by : <br><br>1. Enter the [link](${fixLink}) <br><br>2. Click on one of the groups with ADMIN tag <br><br>3. Choose members to remove admin access (in order to keep them write/read permissions, make sure those members exist on other permission groups) <br><br>4. Click on Remove <br> <br>`;

          break;
      }

      let orgType = "";

      switch (gitType) {
        case repoType.azureGit:

        case repoType.github:
          orgType = "org";
          break;

        case repoType.gitlab:
          orgType = "first-level group";
          break;

        case repoType.bitbucket:
          orgType = "workspace";
          break;
      }

      const owner = jsonData.allUsers.length - admins == 1 ? "an owner" : "owners";
      const item = this.generateItemForReport(
        true,
        `Too many owners for ${orgType} ${org}: ${admins} owners (${this.adminPercentageFromTotal(
          admins,
          jsonData.allUsers.length,
        ).toFixed()}% of all users)`,
        `There are too many owners assigned to manage ${orgType} ${org}. There are a total of ${admins} ${pluralize("owner", admins)} and ${
          jsonData.allUsers.length - admins
        } ${pluralize("user", jsonData.allUsers.length - admins)} who ${pluralize(
          "is",
          jsonData.allUsers.length - admins,
        )} not ${owner}. Based on your policy settings you should have at most ${greaterMin} ${pluralize("owner", greaterMin)}.`,
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
        [resourceType.allUsers],
        extraInfo,
        this.getCustomIssueId(`${jsonData.code_repo.type}_${org}_${orgId}`),
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
        ["Way too many owners", "75% of all users are owners"],
        getSeverityChanges(this.policyRuleMetadata.severity, changedSeverity),
        changeReasons,
      );

      let max = admins - greaterMin;

      if (data.length - max === 1) {
        max--;
      }

      const warning = `You may select up to a max of ${max} user${
        max == 1 ? "" : "s"
      }. This number was calculated to ensure you would still have an acceptable number of Owners.`;
      const description = "There are too many owners in the organization. Please select owners to remove or downgrade from the list below.";

      const dataSortedByMinimalActivity = data.reverse();

      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        item.fixes = generateFixesForUserOrgRoles(
          dataSortedByMinimalActivity,
          org,
          this.policyRuleMetadata,
          SettingType.changeOrgUserStatus,
          warning,
          description,
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

export function generateFixesForUserRepoPermissions(
  data: AdminsAggItem[],
  repo: Repo,
  policyRuleMetadata: Policy,
  settingType: string,
  warning: string,
  description,
  max: number,
  min: number,
  sourceCodeType: string,
  isAvaliableAuditLogs?: boolean,
  typeOfRole?: string,
) {
  try {
    if (max == 0) {
      logger.error(`failed to generate fixes, policy: ${policyRuleMetadata.name}, max is 0`);
      return;
    }
    const p: PolicyFix = new PolicyFix();
    p.description = description;
    p.settingType = settingType;
    p.warning = warning ? warning : "";
    p.confirmation = `Note: To later undo this action you will need to log in to ${getType(
      sourceCodeType,
    )}. You will not be able to undo this action through OX Security.\n\nWould you like to continue?`;

    const clone = data.slice();

    const input: Input = new Input();
    input.maxSelect = max >= 0 ? max : -1;
    input.minSelect = max >= 0 ? min : -1;
    input.type = "select";
    input.name = InputType.users;
    input.displayName = "Users";
    input.multiSelect = true;
    input.maxSelect = max;
    input.minSelect = min;

    let counter = max;

    const teams = repo.teams;
    const teamsToCheck = teams.filter(i => i.permission === "admin");
    input.options = clone.map(i => {
      let toolTipInfo = `Activity: Development - ${i.devOperation}, Review - ${i.reviewOperation}`;
      if (isAvaliableAuditLogs) {
        toolTipInfo = `Activity: Admin - ${i.adminOperation}, Development - ${i.devOperation}, Review - ${i.reviewOperation}`;
      }
      counter--;
      let isSelected = true;
      let isDisabled = false;
      let isMemberInTeam = false;
      let teamName = [];
      for (const team of teamsToCheck) {
        if (team.members.find(member => member === i.user)) {
          isMemberInTeam = true;
          teamName.push(team.slug);
        }
      }
      if (isMemberInTeam) {
        counter++;
        isSelected = false;
        isDisabled = true;
        toolTipInfo = `The user can not be downgraded or removed since he/she is a member of the ${teamName.join(",")} ${pluralize(
          "team",
          teamName.length,
        )}.`;
      }

      if (max != -1 && counter < 0) {
        isSelected = false;
      }

      const o: InputOption = new InputOption();
      o.name = i.userInfo.name;
      o.displayName = o.name;
      o.selected = isSelected;
      o.info = toolTipInfo;
      o.isDisabled = isDisabled;
      o.metadata = JSON.stringify({
        owner: repo.ownerNameApi,
        repo: repo.name,
        userName: i.userInfo.name,
        scanId: StatesHelper.Instance.uuid,
        orgId: StatesHelper.Instance.orgName,
      });
      return o;
    });
    p.inputs.push(input);

    const input2: Input = new Input();
    input2.type = "radio";
    input2.name = InputType.permissions;
    input2.displayName = "Downgrade Permission";
    if (policyRuleMetadata.functionName === "policyOutsideCollaboratorsWithNoActivityRepo") {
      input2.displayName = "Remove Outside Collaborators";
    }

    let o4: InputOption = new InputOption();
    const o1: InputOption = new InputOption();
    o1.name = "pull";
    o1.displayName = "Read";
    o1.info =
      "This is the least permissive of all repository roles. Users with this role can only read code and participate in discussions on a repository. They also can not push code to the repository.";
    o1.metadata = JSON.stringify({
      scanId: StatesHelper.Instance.uuid,
      orgId: StatesHelper.Instance.orgName,
    });
    const o2: InputOption = new InputOption();
    o2.name = "push";
    o2.selected = true;
    o2.displayName = "Write";
    o2.info = "This is the default role that developers who are actively pushing code to the repository should have.";
    o2.metadata = JSON.stringify({
      scanId: StatesHelper.Instance.uuid,
      orgId: StatesHelper.Instance.orgName,
    });
    if (!(typeOfRole === "maintainer")) {
      o4.name = "maintain";
      o4.displayName = "Maintain";
      o4.info =
        "Repository Maintainers have significant access to a repo. However, they are limited in the destructive actions that they can execute. They can not, for example, delete a repository.";
      o4.metadata = JSON.stringify({
        scanId: StatesHelper.Instance.uuid,
        orgId: StatesHelper.Instance.orgName,
      });
    }
    const o5: InputOption = new InputOption();
    o5.name = "triage";
    o5.displayName = "Triage";
    o5.info = "This is a role for users managing issues and pull requests. This does not allow a user to push code to the repository.";
    o5.metadata = JSON.stringify({
      scanId: StatesHelper.Instance.uuid,
      orgId: StatesHelper.Instance.orgName,
    });
    const o6: InputOption = new InputOption();
    o6.name = "remove user";
    o6.displayName = "Remove User";
    o6.info = "This option will remove the user’s access from the repository (if not inherited). Use with care!";
    o6.metadata = JSON.stringify({
      scanId: StatesHelper.Instance.uuid,
      orgId: StatesHelper.Instance.orgName,
    });
    if (policyRuleMetadata.functionName != "policyOutsideCollaboratorsWithNoActivityRepo") {
      input2.options.push(o1);
      input2.options.push(o2);
      if (!(typeOfRole === "maintainer")) {
        input2.options.push(o4);
      }
      input2.options.push(o5);
    }
    if (policyRuleMetadata.functionName === "policyOutsideCollaboratorsWithNoActivityRepo") {
      o6.selected = true;
    }
    input2.options.push(o6);
    p.inputs.push(input2);

    return p;
  } catch (e) {
    logger.error(`failed to generate fixes, policy: ${policyRuleMetadata.name}, error: ${e}`);
  }
}

export function getType(source: string) {
  if (source.toLowerCase() === "github") {
    return "GitHub";
  }
}

export function generateFixesForUserOrgRoles(
  data: AdminsAggItem[],
  org: string,
  policyRuleMetadata: Policy,
  settingType: string,
  warning: string,
  description: string,
  max: number,
  min: number,
  sourceCodeType: string,
  isAvaliableAuditLogs?: boolean,
  isOnlyOwner?: boolean,
) {
  try {
    if (isOnlyOwner) {
      return;
    }
    if (max == 0) {
      logger.error(`failed to generate fixes, policy: ${policyRuleMetadata.name}, max is 0`);
      return;
    }

    const p: PolicyFix = new PolicyFix();
    p.description = description;
    p.settingType = settingType;
    p.warning = warning ? warning : "";
    p.confirmation = `Note: To later undo this action you will need to log in to ${getType(
      sourceCodeType,
    )}. You will not be able to undo this action through OX Security.\n\nWould you like to continue?`;

    const memberTooltip =
      "The default, non-administrative role for people in an organization, is the organization member. Organization members can create repositories and project boards. They cannot set org-level settings or add/remove/modify org-level roles.";
    const removeUser = "This option will remove the user’s access from the organization and its associated repositories. Use with care!";

    const clone = data.slice();

    const input: Input = new Input();
    input.type = "select";
    input.name = InputType.users;
    input.displayName = "Users";
    input.multiSelect = true;
    input.minSelect = min;
    input.maxSelect = max;

    let counter = max;

    input.options = clone.map(i => {
      let toolTipInfo = `Development - ${i.devOperation}, Review - ${i.reviewOperation}`;
      if (isAvaliableAuditLogs) {
        toolTipInfo = `Activity: Admin - ${i.adminOperation}, Development - ${i.devOperation}, Review - ${i.reviewOperation}`;
      }
      counter--;
      let isSelected = true;
      if (max != -1 && counter < 0) {
        isSelected = false;
      }

      const o: InputOption = new InputOption();
      o.name = i.userInfo.name;
      o.displayName = o.name;
      o.selected = isSelected;
      o.info = toolTipInfo;
      o.metadata = JSON.stringify({
        org: org,
        userName: i.userInfo.name,
        scanId: StatesHelper.Instance.uuid,
        orgId: StatesHelper.Instance.orgName,
      });
      return o;
    });
    p.inputs.push(input);

    const input2: Input = new Input();
    input2.type = "radio";
    input2.name = InputType.permissions;
    input2.displayName = "Downgrade Permission";
    const o1: InputOption = new InputOption();
    o1.name = "member";
    o1.displayName = "Member";
    o1.info = memberTooltip;
    o1.selected = true;
    o1.metadata = JSON.stringify({
      scanId: StatesHelper.Instance.uuid,
      orgId: StatesHelper.Instance.orgName,
    });
    const o2: InputOption = new InputOption();
    o2.name = "remove user";
    o2.displayName = "Remove User";
    o2.info = removeUser;
    o2.metadata = JSON.stringify({
      scanId: StatesHelper.Instance.uuid,
      orgId: StatesHelper.Instance.orgName,
    });
    input2.options.push(o1);
    input2.options.push(o2);

    p.inputs.push(input2);

    return p;
  } catch (e) {
    logger.error(`failed to generate fixes, policy: ${policyRuleMetadata.name}, error: ${e}`);
  }
}

export class AdminsAggItem extends AggregatedInfoForExclusion {
  user: string;
  userLink: string = "";
  userAvatar: string = "";
  devOperation?: string = "No Activity";
  devOperationDate: string = "";
  reviewOperation?: string = "No Activity";
  reviewOperationDate: string = "";
  adminOperation?: string = "No Audit Log Access";
  adminOperationDate: string = "";
  lastAdminOperation?: string = "No Audit Log Access";
  orgRole: string = "";
  earliestActivityDate: string = "";
  repoPermissions: string = "";
  adminLocation: string = "";

  userInfo: User;

  getExclusionObj() {
    const i: AggregatedUser = new AggregatedUser();
    i.user = this.user;
    return i;
  }

  setAggId() {
    this.aggId = StringHelper.combineStrings(this.user);
    this.hashAggId = StringHelper.hashMd5(this.aggId);
  }
}

export default policyDspmMaxAdmins;
