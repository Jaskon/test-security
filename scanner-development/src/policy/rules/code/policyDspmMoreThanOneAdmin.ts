import { repoType, resourceType, User } from "../../../entitis/codeRepoTypes";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { Severity } from "../../../entitis/reportTypes";
import { severityReasons } from "../../../entitis/service/blameTypes";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import { Input, InputOption, Policy, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { getType } from "./policyDspmMaxAdmins";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class policyDspmMoreThanOneAdmin extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      if (jsonData.code_repo.realRepo || !jsonData.allUsers.length) {
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
      if (!jsonData.allUsers) {
        return [];
      }
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(jsonData.code_repo.org);
      const res = [];
      const extraInfo = [];
      const minUsers = this.getValueFromRuleArgs("minUsers");

      // get correct role names for github org and repo level
      const orgAdminRole = jsonData.code_repo.gitRoles.org.admin.toLowerCase();

      let changedSeverity = this.policyRuleMetadata.severity;
      let changeReason = null;

      let admins = 0;
      let data: User[] = [];

      for (const user of jsonData.allUsers as User[]) {
        const userOrgRoles = Array.from(user.orgRole) as string[];

        if (userOrgRoles.find(i => i.toLowerCase() === orgAdminRole)) {
          admins++;
          data.push(user);
        }
      }

      if (jsonData.allUsers.length < minUsers || admins > 1) {
        return [];
      }

      if (jsonData.allUsers.length > 100) {
        changedSeverity = changedSeverity + 1;
        changeReason = severityReasons.LargeNumberOfUsers;
      }

      extraInfo.push({
        key: "Total Owners",
        value: `${admins}`,
      });
      extraInfo.push({
        key: "Total Users",
        value: `${jsonData.allUsers.length}`,
      });

      const withLastActivity = data.filter(i => i.lastActivityData);
      const withoutLastActivity = data.filter(i => !i.lastActivityData);
      const withLastActivitySorted = withLastActivity.sort((a, b) => b.lastActivityData.getTime() - a.lastActivityData.getTime());
      data = [...withLastActivitySorted, ...withoutLastActivity];

      const issueOwner = { name: data[0].name, email: data[0].name || "" };
      const org = jsonData.code_repo.org;
      const orgId = jsonData.code_repo.orgId;

      let newVi = "";
      let fixLink = "";
      let recommendation = "";
      let issueDesc = "";
      switch (gitType) {
        case repoType.azure:
          fixLink = `https://dev.azure.com/${org}/_settings/groups`;
          newVi = `There are too many owners assigned to manage the ${jsonData.code_repo.type} organization.`;
          recommendation = `Please consider adding another org owner to provide redundancy. <br>
            1. Enter the [link](${fixLink}) <br>
            2. Click 'Add' button on the top right <br>
            3. Enter a member email/username <br>
            4. Click the 'Save' button`;

          issueDesc = `${issueOwner.name} is the only org owner available to manage ${jsonData.allUsers.length} users. Please consider adding another org owner to provide redundancy.`;
          break;

        case repoType.github:
          fixLink = `https://github.com/orgs/${org}/people`;
          newVi = `There are too many owners assigned to manage the ${jsonData.code_repo.type} organization.`;
          recommendation = `Please consider adding another org owner to provide redundancy. <br>
            1. Enter the [link](${fixLink}) <br>
            2. Click 'Invite Member' button on the top right <br>
            3. Enter a member email/username <br>
            4. Click the 'Invite' button`;

          issueDesc = `${issueOwner.name} is the only org owner available to manage ${jsonData.allUsers.length} users. Please consider adding another org owner to provide redundancy.`;
          break;

        case repoType.gitlab:
          fixLink = `https://gitlab.com/groups/${org}/-/group_members`;
          newVi = `There are too many owners assigned to manage the ${jsonData.code_repo.type} first-level group.`;
          recommendation = `Please consider adding another group owner to provide redundancy. <br>
            1. Enter the [link](${fixLink}) <br>
            2. Click 'Invite Member' button on the top right <br>
            3. Enter a member email/username <br>
            4. Click the 'Invite' button`;

          issueDesc = `${issueOwner.name} is the only group owner available to manage ${jsonData.allUsers.length} users. Please consider adding another group owner to provide redundancy.`;
          break;

        case repoType.bitbucket:
          fixLink = `https://bitbucket.org/${org}/workspace/settings/groups`;
          newVi = `There are too many owners assigned to manage the ${jsonData.code_repo.type} workspace.`;
          recommendation = `Please consider adding another workspace owner to provide redundancy. <br>
              1. Enter the [link](${fixLink}) <br>
              2. Click on a group with an "Admin" tag <br>
              3. Click on "Add members" <br>
              4. Enter a member email/username and click "Confirm"`;

          issueDesc = `${issueOwner.name} is the only workspace owner available to manage ${jsonData.allUsers.length} users. Please consider adding another worksapce owner to provide redundancy.`;
          break;
      }

      let orgType;

      switch (gitType) {
        case repoType.github:
          orgType = "Org";
          break;

        case repoType.gitlab:
          orgType = "First-level group";
          break;

        case repoType.bitbucket:
          orgType = "Workspace";
          break;

        case repoType.azureGit || repoType.azure:
          orgType = "Org";
          break;
      }

      const item = this.generateItemForReport(
        true,
        `${orgType} ${org} needs more than 1 owner`,
        issueDesc,
        newVi,
        recommendation,
        "Code Change",
        "Code Repository",
        "",
        [],
        true,
        fixLink,
        [],
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
        [],
        getSeverityChanges(this.policyRuleMetadata.severity, changedSeverity),
        [],
      );
      res.push(item);

      if (gitType === repoType.github && auditLogsAvailable) {
        const relevantUsers = jsonData.allUsers.filter(i => !i.affiliation.has("outside") && !i.orgRole.has("Owner"));
        const sorted = relevantUsers.sort((a, b) => b.repoAdminActivity.length - a.repoAdminActivity.length);
        const data = [];
        for (const user of sorted) {
          let item = { name: user.name, adminOperation: "", devOperation: "", reviewOperation: "" };
          if (user.foundAdminData) {
            item.adminOperation = this.getUserActivityBasedPretty(user.adminOperation, user.adminOperationDate);
          } else {
            item.adminOperation = "No Activity";
          }
          if (user.foundDevData) {
            item.devOperation = this.getUserActivityBasedPretty(user.devOperation, user.devOperationDate);
          } else {
            item.devOperation = "No Activity";
          }

          if (user.foundReviewData) {
            item.reviewOperation = this.getUserActivityBasedPretty(user.reviewOperation, user.reviewOperationDate);
          } else {
            item.reviewOperation = "No Activity";
          }
          data.push(item);
        }

        item.fixes = this.generateFixesForUserUpgradeOrgRole(data, jsonData.code_repo.type.toLowerCase(), org, this.policyRuleMetadata);
      }

      return res;
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
    return [];
  }
  generateFixesForUserUpgradeOrgRole(data, sourceType, org: string, policyRuleMetadata: Policy) {
    try {
      const p: PolicyFix = new PolicyFix();
      p.description = "This will update the user organization role to owner";
      p.settingType = SettingType.upgradeOrgUserRole;
      p.confirmation = `Note: To later undo this action you will need to log in to ${getType(
        sourceType,
      )} . You will not be able to undo this action through OX Security.\n\nWould you like to continue?`;

      const clone = data.slice();
      let count = 0;

      const input: Input = new Input();
      input.type = "select";
      input.name = InputType.users;
      input.displayName = "Users";
      input.multiSelect = true;
      input.minSelect = 1;

      input.options = clone.map(i => {
        let isSelected = false;
        count++;
        const toolTipInfo = `Activity: Admin - ${i.adminOperation}, Development - ${i.devOperation}, Review - ${i.reviewOperation}`;
        if (count == 1) {
          isSelected = true;
        }
        const o: InputOption = new InputOption();
        o.name = i.name;
        o.displayName = o.name;
        o.selected = isSelected;
        o.info = toolTipInfo;
        o.metadata = JSON.stringify({
          org: org,
          userName: i.name,
          scanId: StatesHelper.Instance.uuid,
          orgId: StatesHelper.Instance.orgName,
        });
        return o;
      });
      p.inputs.push(input);
      return p;
    } catch (e) {
      logger.error(`failed to generate fixes, policy: ${policyRuleMetadata.name}, error: ${e}`);
    }
  }
}

export default policyDspmMoreThanOneAdmin;
