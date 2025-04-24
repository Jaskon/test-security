import pluralize from "pluralize";
import { AlertSeverity, Repo, repoType, User } from "../../../entitis/codeRepoTypes";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { ChangeCategory, ChangeReason, severityReasons } from "../../../entitis/service/blameTypes";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import { Input, InputOption, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class policyBotNoOrgAdmin extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const repo: Repo = jsonData.code_repo;
      let codeOwnersApplied = false;
      if (!repo.realRepo || !repo.workflowPermissions) {
        return [];
      }

      // run policy only if git type is supported
      if (jsonData.code_repo.type.toLowerCase() !== repoType.github) {
        return [];
      }

      const reposType = this.getValueFromRuleArgs("RepoType");
      const branchProtectionRequired = this.getValueFromRuleArgs("branchProtection");

      if (branchProtectionRequired && !jsonData.branchSettings.branchProtection) {
        return [];
      }

      if (jsonData.branchSettings.branchProtection && jsonData.branchSettings.codeOwnerApproval) {
        codeOwnersApplied = true;
      }

      if ((reposType === "Private" && !repo.privateVisability) || (reposType === "Public" && repo.privateVisability)) {
        return [];
      }

      if (!repo.defaultWorkflowPermissions?.can_approve_pull_request_reviews || !repo.workflowPermissions?.enabled) {
        return [];
      }

      // get correct role names for github org and repo level
      const orgAdminRole = jsonData.code_repo.gitRoles.org.admin.toLowerCase();
      const repoAdminRole = jsonData.code_repo.gitRoles.repo.admin.toLowerCase();

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

      const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);
      const severity = codeOwnersApplied ? AlertSeverity.Info : this.policyRuleMetadata.severity;
      const issueName = `GitHub Actions can be used to bypass code reviews`;
      const description = `GitHub Actions can be used to bypass code reviews. This means that a compromise of a single account may allow an adversary to push their own code directly into the repository.<br>
       The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;
      const fixLink = `${repo.link}/settings/actions`;
      const recommendationNoCodeOwners = `It is recommended to disable the setting that allows GitHub Actions to impersonate a code reviewer. <br>
      &bull; Go to [repo settings > actions page](${fixLink}). <br>
      &bull; Scroll to bottom to workflow permissions section' and uncheck "Allow GitHub Actions to create and approve pull requests". <br>
      &bull; Click Save.`;

      const recommendationCodeOwners = `GitHub Actions can not be used for code reviews because branch protection with required reviews from Code Owners is enabled.<br>
However, you should also explicitly prevent GitHub Actions from doing code reviews using the instructions below for additional security. <br>
      &bull; Go to [repo settings > actions page](${fixLink}). <br>
      &bull; Scroll to bottom to workflow permissions section' and uncheck "Allow GitHub Actions to create and approve pull requests". <br>
      &bull; Click Save.`;

      const recommendation = codeOwnersApplied ? recommendationCodeOwners : recommendationNoCodeOwners;
      const descriptionCodeOwners = `The repo's GitHub Actions settings option that allows it to do code reviews is enabled. However, GitHub Actions can not be used for code reviews because branch protection with required reviews from Code Owners is enabled.<br>
       The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;
      const secondTitle = codeOwnersApplied ? descriptionCodeOwners : description;

      const changeReason: ChangeReason = new ChangeReason(
        "Override Settings",
        "The setting value is overridden by another setting or configuration or is not applicable",
        -3,
        ChangeCategory.Reachable,
      );
      const changeReasons = [];
      if (codeOwnersApplied) {
        changeReasons.push(changeReason);
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
        [],
        [Constant.cicdPosture],
        ["UNKNOWN"], // roman fill cicd
        [],
        this.getCustomIssueId(`${jsonData.code_repo.type}`),
        [issueOwner],
        "",
        "",
        [],
        "",
        [],
        severity,
        [],
        "",
        "",
        [],
        getSeverityChanges(this.policyRuleMetadata.severity, severity),
        changeReasons,
      );

      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        item.fixes = this.generateFixes(repo);
      }

      const bp = "";
      return [item];
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
    return [];
  }

  generateFixes(repo: Repo) {
    try {
      const p: PolicyFix = new PolicyFix();
      p.description = "This action will prevent creation and approval of pull requests by GitHub Actions.";
      p.settingType = SettingType.changeCiCdBot;
      p.confirmation = "After this fix, GitHub Actions will not have the permissions to create and approve pull requests.";
      p.tooltip = "Update GitHub Actions permissions";

      const input: Input = new Input();
      input.type = "radio";
      input.name = InputType.settingsOption;
      input.displayName = "Fix Options";

      const o1: InputOption = new InputOption();
      o1.name = "Repo settings";
      o1.displayName = `'${repo.name}' repo only`;
      o1.info = "This will update GitHub Actions permissions for this repo only.";
      o1.metadata = JSON.stringify({
        repo: repo.name,
        owner: repo.ownerNameApi,
        org: repo.organization,
        scanId: StatesHelper.Instance.uuid,
        orgId: StatesHelper.Instance.orgName,
      });
      const o2: InputOption = new InputOption();
      o2.name = "Organization settings";
      o2.selected = true;
      o2.displayName = `All repos in '${repo.organization}' org`;
      o2.info = "This will update GitHub Actions permissions for all repos in the organization.";
      o2.metadata = JSON.stringify({
        repo: repo.name,
        owner: repo.ownerNameApi,
        org: repo.organization,
        scanId: StatesHelper.Instance.uuid,
        orgId: StatesHelper.Instance.orgName,
      });
      input.options.push(o1);
      input.options.push(o2);
      p.inputs.push(input);

      return p;
    } catch (e) {
      logger.error(`failed to generate fixes, policy: ${this.policyRuleMetadata.name}, error: ${e}`);
    }
  }
}

export default policyBotNoOrgAdmin;
