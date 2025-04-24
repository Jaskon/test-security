import { Repo, repoResourceType, repoType, User } from "../../../entitis/codeRepoTypes";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { BranchProtectionRule, changedValues } from "../../../helper/service/auto-fix-service/updateBranchProtectionRule";
import { Input, InputOption, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { checkingListsValidForUpdate, creatingFixedRule } from "./policyLimitBranchDeletionsToAdmins";
import PolicyRulesBase from "./policyRulesBase";
const logger = loggerImport.getDebugLogger();

class policyRequireSignedCommits extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const gitType = jsonData.code_repo.type.toLowerCase();
      const repoTypes = this.getValueFromRuleArgs("RepoType");
      const repo = jsonData.code_repo;
      const privateVisability = repo.privateVisability;

      if (!jsonData.code_repo.realRepo) {
        return [];
      }

      let shouldRunPolicy = false;
      let fixLink;
      if (gitType === repoType.github) {
        fixLink = repo.settingLink.concat("/branches");
        shouldRunPolicy = true;
      }

      if (gitType === repoType.gitlab) {
        fixLink = `${repo.link}/-/settings/repository`;
        shouldRunPolicy = true;
      }

      if (!shouldRunPolicy) {
        return [];
      }

      if ((repoTypes === "Private" && !privateVisability) || (repoTypes === "Public" && privateVisability)) {
        return [];
      }

      const users = jsonData.users;
      const branchSettings = jsonData.branchSettings;
      const signedCommits = branchSettings.requiredSignedCommits;
      const isBranchProtection = branchSettings.branchProtection;

      // if there was no branch protection rule at all, we are not violating
      if (!isBranchProtection) {
        return [];
      }

      const defaultBranchName = repo.defaultBranch;

      if (signedCommits) {
        return [];
      }

      const adminRole = repo.gitRoles.repo.admin.toLowerCase();
      const orgAdminRole = repo.gitRoles.org.admin.toLowerCase();
      let userIssueOwner = this.getAdminWithMaxOperations(users as User[], adminRole, true);
      if (!userIssueOwner) {
        userIssueOwner = this.getAdminWithMaxOperations(jsonData.allUsers as User[], orgAdminRole);
      }
      if (!userIssueOwner) {
        userIssueOwner = { name: repo.ownerName, email: repo.ownerEmail || "" };
      }

      let issueName, issueDesc, recommendation;

      switch (gitType) {
        case repoType.github:
          issueName = "Signed commits are not being enforced";
          issueDesc = `Signing commits improves security by verifying the identity of the author of the commit.  Currently, the protected branch of this repo does not enforce signed commits. <br> <br>
           The repo was created ${this.dateToDaysNow(repo.createdAt)} days ago`;

          recommendation = `It is highly recommended that repos for which you are turning on branch protection also enforce signed commits. To enforce this please follow the instructions below: <br>
            1. Enter the [link](${fixLink}) <br>
            2. If you don't have any rules for ${defaultBranchName} <br>
              &bull; Click 'Add rule' and under 'Branch name pattern' type ${defaultBranchName}. Otherwise: <br>
              &bull; Click on 'Edit' for the rule applied to ${defaultBranchName} <br>
            3. Check the box of 'Require signed commits' <br>`;
          break;

        case repoType.gitlab:
          issueName = "Signed commits are not being enforced";
          issueDesc = `Signing commits improves security by verifying the identity of the author of the commit.  Currently, the protected branch of this project does not enforce signed commits. <br> <br>
          The repo was created ${this.dateToDaysNow(repo.createdAt)} days ago`;
          recommendation = `It is highly recommended that projects for which you are turning on branch protection also enforce signed commits. To enforce this please follow the instructions below: <br>
            1. Enter the [link](${fixLink}) <br>
            2. Click on "Push rules" <br>
            3. Check the box of 'Reject unsigned commits' <br>`;
          break;
      }

      const rule = branchSettings.rule;

      const item = this.generateItemForReport(
        true,
        issueName,
        issueDesc,
        issueDesc,
        recommendation,
        "N/A",
        "N/A",
        "",
        "",
        true,
        fixLink,
        [],
        [Constant.gitPosture],
        [repoResourceType.branchSettings],
        [],
        this.getGeneralIssueId(),
        [userIssueOwner],
      );
      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        let fixedRule = creatingFixedRule(rule, this.policyRuleMetadata.name);

        if (fixedRule) {
          fixedRule.signedCommits = true;
        }

        item.fixes = this.generateFixes(repo, defaultBranchName, fixedRule, isBranchProtection);
      }
      return [item];
    } catch (e) {
      const repoName = jsonData.code_repo.fullName;
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}, repo: ${repoName}`);
    }
    return [];
  }

  generateFixes(repo: Repo, branch: string, fixedRule: BranchProtectionRule, hasRule: boolean) {
    try {
      // in case we couldn't create a fixed rule to send
      if (!fixedRule || (!fixedRule.requiredPullRequestReviews && fixedRule.requiredPullRequestReviews != null)) {
        return;
      }
      //in case we couldn't create lists to send / couldn't determine if the lists are valid
      if (!checkingListsValidForUpdate(fixedRule, this.policyRuleMetadata.name, repo.fullName)) {
        return;
      }

      const p: PolicyFix = new PolicyFix();
      p.description = "This action will add to the protected branch the requirement to sign commits.";
      p.settingType = SettingType.setRepoBranchProtectionForAddingSignedCommits;
      p.confirmation = "After this fix the protected branch will require signed commits.";
      p.tooltip = "Require signed commits";

      const input: Input = new Input();
      input.type = "select";
      input.name = InputType.branch;
      input.displayName = "Branch";
      const o: InputOption = new InputOption();
      o.name = branch;
      o.displayName = branch;
      o.selected = true;
      o.metadata = JSON.stringify({
        owner: repo.ownerNameApi,
        repo: repo.name,
        branch: branch,
        fixedRule: fixedRule,
        changedValues: [changedValues.SignedCommits],
        hasRule: hasRule,
        scanId: StatesHelper.Instance.uuid,
        orgId: StatesHelper.Instance.orgName,
      });

      input.options.push(o);
      p.inputs.push(input);

      return p;
    } catch (e) {
      logger.error(`failed to generate fixes, policy: ${this.policyRuleMetadata.name}, error: ${e}`);
    }
  }
}
export default policyRequireSignedCommits;
