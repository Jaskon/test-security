import { Repo, repoResourceType, repoType, User } from "../../../entitis/codeRepoTypes";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { Input, InputOption, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class PolicyPublicRepo extends PolicyRulesBase {
  async eval(jsonData) {
    const repo: Repo = jsonData.code_repo;
    if (!repo.realRepo) {
      return [];
    }

    if (repo.privateVisability) {
      return [];
    }

    const publicRepoNumber = Number(this.getValueFromRuleArgs("publicreponumber")) / 100;
    if (publicRepoNumber === undefined) {
      throw `publicRepoNumber is not exist`;
    }

    const checkLicense = this.getValueFromRuleArgs("checkLicense");

    //Public Repo Policy - If more than 25% of repos scanned are public then this policy should be ignored
    const reposNumber = StatesHelper.Instance.publicReposCount / StatesHelper.Instance.numberOfApps;
    if (reposNumber >= publicRepoNumber) {
      return [];
    }

    const tools = [];
    if (checkLicense[0] === "True") {
      // check for license file
      tools.push(repoResourceType.specialFiles);
      const license = repo.specialFiles["LICENSE"];
      const hasValidFile = license?.some(f => f.isValid);
      if (hasValidFile) {
        return [];
      }
    }

    let fixLink = jsonData.code_repo.settingLink;
    if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
      fixLink = jsonData.code_repo.settingLink.concat("#danger-zone");
    }

    let issueDescription = `The repository ${jsonData.code_repo.name} was found to have public visibility. This means that all the code in the repository is not private. `;
    if (checkLicense[0] === "True") {
      issueDescription += `There was no license file found indicating that this may not be a repo that you wanted to expose publicly.`;
    }

    const orgAdminRole = jsonData.code_repo.gitRoles.org.admin.toLowerCase();
    const repoAdminRole = jsonData.code_repo.gitRoles.repo.admin.toLowerCase();
    let issueOwner;
    let userIssueOwner = this.getAdminWithMaxOperations(jsonData.users as User[], repoAdminRole, true);

    if (!userIssueOwner) {
      jsonData.allUsers = jsonData.allUsers[jsonData.code_repo.organization] || [];
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
    let secondTitle = `The repository ${repo.name} was found to have public visibility. This means that all the code in the repository is viewable by anyone outside your organization. <br>
     The repository was created at: ${repo.createdAt}.`;
    if (checkLicense[0] === "True") {
      secondTitle += `There was no license file found indicating that this may not be a repo that you wanted to expose publicly. <br>`;
    }
    let res = [];
    res = [
      this.generateItemForReport(
        true,
        "Public repo",
        secondTitle,
        "Public repo",
        "Please change repository access to private",
        "N/A",
        "N/A",
        [],
        "Public repository can be cloned by anyone without authentication",
        true,
        fixLink,
        [],
        [Constant.gitPosture],
        tools,
        [],
        this.getGeneralIssueId(),
        issueOwner,
      ),
    ];

    if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
      res[0].fixes = this.generateFixes([jsonData.code_repo as Repo]);
    }

    return res;
  }

  generateFixes(data: Repo[]) {
    try {
      const p: PolicyFix = new PolicyFix();
      p.description = "The repository has public visibility. Would you like to make the repository private?";
      p.settingType = SettingType.setRepoToPrivate;
      p.confirmation =
        "After this fix only organization members and explicitly added Outside Collaborators will be able to access the repo.";
      p.tooltip = "";
      p.warning = "";

      const input: Input = new Input();
      input.type = "radio";
      input.name = InputType.repos;
      input.displayName = "Change the following repository’s visibility to private";
      input.multiSelect = true;

      input.options = data.map(i => {
        const o: InputOption = new InputOption();
        o.name = i.name;
        o.displayName = o.name;
        o.selected = true;
        o.metadata = JSON.stringify({
          owner: i.ownerNameApi,
          repo: i.name,
          scanId: StatesHelper.Instance.uuid,
          orgId: StatesHelper.Instance.orgName,
        });
        return o;
      });
      p.inputs.push(input);

      return p;
    } catch (e) {
      logger.error(`failed to generate fixes, policy: ${this.policyRuleMetadata.name}, error: ${e}`);
    }
  }
}

export default PolicyPublicRepo;
