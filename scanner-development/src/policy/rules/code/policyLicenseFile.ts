import pluralize from "pluralize";
import { Repo, repoType, File, repoResourceType, resourceType } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import loggerImport from "../../../logger";
import PolicyRulesBase, { Tool } from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class PolicyLicenseFile extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const repo: Repo = jsonData.code_repo;

      if (!repo.realRepo) {
        return [];
      }

      const licenseFileNames = this.getValueFromRuleArgs("licenseFileNames");
      const reposType = this.getValueFromRuleArgs("RepoType");
      const policyOnFile = this.getValueFromRuleArgs("fileDisplayName");
      const repoAdminRole = repo.gitRoles.repo.admin;
      const orgAdminRole = repo.gitRoles.org.admin;
      const privateVisability = repo.privateVisability;
      let filesNotInDesignatedDir: File[] = [];
      let emptyFiles: File[] = [];

      // this is only for codeowners file
      const branchProtectionRequired = this.getValueFromRuleArgs("branchProtection");
      const tools: Tool[] = [repoResourceType.specialFiles];
      if (branchProtectionRequired) {
        tools.push(repoResourceType.branchSettings);
        if (branchProtectionRequired === true && !jsonData.branchSettings.branchProtection) {
          return [];
        }
      }

      if ((reposType === "Private" && !privateVisability) || (reposType === "Public" && privateVisability)) {
        return [];
      }

      let issueOwner;
      let userIssueOwner = this.getAdminWithMaxOperations(jsonData.users, repoAdminRole, true);

      if (!userIssueOwner) {
        userIssueOwner = this.getAdminWithMaxOperations(jsonData.allUsers, orgAdminRole);
      }

      if (!userIssueOwner) {
        issueOwner = { name: repo.ownerName, email: repo.ownerEmail || "" };
      } else {
        issueOwner = {
          name: userIssueOwner.name,
          email: userIssueOwner.email || "",
        };
      }

      // build issue details
      let issueName = "";
      let secondTitle = "";
      let recommendation = "";

      let fixLink = jsonData.code_repo.link;
      const privatePublic = this.publicOrPrivate(repo);

      const fileItems = repo.specialFiles[policyOnFile.toUpperCase()];
      const hasValidFile = fileItems?.some(f => f.isValid);
      if (hasValidFile) {
        return [];
      } else {
        filesNotInDesignatedDir = fileItems?.filter(f => !f.isInValidDir) || [];
        emptyFiles = fileItems?.filter(f => f.isEmpty) || [];
      }

      switch (policyOnFile.toLowerCase()) {
        case "codeowners":
          if (!emptyFiles.length) {
            if (jsonData.branchSettings.branchProtection) {
              issueName = `CODEOWNERS file missing from ${privatePublic} repo with branch protection`;
            } else {
              issueName = `CODEOWNERS file missing from ${privatePublic} repo`;
            }
          } else {
            if (jsonData.branchSettings.branchProtection) {
              issueName = `CODEOWNERS file is empty in ${privatePublic} repo with branch protection`;
            } else {
              issueName = `CODEOWNERS file is empty in  ${privatePublic} repo`;
            }
          }
          const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);
          if (jsonData.branchSettings.branchProtection) {
            secondTitle = `A CODEOWNERS file is missing from the ${privatePublic} repo ${
              repo.name
            } with branch protection turned on. Defining a CODEOWNERS file allows you to specify the users who would be automatically assigned to review code in the repo.<br>
            The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;
          } else {
            secondTitle = `A CODEOWNERS file is missing from the ${privatePublic} repo ${
              repo.name
            }.  Defining a CODEOWNERS file allows you to specify the users who would be automatically assigned to review code in the repo. <br>
            The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;
          }

          recommendation = `Ensure that your repository has a CODEOWNERS file. Please maintain case as shown when creating the file. Create the file in one of the following folders: <br>
          &bull; root <br>
          &bull; .${repo.type.toLowerCase()}/ <br>
          &bull; docs/ `;
          break;

        case "license":
          issueName = `License file missing from ${privatePublic} repo`;
          if (emptyFiles.length) {
            issueName = `License file is empty in ${privatePublic} repo`;
          }
          secondTitle = `A license file is missing from the ${privatePublic} repo ${repo.name}. License files allow external users to identify if the files in a repo can be re-used or edited. Without a license file present, repos are considered NOT to be open source. `;
          recommendation = `Ensure that your repository has a license file. Typical names for license files can be LICENSE, LICENSE.md, LICENSE.txt and LICENSE.rst. Please maintain case as shown when creating the file. Also, please create the file in the top-level folder. `;
          break;

        case "security":
          issueName = `Security Policy missing from ${privatePublic} repo`;
          if (emptyFiles.length) {
            issueName = `Security Policy is empty in ${privatePublic} repo`;
          }
          secondTitle = `The SECURITY.md file (Security Policy) is missing from the ${privatePublic} repo ${repo.name}. This may discourage users who discover security vulnerabilities from reporting them. The Security Policy file\’s presence also indicates that you have a security vulnerability handling procedure in place.`;
          recommendation = `Ensure that your repository has a SECURITY.md file (Security Policy). Please maintain case as shown when creating the file. Create the file in one of the following folders: <br>
          &bull; root <br>
          &bull; .${repo.type.toLowerCase()}/ <br>
          &bull; docs/ `;
          break;
      }

      const item = this.generateItemForReport(
        true,
        issueName,
        secondTitle,
        "newVi",
        recommendation,
        "Code Change",
        "Code Repository",
        "",
        [],
        true,
        fixLink,
        [],
        [Constant.gitPosture],
        tools,
        [],
        this.getGeneralIssueId(),
        [issueOwner],
      );

      return [item];
    } catch (e) {
      `failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`;
    }
    return [];
  }
}

export default PolicyLicenseFile;
