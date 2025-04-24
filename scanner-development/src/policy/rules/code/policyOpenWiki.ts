import { Repo, repoType } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class PolicyOpenWiki extends PolicyRulesBase {
  async eval(jsonData) {
    if (!jsonData.code_repo.realRepo) {
      return [];
    }

    const repo: Repo = jsonData.code_repo;
    if (!repo.openWiki) {
      return [];
    }

    let fixLink = repo.settingLink;
    if (repo.type.toLowerCase() === repoType.github) {
      fixLink = repo.settingLink.concat("#features");
    }

    const issueOwners = this.getOwnersFromUsers(jsonData);
    let res = [];
    if (repo.privateVisability == false) {
      const privateOrPublic = this.publicOrPrivate(repo) === "private" ? "Private" : "Public";

      res = [
        this.generateItemForReport(
          true,
          `${privateOrPublic} wiki for repo is editable by anyone`,
          `${privateOrPublic} wiki for repo is editable by anyone. This means that anyone can create ${
            repo.type.toLowerCase() === repoType.azure ? "an" : "a"
          } ${repo.type} account and then add links in the wiki pointing to malware.`,
          "",
          `Allow only project collaborators to edit the wiki:\\
          1. [Go to your repository settings](${fixLink})
          2. Scroll to the "Features" section
          3. Check "Restrict editing to collaborators only"`,
          "N/A",
          "N/A",
          [],
          "",
          true,
          fixLink,
          [],
          [Constant.gitPosture],
          [],
          [],
          this.getGeneralIssueId(),
          issueOwners,
          "https://www.crowdstrike.com/blog/how-threat-actors-use-github-repositories-to-deploy-malware/",
        ),
      ];
    }

    return res;
  }
}

export default PolicyOpenWiki;
