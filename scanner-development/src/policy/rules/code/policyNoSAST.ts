import { AlertSeverity, Repo } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import ToolsConnectorsHelper from "../../../helper/tools/toolsConnectorsHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import { createItem } from "./policyUntouchedReposShouldBeArchived";

const logger = loggerImport.getDebugLogger();

class PolicyNoSAST extends PolicyRulesBase {
  async eval(jsonData) {
    const repo: Repo = jsonData.code_repo;

    if (repo.realRepo) {
      return [];
    }

    if (!jsonData.allOrgsRepos.length) {
      return [];
    }

    if (jsonData.code_repo.oxSecurityTools.oxSastTools.length > 0) {
      this.policyRuleMetadata.severity = AlertSeverity.Medium;
    }

    const securityToolsFromArgs = this.getValueFromRuleArgs("securityTools");
    if (!Array.isArray(securityToolsFromArgs)) {
      throw `securityTools is not array type, ${securityToolsFromArgs.toString()}`;
    }

    const ignoreIfOXSastEnabled = this.getValueFromRuleArgs("ignoreIfOXSastEnabled");
    if (ignoreIfOXSastEnabled) {
      const oxSastTools = jsonData.allOrgsRepos[0].oxSecurityTools.oxSastTools;
      for (const tool of oxSastTools) {
        const isOxSastEnabled = ToolsConnectorsHelper.Instance.getOXConnectorForTool(tool.name);
        if (isOxSastEnabled) {
          return [];
        }
      }
    }

    const data = [];
    for (const repo of jsonData.allOrgsRepos) {
      const sastFromPolicy = repo.sast.filter(
        sastTool => securityToolsFromArgs.some(sastArgs => sastArgs.toLowerCase() === sastTool.toLowerCase()) == true,
      );
      if (sastFromPolicy.length) {
        continue;
      }

      const item = createItem(repo);
      data.push(item);
    }

    if (!data.length) {
      return [];
    }
    const aggregated = {
      columns: "policyUntouchedReposShouldBeArchived",
      aggregatedItems: data,
    };

    let authApp: string = "";
    if (securityToolsFromArgs.length == 1) {
      authApp = `The authorized SAST app is ${securityToolsFromArgs[0]}`;
    } else {
      let apps: string = securityToolsFromArgs.join(", ");
      authApp = `The list of authorized SAST apps are ${apps}`;
    }

    let newVi = "Missing SAST";
    let appDeploy: string = `Please add to the repo's pipeline an authorized SAST app. ${authApp}`;

    // if (StatesHelper.Instance.githubSastEnable && !sastFromPolicy.length) {
    //   newVi += " - GitHub CodeQL is disabled for repo";
    //   appDeploy = `Please enable and configure CodeQL in repo settings > security and analysis`;
    // }

    let res = [];
    const issueOwners = this.getOwnersFromUsers(jsonData);

    res = [
      this.generateItemForReport(
        true,
        newVi,
        "",
        newVi,
        appDeploy,
        "N/A",
        "N/A",
        [],
        "",
        true,
        "",
        aggregated,
        [Constant.cicdPosture],
        ["UNKNOWN"],
        [],
        this.getGeneralIssueId(),
        issueOwners,
      ),
    ];

    return res;
  }
}

export default PolicyNoSAST;
