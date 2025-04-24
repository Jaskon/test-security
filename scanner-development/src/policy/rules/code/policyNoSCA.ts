import PolicyRulesBase from "../code/policyRulesBase";
import { AlertSeverity, Repo } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import StatesHelper from "../../../helper/statesHelper";
import { createItem } from "./policyUntouchedReposShouldBeArchived";
import ToolsConnectorsHelper from "../../../helper/tools/toolsConnectorsHelper";

class PolicyNoSCA extends PolicyRulesBase {
  async eval(jsonData) {
    const repo: Repo = jsonData.code_repo;

    if (repo.realRepo) {
      return [];
    }

    if (!jsonData.allOrgsRepos.length) {
      return [];
    }

    if (jsonData.code_repo.oxSecurityTools.oxScaTools.length > 0) {
      this.policyRuleMetadata.severity = AlertSeverity.Medium;
    }

    const securityToolsFromArgs = this.getValueFromRuleArgs("securityTools");

    if (!Array.isArray(securityToolsFromArgs)) {
      throw `securityTools is not array type, ${securityToolsFromArgs.toString()}`;
    }

    const ignoreIfOXScaEnabled = this.getValueFromRuleArgs("ignoreIfOXScaEnabled");
    if (ignoreIfOXScaEnabled) {
      const oxScaTools = jsonData.allOrgsRepos[0].oxSecurityTools.oxScaTools;
      for (const tool of oxScaTools) {
        const isOxScaEnabled = ToolsConnectorsHelper.Instance.getOXConnectorForTool(tool.name);
        if (isOxScaEnabled) {
          return [];
        }
      }
    }

    const data = [];
    for (const repo of jsonData.allOrgsRepos) {
      const scaFromPolicy = repo.sca.filter(
        scaTool => securityToolsFromArgs.some(scaArgs => scaArgs.toLowerCase() === scaTool.toLowerCase()) == true,
      );
      if (scaFromPolicy.length) {
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
      authApp = `The authorized SCA app is ${securityToolsFromArgs[0]}`;
    } else {
      let apps: string = securityToolsFromArgs.join(", ");
      authApp = `The list of authorized SCA apps are ${apps}`;
    }

    let newVi = "Missing SCA";
    let appDeploy: string = `Please add to the repo's pipeline an authorized SCA app. ${authApp}`;

    // if (!scaFromPolicy.length && StatesHelper.Instance.dependabotEnable) {
    //   newVi += " - GitHub Dependabot is disabled for repo";
    //   appDeploy = `Please enable Dependabot in repo settings > security and analysis`;
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

export default PolicyNoSCA;
