import { AlertSeverity, DevLanguages, IssueOwner, Repo, User, UserRole } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { ToolConfig } from "../../../entitis/tool/secuirtyToolsConfig";
import { ToolNameForUI } from "../../../entitis/tool/toolsTypes";
import StatesHelper from "../../../helper/statesHelper";
import ToolsConnectorsHelper from "../../../helper/tools/toolsConnectorsHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import { createItem, RepoOfOrgAggItem } from "./policyUntouchedReposShouldBeArchived";

const logger = loggerImport.getDebugLogger();

class policyNoSecrets extends PolicyRulesBase {
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

    const ignoreIfOXSecretsEnabled = this.getValueFromRuleArgs("ignoreIfOXSecretsEnabled");

    if (ignoreIfOXSecretsEnabled) {
      const oxSecretsTools = jsonData.allOrgsRepos[0].oxSecurityTools.oxSecretsTools;
      for (const tool of oxSecretsTools) {
        const isOxSecretsEnabled = ToolsConnectorsHelper.Instance.getOXConnectorForTool(tool.name);
        if (isOxSecretsEnabled) {
          return [];
        }
      }
    }

    const data = [];
    for (const repo of jsonData.allOrgsRepos) {
      const secretsFromPolicy = repo.secrets.filter(
        secretsTool => securityToolsFromArgs.some(sastArgs => sastArgs.toLowerCase() === secretsTool.toLowerCase()) == true,
      );
      if (secretsFromPolicy.length) {
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
      authApp = `The authorized secret scanning app is ${securityToolsFromArgs[0]}`;
    } else {
      let apps: string = securityToolsFromArgs.join(", ");
      authApp = `The list of authorized secret scanning apps are ${apps}`;
    }

    let newVi = "Missing Secrets";
    let appDeploy: string = `Please add to the repo's pipeline an authorized secret scanning app. ${authApp}`;

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

export default policyNoSecrets;
