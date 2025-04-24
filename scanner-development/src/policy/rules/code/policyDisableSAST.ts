import PolicyRulesBase from "./policyRulesBase";
import { AlertSeverity } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";

class PolicyDisableSAST extends PolicyRulesBase {
  async eval(jsonData) {
    if (!jsonData.code_repo.realRepo) {
      return [];
    }

    if (jsonData.code_repo.oxSecurityTools.oxSastTools.length > 0) {
      this.policyRuleMetadata.severity = AlertSeverity.Medium;
    }

    const securityToolsFromArgs = this.getValueFromRuleArgs("securityTools");
    if (!Array.isArray(securityToolsFromArgs)) {
      throw `securityTools is not array type, ${securityToolsFromArgs.toString()}`;
    }

    const enableSecurityTools = [];
    const disableSecurityTools = [];
    for (const securityToolFromArgs of securityToolsFromArgs) {
      for (const sast of jsonData.code_repo.sast) {
        if (sast.toLowerCase() === securityToolFromArgs.toLowerCase()) {
          enableSecurityTools.push(sast);
        }
      }
    }
    for (const securityToolFromArgs of securityToolsFromArgs) {
      for (const sast of jsonData.code_repo.disableSast) {
        if (sast.toLowerCase() === securityToolFromArgs.toLowerCase()) {
          disableSecurityTools.push(sast);
        }
      }
    }

    let res = [];
    if (enableSecurityTools.length == 0 && disableSecurityTools.length > 0) {
      for (const securityTool of disableSecurityTools) {
        const replaceInfo = [{ replace: "*SAST*", replaceTo: securityTool }];
        const newVi = "SAST disabled: *SAST*";
        const issueOwners = this.getOwnersFromUsers(jsonData);
        const item = this.generateItemForReport(
          true,
          newVi,
          "",
          newVi,
          "Please re-enable the SAST app: *SAST*",
          "*SAST*",
          "SAST Tool",
          replaceInfo,
          "",
          true,
          "",
          [],
          [Constant.cicdPosture],
          ["UNKNOWN"],
          [],
          this.getGeneralIssueId(),
          issueOwners,
        );
        res.push(item);
      }
    }

    return res;
  }
}

export default PolicyDisableSAST;
