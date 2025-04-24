import PolicyRulesBase from "./policyRulesBase";
import { AlertSeverity } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";

class PolicyDisableSCA extends PolicyRulesBase {
  async eval(jsonData) {
    if (!jsonData.code_repo.realRepo) {
      return [];
    }

    if (jsonData.code_repo.oxSecurityTools.oxScaTools.length > 0) {
      this.policyRuleMetadata.severity = AlertSeverity.Medium;
    }

    const securityToolsFromArgs = this.getValueFromRuleArgs("securityTools");
    if (!Array.isArray(securityToolsFromArgs)) {
      throw `securityTools is not array type, ${securityToolsFromArgs.toString()}`;
    }

    const enableSecurityTools = [];
    const disableSecurityTools = [];
    for (const securityToolFromArgs of securityToolsFromArgs) {
      for (const sca of jsonData.code_repo.sca) {
        if (sca.toLowerCase() === securityToolFromArgs.toLowerCase()) {
          enableSecurityTools.push(sca);
        }
      }
    }
    for (const securityToolFromArgs of securityToolsFromArgs) {
      for (const sca of jsonData.code_repo.disableSca) {
        if (sca.toLowerCase() === securityToolFromArgs.toLowerCase()) {
          disableSecurityTools.push(sca);
        }
      }
    }

    let res = [];
    if (enableSecurityTools.length == 0 && disableSecurityTools.length > 0) {
      for (const securityTool of disableSecurityTools) {
        const replaceInfo = [{ replace: "*SCA*", replaceTo: securityTool }];
        const newVi = "SCA disabled: *SCA*";
        const issueOwners = this.getOwnersFromUsers(jsonData);
        const item = this.generateItemForReport(
          true,
          newVi,
          "",
          newVi,
          "Please re-enable the SCA app: *SCA*.",
          "*SCA*",
          "SCA Tool",
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

export default PolicyDisableSCA;
