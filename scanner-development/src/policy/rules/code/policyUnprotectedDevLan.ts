import { AlertSeverity, IssueOwner, User, UserRole } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { ToolConfig } from "../../../entitis/tool/secuirtyToolsConfig";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class PolicyUnprotectedSASTDevLan extends PolicyRulesBase {
  async eval(jsonData) {
    if (!jsonData.code_repo.realRepo) {
      return [];
    }

    const scanTypeFromArgs = this.getValueFromRuleArgs("scanType");

    if (Array.isArray(scanTypeFromArgs)) {
      throw `scanType is array and not string type, ${scanTypeFromArgs.toString()}`;
    }

    let unprotectedDevLan = [];
    let oxSecTools: ToolConfig[] = [];
    let externalSecTools = [];
    if (scanTypeFromArgs.toLowerCase() === "sast") {
      unprotectedDevLan = jsonData.code_repo.unprotectedSastDevLanguages;
      oxSecTools = jsonData.code_repo.oxSecurityTools.oxSastTools;
      externalSecTools = jsonData.code_repo.sast;
    } else {
      //sca
      unprotectedDevLan = jsonData.code_repo.unprotectedScatDevLanguages;
      oxSecTools = jsonData.code_repo.oxSecurityTools.oxScaTools;
      externalSecTools = jsonData.code_repo.sca;
    }

    if (oxSecTools.length > 0) {
      this.policyRuleMetadata.severity = AlertSeverity.Medium;
    }

    let res = [];
    const uniqeLans = new Set<string>();
    for (const len of unprotectedDevLan) {
      const tolowerLan = len.language.toLowerCase();
      if (
        tolowerLan === "html" ||
        tolowerLan === "makefile" ||
        tolowerLan === "perl" ||
        tolowerLan === "shell" ||
        tolowerLan === "hcl" ||
        tolowerLan === "smarty" ||
        tolowerLan === "css" ||
        tolowerLan === "text" ||
        tolowerLan === "yml" ||
        tolowerLan === "yaml" ||
        tolowerLan === "markdown" ||
        tolowerLan === "json" ||
        tolowerLan === "ini" ||
        tolowerLan === "xml" ||
        tolowerLan === "sparql" ||
        tolowerLan === "rebol"
      )
        continue;

      if (len.languagePercentage < 10) {
        continue;
      }

      uniqeLans.add(len.language);

      const replaceInfo = [
        { replace: "*language_output*", replaceTo: len.language },
        { replace: "*percent*", replaceTo: len.languagePercentage },
        { replace: "*language*", replaceTo: len.language },
        { replace: "*typeInfo*", replaceTo: scanTypeFromArgs },
      ];

      let newVi = `Languages not covered by ${scanTypeFromArgs}: ${len.language}`;
      let recom: string = "Please consider adding a *typeInfo* app that supports language *language*.";

      const issueOwners = this.getOwnersFromUsers(jsonData);
      const item = this.generateItemForReport(
        true,
        newVi,
        "",
        newVi,
        recom,
        "*language_output*",
        "Repository Development Language",
        replaceInfo,
        "",
        true,
        "",
        [],
        [Constant.gitPosture],
        ["UNKNOWN"],
        [],
        this.getGeneralIssueId(),
        issueOwners,
      );
      res.push(item);
    }

    return res;
  }
}

export default PolicyUnprotectedSASTDevLan;
