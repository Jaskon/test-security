import { IssueOwner, User, UserRole } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";

const util = require("util");

class policyWebhookCICD extends PolicyRulesBase {
  async eval(jsonData) {
    let res = [];
    if ("repoName" in jsonData.repositories) {
      if (!jsonData.repositories.webhookTriggered) {
        const issueOwners = this.getOwnersFromUsers(jsonData);
        const item = this.generateItemForReport(
          true,
          "The repo has one or more commits that did not trigger a CI/CD job.",
          "",
          "The repo has one or more commits that did not trigger a CI/CD job.",
          "Please review all the previous commits and ensure that the build pipeline is not bypassed.",
          "CI/CD",
          "System",
          "",
          "",
          true,
          "",
          [],
          [Constant.cicdPosture],
          ["UNKNOWN"],
          [],
          this.getGeneralIssueId(),
        );
        res.push(item);
      }
    }
    return res;
  }
}

export default policyWebhookCICD;
