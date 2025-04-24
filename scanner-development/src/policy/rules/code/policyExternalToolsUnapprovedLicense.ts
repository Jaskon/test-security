import { IssueOwner, SecurityAlertType, SecurityEvent } from "../../../entitis/codeRepoTypes";
import { SeverityChange } from "../../../entitis/service/blameTypes";
import PolicyRulesBase, { Tool } from "./policyRulesBase";
import loggerImport from "../../../logger";
import { isDevelopment } from "../../../helper/envUtils";
import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
const logger = loggerImport.getDebugLogger();

class PolicyExternalToolsLicenseViolations extends PolicyRulesBase {
  async eval(jsonData) {
    let res = [];
    if (jsonData.securityEvents.length === 0) {
      return [];
    }
    const securityEvents = jsonData.securityEvents as SecurityEvent[];
    for (const securityEvent of securityEvents) {
      if (securityEvent.securityAlertType === SecurityAlertType.license) {
        let extraInfo = [];
        extraInfo.push({
          key: "Target File",
          value: `${securityEvent.link}`,
        });
        extraInfo.push({
          key: "Rule ID",
          value: `${securityEvent.ruleId}`,
        });
        extraInfo.push({
          key: "URL",
          value: `${securityEvent.moreInfoLink}`,
        });

        let issueOwners: IssueOwner[] = [];
        const { ownerEmail, ownerName } = jsonData.code_repo;
        issueOwners.push({
          name: ownerName,
          email: ownerEmail,
        });

        if (issueOwners.length === 0) {
          issueOwners = this.getOwnersFromUsers(jsonData);
        }
        if (issueOwners.length === 0) {
          issueOwners = this.getOwnersFromAppOwnersConfig(jsonData);
        }
        if (issueOwners.length === 0) {
          issueOwners = this.getOwnersFromAppCreator(jsonData);
        }

        let fixLink = `https://www.google.com/search?q=alternative+to+${securityEvent.pkgName} library`;

        const item = this.generateItemForReport(
          true,
          securityEvent.title,
          securityEvent.violationInfo,
          securityEvent.title,
          securityEvent.recommendation,
          "N/A",
          "N/A",
          [],
          securityEvent.additionalInfo,
          true,
          fixLink,
          [],
          [SourceToolType.SBOM],
          [securityEvent.securityProvider.toLowerCase() as Tool],
          extraInfo,
          this.getCustomIssueId(securityEvent.ruleId.concat(securityEvent.realMatch)),
          issueOwners,
          securityEvent.additionalInfo,
          securityEvent.ruleId,
          [],
          "",
          [],
          securityEvent.severity,
          [],
          "",
          "",
          [],
          SeverityChange.NotApplicable,
          [],
          [],
          this.getOriginalSev([securityEvent]),
        );
        res.push(item);
      }
    }
    return res;
  }
}

export default PolicyExternalToolsLicenseViolations;
