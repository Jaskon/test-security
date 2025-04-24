import {
  CodeRepoTypes,
  getToolsNames,
  getUniqueInfoForAggregation,
  Repo,
  SecurityAlertType,
  SecurityEvent,
  User,
} from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { Severity } from "../../../entitis/reportTypes";
import { severityReasons } from "../../../entitis/service/blameTypes";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import loggerImport from "../../../logger";
import { cicdPostureRules } from "./policyCICDContextValues";
import PolicyRulesBase from "./policyRulesBase";
import { PolicySecurityScanAggItem as PolicyCICDContextValues } from "./policySecurityScan";
const logger = loggerImport.getDebugLogger();

class policyCICDEchoSecrets extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const supportedGitTypes = ["github"];

      const repo: Repo = jsonData.code_repo;
      const gitType = repo.type.toLowerCase();
      const privateVisability = repo.privateVisability;

      if (!supportedGitTypes.includes(gitType)) {
        return [];
      }

      const reposType = this.getValueFromRuleArgs("RepoType");
      if ((reposType === "Private" && !privateVisability) || (reposType === "Public" && privateVisability)) {
        return [];
      }

      if (!jsonData.securityEvents.length) {
        return [];
      }

      const ruleName = cicdPostureRules.get(this.policyRuleMetadata.functionName);

      const securityEvents: SecurityEvent[] = jsonData.securityEvents;
      const violationEvents = securityEvents.filter(event => event.ruleId === ruleName);

      if (!violationEvents.length) {
        return [];
      }

      let changedSeverity = this.policyRuleMetadata.severity;
      let changeReason = null;

      const reasons = [];

      if (repo.workflowPermissions?.enabled === false || !repo.workflowPermissions.hasOwnProperty("enabled")) {
        changedSeverity = 1;
        changeReason = severityReasons.ghActionsOff;
        reasons.push(changeReason);
      }

      const data = [];

      for (const event of violationEvents) {
        let reviewersAsString = "";
        let pushType = "";
        let link = event.link;
        let mergedBy = "";
        let titleInfo = "";

        const isSecret = event.securityAlertType === SecurityAlertType.secrets;

        let secretStatus = null;
        if (isSecret) {
          if (event.secretChecked) {
            if (event.validSecret) {
              secretStatus = "active";
              //   event.recommendation = `Contact ${
              //     issueOwners.length > 0
              //       ? issueOwners.map((u) => u.name).join(", ")
              //       : event.blame.commiterName
              //   } to remove the ${
              //     event.violationInfo
              //   } from the source code to an environment variable or a vault.\nFollowing that generate a new ${
              //     event.violationInfo
              //   } and revoke the previous one.`;
            } else {
              secretStatus = "inactive";
              event.recommendation = `Contact ${event.blame.commiterName} and inform the developer that putting secrets in code exposes the organization to unnecessary security risks. Secrets should be read by the application from an environment variable or a vault.`;
            }
          }
        }

        if (event.relatedPR !== undefined) {
          try {
            //if there's no related PR will return blanks
            const reviewers = event.relatedPR.reviewers.map(reviewer => reviewer.author);
            if (reviewers.length) {
              reviewersAsString = reviewers.join(",");
            } else {
              reviewersAsString = Constant.NO_REVIEWER;
            }
            pushType = event.relatedPR.objType == CodeRepoTypes.pulls ? "Pull Request" : "Push";
            link = event.relatedPR.link;
            mergedBy = event.relatedPR.mergeUser.author;
          } catch (err) {
            logger.error(`failed set pr security event ${JSON.stringify(event, null, 4)}`);
          }
        }

        if (event.blame.commitDescription != undefined) {
          titleInfo =
            event.blame.commitDescription.length > 1000 ? event.blame.commitDescription.substring(0, 1000) : event.blame.commitDescription;
        }

        let snippet =
          event.snippetContent.length > Constant.SNIPPET_CHARS_LIMIT
            ? event.snippetContent.substring(0, Constant.SNIPPET_CHARS_LIMIT)
            : event.snippetContent;

        let lineContent =
          event.lineContent.length > Constant.MATCH_CHARS_LIMIT
            ? event.lineContent.substring(0, Constant.MATCH_CHARS_LIMIT)
            : event.lineContent;

        const item: PolicyCICDContextValues = new PolicyCICDContextValues();
        item.match = lineContent;
        item.fileName = event.fileName || "";
        item.fileUri = event.link;
        item.startLine = event.startLineNumber;
        item.endLine = event.endLineNumber;
        item.commiterName = event.blame.commiterName || "";
        item.commiterEmail = event.blame.commiterEmail || "";
        item.securityAlert = event;
        item.commitLink =
          event.blame.commitSha && jsonData.code_repo != undefined ? `${jsonData.code_repo.commitLink}/${event.blame.commitSha}` : "";
        item.commitBy = `${event.blame.commiterName || ""} ${event.blame.commiterEmail || ""}`;
        item.commiterName = event.blame.commiterName || "";
        item.commiterEmail = event.blame.commiterEmail || "";
        item.date = event.blame.commitDate;
        item.pushType = pushType;
        item.title = titleInfo;
        item.mergedBy = mergedBy;
        item.link = link;
        item.reviewers = reviewersAsString;
        item.realMatch = event.realMatch || ""; //Dont change it!!!
        item.source = event.securityProvider;
        item.ruleId = event.ruleId || "";
        item.snippet = snippet;
        item.snippetLineNumber = event.blame.snippetLineNumber;

        item.setAggId();
        data.push(item);
      }

      const aggregated = {
        aggregatedItems: data,
        columns: "policySecurityScan",
      };

      const eventsOfAggs: SecurityEvent[] = data.map(i => i.securityAlert);

      const topEvent = violationEvents[0];

      const uniqueAgg = this.getCustomIssueId(getUniqueInfoForAggregation(topEvent));

      const repoAdminRole = jsonData.code_repo.gitRoles.repo.admin.toLowerCase();
      let issueOwner;
      let userIssueOwner = this.getAdminWithMaxOperations(repo.repoUsers as User[], repoAdminRole, true);

      if (!userIssueOwner) {
        issueOwner = { name: repo.ownerName, email: repo.ownerEmail || "" };
      } else {
        issueOwner = {
          name: userIssueOwner.name,
          email: userIssueOwner.email || "",
        };
      }

      const fixLink = "https://docs.github.com/en/actions/security-guides/encrypted-secrets#accessing-your-secrets";
      const issueName = `Secrets are being echoed in the pipeline  `;
      const secondaryTitle = `Secrets were echoed in the pipeline. These secrets are viewable by anyone who has access to the logs.`;
      const recommendation =
        "Please stop echoing secrets in your pipeline. In addition, please remove log entries if possible mentioning your secrets. Finally, assume the secret has leaked and consider rotating your secrets out.";

      const item = this.generateItemForReport(
        true,
        issueName,
        secondaryTitle,
        "",
        recommendation,
        topEvent.securityProvider,
        topEvent.securityAlertTypeStr,
        [],
        "",
        true,
        fixLink,
        aggregated,
        [Constant.cicdPosture],
        getToolsNames(topEvent.securityProviders, topEvent.tools),
        [],
        uniqueAgg,
        [issueOwner],
        topEvent.moreInfoLink,
        topEvent.ruleId,
        topEvent.blame.cwe,
        topEvent.snippetContent,
        topEvent.blame.cweList,
        changedSeverity,
        topEvent.blame.dependencyChain,
        topEvent.blame.publicExploitLink,
        Severity[this.policyRuleMetadata.severity],
        [],
        getSeverityChanges(this.policyRuleMetadata.severity, changedSeverity),
        reasons,
        [],
        this.getOriginalSev(eventsOfAggs),
      );

      return [item];
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}, repo: ${jsonData.code_repo.name}`);
    }
    return [];
  }
}
export default policyCICDEchoSecrets;
