import { CodeRepoTypes, getToolsNames, getUniqueInfoForAggregation, Repo, SecurityEvent, User } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { Severity } from "../../../entitis/reportTypes";
import { severityReasons } from "../../../entitis/service/blameTypes";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import { PolicySecurityScanAggItem as PolicyCICDContextValuesAggItem } from "./policySecurityScan";
const logger = loggerImport.getDebugLogger();

export const cicdPostureRules = new Map([
  // semgrep
  ["policyCICDContextValues", "cicd.github-actions.command-injection-via-the-github-context"],
  ["policyCICDPlainTextSecrets", "cicd.github-actions.plain-text-secrets"],
  ["policyCICDEchoSecrets", "cicd.github-actions.echo-secrets"],
  ["policyCICDSecretsRepoVars", "cicd.github-actions.env-vars-secrets"],
  ["policyWorkflowMinPerm", "cicd.github-actions.github-actions-token-least-privileges"],
  ["policyPinActionSha", "cicd.github-actions.pin-actions-to-commit-sha"],
  ["policyDeprecatedCommand", "cicd.github-actions.allowed-unsecure-commands"],
  // checkov
  ["policyGeneralCICD", "CKV_CIRCLECIPIPELINES_"],
  ["policyGeneralCICD", "CKV_AZUREPIPELINES_"],
  ["policyGeneralCICD", "CKV_BITBUCKETPIPELINES_"],
  ["policyGeneralCICD", "CKV_GHA_"],
  ["policyGeneralCICD", "CKV_GITLABCI_"],
]);

class policyCICDContextValues extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const gitType = jsonData.code_repo.type.toLowerCase();
      const supportedGitTypes = ["github"];

      if (!supportedGitTypes.includes(gitType)) {
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

      const repo: Repo = jsonData.code_repo;
      let changedSeverity = this.policyRuleMetadata.severity;
      let changeReason = null;

      const reasons = [];

      if (repo.workflowPermissions?.enabled === false || !repo.workflowPermissions.hasOwnProperty("enabled")) {
        changedSeverity = 1;
        changeReason = severityReasons.ghActionsOff;
        reasons.push(changeReason);
      }

      const issueName = "GitHub context usage can lead to malicious code execution in the pipeline.  ";
      const secondaryTitle =
        "GitHub context usage can lead to malicious code execution in the pipeline.  A single compromised developers account can allow an attacker to hijack and then control a GitHub runner. ";
      const recommendation =
        "Use 'with' to pass the context as an argument instead, or set the value to an intermediate environment variable by using 'env'.";

      const data = [];

      for (const event of violationEvents) {
        let reviewersAsString = "";
        let pushType = "";
        let link = event.link;
        let mergedBy = "";
        let titleInfo = "";

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

        const item: PolicyCICDContextValuesAggItem = new PolicyCICDContextValuesAggItem();
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

      const eventsOfAggs: SecurityEvent[] = data.map(i => i.securityAlert);

      const aggregated = {
        aggregatedItems: data,
        columns: "policySecurityScan",
      };

      const topEvent = violationEvents[0];
      const fixLink =
        "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-an-action-instead-of-an-inline-script-recommended";
      const moreInfoLink = "https://securitylab.github.com/research/github-actions-untrusted-input";
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
        moreInfoLink,
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
export default policyCICDContextValues;
