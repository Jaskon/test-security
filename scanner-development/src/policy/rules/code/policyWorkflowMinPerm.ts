import { getUniqueInfoForAggregation, Repo, repoType, SecurityEvent, User } from "../../../entitis/codeRepoTypes";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { Severity } from "../../../entitis/reportTypes";
import { severityReasons } from "../../../entitis/service/blameTypes";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import AutoFix from "../../../helper/service/auto-fix-service/auto-fix";
import { Input, InputOption, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { cicdPostureRules } from "./policyCICDContextValues";
import PolicyRulesBase from "./policyRulesBase";
import { PolicySecurityScanAggItem as PolicyWorkflowMinPermAggItem } from "./policySecurityScan";
const { Octokit } = require("@octokit/core");
const logger = loggerImport.getDebugLogger();

class policyWorkflowMinPerm extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const supportedGitTypes = ["github"];

      const repo: Repo = jsonData.code_repo;
      const gitType = repo.type.toLowerCase();
      const privateVisability = repo.privateVisability;

      if (!supportedGitTypes.includes(gitType) || !repo.realRepo) {
        return [];
      }

      const reposType = this.getValueFromRuleArgs("RepoType");
      if ((reposType === "Private" && !privateVisability) || (reposType === "Public" && privateVisability)) {
        return [];
      }

      let changedSeverity = this.policyRuleMetadata.severity;
      let changeReason = null;

      const reasons = [];

      const dataSource = this.getValueFromRuleArgs("dataSource");

      let data = [];
      let aggregated;

      let topEvent;
      let uniqueAgg = "";
      let issueName;
      let recommendation;

      let fixLink;

      const ruleName = cicdPostureRules.get(this.policyRuleMetadata.functionName);
      const securityEvents: SecurityEvent[] = jsonData.securityEvents;
      const violationEvents = securityEvents.filter(event => event.ruleId === ruleName);

      if (dataSource === "code") {
        // semgrep rule

        if (!violationEvents.length) {
          return [];
        }

        issueName = `Workflow file should be configured with minimum required permissions`;
        recommendation = `You can use the permissions key in your workflow file to modify permissions for the GITHUB_TOKEN for an entire workflow or for individual jobs. This allows you to configure the minimum required permissions for a workflow or job. When the permissions key is used, all unspecified permissions are set to no access, with the exception of the metadata scope, which always gets read access. Thus choose only the needed permissions for the specific job/worfklow. 
<br> 
[GitHub Actions workflow syntax](https://docs.github.com/en/actions/using-workflows/workflow-syntax-for-github-actions#permissions)  <br> 
[Permissions for the GITHUB_TOKEN](https://docs.github.com/en/actions/security-guides/automatic-token-authentication#permissions-for-the-github_token)`;

        for (const event of violationEvents) {
          let reviewersAsString = "";
          let pushType = "";
          let link = event.link;
          let mergedBy = "";
          let titleInfo = "";

          if (event.blame.commitDescription != undefined) {
            titleInfo =
              event.blame.commitDescription.length > 1000
                ? event.blame.commitDescription.substring(0, 1000)
                : event.blame.commitDescription;
          }

          let snippet =
            event.snippetContent.length > Constant.SNIPPET_CHARS_LIMIT
              ? event.snippetContent.substring(0, Constant.SNIPPET_CHARS_LIMIT)
              : event.snippetContent;

          let lineContent =
            event.lineContent.length > Constant.MATCH_CHARS_LIMIT
              ? event.lineContent.substring(0, Constant.MATCH_CHARS_LIMIT)
              : event.lineContent;

          const item: PolicyWorkflowMinPermAggItem = new PolicyWorkflowMinPermAggItem();
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

        topEvent = violationEvents[0];
        uniqueAgg = this.getCustomIssueId(getUniqueInfoForAggregation(topEvent));

        aggregated = {
          aggregatedItems: data,
          columns: "policySecurityScan",
        };
      } else if (dataSource === "api") {
        //  api call

        // if we have violations for semgrep then bail, we will show the code viloation instead of this api

        if (violationEvents.length) {
          return [];
        }
        fixLink = `${repo.settingLink}/actions`;
        issueName = `Workflow settings should be configured with minimum required permissions`;
        recommendation = `Please ensure that GitHub Actions workflow is configured correctly and is set to use the minimum needed permissions:
        <pre>
        1. Enter the [link](${fixLink}) <br>
        2. Scroll down to 'Workflow permissions' section <br>
        3. Select the 'Read repository contents ...' option <br>
        4. Uncheck the 'Allow GitHub Actions to create and approve pull request' <br>
        3. Click 'Save'</pre>`;

        if (repo.defaultWorkflowPermissions?.default_workflow_permissions === "read") {
          return [];
        }

        aggregated = [];
        uniqueAgg = this.getGeneralIssueId();
        topEvent = {
          securityProvider: "Settings",
          securityAlertTypeStr: "Settings",
          moreInfoLink: "",
          ruleId: "",
          blame: null,
          snippetContent: "",
        };
        aggregated = [];
      }

      if (repo.workflowPermissions?.enabled === false || !repo.workflowPermissions?.hasOwnProperty("enabled")) {
        changedSeverity = 1;
        changeReason = severityReasons.ghActionsOff;
        reasons.push(changeReason);
      } else {
        if (!repo.defaultWorkflowPermissions?.can_approve_pull_request_reviews) {
          changedSeverity = 1;
          changeReason = severityReasons.defaultWorkflowPermissionOff;
          reasons.push(changeReason);
        }
      }

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

      const learnMore = `https://docs.github.com/en/repositories/managing-your-repositorys-settings-and-features/enabling-features-for-your-repository/managing-github-actions-settings-for-a-repository`;

      let secondaryTitle = `The workflow is configured with more than the basic permissions. This means that someone who gets access to the GITHUB_TOKEN generated from an execution of a job may be able to elevate their privileges if the GITHUB_TOKEN has a higher permission than them. <br> <br>`;

      if (repo.defaultWorkflowPermissions?.can_approve_pull_request_reviews) {
        secondaryTitle +=
          "This workflow has permission to open Pull Requests. A compromised workflow will allow a malicious actor to bypass review requirements when pushing code. <br>";
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
        ["min-permissions"],
        [],
        uniqueAgg,
        [issueOwner],
        learnMore,
        topEvent.ruleId,
        topEvent.blame?.cwe,
        "",
        topEvent.blame?.cweList,
        changedSeverity,
        topEvent.blame?.dependencyChain,
        topEvent.blame?.publicExploitLink,
        Severity[this.policyRuleMetadata.severity],
        topEvent.blame?.severityChangeReason,
        getSeverityChanges(this.policyRuleMetadata.severity, changedSeverity),
        reasons,
      );

      if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
        item.fixes = this.generateFixes(repo);
      }

      return [item];
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}, repo: ${jsonData.code_repo.name}`);
    }
    return [];
  }
  generateFixes(repo: Repo) {
    try {
      const p: PolicyFix = new PolicyFix();
      p.description =
        "This action will update the default workflows permissions to read only. GitHub Actions will not have the permission to create and approve pull requests.";
      p.settingType = SettingType.changeWorkflowsPerm;
      p.confirmation = "After this fix, only read permissions will be granted under the workflows scope.";
      p.tooltip = "Update workflows permissions";

      const input: Input = new Input();
      input.type = "radio";
      input.name = InputType.settingsOption;
      input.displayName = "Fix Options";

      const o1: InputOption = new InputOption();
      o1.name = "Repo settings";
      o1.displayName = `'${repo.name}' repo only`;
      o1.info = "This will update workflows permissions for this repo only.";
      o1.metadata = JSON.stringify({
        repo: repo.name,
        owner: repo.ownerNameApi,
        org: repo.organization,
        scanId: StatesHelper.Instance.uuid,
        orgId: StatesHelper.Instance.orgName,
      });
      const o2: InputOption = new InputOption();
      o2.name = "Organization settings";
      o2.selected = true;
      o2.displayName = `All repos in '${repo.organization}' org`;
      o2.info = "This will update workflows permissions all repos in the organization.";
      o2.metadata = JSON.stringify({
        repo: repo.name,
        owner: repo.ownerNameApi,
        org: repo.organization,
        scanId: StatesHelper.Instance.uuid,
        orgId: StatesHelper.Instance.orgName,
      });
      input.options.push(o1);
      input.options.push(o2);
      p.inputs.push(input);

      return p;
    } catch (e) {
      logger.error(`failed to generate fixes, policy: ${this.policyRuleMetadata.name}, error: ${e}`);
    }
  }
}

export default policyWorkflowMinPerm;
