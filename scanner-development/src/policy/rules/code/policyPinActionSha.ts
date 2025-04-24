import { CodeRepoTypes, getToolsNames, getUniqueInfoForAggregation, Repo, SecurityEvent, User } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { Severity } from "../../../entitis/reportTypes";
import { severityReasons } from "../../../entitis/service/blameTypes";
import { isDevelopment } from "../../../helper/envUtils";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import loggerImport from "../../../logger";
import { cicdPostureRules } from "./policyCICDContextValues";
import PolicyRulesBase from "./policyRulesBase";
import { PolicySecurityScanAggItem as PolicyPinActionShaAggItem } from "./policySecurityScan";
const logger = loggerImport.getDebugLogger();

class policyPinActionSha extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      if (!jsonData.code_repo.realRepo) {
        return [];
      }

      //const debug = JSON.stringify(jsonData.securityEvents);

      const gitType = jsonData.code_repo.type.toLowerCase();
      const supportedGitTypes = ["github"];

      if (!supportedGitTypes.includes(gitType)) {
        return [];
      }

      if (!jsonData.securityEvents.length) {
        return [];
      }

      const privateVisability = jsonData.code_repo.privateVisability;
      const reposType = this.getValueFromRuleArgs("RepoType");
      if ((reposType === "Private" && !privateVisability) || (reposType === "Public" && privateVisability)) {
        return [];
      }
      const skipVerified = this.getValueFromRuleArgs("skipVerified");
      let excludedActions = this.getValueFromRuleArgs("excludedActions");
      excludedActions = excludedActions.map(a => a.toLowerCase());

      const res = [];
      const ruleName = cicdPostureRules.get(this.policyRuleMetadata.functionName);
      const securityEvents: SecurityEvent[] = jsonData.securityEvents;
      const violationEvents = securityEvents.filter(event => event.ruleId === ruleName);

      if (!violationEvents.length) {
        return [];
      }

      const repo: Repo = jsonData.code_repo;

      let githubActionsDisabled;
      if (repo.workflowPermissions?.enabled === false || !repo.workflowPermissions?.hasOwnProperty("enabled")) {
        // bail?

        githubActionsDisabled = true;
      }

      const recommendation = `Please ensure that any third-party Actions are pinned to a commit SHA that you have verified. <br>
      Example 1: <br>
      uses: actions/checkout@**755da8c3cf115ac066823e79a1e1788f8940201b** <br>
      (and not  uses: actions/checkout@**v3.2.0**) <br>
      [Commits · actions/checkout](https://github.com/actions/checkout/commits/v3.2.0)
      <br> <br> 
      Example 2: <br>
      uses: DataDog/upload-dsyms-github-action@**9d7b8b17366d0aa70f01e0eae43d86cb455a8552** <br>
      (and not  uses: DataDog/upload-dsyms-github-action@**v0.1.0**) <br>
      [Commits · DataDog/upload-dsyms-github-action](https://github.com/DataDog/upload-dsyms-github-action/commits/v0.1.0)
      <br> <br>
      Note: the commit is the last commit of the release
      `;

      const actionsWithVer = {};
      for (const event of violationEvents) {
        if (!event.metaVars) {
          continue;
        }

        const { $1, $2, $3 } = event.metaVars;
        const actionOwner = $1.abstract_content;
        const actionName = `${$1.abstract_content}/${$2.abstract_content}`;

        if (!this.getActionInfo(repo, actionName)) {
          continue;
        }

        if (excludedActions.includes(actionOwner.toLowerCase())) {
          continue;
        }

        actionsWithVer[actionName] = actionsWithVer[actionName] || [];
        actionsWithVer[actionName].push(event);
      }

      for (const [action, actionVersions] of Object.entries(actionsWithVer)) {
        const data = [];
        const issueName = `Workflow uses third-party Actions that are not tied to a specific release: ${action}`;
        const extraInfo = [];
        const reasons = [];

        let secondaryTitle = `The workflow is using a third-party Actions '${action}' that are not tied to a specific release. By not tying the workflow to a specific release, a compromise of the third-party Actions can lead to a compromise on your system. <br>`;
        let changedSeverity = this.policyRuleMetadata.severity;
        let changeReason = null;
        let isVerifiedString = "";

        const actionInfo = this.getActionInfo(repo, action);

        if (actionInfo) {
          if (actionInfo.isVerified !== null) {
            if (actionInfo.isVerified) {
              secondaryTitle += `<br>The repo creator is verified by GitHub as a partner organization. `;

              changedSeverity = changedSeverity - 1;
              changeReason = severityReasons.verifiedOrg;

              isVerifiedString = "Repo Creator Is Verified";
              reasons.push(changeReason);
              if (skipVerified) {
                continue;
              }
            } else {
              secondaryTitle += `<br>The repo creator is not a verified partner organization of GitHub. `;

              changeReason = severityReasons.unverifiedOrg;
              isVerifiedString = "Repo Creator Is Not Verified";
              reasons.push(changeReason);
            }

            extraInfo.push({
              key: "Verified by GitHub",
              value: `${isVerifiedString}`,
            });
          }
        }

        secondaryTitle += `<br> <br> Note: Third Party Actions are external repos that are being used in your build system.`;

        if (actionInfo) {
          if (actionInfo.stars !== null) {
            if (actionInfo.stars >= 100) {
              changedSeverity = changedSeverity - 1;
              changeReason = severityReasons.highStarsCount;
              reasons.push(changeReason);
            }
            if (actionInfo.stars >= 20 && actionInfo.stars < 100) {
              changeReason = severityReasons.mediumStarsCount;
              reasons.push(changeReason);
            }
            if (actionInfo.stars < 20) {
              changeReason = severityReasons.lowStarsCount;
              reasons.push(changeReason);
            }

            extraInfo.push({
              key: "Stargazers Count",
              value: `${actionInfo.stars}`,
            });
          }
        }

        if (!actionInfo) {
          logger.error(`getActionInfo failed to find info`);
        }

        if (githubActionsDisabled) {
          changedSeverity = 1;
          changeReason = severityReasons.ghActionsOff;
          reasons.push(changeReason);
        }

        for (const event of Object.values(actionVersions)) {
          let reviewersAsString = "";
          let pushType = "";
          let link = event.link;
          let mergedBy = "";
          let titleInfo = "";

          let lineContent =
            event.lineContent.length > Constant.MATCH_CHARS_LIMIT
              ? event.lineContent.substring(0, Constant.MATCH_CHARS_LIMIT)
              : event.lineContent;

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
              event.blame.commitDescription.length > 1000
                ? event.blame.commitDescription.substring(0, 1000)
                : event.blame.commitDescription;
          }

          let snippet =
            event.snippetContent.length > Constant.SNIPPET_CHARS_LIMIT
              ? event.snippetContent.substring(0, Constant.SNIPPET_CHARS_LIMIT)
              : event.snippetContent;

          const item: PolicyPinActionShaAggItem = new PolicyPinActionShaAggItem();
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

        const securityItems: SecurityEvent[] = data.map(i => i.securityAlert);
        const topEvent: SecurityEvent = actionVersions[0];
        const moreInfoLink =
          "https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions#using-third-party-actions";
        const uniqueAgg = this.getCustomIssueId(`${action}_${repo.name}`);

        const repoAdminRole = repo.gitRoles.repo.admin.toLowerCase();

        let issueOwner;
        issueOwner = { name: repo.ownerName, email: repo.ownerEmail || "" };

        // let userIssueOwner = this.getAdminWithMaxOperations(repo.repoUsers as User[], repoAdminRole, true);

        // if (!userIssueOwner) {
        // } else {
        //   issueOwner = {
        //     name: userIssueOwner.name,
        //     email: userIssueOwner.email || "",
        //   };
        // }

        const violation = this.generateItemForReport(
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
          topEvent.link,
          aggregated,
          [Constant.cicdPosture],
          getToolsNames(topEvent.securityProviders, topEvent.tools),
          extraInfo,
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
          this.getOriginalSev(securityItems),
        );
        res.push(violation);
      }

      return res;
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}, repo: ${jsonData.code_repo.name}`);
    }
    return [];
  }

  getActionInfo(repo: Repo, action: string) {
    try {
      return repo.unlistedActions.get(action);
    } catch (e) {
      logger.error(`getActionInfo failed in pinActions policy err:${e}, repo: ${repo.fullName}`);
    }
  }
}
export default policyPinActionSha;
