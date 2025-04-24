import GlobalCodeRepoData from "../../../dal/GolobalCollectorData/globalCodeRepoData";
import { OrgRoles, Repo, repoType, resourceType, SecurityAlertType, SecurityEvent, User } from "../../../entitis/codeRepoTypes";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import { RepoOfOrgAggItem } from "./policyUntouchedReposShouldBeArchived";
import pluralize from "pluralize";
import { Severity } from "../../../entitis/reportTypes";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import { ChangeReason, severityReasons, ChangeCategory } from "../../../entitis/service/blameTypes";
import Constant from "../../../entitis/constant";
import { isInt } from "../../../helper/commonUtils";
import { SourceToolType } from "@oxappsec/ox-consolidated-categories";

const logger = loggerImport.getDebugLogger();

class policyDepConfusion extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const repo: Repo = jsonData.code_repo;
      if (repo.realRepo) {
        return [];
      }

      let securityEvents: SecurityEvent[] = jsonData.allSecEvents;
      const scopeRepoMap = jsonData.scopesRepoMap;
      const allOrgsRepos = jsonData.allOrgsRepos;
      const res = [];
      const scopesToPass = this.getValueFromRuleArgs("ignoreInternalPackageScopes");
      let isOneRepoPublic = false;
      if (allOrgsRepos.length === 0) {
        return [];
      }

      securityEvents = securityEvents.filter(i => i.securityAlertType === SecurityAlertType.depConfusionScopes);
      if (securityEvents.length === 0) {
        return [];
      }

      const possibleFixLinks = { npm: "https://www.npmjs.com/org/create" };
      const orgName = jsonData.code_repo.org;
      let issueOwner = { name: "", email: "" };
      const orgAdminRole = jsonData.code_repo.gitRoles.org.admin.toLowerCase();
      let userIssueOwner = this.getAdminWithMaxDevOperations(jsonData.allUsers as User[], orgAdminRole);
      if (userIssueOwner) {
        issueOwner = {
          name: userIssueOwner.name,
          email: userIssueOwner.email || "",
        };
      }

      for (const scope in scopeRepoMap) {
        const changeReasons = [];
        let changedSev = this.policyRuleMetadata.severity;
        let event;

        const events = securityEvents.filter(event => event.orgScopeId === scope);
        if (scopesToPass.find(i => i === scope)) {
          continue;
        }
        if (events.length === 0) {
          continue;
        } else {
          event = events[0];
        }
        const getOriginalSev = this.getOriginalSev(events);
        const fixLink = "https://www.npmjs.com/org/create";
        const createAccount = "https://www.npmjs.com/";
        // for now all the alerts are for org scope name which is not used in a public registry
        const recommendation = `In order to prevent malicious use of the scope name "${event.orgScopeId}", please register the organization scope on ${event.publicRegistry} by following the instructions below: <br>
      1. If you don't have an account, create one in this [link](${createAccount}) <br>
      2. Enter the [link](${fixLink})<br>
      3. Click on your avatar and click on "Add an Organization" <br>
      4. In the Name field, type "${event.orgScopeId}"  as the organization name, this will also be your organization scope <br>
      5. Choose "Unlimited private packages" paid plan or the "Unlimited public packages" free plan and click Buy or Create <br>
      6. Click "Skip for now" or invite users to your organization`;

        const issueName = `The internal organization scope @${scope} is open to dependency confusion attacks on the ${event.publicRegistry} public registry`;
        const repoList = scopeRepoMap[scope];

        const data: RepoOfOrgAggItem[] = [];
        for (const repoFullName of repoList) {
          const currRepo = allOrgsRepos.find(i => i.fullName === repoFullName);
          if (!currRepo) {
            continue;
          }
          if (currRepo.disable) {
            continue;
          }
          if (!currRepo.privateVisability) {
            isOneRepoPublic = true;
          }
          const item: RepoOfOrgAggItem = new RepoOfOrgAggItem();
          item.repo = currRepo.fullName;
          item.repoItem = currRepo;
          item.repoCreator = currRepo.ownerName;
          item.lastCodeDate = currRepo.lastPushTime;
          item.createdAt = repo.createdAt;
          item.setAggId();
          data.push(item);
        }

        if (isOneRepoPublic) {
          changedSev = changedSev + 1;
          const reason = new ChangeReason(
            "Internal Scope Exposure",
            "The issue is associated with a public repository that exposes internal organization scopes for libraries, increasing the risk of unauthorized access and potential exploitation of proprietary information and systems.",
            1,
            ChangeCategory.Reachable,
          );
          if (changeReasons.length === 0) {
            changeReasons.push(reason);
          }
        } else {
          const reason = new ChangeReason(
            "Internal Scope Hidden",
            "The issue is associated with a private repository that does not expose internal organization scopes for libraries. This reduces the risk of unauthorized access and potential exploitation of proprietary information and systems.",
            -0.1,
            ChangeCategory.Reachable,
          );
          if (changeReasons.length === 0) {
            changeReasons.push(reason);
          }
        }

        const aggregated = {
          columns: "policyUntouchedReposShouldBeArchived",
          aggregatedItems: data,
        };

        const newVi = `Dependency confusion attacks can have serious impacts, such as data breaches, service disruptions, and resource hijacking.<br>
<br>
The availability of organizational scope @${scope} for public registration on ${
          event.publicRegistry
        } can enable such attacks. Attackers could register this scope and publish malicious software packages with the same names as your internal ones. This could result in your systems downloading harmful packages instead of your safe, internal ones. <br>
        <br>
        <br>
&bull; @${scope} is used as an internal organization scope on the ${event.privateRegistryName} private registry, at: ${
          event.privateRegistryUrl
        }. <br>
&bull; @${scope} is used in ${data.length} ${pluralize("repo", data.length)}`;

        const availableForRegistryReason = ChangeReason.copy(severityReasons.availableForRegistry);
        const rceReason = ChangeReason.copy(severityReasons.potentialRCE);
        changeReasons.push(availableForRegistryReason);
        changeReasons.push(rceReason);
        if (isInt(severityReasons.potentialRCE.changeNumber)) {
          changedSev += severityReasons.potentialRCE.changeNumber;
        }

        const itemToAdd = this.generateItemForReport(
          true,
          issueName,
          newVi,
          issueName,
          recommendation,
          event.securityProvider,
          event.securityAlertTypeStr,
          "",
          [],
          true,
          fixLink,
          aggregated,
          [SourceToolType.SBOM],
          [resourceType.depConfusionAlert],
          [],
          this.getCustomIssueId(`${jsonData.code_repo.type}_${orgName}_${event.orgScopeId}`),
          [issueOwner],
          "",
          "",
          [],
          "",
          [],
          changedSev,
          [],
          "",
          Severity[this.policyRuleMetadata.severity],
          [],
          getSeverityChanges(this.policyRuleMetadata.severity, changedSev),
          changeReasons,
          [],
          getOriginalSev,
        );
        itemToAdd.blameExists = true;
        itemToAdd.graphExists = true;
        res.push(itemToAdd);
      }

      return res;
    } catch (e) {
      logger.error(
        `failed to eval policy, policy: ${this.policyRuleMetadata.functionName}, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`,
      );
    }
    return [];
  }
}
export default policyDepConfusion;
