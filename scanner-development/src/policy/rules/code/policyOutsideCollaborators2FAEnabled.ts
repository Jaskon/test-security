import { AffiliationType, OrgRoles, repoType, resourceType, User } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { Severity } from "../../../entitis/reportTypes";
import { ChangeReason, severityReasons } from "../../../entitis/service/blameTypes";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import { AdminsAggItem } from "./policyDspmMaxAdmins";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class PolicyOutsideCollaborators2FAEnabled extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      if (jsonData.code_repo.realRepo) {
        return [];
      }
      // run policy only if git type is supported
      if (jsonData.code_repo.type.toLowerCase() !== repoType.github) {
        return [];
      }
      if (!jsonData.allUsers) {
        return [];
      }

      const orgName = jsonData.code_repo.org;
      const commonUserPrefixSuffix = Object.keys(StatesHelper.Instance.commonUserPrefixSuffix);
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);
      let items: AdminsAggItem[] = [];
      for (const user of jsonData.allUsers as User[]) {
        if (user.affiliation.has(AffiliationType.outside) && !user.twoFactorEnabled) {
          const partOfCommon = commonUserPrefixSuffix.find(i => user.username.startsWith(i) || user.username.endsWith(i));
          if (partOfCommon) {
            continue;
          }

          const item: AdminsAggItem = new AdminsAggItem();
          item.user = user.name;
          item.userInfo = user;
          item.userLink = user.htmlLink;
          item.userAvatar = user.avatarUrl;

          item.orgRole = Array.from(user.orgRole).join(", ");
          item.repoPermissions = ""; //this for repo only
          item.earliestActivityDate = user.createdAtDate ? user.createdAtDate.toString() : "";

          if (auditLogsAvailable) {
            if (user.foundAdminData) {
              item.adminOperation = this.getUserActivityBasedPretty(user.adminOperation, user.adminOperationDate);
              item.adminLocation = user.adminLocation;
              item.adminOperationDate = user.adminOperationDate.toString();
              item.lastAdminOperation = user.lastAdminOperation;
            } else {
              item.adminOperation = "No Activity";
              item.lastAdminOperation = "No Activity";
            }
          }

          if (user.foundDevData) {
            item.devOperation = this.getUserActivityBasedPretty(user.devOperation, user.devOperationDate);
            item.devOperationDate = user.devOperationDate.toString();
          }

          if (user.foundReviewData) {
            item.reviewOperation = this.getUserActivityBasedPretty(user.reviewOperation, user.reviewOperationDate);
            item.reviewOperationDate = user.reviewOperationDate.toString();
          }

          item.earliestActivityDate = user.lastActivityData ? user.lastActivityData.toString() : "";

          item.setAggId();
          items.push(item);
        }
      }

      if (items.length == 0) {
        return [];
      }

      let issueOwner = { name: "", email: "" };
      const orgAdminRole = jsonData.code_repo.gitRoles.org.admin.toLowerCase();

      const userIssueOwner = this.getAdminWithMaxOperations(jsonData.allUsers as User[], orgAdminRole);
      if (userIssueOwner) {
        issueOwner = {
          name: userIssueOwner.name,
          email: userIssueOwner.email || "",
        };
      }

      //Sort alerts based on last activity
      const withLastActivity = items.filter(i => i.userInfo.lastActivityData);
      const withoutLastActivity = items.filter(i => !i.userInfo.lastActivityData);
      const withLastActivitySorted = withLastActivity.sort(
        (a, b) => b.userInfo.lastActivityData.getTime() - a.userInfo.lastActivityData.getTime(),
      );
      items = [...withLastActivitySorted, ...withoutLastActivity];

      const org = jsonData.code_repo.org;
      const orgId = jsonData.code_repo.orgId;

      const aggregated = {
        columns: "policyOutsideCollaborators2FAEnabled",
        aggregatedItems: items,
      };

      const cola = items.length > 1 ? "collaborators" : "collaborator";

      const fixLink = `https://github.com/orgs/${org}/people?query=two-factor%3Adisabled`;
      const newVi = `There ${items.length > 1 ? "are" : "is"} ${items.length} outside ${cola} who ${
        items.length > 1 ? "do not" : " does not"
      } have Two-Factor Authentication (2FA) enabled. Outside collaborators are not direct members of your ${org} org. Enabling 2FA will decrease the likelihood that the systems hosting your code are breached.`;
      const recommendation = `Outside collaborators should have 2FA enabled. To enable 2FA please do the following: <br>
      1. Enter the [link](${fixLink}) <br>
      2. The following users filtered to show only outside collaborators with 2FA disabled <br>
      3. Please ask from the following users to enable 2FA`;
      const issueName = `2FA not enabled for ${items.length} outside ${cola}`;

      let changedSeverity = this.policyRuleMetadata.severity;

      const changeReasons: ChangeReason[] = [];
      if (jsonData.code_repo.isOrg2faEnabled === true) {
        changedSeverity = changedSeverity - 1;
        changeReasons.push(severityReasons.twoFactorOn);
      } else if (jsonData.code_repo.isOrg2faEnabled === false) {
        changeReasons.push(severityReasons.twoFactorOff);
      }

      const res = [];
      const extraInfo = [];
      const item = this.generateItemForReport(
        true,
        issueName,
        newVi,
        newVi,
        recommendation,
        "Code Change",
        "Code Repository",
        "",
        [],
        true,
        fixLink,
        aggregated,
        [Constant.gitPosture],
        [resourceType.allUsers],
        extraInfo,
        this.getCustomIssueId(`${jsonData.code_repo.type}_${org}_${orgId}`),
        [issueOwner],
        "",
        "",
        [],
        "",
        [],
        changedSeverity,
        [],
        "",
        Severity[this.policyRuleMetadata.severity],
        [],
        getSeverityChanges(this.policyRuleMetadata.severity, changedSeverity),
        changeReasons,
      );
      res.push(item);
      return res;
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
    return [];
  }
}

export default PolicyOutsideCollaborators2FAEnabled;
