import { OrgRoles, Repo, repoType, resourceType, User } from "../../../entitis/codeRepoTypes";
import StatesHelper from "../../../helper/statesHelper";
import { Severity } from "../../../entitis/reportTypes";
import { ChangeReason, severityReasons } from "../../../entitis/service/blameTypes";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import loggerImport from "../../../logger";
import { AdminsAggItem } from "./policyDspmMaxAdmins";
import PolicyRulesBase from "./policyRulesBase";
import Constant from "../../../entitis/constant";

const logger = loggerImport.getDebugLogger();

class Policy2FAEnabled extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const repo: Repo = jsonData.code_repo;

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
      if (repo.fullName === "*GitHub-Members") {
        return [];
      }

      const orgName = jsonData.code_repo.org;

      const enforceFor = this.getValueFromRuleArgs("enforceFor");
      if (enforceFor === undefined) {
        throw `enforceFor is not exist`;
      }

      // get correct role names for github org and repo level
      const orgAdminRole = jsonData.code_repo.gitRoles.org.admin.toLowerCase();
      const orgMemberRole = jsonData.code_repo.gitRoles.org.member.toLowerCase();

      const findRolls = [];
      if (enforceFor.toLowerCase().includes("admin")) {
        findRolls.push(orgAdminRole);
      }
      if (enforceFor.toLowerCase().includes("member")) {
        findRolls.push(orgMemberRole);
      }
      const auditLogsAvailable = StatesHelper.Instance.isOrgHaveAuditLogs(orgName);

      let items: AdminsAggItem[] = [];
      for (const user of jsonData.allUsers as User[]) {
        let affiliations = Array.from(user.orgRole);
        affiliations = (affiliations as string[]).map(x => x.toLowerCase());
        let exist = false;
        affiliations.forEach(i => {
          findRolls.forEach(j => {
            if (i === j) {
              exist = true;
            }
          });
        });

        if (exist && !user.twoFactorEnabled) {
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

      //Sort alerts based on last activity
      const withLastActivity = items.filter(i => i.userInfo.lastActivityData);
      const withoutLastActivity = items.filter(i => !i.userInfo.lastActivityData);
      const withLastActivitySorted = withLastActivity.sort(
        (a, b) => b.userInfo.lastActivityData.getTime() - a.userInfo.lastActivityData.getTime(),
      );
      items = [...withLastActivitySorted, ...withoutLastActivity];

      let issueOwner = { name: "", email: "" };
      const userIssueOwner = this.getAdminWithMaxOperations(jsonData.allUsers as User[], orgAdminRole);
      if (userIssueOwner) {
        issueOwner = {
          name: userIssueOwner.name,
          email: userIssueOwner.email || "",
        };
      }

      const org = jsonData.code_repo.org;
      const orgId = jsonData.code_repo.orgId;

      const aggregated = {
        columns: "policy2FAEnabled",
        aggregatedItems: items,
      };

      const adminsNum = items.filter(i => i.userInfo.orgRole.has(OrgRoles.ADMIN)).length;
      const membersNum = items.filter(i => i.userInfo.orgRole.has(OrgRoles.MEMBER)).length;

      if (adminsNum === 0 && membersNum === 0) {
        throw "all data empty";
      }

      const adminOnly = adminsNum > 0 ? `2FA not enabled for ${org} owners: ${adminsNum} owner${adminsNum > 1 ? "s" : ""}` : "";
      const memberOnly = membersNum > 0 ? `2FA not enabled for ${org} users: ${membersNum} member${membersNum > 1 ? "s" : ""}` : "";
      const both =
        adminsNum > 0 && membersNum > 0
          ? `2FA not enabled for ${org} users: ${adminsNum} owner${adminsNum > 1 ? "s" : ""}, ${membersNum} member${
              membersNum > 1 ? "s" : ""
            }`
          : "";

      let newVi = "";
      if (both) {
        newVi = both;
      } else if (memberOnly) {
        newVi = memberOnly;
      } else if (adminOnly) {
        newVi = adminOnly;
      }

      let issueName = "";
      if (both) {
        issueName = `There ${membersNum > 1 ? "are" : "is"} ${membersNum} ${org} member${membersNum > 1 ? "s" : ""} and ${
          adminsNum > 1 ? "are" : "is"
        } ${adminsNum} ${org} owner${adminsNum > 1 ? "s" : ""} who ${
          adminsNum + membersNum > 1 ? "do not" : " does not"
        } have Two-Factor Authentication (2FA) enabled. Enabling 2FA will decrease the likelihood that the systems hosting your code are breached.`;
      } else if (memberOnly) {
        issueName = `There ${membersNum > 1 ? "are" : "is"} ${membersNum} ${org} member${membersNum > 1 ? "s" : ""} who ${
          membersNum > 1 ? "do not" : " does not"
        } have Two-Factor Authentication (2FA) enabled. Enabling 2FA will decrease the likelihood that the systems hosting your code are breached.`;
      } else if (adminOnly) {
        issueName = `There ${adminsNum > 1 ? "are" : "is"} ${adminsNum} ${org} owner${adminsNum > 1 ? "s" : ""} who ${
          adminsNum > 1 ? "do not" : " does not"
        } have Two-Factor Authentication (2FA) enabled. Enabling 2FA will decrease the likelihood that the systems hosting your code are breached.`;
      }

      let changedSeverity = this.policyRuleMetadata.severity;
      const changeReasons: ChangeReason[] = [];
      if (jsonData.code_repo.isOrg2faEnabled === true) {
        changedSeverity = changedSeverity - 1;
        changeReasons.push(severityReasons.twoFactorOn);
      } else if (jsonData.code_repo.isOrg2faEnabled === false) {
        changedSeverity = changedSeverity + 0.1;
        changeReasons.push(severityReasons.twoFactorOff);
      }

      let suffix = "";
      let str = "";
      let rec = "";
      if (both) {
        str = "users";
        rec = "Enable 2FA for owners and members";
      } else if (adminOnly) {
        suffix = `+role%3Aowner`;
        str = "owners";
        rec = "Enable 2FA for all owners";
      } else if (memberOnly) {
        suffix = "+role%3Amember";
        str = "members";
        rec = "Enable 2FA for all members";
      }

      const fixLink = `https://github.com/orgs/${org}/people?query=two-factor%3Adisabled${suffix}`;
      const recommendation = `${rec}. Please do the following: <br>
      1. Enter the [link](${fixLink})<br>
      2. The following users filtered to show only ${str} with 2FA disabled <br>
      3. Please ask from the following users to enable 2FA.`;

      const res = [];
      const extraInfo = [];
      const item = this.generateItemForReport(
        true,
        newVi,
        issueName,
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

export default Policy2FAEnabled;
