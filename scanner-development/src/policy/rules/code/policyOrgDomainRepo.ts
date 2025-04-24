import { repoResourceType, User } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { AggregatedUser, AggregatedInfoForExclusion } from "../../../entitis/service/exclusionTypes";
import StringHelper from "../../../helper/stringHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();
class policyOrgDomainRepo extends PolicyRulesBase {
  problematicUserDomain = "";

  async eval(jsonData) {
    if (!jsonData.code_repo.realRepo) {
      return [];
    }

    if (jsonData.users.length == 0) {
      return [];
    }
    const repoType = this.getValueFromRuleArgs("repoType");
    if (repoType === undefined) {
      throw `repoType is not exist`;
    }
    if (repoType != "Private or Public") {
      if (repoType.toLowerCase() === "private") {
        if (jsonData.code_repo.privateVisability == false) return [];
      }
      if (repoType.toLowerCase() === "public") {
        if (jsonData.code_repo.privateVisability) return [];
      }
    }

    let allowedDomainsList = this.getValueFromRuleArgs("domains");
    if (allowedDomainsList === undefined) {
      throw `allowedDomainsList is not exist`;
    }

    allowedDomainsList = [...allowedDomainsList, ...this.identifyCommonDomain(jsonData.users)];
    allowedDomainsList = allowedDomainsList.reduce((unique, o) => {
      if (!unique.some(obj => obj === o)) {
        unique.push(o);
      }
      return unique;
    }, []);

    allowedDomainsList = allowedDomainsList.filter(i => i != "");

    const allowedUsers = new Set();
    const usersIssues: User[] = [];
    for (const user of jsonData.users) {
      if (user.email == "" || user.domain == "" || user.email == undefined) {
        continue;
      }
      if (user.email.includes(".local")) {
        continue;
      }
      if (allowedDomainsList.includes(user.domain)) {
        continue;
      }
      usersIssues.push(user);
    }
    let aggregatedItems = {};
    if (usersIssues.length > 0) {
      aggregatedItems = this.getAggragatedUsersInfo(usersIssues);
    }

    const aggregated = {
      columns: "policyOrgDomainRepo",
      aggregatedItems: Object.values(aggregatedItems),
    };

    if (aggregated.aggregatedItems.length == 0) {
      return [];
    }

    const newVi = "The following users of the repo should not have access to the system.";
    const res = this.generateItemForReport(
      true,
      newVi,
      "",
      newVi,
      "The following users of the repo should not have access to the system.",
      "Please consider revoking all access from the users.",
      "Code Repository",
      "",
      [],
      true,
      "",
      aggregated,
      [Constant.gitPosture],
      [repoResourceType.users],
      [],
      this.getGeneralIssueId(),
    );

    return [res];
  }

  getAggragatedUsersInfo(usersIssues) {
    let aggregatedItems = {};
    for (const userIssues of usersIssues) {
      {
        const currentDiffFromNowToCreatedInDays = userIssues.diffFromNowToCreatedAtInDays;
        const createdAt = userIssues.createdAt;
        const userName = userIssues.name;

        if (aggregatedItems.hasOwnProperty(userName)) {
          let info = aggregatedItems[userName];
          info.pullRequestsCount++;
          if (info.diffFromNowToCreatedAtInDays > currentDiffFromNowToCreatedInDays) {
            info.lastAccess = createdAt;
            info.diffFromNowToCreatedAtInDays = currentDiffFromNowToCreatedInDays;
          }
        } else {
          const info: PolicyOrgDomainRepoAggItem = new PolicyOrgDomainRepoAggItem();
          info.user = userName || "";
          info.email = userIssues.email;
          info.pullRequestsCount = 1;
          info.lastAccess = createdAt; // string
          info.diffFromNowToCreatedAtInDays = currentDiffFromNowToCreatedInDays; // number
          info.setAggId();
          aggregatedItems[userName] = info;
        }
        this.problematicUserDomain = userIssues.name;
      }
    }
    return aggregatedItems;
  }

  identifyCommonDomain(users: User[]) {
    const res = [];
    try {
      const domainMap = {};
      for (const user of users) {
        if (user.domain == undefined) {
          continue;
        }
        if (domainMap.hasOwnProperty(user.domain)) {
          domainMap[user.domain]++;
        } else {
          domainMap[user.domain] = 1;
        }
      }

      for (const [key, value] of Object.entries(domainMap)) {
        const val = value as number;
        if (val / users.length > 0.1) {
          res.push(key);
          continue;
        }
      }
    } catch (err) {
      logger.error(`failed identify common domains, err: ${err}`);
    }
    return res;
  }
}

export class PolicyOrgDomainRepoAggItem extends AggregatedInfoForExclusion {
  user: string;
  email: string;
  pullRequestsCount: number;
  lastAccess: string;
  diffFromNowToCreatedAtInDays: number;

  getExclusionObj() {
    const i: AggregatedUser = new AggregatedUser();
    i.user = this.user;
    return i;
  }
  setAggId() {
    this.aggId = StringHelper.combineStrings(this.user);
    this.hashAggId = StringHelper.hashMd5(this.aggId);
  }
}

export default policyOrgDomainRepo;
