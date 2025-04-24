import pluralize from "pluralize";
import Constant from "../../../entitis/constant";
import { AggregatedInfoForExclusion, AggregatedUser } from "../../../entitis/service/exclusionTypes";
import StringHelper from "../../../helper/stringHelper";
import TimeHelper from "../../../helper/timeHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class removeWriteAccessRepo extends PolicyRulesBase {
  private timeHelper: TimeHelper = new TimeHelper("");

  eval(jsonData) {
    return [];

    if (!jsonData.code_repo.realRepo) {
      return [];
    }
    if (!jsonData.allUsers.length) {
      return [];
    }

    const daysNewUserFromArgs = this.getValueFromRuleArgs("daysNewUser") as number;
    if (isNaN(daysNewUserFromArgs)) {
      throw `daysNewUser is not a number, ${daysNewUserFromArgs.toString()}`;
    }

    const data: RemoveWriteAccessRepoAggItem[] = [];
    const uniqueReviewers = new Set();

    jsonData.allPulls.forEach(pull => {
      i => i.reviewers.forEach(j => uniqueReviewers.add(j.author));
    });

    let inactiveUsers = jsonData.allUsers.filter(i => i.accessLevel.every(u => u.lastActivityDays == -1));

    for (const user of inactiveUsers) {
      if (user.createdAtDays <= daysNewUserFromArgs) {
        continue;
      }

      if (uniqueReviewers.has(user.name)) {
        continue;
      }

      const repoAccessLevel = user.accessLevel.find(u => u.repo.fullName === jsonData.code_repo.fullName);
      if (repoAccessLevel == undefined) {
        continue;
      }

      if (!repoAccessLevel.accessLevel.includes("write")) {
        continue;
      }

      const item: RemoveWriteAccessRepoAggItem = new RemoveWriteAccessRepoAggItem();
      item.user = user.name;
      item.username = user.username || "";
      item.accessLevel = "";
      item.createdAt = user.createdAt;
      item.lastAccess = "";
      item.setAggId();

      data.push(item);
    }

    const users = data.map(i => i.username);
    const newVi = `User has excessive code access: ${users.join(", ")}`;

    if (data.length == 0) {
      return 0;
    }

    const violationInfoTitle = `${pluralize("User", data.length, true)} found`;

    let issueOwners = this.getOwnersFromAppCreator(jsonData);
    if (issueOwners.length > 0) {
      this.getOwnersFromUsers(jsonData);
    }

    if (issueOwners.length === 0) {
      issueOwners = this.getOwnersFromAppOwnersConfig(jsonData);
    }
    const aggregated = {
      violationInfoTitle,
      aggregatedItems: this.sortEvents(data),
      columns: "policyRemoveWriteAccessRepo",
    };

    const haveHas = data.length > 1 ? "have" : "has";
    let issueOwnerName = "";
    if (issueOwners.length > 0) {
      issueOwnerName = issueOwners[0].name;
    }
    const replaceInfo = [
      { replace: "*repoType*", replaceTo: jsonData.code_repo.type },
      { replace: "*repoName*", replaceTo: jsonData.code_repo.fullName.trim() },
      { replace: "*repoOwner*", replaceTo: issueOwnerName },
      { replace: "*haveHas*", replaceTo: haveHas },
      { replace: "*haveHas*", replaceTo: haveHas },
    ];
    const inform = issueOwnerName !== "" ? "Please inform the maintainer: *repoOwner" : "";
    const item = this.generateItemForReport(
      true,
      newVi,
      "",
      newVi,
      `Please consider revoking all write access from the ${pluralize("user", data.length)} with access to *repoName*. ${inform}`,
      "N/A", //?
      "N/A", //?
      replaceInfo,
      [],
      true,
      "",
      aggregated,
      [Constant.gitPosture],
      [],
      [],
      this.getGeneralIssueId(),
      issueOwners,
    );

    return [item];
  }

  sortEvents(users: RemoveWriteAccessRepoAggItem[]) {
    try {
      const res = users.sort(
        (a, b) => this.timeHelper.getTimeIntervalFronNowInMili(a.createdAt) - this.timeHelper.getTimeIntervalFronNowInMili(b.createdAt),
      );
      return res;
    } catch (err) {
      logger.error(`failed sort ${this.policyRuleMetadata.name}, err: ${err}`);
    }
    return users;
  }
}

export class RemoveWriteAccessRepoAggItem extends AggregatedInfoForExclusion {
  user: string;
  username: string;
  accessLevel: string;
  createdAt: string;
  lastAccess: string;

  getExclusionObj() {
    const i: AggregatedUser = new AggregatedUser();
    i.user = this.username;
    return i;
  }
  setAggId() {
    this.aggId = StringHelper.combineStrings(this.user);
    this.hashAggId = StringHelper.hashMd5(this.aggId);
  }
}

export default removeWriteAccessRepo;
