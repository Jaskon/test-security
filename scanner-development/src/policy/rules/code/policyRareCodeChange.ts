import { countBy, groupBy } from "lodash";
import GlobalCodeRepoData from "../../../dal/GolobalCollectorData/globalCodeRepoData";
import { CodeRepoTypes, PullRequest, Repo, repoResourceType, repoType, User } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { Severity } from "../../../entitis/reportTypes";
import { severityReasons } from "../../../entitis/service/blameTypes";
import { AggregatedCommit, AggregatedInfoForExclusion } from "../../../entitis/service/exclusionTypes";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import StringHelper from "../../../helper/stringHelper";
import TimeHelper from "../../../helper/timeHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import pluralize from "pluralize";

const logger = loggerImport.getDebugLogger();

export default class PolicyRareCodeChange extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const repo: Repo = jsonData.code_repo;
      const users: User[] = jsonData.users;

      // no fake apps
      if (!repo.realRepo) {
        return [];
      }

      if (repo.type === repoType.awsCodeCommit) {
        return [];
      }

      const all = [...jsonData.pulls, ...jsonData.pushedCommits];
      const countedBy = countBy(all, "author");
      const groupedByAuthor = groupBy(all, "author");

      // get config params
      const maxCodeChanges = this.getValueFromRuleArgs("maxCodeChanges");
      const minReviews = this.getValueFromRuleArgs("minReviews");
      const minCodePushes = this.getValueFromRuleArgs("minCodePushes");
      const ignoreOldChangesInMonths = this.getValueFromRuleArgs("ignoreOldChangesInMonths");
      const minBP = this.getValueFromRuleArgs("minBP");
      const ignoreFileTypes = this.getValueFromRuleArgs("ignoreFileTypes");
      const repoCreatedinMonths = this.getValueFromRuleArgs("repoCreatedinMonths");
      const ignoreAdminOwners = this.getValueFromRuleArgs("ignoreAdminOwners");
      let alwaysIgnore = this.getValueFromRuleArgs("alwaysIgnore");

      if (!alwaysIgnore || !Array.isArray(alwaysIgnore)) {
        logger.error(
          `alwaysIgnore missing policy: ${this.policyRuleMetadata.functionName}, repo: ${repo.name}, ${
            this.policyRuleMetadata.args[3]
          },typeof: ${typeof alwaysIgnore}`,
        );

        alwaysIgnore = [];
      }

      const timeHelper = new TimeHelper(this.uuid);
      const veterans = new Map();
      const veteransData = new Map();
      const rarePushers = new Map();
      const rarePushersData = new Map();
      const usersReviewsCount = new Map();
      const nonReviewedViolations = [];
      const reviewedByNonVeteranViolations = [];

      // roles
      const orgAdminRole = jsonData?.code_repo?.gitRoles?.org?.admin?.toLowerCase();
      const repoAdminRole = jsonData?.code_repo?.gitRoles?.repo?.admin?.toLowerCase();
      if (!orgAdminRole || !repoAdminRole) {
        return [];
      }

      // severity
      let changedSeverity = this.policyRuleMetadata.severity;
      let changeReason = severityReasons.noCodeReview;

      // Repo created that is less than Z months old - bail
      const isNewRepo = timeHelper.getTimeIntervalFromNowInMonths(repo.createdAt) < repoCreatedinMonths;
      if (isNewRepo) {
        return [];
      }

      // low BP - bail
      if (repo.repoImportance.total < minBP) {
        return [];
      }

      const pullsObj = {};

      for (const [author, pulls] of Object.entries(groupedByAuthor)) {
        pullsObj[author] = pulls[author] || {};
        pullsObj[author]["count"] = Object.values(pulls).length;
        pullsObj[author]["lastPullRequest"] = this.getLastPR(pulls as PullRequest[]);
        pullsObj[author]["pulls"] = pulls;
      }

      jsonData.allPulls = pullsObj;

      for (const user of users) {
        const reviewed = all.filter(x => x.reviewerCount > 0);
        const userReviews = reviewed.filter(x => x.reviewers.some(i => i.author === user.name));

        usersReviewsCount.set(user.name, userReviews.length);
        if (alwaysIgnore.includes(user.name)) {
          const hasReviews = usersReviewsCount.get(user.name);
          veterans.set(user.name, hasReviews);
          veteransData.set(user.name, user);
        }
      }

      for (const user of users) {
        if (!jsonData.allPulls[user.name]) {
          continue;
        }

        const hasReviews = usersReviewsCount.get(user.name);

        if (hasReviews && jsonData.allPulls[user.name]) {
          if (hasReviews > minReviews || jsonData.allPulls[user.name].count >= minCodePushes) {
            veterans.set(user.name, hasReviews);
            veteransData.set(user.name, user);
          }
        }

        // ignore admins if setting
        if (ignoreAdminOwners) {
          const userOrgRoles = Array.from(user.orgRole) as string[];

          const isUserRepoAdmin = user.repoRolesRaw.find(i => i.toLowerCase() === repoAdminRole);

          const isUserOrgAdmin = userOrgRoles.find(i => i.toLowerCase() === orgAdminRole);

          if (isUserOrgAdmin || isUserRepoAdmin) {
            continue;
          }
        }

        if (alwaysIgnore.length) {
          const alwaysIgnoreToLowerCase = alwaysIgnore.map(x => x.toLowerCase());
          if (alwaysIgnoreToLowerCase.includes(user.name.toLowerCase())) {
            continue;
          }
        }

        if (jsonData.allPulls[user.name]) {
          if (jsonData.allPulls[user.name].count > 0 && jsonData.allPulls[user.name].count < maxCodeChanges) {
            if (!veterans.has(user.name)) {
              rarePushers.set(user.name, jsonData.allPulls[user.name].pulls);
              rarePushersData.set(user.name, user);
            }
          }
        }
      }

      if (!veterans.size) {
        return [];
      }
      for (const [rarePusher, pushes] of rarePushers.entries()) {
        //  filter old changes
        const changes = pushes.filter(p => timeHelper.getTimeIntervalFromNowInMonths(p.createdAt) <= ignoreOldChangesInMonths);

        // filter ignored files
        const filteredPushes = changes.filter(i => this.getFilesAfterFilter(i, ignoreFileTypes).length > 0);

        const veteranNames = [...veterans.keys()];

        const nonReviewed = filteredPushes.filter(push => push.reviewerCount === 0 || push.reviewers.find(r => r.author === push.author));

        const reviewedByNonVeteran = filteredPushes.filter(
          push =>
            push.reviewerCount > 0 &&
            push.reviewers.every(rev => !veteranNames.includes(rev.author)) &&
            push.reviewers.find(r => r.author !== push.author),
        );

        if (nonReviewed.length) {
          const vi = { user: rarePusher, codePush: nonReviewed };
          nonReviewedViolations.push(vi);
        }

        if (reviewedByNonVeteran.length) {
          const vi = { user: rarePusher, codePush: reviewedByNonVeteran };
          reviewedByNonVeteranViolations.push(vi);
        }
      }

      // for both
      const res = [];
      let fixLink;
      switch (repo.type.toLowerCase()) {
        case repoType.gitlab:
          fixLink = `${repo.link}/-/project_members`;
          break;
        case repoType.github:
          fixLink = `${repo.link}/settings/access`;
          break;

        default:
          fixLink = repo.link;
          break;
      }

      let highestVeteran;
      if (veterans.size) {
        highestVeteran = [...veterans.entries()].reduce((a, e) => (e[1] > a[1] ? e : a))[0];
      }
      const highestVeteranData = veteransData.get(highestVeteran);

      // issue owner
      const issueOwner = {
        name: highestVeteran,
        email: "",
      };

      // recommendation
      const recommendation = highestVeteran
        ? `Please have all the code changes reviewed by a veteran reviewer like ${highestVeteran}.`
        : `Please note that there is no veteran of the repo to review the changes. Please consider a veteran reviewer from another repo to review the code changes.`;

      // reviewed but not by veteran
      for (const v of reviewedByNonVeteranViolations) {
        const data = [];
        const extraInfo = [];
        let reviewers = this.setAggData(v, data);

        const aggregated = {
          columns: "policyRarePusherVeteranReviews",
          aggregatedItems: data,
        };

        const user = rarePushersData.get(v.user);
        let email = this.getUserMail(v, user);

        // extra data
        extraInfo.push({
          key: "User Dev Activity Count",
          value: countedBy[user.name],
        });

        if (user.createdAtDate) {
          extraInfo.push({
            key: "User Repo Join Date",
            value: user.createdAtDate,
          });
        }

        const revReviews = {
          key: "Reviewer Review Activity Count",
          value: ``,
        };

        const revPushes = {
          key: "Reviewer Dev Activity Count",
          value: ``,
        };

        for (const reviewer of reviewers) {
          revReviews.value += `${reviewer}: ${usersReviewsCount.get(reviewer)} `;
          revPushes.value += `${reviewer}: ${countedBy[reviewer]} `;

          if (!revReviews.value.includes("undefined")) {
            extraInfo.push(revReviews);
          }

          if (!revPushes.value.includes("undefined")) {
            extraInfo.push(revPushes);
          }
        }

        extraInfo.push(
          {
            key: "Most Veteran Reviewer Review Activity Count",
            value: `${highestVeteran}: ${usersReviewsCount.get(highestVeteranData.name)}`,
          },
          {
            key: "Most Veteran Reviewer Dev Activity Count",
            value: `${highestVeteran}: ${countedBy[highestVeteran]}`,
          },
        );

        // texts
        const daysSinceRepoCreated = this.dateToDaysNow(repo.createdAt);
        const issueName = `Developer changed unfamiliar code without a veteran review: ${user.name}`;
        const issueDescription = `There were ${v.codePush.length} code changes that were made by ${
          user.name
        } who may not be familiar with the repo. The reviews of the changes were not conducted by a veteran reviewer. ${
          user.name
        } is considered to be unfamiliar with the code base because they have a total of ${v.codePush.length} PRs or Push events.  ${
          user.createdAtDate ? `${user.name} joined on ${user.createdAtDate}` : ""
        } <br>
        The repo was created ${daysSinceRepoCreated} ${pluralize("day", daysSinceRepoCreated)} ago.`;

        const item = this.generateItemForReport(
          true,
          issueName,
          issueDescription,
          "",
          recommendation,
          "Code Change",
          "Code Repository",
          "",
          [],
          true,
          fixLink,
          aggregated,
          [Constant.gitPosture],
          [repoResourceType.pulls, repoResourceType.pushedCommits, repoResourceType.users],
          extraInfo,
          this.getCustomIssueId(user.name + "reviewedByNonVeteranViolation"),
          [issueOwner],
        );

        res.push(item);
      }

      // not reviewd at all
      for (const v of nonReviewedViolations) {
        const data = [];
        const extraInfo = [];
        this.setAggData(v, data);

        const aggregated = {
          columns: "policyRarePusherVeteranReviews",
          aggregatedItems: data,
        };

        const user = rarePushersData.get(v.user);

        extraInfo.push({
          key: "User Dev Activity Count",
          value: `${countedBy[user.name]}`,
        });

        if (user.createdAtDate) {
          extraInfo.push({
            key: "User Repo Join Date",
            value: `${user.createdAtDate}`,
          });
        }

        extraInfo.push(
          {
            key: "Most Veteran Reviewer Review Activity Count",
            value: `${highestVeteran}: ${usersReviewsCount.get(highestVeteran)}`,
          },
          {
            key: "Most Veteran Reviewer Dev Activity Count",
            value: `${highestVeteran}: ${countedBy[highestVeteran]}`,
          },
        );

        const issueName = `Developer changed unfamiliar code with no reviews: ${user.name}`;
        const issueDescription = `There were ${v.codePush.length} code changes that were made by ${
          user.name
        } who may not be familiar with the repo. There were no reviews which is extremely dangerous.
        ${user.name} is considered to be unfamiliar with the code base because they have a total of ${
          v.codePush.length
        } PRs or Push events.  ${user.createdAtDate ? `${user.name} joined on ${user.createdAtDate}` : ""} <br>
        The repository was created at: ${repo.createdAt}.`;

        const item = this.generateItemForReport(
          true,
          issueName,
          issueDescription,
          "",
          recommendation,
          "Code Change",
          "Code Repository",
          "",
          [],
          true,
          fixLink,
          aggregated,
          [Constant.gitPosture],
          ["UNKNOWN"],
          extraInfo,
          this.getCustomIssueId(user.name + "nonReviewedViolation"),
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
          ["No code review", "There was no code review done."],
          getSeverityChanges(this.policyRuleMetadata.severity, changedSeverity),
          changeReason ? [changeReason] : [],
        );

        res.push(item);
      }

      return res;
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}, repo: ${jsonData.code_repo.name}`);
    }
    return [];
  }

  getUserMail(v, user: User) {
    let email = "";
    try {
      email = GlobalCodeRepoData.Instance.userMailMap.get(user.name);

      if (!email) {
        email = GlobalCodeRepoData.Instance.userMailMap.get(user.username);
      }

      if (!email || email === "") {
        if (v.codePush[0] !== undefined && v.codePush[0].email != "") {
          email = v.codePush[0].email;
          return `(${email})`;
        }
      }

      return email ? `(${email})` : "";
    } catch (e) {
      logger.error(`getUserMail ${e}`);
    }
    return "";
  }

  setAggData(v, data) {
    try {
      const reviewers = [];
      for (const codePush of v.codePush) {
        let reviewersAsString = Constant.NO_REVIEWER;

        if (codePush.reviewers.length > 0) {
          reviewersAsString = codePush.reviewers.map(r => r.author).join(", ");
        }

        const aItem: policyRareCodeChangeAggItem = new policyRareCodeChangeAggItem();

        aItem.pushType = codePush.objType === CodeRepoTypes.pulls ? "Pull Request" : "Push";

        aItem.sha = codePush.sha;
        aItem.mergedBy = codePush.mergeUser.author;
        aItem.title = codePush.title;
        aItem.link = codePush.link;
        aItem.date = codePush.mergedAt;
        aItem.reviewers = reviewersAsString;
        aItem.fileCount = codePush.uniqueFilesChanged.length;
        aItem.diffInDays = codePush.diffFromNowToCreatedAtInDays;
        aItem.setAggId();

        data.push(aItem);
        const revs = codePush.reviewers.map(r => r.author).flat();
        reviewers.push(...revs);
      }
      return [...new Set(reviewers)];
    } catch (e) {
      logger.error(`setAggData error: ${e}`);
    }
    return [];
  }

  getLastPR(pulls: PullRequest[]) {
    try {
      (Object.values(pulls) as any).sort((a, b) => {
        return b.mergedAt - a.mergedAt;
      })[0];
    } catch (e) {
      logger.error(`failed to getlast pr, err: ${e}`);
    }
  }
}

export class policyRareCodeChangeAggItem extends AggregatedInfoForExclusion {
  pushType: string;
  sha: string;
  title: string;
  link: string;
  reviewers: string;
  mergedBy: string;
  date: string;
  fileCount: number;
  diffInDays: number;

  getExclusionObj() {
    const i: AggregatedCommit = new AggregatedCommit();
    i.sha = this.sha;
    return i;
  }
  setAggId() {
    this.aggId = StringHelper.combineStrings(this.sha);
    this.hashAggId = StringHelper.hashMd5(this.aggId);
  }
}
