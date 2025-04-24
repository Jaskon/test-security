import pluralize from "pluralize";
import { CodeRepoTypes, PullRequest, repoResourceType } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { AggregatedCommit, AggregatedInfoForExclusion } from "../../../entitis/service/exclusionTypes";
import StringHelper from "../../../helper/stringHelper";
import TimeHelper from "../../../helper/timeHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import { isDevelopment } from "../../../helper/envUtils";

const logger = loggerImport.getDebugLogger();

class policyCommitReviewCount extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const pullsAndPushes = [...jsonData.pulls, ...jsonData.pushedCommits] as PullRequest[];

      if (pullsAndPushes.length == 0) {
        return [];
      }

      const key = "sha";
      const allPulls = [...new Map(pullsAndPushes.map(item => [item[key], item])).values()];
      //TODO: allowFirstDaysWithoutReview should be configurable from the policy
      const allowFirstDaysWithoutReview = 90;
      //Filter reviews count
      const reviewCountFromArgs = this.getValueFromRuleArgs("reviews") as number;
      if (isNaN(reviewCountFromArgs)) {
        throw `reviews is not array type, ${reviewCountFromArgs.toString()}`;
      }
      const repoCreatedAt = jsonData.code_repo.createdAt;
      const repoCreatedAtDate: Date = new Date(repoCreatedAt);
      const oneDay = 1000 * 60 * 60 * 24;

      // if 33% or more of the languages are not in SAST, ignore this policy for the repo.
      const dominantPercentage = this.getValueFromRuleArgs("dominantPercentage");
      const isSastDominant = this.languageHelper.isSastDominant(jsonData.code_repo.languages, dominantPercentage);

      if (!isSastDominant) {
        return [];
      }

      // low BP - bail
      const minBP = this.getValueFromRuleArgs("minBP");
      if (jsonData.code_repo.repoImportance.total < minBP) {
        return [];
      }
      let pullesWithoutReview: PullRequest[] = allPulls.filter(i => {
        //-1 means error in getting this data
        if (i.reviewerCount == -1) {
          return false;
        }

        if (!i.isMerged) {
          return false;
        }

        const mergedBy = i.mergeUser.author;
        let reviewers = i.reviewerCount;
        if (mergedBy !== i.author && mergedBy !== "") {
          reviewers++;
        }
        return reviewers < reviewCountFromArgs && i.mergedAt != "";
      });

      const ignoreAdminOwners = this.getValueFromRuleArgs("ignoreAdminOwners");

      const timeHelper = new TimeHelper(this.uuid);
      //Filter days number
      const monthsFromArgs = this.getValueFromRuleArgs("minConsideration") as number;
      if (isNaN(monthsFromArgs)) {
        throw `days from args is not number, ${monthsFromArgs.toString()}`;
      }
      pullesWithoutReview = pullesWithoutReview.filter(
        i =>
          timeHelper.getTimeIntervalFromNowInMonths(i.createdAt) <= monthsFromArgs &&
          timeHelper.getTimeIntervalFromNowInMonths(i.createdAt) != -1 &&
          Math.round((new Date(i.createdAt).getTime() - repoCreatedAtDate.getTime()) / oneDay) > allowFirstDaysWithoutReview,
      );

      //Filter files number
      const extensionsIgnoreFromArgs = this.getValueFromRuleArgs("alwaysIgnoreFileTypes");
      if (!Array.isArray(extensionsIgnoreFromArgs)) {
        throw `extensions ignore from args is not array, ${extensionsIgnoreFromArgs.toString()}`;
      }
      const filesFromArgs = this.getValueFromRuleArgs("files") as number;
      if (isNaN(filesFromArgs)) {
        throw `files from args is not number, ${filesFromArgs.toString()}`;
      }

      pullesWithoutReview = pullesWithoutReview.filter(i => this.getFilesAfterFilter(i, extensionsIgnoreFromArgs).length >= filesFromArgs);
      let issueOwners = this.getVeteranReviewer(allPulls);
      if (issueOwners.length === 0) {
        issueOwners = this.getOwnersFromUsers(jsonData);
      }
      let res = [];
      let aggragatedInfo = this.getAggragatedCommitInfo(pullesWithoutReview, extensionsIgnoreFromArgs);

      for (const events of Object.values(aggragatedInfo) as any) {
        const pullReq: PullRequest = events.topLevel;

        try {
          const user = jsonData.users.find(u => u.name === pullReq.author || u.name === pullReq.authorUserName);
          const gitType = jsonData.code_repo.type.toLowerCase();
          const supportedGitTypes = ["github", "github", "bitbucket"];
          // run policy only if git type is supported
          if (supportedGitTypes.includes(gitType)) {
            // ignore admins if setting
            if (ignoreAdminOwners && user != undefined) {
              // roles
              const orgAdminRole = jsonData.code_repo.gitRoles.org.admin.toLowerCase();
              const repoAdminRole = jsonData.code_repo.gitRoles.repo.admin.toLowerCase();

              const userOrgRoles = Array.from(user.orgRole) as string[];

              const isUserRepoAdmin = user.repoRolesRaw.find(i => i.toLowerCase() === repoAdminRole);

              const isUserOrgAdmin = userOrgRoles.find(i => i.toLowerCase() === orgAdminRole);

              if (isUserOrgAdmin || isUserRepoAdmin) {
                continue;
              }
            }
          }
        } catch (e) {
          logger.error(`ignore admin failed ${e}`);
        }

        const email = pullReq.email === "" ? "" : `(${pullReq.email}) `;
        const violationInfoTitle =
          events.aggregated.length &&
          `${pluralize("code change", events.aggregated.length, true)} involving ${pluralize("file", events.uniqueFiles.size, true)} by ${
            pullReq.author
          } ${pullReq.email || ""}`;
        const aggregated = {
          violationInfoTitle,
          aggregatedItems: this.sortEvents(events.aggregated),
          columns: "policyCommitReviewCount",
        };

        const newVi = `Unreviewed code: ${pullReq.author} ${email}`;

        const item = this.generateItemForReport(
          true,
          newVi,
          "",
          newVi,
          `Please have the code pushes done by users ${pullReq.author} ${email}reviewed.`,
          "Code Change",
          "Code Repository",
          "",
          [],
          true,
          "",
          aggregated,
          [Constant.gitPosture],
          [repoResourceType.pulls, repoResourceType.pushedCommits],
          [],
          this.getCustomIssueId(pullReq.author),
          issueOwners,
        );
        res.push(item);
      }

      return res;
    } catch (e) {
      logger.error(`policyCommitReviewCount failed err: ${e}`);
    }
    return [];
  }

  sortEvents(commits: policyCommitReviewCountAggItem[]) {
    try {
      const res = commits.sort((a, b) => a.diffInDays - b.diffInDays);
      return res;
    } catch (err) {
      logger.error(`failed sort ${this.policyRuleMetadata.name}, err: ${err}`);
    }
    return commits;
  }

  getAggragatedCommitInfo(pullesWithoutReview: PullRequest[], extensionsIgnoreFromArgs) {
    let aggregatedItems = {};
    for (const pulleWithoutReview of pullesWithoutReview) {
      const filteredFiles = this.getFilesAfterFilter(pulleWithoutReview, extensionsIgnoreFromArgs);

      const singleItem: policyCommitReviewCountAggItem = new policyCommitReviewCountAggItem();

      const reviewers = pulleWithoutReview.reviewers.map(rewiewer => rewiewer.author);
      let reviewersAsString = Constant.NO_REVIEWER;
      if (reviewers.length > 0) {
        reviewersAsString = reviewers.join(",");
      }

      singleItem.pushType = pulleWithoutReview.objType == CodeRepoTypes.pulls ? "Pull Request" : "Push";
      singleItem.sha = pulleWithoutReview.sha || "";
      singleItem.title = pulleWithoutReview.title;
      singleItem.link = pulleWithoutReview.link;
      singleItem.mergedBy = pulleWithoutReview.mergeUser.author;
      singleItem.date = pulleWithoutReview.mergedAt;
      singleItem.reviewers = reviewersAsString;
      singleItem.fileCount = filteredFiles.length;
      singleItem.diffInDays = pulleWithoutReview.diffFromNowToCreatedAtInDays;
      singleItem.setAggId();

      let unique = pulleWithoutReview.author;

      if (aggregatedItems.hasOwnProperty(unique)) {
        let info = aggregatedItems[unique];

        filteredFiles.forEach(i => info.uniqueFiles.add(i));
        info.aggregated.push(singleItem);
        info.aggregated = info.aggregated.sort(function (a, b) {
          return a.diffInDays - b.diffInDays;
        });
      } else {
        const info = {
          topLevel: pulleWithoutReview,
          aggregated: [],
          uniqueFiles: null,
        };

        info.uniqueFiles = new Set();
        filteredFiles.forEach(i => info.uniqueFiles.add(i));
        info.aggregated.push(singleItem);

        aggregatedItems[unique] = info;
      }
    }
    return aggregatedItems;
  }

  private getVeteranReviewer(pulls: PullRequest[]) {
    try {
      const usersCommitsReviews = new Map<string, number>();
      for (const pr of pulls) {
        if (pr.author === "") {
          continue;
        }

        const isUser = usersCommitsReviews.has(pr.author);
        if (!isUser) {
          usersCommitsReviews.set(pr.author, 1);
        } else {
          usersCommitsReviews.set(pr.author, usersCommitsReviews.get(pr.author) + 1);
        }

        const reviewers = pr.reviewers;
        for (const re of reviewers) {
          if (re.author === "") {
            continue;
          }
          const isReviewer = usersCommitsReviews.has(re.author);
          if (!isReviewer) {
            usersCommitsReviews.set(re.author, 1);
          } else {
            usersCommitsReviews.set(re.author, usersCommitsReviews.get(re.author) + 1);
          }
        }
      }

      const sort = new Map(
        [...usersCommitsReviews.entries()].sort((a, b) => {
          return a[1] < b[1] ? 1 : -1;
        }),
      );

      if (sort.size > 0) {
        const [reviewer] = sort.keys();
        return [{ name: reviewer, email: "" }];
      }
      return [];
    } catch (e) {
      logger.error(`failed to get veteran reviewer. error: ${e}`);
    }
    return [];
  }
}

export class policyCommitReviewCountAggItem extends AggregatedInfoForExclusion {
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

export default policyCommitReviewCount;
