import { CodeRepoTypes, PullRequest, User, UserRole, IssueOwner, repoResourceType } from "../../../entitis/codeRepoTypes";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import pluralize from "pluralize";
import { policyCommitReviewCountAggItem } from "./policyCommitReviewCount";
import Constant from "../../../entitis/constant";
const logger = loggerImport.getDebugLogger();

class policyRarePusherVeteranReviews extends PolicyRulesBase {
  mostHighersVeteranCommiter: string;
  veteranCommiters: Set<string>;
  rareCommiters: Set<string>;
  userMRCountMap: Map<string, number>;
  userMRReviewsCountMap: Map<string, number>;
  userEmailMap: Map<string, string> = new Map();

  async eval(jsonData) {
    try {
      if (!jsonData.code_repo.realRepo) {
        return [];
      }

      this.veteranCommiters = new Set();
      this.rareCommiters = new Set();
      this.userMRCountMap = new Map();
      this.userMRReviewsCountMap = new Map();
      this.mostHighersVeteranCommiter = "";

      const res = [];

      //TODO: allowFirstDaysWithoutReview should be configurable from the policy
      const allowFirstDaysWithoutReview = 90;

      const pusherPushes = this.getValueFromRuleArgs("pusherPushes");

      const pusherDays = this.getValueFromRuleArgs("pusherDays");

      const reviewerReviews = this.getValueFromRuleArgs("reviewerReviews");

      const reviewerPushes = this.getValueFromRuleArgs("reviewerPushes");

      const maxTimeIdentify = this.getValueFromRuleArgs("maxTimeIdentify");

      const minConsideration = this.getValueFromRuleArgs("minConsideration");

      const alwaysIgnoreFileTypes = this.getValueFromRuleArgs("alwaysIgnoreFileTypes");
      const isSastDominant = this.languageHelper.isSastDominant(jsonData.code_repo.languages);

      if (!isSastDominant) {
        return [];
      }

      const repoCreatedAt = jsonData.code_repo.createdAt;
      const repoCreatedAtDate: Date = new Date(repoCreatedAt);
      const oneDay = 1000 * 60 * 60 * 24;
      const difference_ms = new Date().getTime() - new Date(repoCreatedAt).getTime();
      const days = Math.round(difference_ms / oneDay);
      const isOldEnoughForMandatoryReview = days > allowFirstDaysWithoutReview;
      if (!isOldEnoughForMandatoryReview) {
        return [];
      }
      const allPulls: PullRequest[] = [...jsonData.pulls, ...jsonData.pushedCommits];
      const ownerNameRepo = jsonData.code_repo.ownerName;
      const pulls: PullRequest[] = allPulls.filter(
        i =>
          i.diffFromNowToCreatedAtInDays <= maxTimeIdentify &&
          i.diffFromNowToCreatedAtInDays != -1 &&
          Math.round((new Date(i.createdAt).getTime() - repoCreatedAtDate.getTime()) / oneDay) > allowFirstDaysWithoutReview,
      );

      let pullsToEval: PullRequest[] = pulls.filter(
        i => i.diffFromNowToCreatedAtInDays <= minConsideration && i.diffFromNowToCreatedAtInDays != -1,
      );
      pullsToEval = pullsToEval.filter(i => {
        return this.getFilesAfterFilter(i, alwaysIgnoreFileTypes).length > 0 || i.author === ownerNameRepo;
      });

      const userCodeChangePerDay = new Map<string, Set<string>>();

      pulls.forEach(pull => {
        const createdAtDate = new Date(pull.createdAt);
        const y = createdAtDate.getUTCFullYear();
        const m = createdAtDate.getUTCMonth();
        const d = createdAtDate.getUTCDate();

        const date = new Date(y, m, d);

        const user = pull.author;
        this.userEmailMap.set(user, pull.email);

        let userCommitsPerDay = userCodeChangePerDay.get(user);
        if (!userCommitsPerDay) {
          userCodeChangePerDay.set(user, new Set());
          userCommitsPerDay = userCodeChangePerDay.get(user);
          userCommitsPerDay.add(date.toString());
          this.userMRCountMap.set(user, this.userMRCountMap.get(user) ? this.userMRCountMap.get(user) + 1 : 1);
        } else {
          if (!userCommitsPerDay.has(date.toString())) {
            userCommitsPerDay.add(date.toString());
            this.userMRCountMap.set(user, this.userMRCountMap.get(user) ? this.userMRCountMap.get(user) + 1 : 1);
          }
        }
        const reviewers = pull.reviewers;
        const mergeUserName = pull.mergeUser.author;
        let isMergeUserInReviewers = false;
        reviewers.forEach(reviewer => {
          const reviewerName = reviewer.author;
          if (reviewerName === mergeUserName) isMergeUserInReviewers = true;
          this.userMRReviewsCountMap.set(
            reviewerName,
            this.userMRReviewsCountMap.get(reviewerName) ? this.userMRReviewsCountMap.get(reviewerName) + 1 : 1,
          );
        });
        if (!isMergeUserInReviewers && user !== mergeUserName && mergeUserName !== "") {
          this.userMRReviewsCountMap.set(
            mergeUserName,
            this.userMRReviewsCountMap.get(mergeUserName) ? this.userMRReviewsCountMap.get(mergeUserName) + 1 : 1,
          );
        }
      });

      // repo with 1 commiter
      if (this.userMRCountMap.size === 1) {
        return [];
      }

      for (const entry of this.userMRCountMap) {
        const user = entry[0];

        if (this.userMRReviewsCountMap.get(user) && this.userMRReviewsCountMap.get(user) > reviewerReviews) {
          this.veteranCommiters.add(user);
          continue;
        } else if (this.userMRCountMap.has(user) && this.userMRCountMap.get(user) > reviewerPushes) {
          this.veteranCommiters.add(user);
          continue;
        } else if (this.userMRCountMap.get(user) && this.userMRCountMap.get(user) < pusherPushes && ownerNameRepo !== user) {
          this.rareCommiters.add(user);
          continue;
        } else {
          const dates = userCodeChangePerDay.get(user);
          const datesAsArray: Date[] = [];
          dates.forEach(date => {
            datesAsArray.push(new Date(date));
          });
          datesAsArray.sort((a, b) => {
            return a.getTime() - b.getTime();
          });
          const minDate = datesAsArray[0];
          const maxDate = datesAsArray[datesAsArray.length - 1];
          const oneDay = 1000 * 60 * 60 * 24;
          const difference_ms = maxDate.getTime() - minDate.getTime();
          const days = Math.round(difference_ms / oneDay);
          const isInfrequentPusher = days < pusherDays;
          if (isInfrequentPusher && user !== ownerNameRepo) {
            this.rareCommiters.add(user);
          }
        }
      }

      let max = 0;
      this.veteranCommiters.forEach(vetCommiter => {
        const numOfReviewes = this.userMRReviewsCountMap.get(vetCommiter);
        const numOfPrs = this.userMRCountMap.get(vetCommiter);
        let score = 0;
        if (numOfReviewes) score = score + numOfReviewes;
        if (numOfPrs) score = score + numOfPrs;
        if (max < score) {
          max = score;
          this.mostHighersVeteranCommiter = vetCommiter;
        }
      });

      //If there is not veteran reviewer on the repo - don't yield rare committer alert
      if (!this.mostHighersVeteranCommiter) {
        return [];
      }

      const pullsWitoutVeteranReview = [];

      for (const pull of pullsToEval) {
        if (this.rareCommiters.has(pull.author) && pull.author !== ownerNameRepo) {
          let isReviewedByVeterian = false;
          for (const reviewer of pull.reviewers) {
            const reviewerName = reviewer.author;
            if (this.veteranCommiters.has(reviewerName)) {
              isReviewedByVeterian = true;
              break;
            }
          }
          const isMergedByVeteranReviewer = this.veteranCommiters.has(pull.mergeUser.author) && pull.mergeUser.author !== "";
          if (!isReviewedByVeterian && !isMergedByVeteranReviewer) {
            pullsWitoutVeteranReview.push(pull);
          }
        }
      }
      const issueOwner = this.getIssueOwner(jsonData);

      const aggragatedInfo = this.getAggragatedCommitInfo(pullsWitoutVeteranReview, alwaysIgnoreFileTypes);

      for (const events of Object.values(aggragatedInfo) as any) {
        const pullReq: PullRequest = events.topLevel;
        const violationInfoTitle =
          events.aggregated.length &&
          `${pluralize("code change", events.aggregated.length, true)} involving ${pluralize("file", events.uniqueFiles.size, true)} by ${
            pullReq.author
          } ${pullReq.email || ""}`;
        const aggregated = {
          violationInfoTitle,
          columns: "policyRarePusherVeteranReviews",
          aggregatedItems: this.sortEvents(events.aggregated),
        };

        const recommendation =
          this.mostHighersVeteranCommiter === ""
            ? "Please note that there is no veteran of the repo to review the commits. Please consider a veteran reviewer from another repo to review the commits."
            : `Please have the commits reviewed by a veteran reviewer like ${this.mostHighersVeteranCommiter}`;
        const email = pullReq.email === "" ? "" : `(${pullReq.email}) `;
        const newVi = `Rare commiter: ${pullReq.author} ${email}`;
        const issueDesc = ``;
        const item = this.generateItemForReport(
          true,
          newVi,
          issueDesc,
          newVi,
          recommendation,
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
          issueOwner,
        );
        res.push(item);
      }

      return res;
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
    return [];
  }

  sortEvents(commits: PolicyRarePusherVeteranReviewsAggItem[]) {
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
      const reviewers = pulleWithoutReview.reviewers.map(rewiewer => rewiewer.author);

      let reviewersAsString = Constant.NO_REVIEWER;
      if (reviewers.length > 0) {
        reviewersAsString = reviewers.join(",");
      }

      const singleItem: PolicyRarePusherVeteranReviewsAggItem = new PolicyRarePusherVeteranReviewsAggItem();

      (singleItem.pushType = pulleWithoutReview.objType == CodeRepoTypes.pulls ? "Pull Request" : "Push"),
        (singleItem.sha = pulleWithoutReview.sha);
      (singleItem.mergedBy = pulleWithoutReview.mergeUser.author), (singleItem.title = pulleWithoutReview.title);
      singleItem.link = pulleWithoutReview.link;
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

  getIssueOwner(jsonData) {
    try {
      let issueOwners: IssueOwner[] = [];
      const users = jsonData.users as User[];
      if (this.mostHighersVeteranCommiter !== "") {
        issueOwners.push({
          name: this.mostHighersVeteranCommiter,
          email: this.userEmailMap.get(this.mostHighersVeteranCommiter),
        });
        return issueOwners;
      }

      const res = this.getOwnersFromUsers(jsonData);
      return res;
    } catch (e) {}
    return [];
  }
}

export class PolicyRarePusherVeteranReviewsAggItem extends policyCommitReviewCountAggItem {
  reviewers: string;
}

export default policyRarePusherVeteranReviews;
