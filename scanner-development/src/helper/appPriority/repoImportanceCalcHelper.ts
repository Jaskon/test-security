import { differenceInCalendarDays } from "date-fns";
import GlobalCodeRepoData from "../../dal/GolobalCollectorData/globalCodeRepoData";
import { Relevance, Repo, RepoImportance, RepoImportanceInfo, RepoImportanceRes, VCSType } from "../../entitis/codeRepoTypes";
import Constant from "../../entitis/constant";
import { IrrelevantReason } from "../../entitis/reportTypes";
import loggerImport from "../../logger";
import { SettingsService } from "../service/scan-settings-service/service/settings-service";
import TimeHelper from "../timeHelper";

import { isDevelopment } from "../envUtils";
import StatesHelper from "../statesHelper";
const logger = loggerImport.getDebugLogger();
export const SEVERITIES = {
  0: 0,
  1: 1,
  2: 5,
  3: 25,
  4: 125,
  5: 625,
};

export class BP {
  max: number = 0;
  setOnce: boolean = false;
  maxFactor: number = 97;
  multiplayerFactor: number = 0;
}

const BASE = 100;
const timeHelper: TimeHelper = new TimeHelper("repoImprtanceCalc");
class RepoImportanceCalcHelper {
  uuid: string;
  orgName: string;

  constructor(uuid: string, orgName: string) {
    this.uuid = uuid;
    this.orgName = orgName;
  }

  isRepoImportanceAreZero(repo: Repo, numberOfFiles: number) {
    const allReasons = [];
    try {
      const irrelevantAppsConfiguredTime = SettingsService.Instance.irrelevantAppTimeInMonths();

      if (repo.vcsType === VCSType.tfvc) {
        return allReasons;
      }

      if (repo.overrideRelevance === Relevance.RELEVANT) {
        logger.info(`repo: ${repo.name} is override relevance`);
        repo.markedAsRelevant = true;
        return allReasons;
      }
      if (repo.overrideRelevance === Relevance.IRRELEVANT) {
        logger.info(`repo: ${repo.name} has been set to not relevant by client, set importance to 0, mono repo: ${repo.monoRepoChild}`);
        //No need to continue after it
        repo.noneRelevantRepo = true;
        allReasons.push(IrrelevantReason.SetByClient);
      }
      if (repo.disable) {
        logger.info(`repo: ${repo.name} disable, set importance to 0, mono repo: ${repo.monoRepoChild}`);
        //No need to continue after it
        repo.noneRelevantRepo = true;
        allReasons.push(IrrelevantReason.archived);
      }
      if (repo.failedClone) {
        logger.info(`repo: ${repo.name} failed clone, set importance to 0, mono repo: ${repo.monoRepoChild}`);
        //No need to continue after it
        repo.noneRelevantRepo = true;
        allReasons.push(IrrelevantReason.failedClone);
        return allReasons;
      }

      if (irrelevantBasedOnDays(repo, irrelevantAppsConfiguredTime)) {
        allReasons.push(`No code changes in the last ${irrelevantAppsConfiguredTime} months`);
      }

      if (numberOfFiles == 0) {
        logger.info(`repo: ${repo.name} have zero files, set importance to 0, mono repo: ${repo.monoRepoChild}`);
        repo.noneRelevantRepo = true;
        allReasons.push(IrrelevantReason.noFiles);
      }
    } catch (err) {
      logger.error(`failed find get repo importance for repo: ${repo.name} , err: ${err}`);
    }
    return allReasons;
  }

  async getRepoImportance(info: RepoImportanceInfo, repo: Repo, extra): Promise<RepoImportance> {
    let numberOfCodeChangesPercentage = 0;
    let daysSinceLastCodeChangePercentage = 0;
    let numberOfLanguageFilesPercentage = 0;
    let numberOfYMLsPercentage = 0;
    let gitIgnorePercentage = 0;
    let readmePercentage = 0;
    let secuirtyMdPercentage = 0;
    let licensePercentage = 0;
    let publicRepoPercentage = 0;
    let numberOfUniqueDaysPercentage = 0;
    let numberOfUniqueUsersPercentage = 0;
    let hasArtifactsAndCloudPercentage = 0;
    let originalBp = 0;

    try {
      numberOfUniqueDaysPercentage = this.numberOfUniqueDays(info.numberOfUniqueCodeChangesByDate);
      numberOfCodeChangesPercentage = this.numberOfCodeChanges(info.numberOfcommits);
      numberOfUniqueUsersPercentage = this.numberOfUniqueUsers(info.uniqueCommits);

      daysSinceLastCodeChangePercentage = this.daysSinceLastCodeChange(timeHelper.getTimeIntervalFronNowInDays(info.lastCodeChange));
      numberOfLanguageFilesPercentage = this.numberOfLanguageFiles(info.numberOfLanguageFiles);
      numberOfYMLsPercentage = this.numberOfYMLs(info.numberOfYMLs);

      gitIgnorePercentage = this.ExistenceOfNonEmptyGitInoreAndLines(info.gitIgnore.exist, info.gitIgnore.lines);
      readmePercentage = this.readmeFileExist(info.readMe);
      secuirtyMdPercentage = this.secuirtyFileExist(info.securityMD);
      licensePercentage = this.licenseFileExist(info.license);
      publicRepoPercentage = this.publicRepo(info.isPrivate);

      if (extra) {
        hasArtifactsAndCloudPercentage = this.hasArtifactsAndCloud(extra);
      }
    } catch (err) {
      const errInfo = `failed find get repo importance for repo: ${repo.name}, info:${JSON.stringify(info, null, 4)}, err: ${err}`;
      logger.error(errInfo);
    }

    const res: RepoImportanceRes = {
      repo_name: repo.name,
      repo_creation_date: info.createdAt,
      repo_creator: info.creator,
      number_of_files: info.numberOfFiles,
      repo_size_bytes: info.size,
      main_branch_name: info.mainBranch,
      numberOfcommits: info.numberOfcommits,
      codeChanges: info.codeChanges,
      commit_count: info.numberOfcommits,
      pushCount: info.numberOfPushes,
      pullCount: info.numberOfPullRequests,
      num_of_unique_user_with_commits: info.uniqueCommits,
      lastCodeChange: info.lastCodeChange,
      tag_count: info.numberOfTags,
      yaml_count: info.numberOfYMLs,
      branch_count: info.branches,
      public_repo: !info.isPrivate,
      extendedInfo: info.extendedInfo,
      irrelevantReasons: [],
    };

    const reason = this.isRepoImportanceAreZero(repo, info.numberOfFiles);
    if (reason.length > 0) {
      res.irrelevantReasons = reason;
      return { res: res, total: 0, info: info };
    }

    let total = 0;
    if (info.numberOfFiles !== 0 && !repo.disable) {
      if (extra) {
        total =
          numberOfCodeChangesPercentage / 2 +
          numberOfUniqueUsersPercentage / 2 +
          daysSinceLastCodeChangePercentage / 2 +
          numberOfLanguageFilesPercentage / 2 +
          numberOfYMLsPercentage / 2 +
          numberOfUniqueDaysPercentage / 2 +
          hasArtifactsAndCloudPercentage;
      } else {
        total =
          numberOfCodeChangesPercentage + // 40
          numberOfUniqueUsersPercentage + // 20
          daysSinceLastCodeChangePercentage + // 10f
          numberOfLanguageFilesPercentage + // 10
          numberOfYMLsPercentage + // 10
          numberOfUniqueDaysPercentage; // 10
      }

      //Reduce business priority only 1 time so ignore recalc
      if (extra) {
        const testWordFound = repo.fullName.toLowerCase().match(Constant.testAppsToIgnore);
        if (testWordFound != undefined) {
          const newRes = total / 2;
          logger.info(
            `reducing app: ${repo.fullName} business priority: ${total} to: ${newRes}, due to the word matches: ${JSON.stringify(
              testWordFound,
            )}`,
          );
          total = newRes;
        }

        //Reduce BP for AWS and Azure Cloud Apps to 50% for 888 only
        if (repo.name.toLowerCase().includes("- cloud")) {
          const newRes = total * 0.5;
          logger.info(`reducing app: ${repo.fullName} business priority: ${total} to: ${newRes}, due to cloud`);
          total = newRes;
        } else {
          //Reduce BP to 25% for all fake repo apps for all orgs
          if (!repo.realRepo) {
            const newRes = total * 0.75;
            logger.info(`reducing app: ${repo.fullName} business priority: ${total} to: ${newRes}, due to not real repo`);
            total = newRes;
          }
        }
      }

      if (total == 0) {
        total = 1;
        logger.error(`repo: ${repo.name} importance are 0`);
      }
    }

    if (total > 100) {
      total = 100;
    }

    if (repo.organization && extra) {
      if (!GlobalCodeRepoData.Instance.orgToBp[repo.organization]) {
        GlobalCodeRepoData.Instance.orgToBp[repo.organization] = total;
      } else {
        const curr = GlobalCodeRepoData.Instance.orgToBp[repo.organization];
        if (curr < total) {
          GlobalCodeRepoData.Instance.orgToBp[repo.organization] = total;
        }
      }
    }
    originalBp = total;
    if (repo.isOverridingPriority) {
      if (isDevelopment()) {
        logger.info(`isOverridingPriority: updated bp for repo ${repo.name} to ${repo.overridePriority}`);
      }
      total = repo.overridePriority;
    }

    return { res: res, total: total, info: info, originalBp } as RepoImportance;
  }

  hasArtifactsAndCloud(extra) {
    try {
      if (extra.hasCloudResource || extra.hasOrchestrator || extra.haskub) return 50;
      if (extra.hasArtifact) return 25;
      return 0;
    } catch (err) {
      logger.error(`failed find artifacts and cloud resources importance, err: ${err}`);
    }
  }
  //Used
  numberOfCodeChanges(num) {
    try {
      logger.debug(`try find number of commits importance for: ${num}`);

      if (num > 500) return 40;
      if (num > 100) return 30;
      if (num > 50) return 20;
      if (num > 10) return 10;
      if (num > 1) return 5;
      return 0;
    } catch (err) {
      logger.error(`failed find number of commits importance for: ${num}, err: ${err}`);
    }
  }
  //Used
  numberOfUniqueDays(num) {
    try {
      logger.debug(`try find number of days importance for: ${num}`);

      if (num > 51) return 10;
      if (num > 20) return 7.5;
      if (num > 11) return 5;
      if (num > 6) return 2.5;

      return 0;
    } catch (err) {
      logger.error(`failed find number of days importance for: ${num}, err: ${err}`);
    }
  }
  //Used
  numberOfUniqueUsers(num) {
    try {
      logger.debug(`try find number of unique commits importance for: ${num}`);

      if (num == 0) return 0;
      if (num == 1) return 5;
      if (num == 2) return 10;
      if (num == 3) return 15;
      if (num >= 4) return 20;

      return 0;
    } catch (err) {
      logger.error(`failed find number of commits importance for: ${num}, err: ${err}`);
    }
    return 0;
  }

  numberOfMerges(num) {
    try {
      logger.debug(`try find number of merges importance for: ${num}`);

      if (num >= 0 && num <= 1) return 0;
      if (num >= 2 && num <= 10) return 5;
      if (num >= 11 && num <= 50) return 7.5;
      if (num >= 51) return 10;
      return 0;
    } catch (err) {
      logger.error(`failed find number of merges for: ${num}, err: ${err}`);
    }
    return 0;
  }

  //Used
  daysSinceLastCodeChange(num) {
    try {
      logger.debug(`try find days since last commit inmportance for: ${num}`);

      if (num >= 0 && num <= 15) return 10;
      if (num >= 16 && num <= 30) return 7.5;
      if (num >= 31 && num <= 60) return 5;
      if (num >= 61 && num <= 100) return 2.5;
      if (num >= 101) return 0;
      return 0;
    } catch (err) {
      logger.error(`failed find days since last commit inmportance for: ${num}, err: ${err}`);
    }
    return 0;
  }

  //Used
  numberOfLanguageFiles(num) {
    try {
      logger.debug(`try find number of language files inmportance for: ${num}`);

      if (num > 500) return 10;
      if (num > 10) return 7.5;
      if (num > 20 && num <= 100) return 5;
      if (num > 1 && num <= 500) return 2.5;
      return 0;
    } catch (err) {
      logger.error(`failed find number of language files inmportance for: ${num}, err: ${err}`);
    }
    return 0;
  }

  numberBranches(num) {
    try {
      logger.debug(`try find number branches inmportance for: ${num}`);

      if (num >= 0 && num <= 1) return 0;
      if (num >= 2 && num <= 5) return 0.625;
      if (num >= 6 && num <= 10) return 1.25;
      if (num >= 11 && num <= 20) return 1.875;
      if (num >= 21) return 2.5;
      return 0;
    } catch (err) {
      logger.error(`failed find number branches inmportance for: ${num}, err: ${err}`);
    }
    return 0;
  }

  numberOfTags(num) {
    try {
      logger.debug(`try find number tags inmportance for: ${num}`);

      if (num >= 2 && num <= 5) return 0.625;
      if (num >= 6 && num <= 10) return 1.25;
      if (num >= 11 && num <= 20) return 1.875;
      if (num >= 21) return 2.5;
      return 0;
    } catch (err) {
      logger.error(`failed find number tags inmportance for: ${num}, err: ${err}`);
    }
    return 0;
  }

  //Used
  numberOfYMLs(num) {
    try {
      logger.debug(`try find number ymls inmportance for: ${num}`);
      if (num > 10) return 10;
      if (num > 5) return 7.5;
      if (num > 2) return 5;
      if (num > 1) return 2.5;
      return 0;
    } catch (err) {
      logger.error(`failed find number ymls inmportance for: ${num}, err: ${err}`);
    }
    return 0;
  }

  ExistenceOfNonEmptyGitInoreAndLines(exist, lines) {
    try {
      logger.debug(`try find existence of non empty .gitignore inmportance'`);
      if (!exist) return 0;

      if (lines >= 0 && lines <= 2) return 0;
      if (lines >= 3 && lines <= 10) return 1.25;
      if (lines >= 11 && lines <= 20) return 3.75;
      if (lines >= 21) return 5;

      return 0;
    } catch (err) {
      logger.error(`failed find existence of non empty .gitignore inmportance`);
    }
  }

  readmeFileExist(val) {
    try {
      logger.debug(`try find readme inmportance'`);

      if (!val) return 0;
      else return 2.5;
    } catch (err) {
      logger.error(`failed find readme inmportance inmportance`);
    }
  }

  secuirtyFileExist(val) {
    try {
      logger.debug(`try find secuirty.md inmportance`);

      if (!val) return 0;
      else return 2.5;
    } catch (err) {
      logger.error(`failed find secuirty.md inmportance inmportance`);
    }
  }

  licenseFileExist(val) {
    try {
      logger.debug(`try find license inmportance`);

      if (!val) return 0;
      else return 2.5;
    } catch (err) {
      logger.error(`failed find license inmportance inmportance`);
    }
  }

  publicRepo(isPrivate) {
    try {
      logger.debug(`try find public repo inmportance`);

      if (isPrivate) return 0;
      else return 2.5;
    } catch (err) {
      logger.error(`failed find days since last commit inmportance, err: ${err}`);
    }
  }
  getSpScore(appRisk, appBP) {
    try {
      const res = Math.trunc(appRisk / (appBP / BASE));
      if (isNaN(res)) {
        return 0;
      }
      return res;
    } catch (e) {
      logger.error(`failed get sp score`);
    }
  }
}

export const addDaysToDate = (numberOfDays: number) => {
  const today = new Date(); // Get today's date
  const futureDate = new Date(today.getTime() + numberOfDays * 24 * 60 * 60 * 1000);
  return futureDate;
};

export function irrelevantBasedOnDays(repo: Repo, timeInMonths: number) {
  try {
    if (!repo.lastPushTime) {
      return false;
    }
    if (repo.vcsType === VCSType.tfvc) {
      return false;
    }

    if (StatesHelper.Instance.orgName === "org_lAV5qgryvJ4YPceY") {
      return false;
    }

    const diffInDays = differenceInCalendarDays(new Date(), new Date(repo.lastPushTime));
    const days = timeInMonths * 30;

    if (diffInDays > days && repo.privateVisability && repo.vcsType == VCSType.git) {
      logger.info(
        `repo: ${repo.fullName} different in days are: ${diffInDays}, lastCodeChange: ${repo.lastPushTime} set importance to 0, mono repo: ${repo.monoRepoChild}`,
      );
      return true;
    }
    return false;
  } catch (err) {
    logger.error(`failed get irrelevant based on days`);
  }
  return false;
}

export default RepoImportanceCalcHelper;
