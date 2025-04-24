import pluralize from "pluralize";
import { Repo, repoType, resourceType, User } from "../../../entitis/codeRepoTypes";
import Constant, { InputType, SettingType } from "../../../entitis/constant";
import { AggregatedInfoForExclusion, AggregatedRepo } from "../../../entitis/service/exclusionTypes";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { Input, InputOption, PolicyFix } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import StringHelper from "../../../helper/stringHelper";
import TimeHelper from "../../../helper/timeHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import { formatDistanceToNow } from "date-fns";
const logger = loggerImport.getDebugLogger();

class policyUntouchedReposShouldBeArchived extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const gitType = jsonData.code_repo.type.toLowerCase();
      let shouldRunPolicy = false;

      switch (gitType) {
        case repoType.github:
          shouldRunPolicy = true;
          break;

        case repoType.gitlab:
          shouldRunPolicy = true;
          break;

        case repoType.bitbucket:
          shouldRunPolicy = true;
          break;
      }

      if (!shouldRunPolicy) {
        return [];
      }

      if (jsonData.code_repo.realRepo || !jsonData.allOrgsRepos.length) {
        return [];
      }

      const getIssueId = (mixedRepoTypes, source, org, isPrivate) => {
        try {
          if (mixedRepoTypes) {
            if (isPrivate) return this.getCustomIssueId(`${source}-${org}-private`);
            else {
              return this.getCustomIssueId(`${source}-${org}-public`);
            }
          }
          return this.getCustomIssueId(`${source}-${org}`);
        } catch (err) {
          logger.error(`Could not get issueId for item, err: ${err}`);
        }
      };

      const source = jsonData.code_repo.type;
      let data: RepoOfOrgAggItem[] = [];
      const dataPublic: RepoOfOrgAggItem[] = [];
      const dataPrivate: RepoOfOrgAggItem[] = [];
      const monthsTillVi = this.getValueFromRuleArgs("MonthsSinceCodeChange");
      const repoTypes = this.getValueFromRuleArgs("RepoType");
      const mixedRepoTypes = repoTypes === "Private or Public";
      const allOrgRepos = jsonData.allOrgsRepos;
      const orgName = allOrgRepos.length === 0 ? "" : allOrgRepos[0].organization;
      const days = monthsTillVi * 30;
      const currDate = new Date().getTime();
      let lastPushTimeDate;
      const org = jsonData.code_repo.org;
      let issueOwner = { name: "", email: "" };
      const orgAdminRole = jsonData.code_repo.gitRoles.org.admin.toLowerCase();
      let userIssueOwner = this.getAdminWithMaxOperations(jsonData.allUsers as User[], orgAdminRole);
      if (userIssueOwner) {
        issueOwner = {
          name: userIssueOwner.name,
          email: userIssueOwner.email || "",
        };
      }
      let orgOrGroup = "";

      switch (gitType) {
        case repoType.github:
          orgOrGroup = "org";
          break;

        case repoType.gitlab:
          orgOrGroup = "top-level group";
          break;

        case repoType.bitbucket:
          orgOrGroup = "workspace";
          break;
      }
      for (const currRepo of allOrgRepos) {
        if (currRepo.disable) {
          continue;
        }
        const isMonoRepoChild = currRepo.monoRepoChild;
        if (isMonoRepoChild && this.policyRuleMetadata.ignoreMonoRepoChild) {
          continue;
        }
        let lastPushTime = currRepo.lastPushTime;
        let privateVisability = jsonData.code_repo.privateVisability;

        //In case of repo with no pushes

        if (!lastPushTime) lastPushTimeDate = new Date(currRepo.createdAt).getTime();
        else lastPushTimeDate = new Date(lastPushTime).getTime();

        let calcDays = (currDate - lastPushTimeDate) / (1000 * 60 * 60 * 24);
        let monthsCalc = Math.round(Math.abs(calcDays)) > days;
        if (!monthsCalc || (repoTypes === "Private" && !privateVisability) || (repoTypes === "Public" && privateVisability)) {
          continue;
        }

        if (mixedRepoTypes) {
          if (currRepo.privateVisability) {
            const privateItem = createItem(currRepo);
            if (!privateItem) {
              continue;
            }
            dataPrivate.push(privateItem);
          } else {
            const publicItem = createItem(currRepo);
            if (!publicItem) {
              continue;
            }
            dataPublic.push(publicItem);
          }
        } else {
          const item = createItem(currRepo);
          if (!item) {
            continue;
          }
          data.push(item);
        }
      }

      if (data.length == 0 && dataPrivate.length == 0 && dataPublic.length == 0) {
        return [];
      }

      let fixLink = "";
      // switch (gitType) {

      //   case repoType.github:
      //     fixLink = `https://github.com/orgs/${orgName}/repositories`;
      //     break;

      //   case repoType.gitlab:
      //     fixLink = `https://gitlab.com/${orgName}`;
      //     break;
      // }
      const res = [];

      if (!mixedRepoTypes) {
        sortByLastCodeDate(data);
        const aggregated = {
          columns: "policyUntouchedReposShouldBeArchived",
          aggregatedItems: data,
        };

        const item = this.generateItemForReport(
          true,
          getIssueName(repoTypes, data, orgOrGroup, false, gitType),
          getIssueDescription(repoTypes, data, monthsTillVi, orgName, false, gitType),
          getIssueDescription(repoTypes, data, monthsTillVi, orgName, false, gitType),
          getRecommendation(repoTypes, data, false, gitType),
          "N/A",
          "N/A",
          "",
          [],
          true,
          fixLink,
          aggregated,
          [Constant.gitPosture],
          [resourceType.allOrgsRepos],
          [],
          getIssueId(mixedRepoTypes, source, org, false),
          [issueOwner],
        );
        if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
          item.fixes = this.generateFixes(data, gitType);
        }
        res.push(item);
      }

      // in case mixed repo types - we will add one alert for public, one alert for private repos
      else {
        sortByLastCodeDate(dataPrivate);
        sortByLastCodeDate(dataPublic);

        if (dataPrivate.length > 0) {
          const aggregated = {
            columns: "policyUntouchedReposShouldBeArchived",
            aggregatedItems: dataPrivate,
          };
          const item = this.generateItemForReport(
            true,
            getIssueName(repoTypes, dataPrivate, orgOrGroup, true, gitType),
            getIssueDescription(repoTypes, dataPrivate, monthsTillVi, orgName, true, gitType),
            getIssueDescription(repoTypes, dataPrivate, monthsTillVi, orgName, true, gitType),
            getRecommendation(repoTypes, dataPrivate, true, gitType),
            "N/A",
            "N/A",
            "",
            [],
            true,
            fixLink,
            aggregated,
            [Constant.gitPosture],
            [resourceType.allOrgsRepos],
            [],
            getIssueId(mixedRepoTypes, source, org, true),
            [issueOwner],
          );
          if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
            item.fixes = this.generateFixes(dataPrivate, gitType);
          }
          res.push(item);
        }

        if (dataPublic.length > 0) {
          const aggregated = {
            columns: "policyUntouchedReposShouldBeArchived",
            aggregatedItems: dataPublic,
          };
          const item = this.generateItemForReport(
            true,
            getIssueName(repoTypes, dataPublic, orgOrGroup, false, gitType),
            getIssueDescription(repoTypes, dataPublic, monthsTillVi, orgName, false, gitType),
            getIssueDescription(repoTypes, dataPublic, monthsTillVi, orgName, false, gitType),
            getRecommendation(repoTypes, dataPublic, false, gitType),
            "N/A",
            "N/A",
            "",
            [],
            true,
            fixLink,
            aggregated,
            [Constant.gitPosture],
            [resourceType.allOrgsRepos],
            [],
            getIssueId(mixedRepoTypes, source, org, false),
            [issueOwner],
          );

          if (jsonData.code_repo.type.toLowerCase() === repoType.github) {
            item.fixes = this.generateFixes(dataPublic, gitType);
          }
          res.push(item);
        }
      }

      return res;
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
    return [];
  }

  generateFixes(data: RepoOfOrgAggItem[], gitType: string) {
    try {
      const p: PolicyFix = new PolicyFix();
      p.settingType = SettingType.archiveRepo;
      p.tooltip = "";
      p.warning = "";

      const input: Input = new Input();
      input.type = "select";
      input.name = InputType.repos;
      input.multiSelect = true;
      const clone = data.slice();

      switch (gitType) {
        case repoType.github:
          p.description = `This action will archive the selected ${pluralize("repo", data.length)}.`;
          p.confirmation = `After archiving the ${pluralize("repo", data.length)} will become read-only to everyone.`;
          input.displayName = `Archive the following ${pluralize("repository", input.options.length)}`;
          break;

        // case repoType.gitlab:
        //   p.description = `This action will archive the selected ${pluralize("project", data.length)}.`;
        //   p.confirmation = `After archiving the ${pluralize("repo", data.length)} will become read-only to everyone.`;
        //   input.displayName = `Archive the following ${pluralize("project", input.options.length)}`;
        //   break;
      }

      input.options = clone.map(i => {
        const timeHelper = new TimeHelper(this.uuid);
        const lastCodeChangeInDays = formatDistanceToNow(new Date(i.lastCodeDate).getTime(), {
          addSuffix: true,
        });
        let toolTipInfo = `Last activity: ${lastCodeChangeInDays}`;
        const o: InputOption = new InputOption();
        o.name = i.repoItem.name;
        o.displayName = o.name;
        o.selected = true;
        o.info = toolTipInfo;
        o.metadata = JSON.stringify({
          owner: i.repoItem.ownerNameApi,
          repo: i.repoItem.name,
          scanId: StatesHelper.Instance.uuid,
          orgId: StatesHelper.Instance.orgName,
        });
        return o;
      });

      p.inputs.push(input);

      return p;
    } catch (e) {
      logger.error(`failed to generate fixes, policy: ${this.policyRuleMetadata.name}, error: ${e}`);
    }
  }
}

export class RepoOfOrgAggItem extends AggregatedInfoForExclusion {
  repo: string;
  repoItem: Repo;
  repoCreator: string;
  lastCodeDate: string;
  createdAt: string;

  getExclusionObj() {
    const i: AggregatedRepo = new AggregatedRepo();
    i.repo = this.repo;
    return i;
  }

  setAggId() {
    this.aggId = StringHelper.combineStrings(this.repo);
    this.hashAggId = StringHelper.hashMd5(this.aggId);
  }
}
export default policyUntouchedReposShouldBeArchived;

const sortByLastCodeDate = data => {
  const withLastActivity = data.filter(i => i.lastCodeDate);
  const withoutLastActivity = data.filter(i => !i.lastCodeDate);
  const withLastActivitySorted = withLastActivity.sort((a, b) => new Date(b.lastCodeDate).getTime() - new Date(a.lastCodeDate).getTime());
  data = [...withLastActivitySorted, ...withoutLastActivity];
};

export const createItem = (currRepo: Repo) => {
  try {
    const item: RepoOfOrgAggItem = new RepoOfOrgAggItem();
    item.repo = currRepo.fullName;
    item.repoItem = currRepo;
    item.repoCreator = currRepo.ownerName;
    item.lastCodeDate = currRepo.lastPushTime;
    item.createdAt = currRepo.createdAt;
    item.setAggId();
    return item;
  } catch (err) {
    logger.error(`Could not create aggItem, err: ${err}`);
  }
};

const getIssueName = (repoTypes, data, orgOrGroup, isPrivate, gitType) => {
  try {
    let issueName = "";

    switch (gitType) {
      case repoType.github:
      case repoType.bitbucket:
        if (repoTypes === "Private" || isPrivate)
          issueName = `Archive ${data.length} private ${pluralize("repo", data.length)} from ${orgOrGroup} with no code changes`;
        else if (repoTypes === "Public" || !isPrivate)
          issueName = `Archive ${data.length} public ${pluralize("repo", data.length)} from ${orgOrGroup} with no code changes`;
        break;

      case repoType.gitlab:
        if (repoTypes === "Private" || isPrivate)
          issueName = `Archive ${data.length} private ${pluralize("project", data.length)} from ${orgOrGroup} with no code changes`;
        else if (repoTypes === "Public" || !isPrivate)
          issueName = `Archive ${data.length} public ${pluralize("project", data.length)} from ${orgOrGroup} with no code changes`;
        break;
    }

    return issueName;
  } catch (err) {
    logger.error(`Could not get issue name for item, err: ${err}`);
  }
};

const getIssueDescription = (repoTypes, data, monthsTillVi, orgName, isPrivate, gitType) => {
  try {
    let issueDesc = "";

    switch (gitType) {
      case repoType.github:
        if (repoTypes === "Private" || isPrivate)
          issueDesc = `There ${pluralize("was", data.length)} ${data.length} ${pluralize(
            "private repo",
            data.length,
          )} found with no code changes in the last ${monthsTillVi} ${pluralize("month", monthsTillVi)} for the organization ${orgName}.
           Consider archiving ${pluralize("this", data.length)} ${pluralize("repo", data.length)}`;
        if (repoTypes === "Public" || !isPrivate)
          issueDesc = `There ${pluralize("was", data.length)} ${data.length} ${pluralize(
            "public repo",
            data.length,
          )} found with no code changes in the last ${monthsTillVi} ${pluralize("month", monthsTillVi)} for the organization ${orgName}.
            Consider archiving ${pluralize("this", data.length)} ${pluralize("repo", data.length)}`;
        break;

      case repoType.gitlab:
        if (repoTypes === "Private" || isPrivate)
          issueDesc = `There ${pluralize("was", data.length)} ${data.length} ${pluralize(
            "private project",
            data.length,
          )} found with no code changes in the last ${monthsTillVi} ${pluralize("month", monthsTillVi)} for the top-level group ${orgName}.
            Consider archiving ${pluralize("this", data.length)} ${pluralize("project", data.length)}`;
        if (repoTypes === "Public" || !isPrivate)
          issueDesc = `There ${pluralize("was", data.length)} ${data.length} ${pluralize(
            "public project",
            data.length,
          )} found with no code changes in the last ${monthsTillVi} ${pluralize("month", monthsTillVi)} for the top-level group ${orgName}.
            Consider archiving ${pluralize("this", data.length)} ${pluralize("project", data.length)}`;

      case repoType.bitbucket:
        if (repoTypes === "Private" || isPrivate)
          issueDesc = `There ${pluralize("was", data.length)} ${data.length} ${pluralize(
            "private repo",
            data.length,
          )} found with no code changes in the last ${monthsTillVi} ${pluralize("month", monthsTillVi)} for the workspace ${orgName}.
           Consider archiving ${pluralize("this", data.length)} ${pluralize("repo", data.length)}`;
        if (repoTypes === "Public" || !isPrivate)
          issueDesc = `There ${pluralize("was", data.length)} ${data.length} ${pluralize(
            "public repo",
            data.length,
          )} found with no code changes in the last ${monthsTillVi} ${pluralize("month", monthsTillVi)} for the workspace ${orgName}.
            Consider archiving ${pluralize("this", data.length)} ${pluralize("repo", data.length)}`;
        break;
    }

    return issueDesc;
  } catch (err) {
    logger.error(`Could not get issue description for item, err: ${err}`);
  }
};

const getRecommendation = (repoTypes, data, isPrivate, gitType) => {
  try {
    const moreThanOne = data.length > 1;
    let recommendation = "";
    switch (gitType) {
      case repoType.github:
        recommendation = `Please consider archiving ${pluralize("this", data.length)} ${pluralize("repo", data.length)}.`;
        if (repoTypes === "Public" || !isPrivate)
          recommendation =
            recommendation +
            `Given that ${pluralize("this", data.length)} ${pluralize("repo", data.length)} ${pluralize("is", data.length)}
           public, please also consider making the ${pluralize("repo", data.length)}
           private (before archiving ${moreThanOne ? "them" : "it"}). `;
        break;

      case repoType.gitlab:
        recommendation = `Please consider archiving ${pluralize("this", data.length)} ${pluralize("project", data.length)}.`;
        if (repoTypes === "Public" || !isPrivate)
          recommendation =
            recommendation +
            `Given that ${pluralize("this", data.length)} ${pluralize("project", data.length)} ${pluralize("is", data.length)}
           public, please also consider making the ${pluralize("project", data.length)}
           private (before archiving ${moreThanOne ? "them" : "it"}). `;
        break;

      case repoType.bitbucket:
        recommendation = `Please consider archiving ${pluralize("this", data.length)} ${pluralize(
          "repo",
          data.length,
        )}. Note that Bitbucket Cloud does not have a formal option to archive old repos. You can do the following: <br>
        1. Create new project named "Archive"
        2. Change all aggregated repos branch restrictions to read-only
        3. Move all aggregated repos to the "Archive" project`;
        if (repoTypes === "Public" || !isPrivate)
          recommendation =
            recommendation +
            `Given that ${pluralize("this", data.length)} ${pluralize("repo", data.length)} ${pluralize("is", data.length)}
           public, please also consider making the ${pluralize("repo", data.length)}
           private (before archiving ${moreThanOne ? "them" : "it"}). `;
        break;
    }

    return recommendation;
  } catch (err) {
    logger.error(`Could not get recommendation for item, err: ${err}`);
  }
};
