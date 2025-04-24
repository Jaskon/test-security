import GlobalCodeRepoData from "../../../dal/GolobalCollectorData/globalCodeRepoData";
import {
  AlertSeverity,
  ForkedRepos,
  ForkReasons,
  IssueOwner,
  OrgRoles,
  Repo,
  repoResourceType,
  repoType,
  resourceType,
  User,
} from "../../../entitis/codeRepoTypes";
import { ChangeReason, severityReasons } from "../../../entitis/service/blameTypes";
import { AggregatedExposedRepo, AggregatedInfoForExclusion } from "../../../entitis/service/exclusionTypes";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import StringHelper from "../../../helper/stringHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase, { Tool } from "./policyRulesBase";
import constants, { Constant, InputType, SettingType } from "../../../entitis/constant";
import { generateFixesForAllowForking } from "./policyAllowForkingPrivateRepos";

const logger = loggerImport.getDebugLogger();

class PolicyMemberCreatePublicRepos extends PolicyRulesBase {
  async eval(jsonData) {
    const res = [];
    try {
      if (this.orgName === "org_OqUihy0OIgK9JeeQ") {
        logger.info(`policy data forks: ${JSON.stringify(this.policyRuleMetadata)}`);
      }

      const filterOldReposByMonth: number = this.getValueFromRuleArgs("monthTime");
      const polType = this.getValueFromRuleArgs("type")[0];
      const usersToReportOn = this.getValueFromRuleArgs("UsersToReportOn") as string[];
      const stopMonitorFormerUserMonth = this.getValueFromRuleArgs("MonitorTimeForFormerMembers") as number;

      //Handle real repo
      const repo: Repo = jsonData.code_repo;
      if (polType === "fork") {
        if (repo.realRepo) {
          this.handleCopiedRepos(repo.forkedRepos, res, filterOldReposByMonth, stopMonitorFormerUserMonth, usersToReportOn, jsonData);
          return res;
        }
      }

      //Handle fake repo
      if (polType === "public") {
        let users: User[] = jsonData.allPublicRepos as any;
        if (users) {
          users.forEach(u => {
            this.handleCopiedRepos(
              u.forkedReposFromOrg,
              res,
              filterOldReposByMonth,
              stopMonitorFormerUserMonth,
              usersToReportOn,
              jsonData,
              true,
            );
          });
          return res;
        }
      }
    } catch (e) {
      logger.error(`failed to eval policy: ${this.policyRuleMetadata.name}, error: ${e}`);
    }
    return res;
  }

  handleCopiedRepos(
    copiedRepos: ForkedRepos[],
    res: any,
    filterOldReposByMonth,
    stopMonitorFormerUserMonth: number,
    usersToReportOn: string[],
    jsonData: any,
    isPublicRepos?: boolean,
  ) {
    try {
      if (copiedRepos.length == 0) {
        return;
      }
      const tools: Tool[] = [resourceType.allPublicRepos];
      if (isPublicRepos) {
        tools.push(resourceType.allPublicRepos);
      }
      const now = new Date();
      const alertsPerType = {};
      copiedRepos.forEach(i => {
        try {
          const createdAt = new Date(i.destination.createdAt);
          const diffInMonthRepo = (now.getTime() - createdAt.getTime()) / (1000 * 3600 * 24 * 30);
          if (diffInMonthRepo > filterOldReposByMonth) {
            return;
          }

          let userName: string = i.user ? i.user.name : i.destinationUserName;
          if (!userName) {
            userName = "Unknown user";
          }

          //Add only 1 each time no need for duplication across reasons
          //this can effect the aggId as well
          const reasonsInfo: string[] = i.reasons;

          const forFromNotWorkingUserSev = reasonsInfo.find(i => i == ForkReasons.forkNoneExitUser);
          if (forFromNotWorkingUserSev) {
            const key = `${ForkReasons.forkNoneExitUser}_${userName}_${i.destination.privateVisability ? "private" : "public"}`;
            if (alertsPerType[key]) {
              alertsPerType[key].push(i);
            } else {
              alertsPerType[key] = [i];
            }
            return;
          }
          const forkSev = reasonsInfo.find(i => i == ForkReasons.fork);
          if (forkSev) {
            const key = `${ForkReasons.fork}_${userName}_${i.destination.privateVisability ? "private" : "public"}`;
            if (alertsPerType[key]) {
              alertsPerType[key].push(i);
            } else {
              alertsPerType[key] = [i];
            }
            return;
          }
          const sameNameSev = reasonsInfo.find(i => i == ForkReasons.sameName);
          if (sameNameSev) {
            const key = `${ForkReasons.sameName}_${userName}_${i.destination.privateVisability ? "private" : "public"}`;
            if (alertsPerType[key]) {
              alertsPerType[key].push(i);
            } else {
              alertsPerType[key] = [i];
            }
            return;
          }
          const publicSev = reasonsInfo.find(i => i == ForkReasons.public);
          if (publicSev) {
            const key = `${ForkReasons.public}_${userName}_${i.destination.privateVisability ? "private" : "public"}`;
            if (alertsPerType[key]) {
              alertsPerType[key].push(i);
            } else {
              alertsPerType[key] = [i];
            }
            return;
          }
        } catch (err) {
          logger.error(`failed set single copied repos, error: ${err}`);
        }
      });

      for (const [name, entry] of Object.entries(alertsPerType)) {
        try {
          let aggItems: ExposedAggItem[] = [];
          let severity = this.policyRuleMetadata.severity;
          const changeReasons: ChangeReason[] = [];
          const unique = new Set();

          let forkedReposCount = 0;
          let forkNoneExitUserCount = 0;
          let forkChangedSettingCount = 0;
          let publicReposCount = 0;
          let sameVerCount = 0;
          const forkedRepos: ForkedRepos[] = entry as any;
          for (const forkedRepo of forkedRepos) {
            try {
              const source: Repo = forkedRepo.source;
              const destination: Repo = forkedRepo.destination;
              const reasonsInfo: string[] = forkedRepo.reasons;

              const exposedAggItem: ExposedAggItem = new ExposedAggItem();
              exposedAggItem.sourceRepoName = source?.fullName ? source?.fullName : "";
              exposedAggItem.sourceRepoLink = source?.link ? source?.link : "";
              exposedAggItem.sourceCreationDate = source?.createdAt ? source?.createdAt : "";
              exposedAggItem.sourceLastModifyDate = source?.lastPushTime ? source?.lastPushTime : "";
              exposedAggItem.destinationRepoName = destination.fullName;
              exposedAggItem.destinationRepoLink = destination.link;
              exposedAggItem.destinationCreationDate = destination.createdAt;
              exposedAggItem.destinationLastModifyDate = destination.lastPushTime;
              exposedAggItem.destinationOrgName = forkedRepo.destinationOrgName;
              exposedAggItem.reasons = reasonsInfo.join(", ");
              exposedAggItem.destinationRepoVisibility = destination.privateVisability ? "private" : "public";

              let userInfoEx: string = forkedRepos[0].user ? forkedRepos[0].user.name : forkedRepos[0].destinationUserName;
              if (!userInfoEx) {
                userInfoEx = forkedRepos[0].destinationOrgName;
              }

              const issueId = this.getCustomIssueId(userInfoEx ? userInfoEx : "no-user");
              exposedAggItem.setAggId();
              if (this.isSingleAggItemExcluded(exposedAggItem.aggId, issueId)) {
                continue;
              }

              const forkSev = reasonsInfo.find(i => i == ForkReasons.fork);
              const forkNoneExitUserSev = reasonsInfo.find(i => i == ForkReasons.forkNoneExitUser);
              const sameNamedSev = reasonsInfo.find(i => i == ForkReasons.sameName);

              if (forkNoneExitUserSev) {
                forkNoneExitUserCount++;
                if (!unique.has(severityReasons.repoForkedFormerUser.shortName)) {
                  unique.add(severityReasons.repoForkedFormerUser.shortName);
                  severity = AlertSeverity.Critical;
                  const changeReason: ChangeReason = new ChangeReason(
                    severityReasons.repoForkedFormerUser.shortName,
                    severityReasons.repoForkedFormerUser.reason,
                    severityReasons.repoForkedFormerUser.changeNumber,
                    severityReasons.repoForkedFormerUser.changeCategory,
                  );
                  changeReasons.push(changeReason);
                }
              } else if (forkSev) {
                forkedReposCount++;
                if (!unique.has(severityReasons.repoForked.shortName)) {
                  unique.add(severityReasons.repoForked.shortName);
                  severity = AlertSeverity.Critical;
                  const changeReason: ChangeReason = new ChangeReason(
                    severityReasons.repoForked.shortName,
                    severityReasons.repoForked.reason,
                    severityReasons.repoForked.changeNumber,
                    severityReasons.repoForked.changeCategory,
                  );
                  changeReasons.push(changeReason);
                }
              } else if (sameNamedSev) {
                sameVerCount++;
                if (!unique.has(severityReasons.repoNameSimilarity.shortName)) {
                  if (severity < AlertSeverity.Critical) {
                    severity = AlertSeverity.Critical;
                  }
                  unique.add(severityReasons.repoNameSimilarity.shortName);
                  const changeReason: ChangeReason = new ChangeReason(
                    severityReasons.repoNameSimilarity.shortName,
                    severityReasons.repoNameSimilarity.reason,
                    severityReasons.repoNameSimilarity.changeNumber,
                    severityReasons.repoNameSimilarity.changeCategory,
                  );
                  changeReasons.push(changeReason);
                }
              } else {
                publicReposCount++;
              }

              aggItems.push(exposedAggItem);
            } catch (err) {
              logger.error(`failed set single ExposedAggItem, err: ${err}`);
            }
          }

          if (aggItems.length == 0) {
            return;
          }

          const user: User = forkedRepos[0].user;
          let userInfo: string = forkedRepos[0].user ? forkedRepos[0].user.name : forkedRepos[0].destinationUserName;
          if (!userInfo) {
            userInfo = forkedRepos[0].destinationOrgName;
          }
          const repo: Repo = forkedRepos[0].source;
          const issueId = this.getCustomIssueId(userInfo ? userInfo : "no-user");

          if (
            forkedReposCount == 0 &&
            sameVerCount == 0 &&
            forkNoneExitUserCount == 0 &&
            forkChangedSettingCount == 0 &&
            publicReposCount > 0
          ) {
            const changeReason: ChangeReason = new ChangeReason(
              severityReasons.noRepoMatch.shortName,
              severityReasons.noRepoMatch.reason,
              severityReasons.noRepoMatch.changeNumber,
              severityReasons.noRepoMatch.changeCategory,
            );
            changeReasons.push(changeReason);
          }

          const settings = {
            isFiltered: true,
            isCOLLABORATORS: false,
            forkedToOrg: false,
            u: "User",
            orgs: [],
          };

          this.setForkSettings(forkedRepos, settings, userInfo, usersToReportOn);

          let isFormerUserId = false;
          if (user) {
            if (user.id == constants.formerUserId) {
              isFormerUserId = true;
            }
          }
          //Former user
          if (isFormerUserId) {
            //Filter by creation data
            if (user.createdAtDate) {
              const diffInMonthUserCreation = (now.getTime() - user.createdAtDate.getTime()) / (1000 * 3600 * 24 * 30);
              if (diffInMonthUserCreation > stopMonitorFormerUserMonth) {
                logger.info(
                  `policy name: ${this.policyRuleMetadata.name}, user: ${JSON.stringify(
                    user,
                  )} due to former user creation time: ${user.createdAtDate.toDateString()}, from policy: ${stopMonitorFormerUserMonth}, diff: ${diffInMonthUserCreation}`,
                );
                continue;
              }
            }
            if (!user.createdAtDate) {
              logger.error(`former user: ${user.name} not have creation date`);
            }
            //Filter by user rule in this case if former user selected
            const shouldContinue = usersToReportOn.find(i => i.toLowerCase() === "former member");
            if (!shouldContinue) {
              logger.info(
                `policy name: ${this.policyRuleMetadata.name}, filter, user org: ${settings.orgs.join(
                  ", ",
                )}, from policy: ${usersToReportOn.join(", ")}, user: ${JSON.stringify(user)} due to former user`,
              );
              continue;
            }
          } else {
            //Check if need skip user
            if (settings.isFiltered && settings.orgs.length > 0) {
              logger.info(
                `policy name: ${this.policyRuleMetadata.name}, filter, user org: ${settings.orgs.join(
                  ", ",
                )}, from policy: ${usersToReportOn.join(", ")}, user: ${JSON.stringify(user)}`,
              );
              continue;
            }
          }

          const additionalInfo = [];
          let issueName;
          let issueDescription;
          this.setAdditionalInfo(forkedRepos, additionalInfo, isFormerUserId);
          this.setPrivatePublicSevReason(aggItems, changeReasons);

          let orgs = settings.orgs;
          let u = settings.u;
          //Set user info string
          if (isFormerUserId) {
            if (severity < AlertSeverity.Medium) {
              severity = AlertSeverity.Medium;
            }
            u = "Former User";
            if (!unique.has(severityReasons.repoForkedFormerUser.shortName)) {
              unique.add(severityReasons.repoForkedFormerUser.shortName);
              const changeReason: ChangeReason = new ChangeReason(
                severityReasons.repoForkedFormerUser.shortName,
                severityReasons.repoForkedFormerUser.reason,
                severityReasons.repoForkedFormerUser.changeNumber,
                severityReasons.repoForkedFormerUser.changeCategory,
              );
              changeReasons.push(changeReason);
            }
          } else if (settings.isCOLLABORATORS) {
            if (severity < AlertSeverity.Medium) {
              severity = AlertSeverity.Medium;
            }
            u = "Outside Collaborator";
            if (!unique.has(severityReasons.outsideCollaborator.shortName)) {
              unique.add(severityReasons.outsideCollaborator.shortName);
              const changeReason: ChangeReason = new ChangeReason(
                severityReasons.outsideCollaborator.shortName,
                severityReasons.outsideCollaborator.reason,
                severityReasons.outsideCollaborator.changeNumber,
                severityReasons.outsideCollaborator.changeCategory,
              );
              changeReasons.push(changeReason);
            }
          }

          //Forked repo
          if (forkedReposCount > 0) {
            issueName = `${u}'s private repo is a fork of orgs private repo: ${userInfo}`;
            issueDescription = `${u} ${userInfo} has forked private repo ${repo.fullName} into their personal account. There are ${forkedReposCount} forked repos. The forked repo in the user’s account is private. This was verified by analyzing all forks of the organization ${repo.organization}.`;
            if (orgs.length) {
              issueDescription = `${issueDescription}<br><br>${userInfo} roles in the orgs are:<br>`;
              orgs.forEach(i => {
                issueDescription = `${issueDescription}${i}<br>`;
              });
              issueDescription = `${issueDescription}<br>`;
            }
            if (settings.isCOLLABORATORS) {
              severity = AlertSeverity.High;
            }
          }
          //Forked repo by none exist member
          else if (forkNoneExitUserCount > 0) {
            issueName = `${u}'s private repo is a fork of orgs private repo: ${userInfo}`;
            issueDescription = `${u} ${userInfo} has forked private repo ${repo.fullName} into their personal account. There are ${forkNoneExitUserCount} forked repos. The forked repo in the user’s account is private. However, user ${userInfo} is no longer a member of any organization affiliated with your company. The fork may have been created when user ${userInfo} still had access to ${repo.fullName}. This was verified by analyzing all forks of the organization ${repo.organization}.`;
            if (orgs.length) {
              issueDescription = `${issueDescription}<br><br>${userInfo} roles in the orgs are:<br>`;
              orgs.forEach(i => {
                issueDescription = `${issueDescription}${i}<br>`;
              });
              issueDescription = `${issueDescription}<br>`;
            }
            severity = AlertSeverity.Critical;
          }
          //Forked repo changed settings
          else if (forkChangedSettingCount > 0) {
            issueName = `${u}'s formerly forked private repo is now public: ${userInfo}`;
            issueDescription = `${u} ${userInfo} previously forked private repo ${
              repo.fullName
            } into their personal account. However, the fork is now broken and the repo is now public. There are ${forkChangedSettingCount} such ${
              forkChangedSettingCount == 1 ? "repo" : "repos"
            }. The fork was created when user ${userInfo} still had access to ${
              repo.fullName
            }. This was verified by analyzing all forks of the organization ${repo.organization}.`;
            if (orgs.length) {
              issueDescription = `${issueDescription}<br><br>${userInfo} roles in the orgs are:<br>`;
              orgs.forEach(i => {
                issueDescription = `${issueDescription}${i}<br>`;
              });
              issueDescription = `${issueDescription}<br>`;
            }
            severity = AlertSeverity.Appoxalypse;
          }
          //based on repo name
          else if (sameVerCount > 0) {
            issueName = `${u}'s public repo name resembles org private repo: ${userInfo}`;
            issueDescription = `${u} ${userInfo} has a public repo that is a close match in name to repo ${
              repo.fullName
            }. There are ${sameVerCount} such ${
              sameVerCount == 1 ? "repo" : "repos"
            }]. Note: We have no visibility into your user’s private repos.`;
            if (settings.isCOLLABORATORS) {
              severity = AlertSeverity.High;
            }
            if (isFormerUserId) {
              const changeReason: ChangeReason = new ChangeReason(
                severityReasons.repoCopiedFormerUser.shortName,
                severityReasons.repoCopiedFormerUser.reason,
                severityReasons.repoCopiedFormerUser.changeNumber,
                severityReasons.repoCopiedFormerUser.changeCategory,
              );
              changeReasons.push(changeReason);
              severity = AlertSeverity.Critical;
            }
          }
          //Handle public repos
          else if (publicReposCount > 0) {
            issueName = `${u} has a public repo: (${userInfo} - ${publicReposCount} ${publicReposCount > 1 ? "repos" : "repo"})`;
            issueDescription = `${u} ${userInfo} has ${publicReposCount} public ${publicReposCount > 1 ? "repos" : "repo"}.`;
            if (orgs.length) {
              issueDescription = `${issueDescription}<br><br>${userInfo} roles in the orgs are:<br>`;
              orgs.forEach(i => {
                issueDescription = `${issueDescription}${i}<br>`;
              });
              issueDescription = `${issueDescription}<br>`;
            } else {
              issueDescription = `${issueDescription}<br><br>`;
            }
            issueDescription = `${issueDescription}Note: We have no visibility into the user's private repos.`;
          }

          const violationInfoTitle = "";
          const aggregated = {
            aggregatedItems: aggItems,
            columns: "policyMemberCreatePublicRepos",
            violationInfoTitle,
          };

          let recommendation;
          if (forkedReposCount > 0) {
            recommendation = `Validate that the forking of any repos to ${userInfo}’s account is compliant with company policy.`;
            if (userInfo == "Unknown user") {
              recommendation = "Validate that the forking of any repos to user’s account is compliant with company policy.";
            }
          } else {
            recommendation = `Please manually verify that user ${userInfo}’s repos do not contain company data.`;
            if (userInfo == "Unknown user") {
              recommendation = `Please manually verify that public repos do not contain company data.`;
            }
          }

          let issueOwners: IssueOwner[] = [];
          if (publicReposCount == 0) {
            try {
              issueOwners = this.getOwnersFromUsers(jsonData);
            } catch (err) {
              logger.error(`failed get owners for: ${this.policyRuleMetadata.name}, error: ${err}`);
            }
          }

          issueOwners.push({
            name: user?.name ? user?.name : "",
            email: user?.email ? user?.email : "",
          });

          try {
            aggItems = aggItems.sort(function (a, b) {
              return new Date(b.destinationCreationDate).getTime() - new Date(a.destinationCreationDate).getTime();
            });
          } catch (err) {
            logger.error(`failed sort, error: ${err}`);
          }

          let item = this.generateItemForReport(
            true,
            issueName,
            issueDescription,
            "",
            recommendation,
            "",
            "",
            [],
            "",
            "",
            "",
            aggregated,
            [Constant.gitPosture],
            tools,
            additionalInfo,
            issueId,
            issueOwners,
            "",
            this.policyRuleMetadata.name,
            [],
            "",
            [],
            this.policyRuleMetadata.severity,
            [],
            undefined,
            AlertSeverity[this.policyRuleMetadata.severity],
            [],
            getSeverityChanges(this.policyRuleMetadata.severity, severity),
            changeReasons,
            [],
          );

          if (
            this.policyRuleMetadata.ruleId === "oxRule__member_create_forked_repos_1" &&
            repo &&
            repo.type.toLowerCase() === repoType.github
          ) {
            item.fixes = generateFixesForAllowForking(repo, this.policyRuleMetadata.name);
          }
          res.push(item);
        } catch (err) {
          logger.error(`failed add single user for forked repos, error: ${err}`);
        }
      }
    } catch (err) {
      logger.error(`failed all user for forked repos, error: ${err}`);
    }
  }

  setForkSettings(forkedRepos: ForkedRepos[], settings: any, userInfo: string, usersToReportOn: string[]) {
    let otherThenColl = false;
    try {
      if (forkedRepos[0].destinationOrgName && !forkedRepos[0].destinationUserName) {
        settings.u = "Outside Organization";
        settings.forkedToOrg = true;
      } else {
        //Set roles
        for (const [name, entry] of Object.entries(GlobalCodeRepoData.Instance.getUsers())) {
          const usersFromGlobal: User[] = entry as any;
          const userFromGlobal = usersFromGlobal.find(i => i.name === userInfo);
          if (userFromGlobal) {
            if (userFromGlobal?.orgRole?.size > 0) {
              settings.orgs.push(`&bull; ${name}: ${Array.from(userFromGlobal.orgRole).join(", ")}`);
            }
            for (const orgRule of Array.from(userFromGlobal.orgRole)) {
              if (usersToReportOn.find(i => i.toLowerCase() === (orgRule as string).toLowerCase())) {
                settings.isFiltered = false;
                if ((orgRule as string).toLowerCase() === OrgRoles.COLLABORATORS.toLowerCase()) {
                  settings.isCOLLABORATORS = true;
                } else {
                  otherThenColl = true;
                }
              }
            }
          }
        }
      }
    } catch (err) {
      logger.error(`failed set fork settings, error: ${err}`);
    }
    if (otherThenColl) {
      settings.isCOLLABORATORS = false;
    }
  }

  setAdditionalInfo(forkedRepos: ForkedRepos[], additionalInfo: any, isFormerUserId: boolean) {
    try {
      const user: User = forkedRepos[0].user;
      let userInfo: string = forkedRepos[0].user ? forkedRepos[0].user.name : forkedRepos[0].destinationUserName;
      if (!userInfo) {
        userInfo = "Unknown user";
      } else {
        additionalInfo.push({
          key: "User name",
          value: user.name,
        });
        if (user?.htmlLink) {
          additionalInfo.push({
            key: "User profile",
            value: user.htmlLink,
          });
        }
        if (user?.createdAt && !isFormerUserId) {
          additionalInfo.push({
            key: "User creation date",
            value: user.createdAt,
          });
        }
        if (user?.orgRole) {
          if (user?.orgRole.size) {
            additionalInfo.push({
              key: "User organization rules",
              value: Array.from(user.orgRole).join(", "),
            });
          }
        }
      }

      //In case the forked happen to user private org
      if (forkedRepos[0].destinationOrgName && forkedRepos[0].destinationOrgName) {
        additionalInfo.push({
          key: "Forked to private organization",
          value: forkedRepos[0].destinationOrgName,
        });
      }
    } catch (err) {
      logger.error(`failed set additional info, pol: ${this.policyRuleMetadata.name}, error: ${err}`);
    }
  }

  setPrivatePublicSevReason(aggItems: any, changeReasons: ChangeReason[]) {
    const visibility = aggItems[0].destinationRepoVisibility;
    if (visibility === "private") {
      const changeReason: ChangeReason = new ChangeReason(
        severityReasons.privateRepo.shortName,
        severityReasons.privateRepo.reason,
        severityReasons.privateRepo.changeNumber,
        severityReasons.privateRepo.changeCategory,
      );
      changeReasons.push(changeReason);
    } else {
      const changeReason: ChangeReason = new ChangeReason(
        severityReasons.publicRepo.shortName,
        severityReasons.publicRepo.reason,
        severityReasons.publicRepo.changeNumber,
        severityReasons.publicRepo.changeCategory,
      );
      changeReasons.push(changeReason);
    }
  }
}

export class ExposedAggItem extends AggregatedInfoForExclusion {
  sourceRepoName: string;
  sourceRepoLink: string;
  sourceCreationDate: string;
  sourceLastModifyDate: string;
  destinationRepoName: string;
  destinationRepoLink: string;
  destinationCreationDate: string;
  destinationLastModifyDate: string;
  destinationRepoVisibility: string;
  destinationOrgName: string;
  reasons: string;

  getExclusionObj() {
    const i: AggregatedExposedRepo = new AggregatedExposedRepo();
    i.sourceRepoName = this.sourceRepoName;
    i.destinationRepoName = this.destinationRepoName;
    return i;
  }

  setAggId() {
    this.aggId = StringHelper.combineStrings(this.sourceRepoName, this.destinationRepoName);
    this.hashAggId = StringHelper.hashMd5(this.aggId);
  }
}

export default PolicyMemberCreatePublicRepos;
