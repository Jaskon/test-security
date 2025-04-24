import {
  CodeRepoTypes,
  Commit,
  OrgRoles,
  PullRequest,
  Repo,
  repoType,
  RepoTypeName,
  resourceType,
  Reviewer,
  SecurityEvent,
  User,
  UserAuditLog,
  Webhook,
} from "../../entitis/codeRepoTypes";
import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();

export class UserPullRequest {
  lastPullRequest: PullRequest;
  count: number = 0;
}

export class UserReviewer {
  lastReviewer: Reviewer;
  lastReviewerRequest: Date;
  count: number = 0;
}

export class UserCommit {
  lastCommit: Commit;
  count: number = 0;
  gitType: repoType;
}

export enum repoAdminRole {
  Admin = "admin",
  Owner = "owner",
}

const repoAdminRoleByGit = {
  GitLab: repoAdminRole.Owner,
  Github: repoAdminRole.Admin,
};

class GlobalCodeRepoData {
  private static _instance: GlobalCodeRepoData;

  uuid: string;
  orgName: string;

  //Global data to process during run
  private users = {};
  repos: Repo[] = [];

  UserPullRequest = {};
  UserReviewers = {};
  auditLogBasedOnUser = {};
  UserCommitsRepo = {};
  domainWebhooksToRepo = {};
  UserPullRequestRepo = {};
  UserReviewersRepo = {};
  userMailMap = new Map();

  formerUsers: User[] = [];

  orgToBp = {};

  orgs = new Map();
  uniqueActionsMap = new Map();

  scopesRepoMap = {};
  secEvents = [];

  usersGitTypeMap = new Map();

  private constructor() {}

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  addSecEvent(events: SecurityEvent[]) {
    try {
      this.secEvents = [...this.secEvents, ...events];
    } catch (err) {
      logger.error(`Could not add security events under org's allSecEvents, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.allSecEvents);
    }
  }

  addRepoToScope(event: SecurityEvent) {
    try {
      if (this.scopesRepoMap[event.orgScopeId]) {
        const exist = this.scopesRepoMap[event.orgScopeId].find(i => i === event.repoFullName);
        if (!exist) {
          this.scopesRepoMap[event.orgScopeId].push(event.repoFullName);
        }
      } else {
        this.scopesRepoMap[event.orgScopeId] = [event.repoFullName];
      }
    } catch (err) {
      logger.error(`Could not add the repo to the scope list, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.scopesRepoMap);
    }
  }

  addRepo(repo: Repo) {
    try {
      this.repos.push(repo);
    } catch (err) {
      logger.error(`failed in add repo, err:${err}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.allOrgsRepos);
    }
  }

  getUsersByOrg(orgWithPrefix: string) {
    try {
      return this.users[orgWithPrefix];
    } catch (err) {
      logger.error(`failed finding org: ${orgWithPrefix}, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.allUsers);
    }
  }

  getUsers() {
    try {
      return this.users;
    } catch (err) {
      logger.error(`failed getting users map, err:${err}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.allPublicRepos);
    }
  }

  updateRepoUserWithCreatedAt(repoObj) {
    const repo: Repo = repoObj.code_repo;
    try {
      const repoUsers: User[] = repoObj[CodeRepoTypes[CodeRepoTypes.users]];

      const usersAuditLog: UserAuditLog[] = Object.values(this.auditLogBasedOnUser).flat() as UserAuditLog[];
      if (usersAuditLog.length == 0) {
        return;
      }

      const usersAuditLogRepo: UserAuditLog[] = usersAuditLog.filter(i => i.repo === repo.fullPath);

      if (usersAuditLogRepo.length == 0) {
        return;
      }

      if (repoUsers) {
        repoUsers.forEach(repoUser => {
          const orgUser: User = this.getUserBasedOnId(repoUser, repo.organization, repo.type.toLowerCase());
          if (!orgUser) {
            return;
          }

          const userLog = usersAuditLogRepo.find(
            logUser => (logUser.name === repoUser.name || logUser.name === repoUser.username) && logUser.action === "repo.add_member",
          );

          if (userLog) {
            repoUser.createdAt = userLog.actionInfo;
            repoUser.createdAtDate = new Date(userLog.actionInfo);
          }
        });
      }
    } catch (e) {
      logger.error(`failed updateRepoUserWithCreatedAt failed, err: ${e}`);
    }
  }

  updateRepoWebhookInfo(repoObj: any, totalRepos: number) {
    try {
      const repoWebhooks: Webhook[] = repoObj[CodeRepoTypes[CodeRepoTypes.webhooks]];
      if (!repoWebhooks) {
        return;
      }

      repoWebhooks.forEach(w => {
        const dataWebhooks = GlobalCodeRepoData.Instance.domainWebhooksToRepo[w.domain];
        if (!dataWebhooks) {
          return;
        }

        const wInfo = Array.from(dataWebhooks) as Webhook[];
        const percentage = wInfo.length / totalRepos;
        w.domainAppearAcrossOrgPercentage = percentage;
        w.numberOfReposDomainAppear = wInfo.length;
      });
    } catch (err) {
      logger.error(`failed updateRepoWebhookInfo, err: ${err}`);
    }
  }

  updateOrgCollaborators(org) {
    try {
      const users = this.users[org];
      if (!users) {
        return;
      }

      for (const user of users) {
        if (!user.orgRole.size) {
          user.orgRole.add(OrgRoles.COLLABORATORS);
        }
      }
    } catch (err) {
      logger.error(`failed updating org:${org} outside collaborators`, err);
    }
  }

  updateUsersRepoWithOrgOperation(repoObj: any, userAdminToRepo: any) {
    try {
      const repoUsers: User[] = repoObj[CodeRepoTypes[CodeRepoTypes.users]];

      if (repoUsers) {
        repoUsers.forEach(repoUser => {
          if (repoUser.repoRolesRaw?.find(i => i?.toLowerCase() === "admin" || i?.toLowerCase() === "owner")) {
            if (userAdminToRepo[repoUser.name]) {
              userAdminToRepo[repoUser.name].add(repoObj.code_repo.fullName);
            } else {
              userAdminToRepo[repoUser.name] = new Set();
              userAdminToRepo[repoUser.name].add(repoObj.code_repo.fullName);
            }
          }

          const orgUser: User = this.getUserBasedOnId(repoUser, repoObj.code_repo.organization, repoObj.code_repo.type.toLowerCase());
          if (!orgUser) {
            return;
          }

          repoUser.devOperation = orgUser.devOperation;
          repoUser.devOperationDate = orgUser.devOperationDate;
          repoUser.foundDevData = orgUser.foundDevData;
          repoUser.foundAdminData = orgUser.foundAdminData;
          repoUser.adminOperation = orgUser.adminOperation;
          repoUser.adminOperationDate = orgUser.adminOperationDate;
          repoUser.adminLocation = orgUser.adminLocation;
          repoUser.lastActivityData = orgUser.lastActivityData;
          repoUser.reviewOperation = orgUser.reviewOperation;
          repoUser.reviewOperationDate = orgUser.reviewOperationDate;
          repoUser.foundReviewData = orgUser.foundReviewData;
          repoUser.lastAdminOperation = orgUser.lastAdminOperation;

          Array.from(orgUser.orgRole).forEach(r => {
            repoUser.orgRole.add(r);
          });
        });
      }
    } catch (err) {
      logger.error(`failed to update users orgs, err:${err}`);
    }
  }

  updateUsersRepoWithDevOperation(repoObj: any) {
    const repo: Repo = repoObj.code_repo;

    try {
      const repoUsers: User[] = repoObj[CodeRepoTypes[CodeRepoTypes.users]];

      const users: UserPullRequest[] = this.UserPullRequestRepo[repo.fullName];
      if (!users) {
        return;
      }
      if (users.length == 0) {
        return;
      }

      if (repoUsers) {
        repoUsers.forEach(repoUser => {
          const u = users.find(i => i.lastPullRequest.author === repoUser.name);
          if (!u) {
            return;
          }

          repoUser.devOperationRepo = u.count;
          repoUser.devOperationDateRepo = u.lastPullRequest.createdAtData;
          repoUser.foundDevDataRepo = true;
        });
      }
    } catch (err) {
      logger.error(`failed to update users dev based on repo: ${repo.fullName}, err:${err}`);
    }
  }

  updateUsersRepoWithReviewOperation(repoObj: any) {
    const repo: Repo = repoObj.code_repo;

    try {
      const repoUsers: User[] = repoObj[CodeRepoTypes[CodeRepoTypes.users]];

      const users: UserReviewer[] = this.UserReviewersRepo[repo.fullName];
      if (!users) {
        return;
      }
      if (users.length == 0) {
        return;
      }

      if (repoUsers) {
        repoUsers.forEach(repoUser => {
          const u = users.find(i => i.lastReviewer.author === repoUser.name);
          if (!u) {
            return;
          }

          repoUser.reviewOperationRepo = u.count;
          repoUser.reviewOperationDateRepo = u.lastReviewerRequest;
          repoUser.foundReviewDataRepo = true;
        });
      }
    } catch (err) {
      logger.error(`failed to update users review based on repo: ${repo.fullName}, err:${err}`);
    }
  }

  updateUsersRepoWithAdminOperation(repoObj: any) {
    const repo: Repo = repoObj.code_repo;

    try {
      const repoUsers: User[] = repoObj[CodeRepoTypes[CodeRepoTypes.users]];
      if (!repoUsers) {
        return;
      }
      if (repoUsers.length == 0) {
        return;
      }
      const usersAuditLog: UserAuditLog[] = Object.values(this.auditLogBasedOnUser).flat() as UserAuditLog[];
      if (usersAuditLog.length == 0) {
        return;
      }
      const usersAuditLogRepo: UserAuditLog[] = usersAuditLog.filter(i => i.repo === repo.fullPath);
      if (usersAuditLogRepo.length == 0) {
        return;
      }

      repoUsers.forEach(repoUser => {
        const userAuditLogInfo = usersAuditLogRepo.filter(i => i.name === repoUser.name);
        if (userAuditLogInfo.length == 0) {
          return;
        }

        const sortedItems = userAuditLogInfo.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

        repoUser.adminOperationRepo = userAuditLogInfo.length;
        repoUser.adminLocationRepo = sortedItems[0].actorLocation;
        if (!repoUser.adminLocationRepo) {
          sortedItems.forEach(i => {
            if (!repoUser.adminLocationRepo && i.actorLocation) {
              repoUser.adminLocationRepo = i.actorLocation;
            }
          });
        }
        repoUser.adminOperationDateRepo = sortedItems[0].timestamp;
        repoUser.foundAdminDataRepo = true;
        repoUser.lastAdminOperationRepo = sortedItems[0].actionFriendly;
      });
    } catch (err) {
      logger.error(`failed to update users admin based on repo: ${repo.fullName}, err:${err}`);
    }
  }

  getUserBasedOnId(user: User, orgName, gitType: string) {
    try {
      const orgWithPrefix = `${gitType}_${orgName}`;
      const orgUsers: User[] = this.users[orgWithPrefix];
      if (!orgUsers) {
        return;
      }
      const u = orgUsers.find(i => i.id === user.id);
      return u;
    } catch (err) {
      logger.error(`failed in get user: ${JSON.stringify(user)}, err:${err}`);
    }
  }

  addUserToGitTypesMap(newUser: User, type: string) {
    try {
      if (!this.usersGitTypeMap.has(type)) {
        this.usersGitTypeMap.set(type, []);
      }
      const gitTypeSet = this.usersGitTypeMap.get(type);
      gitTypeSet.push(newUser);
    } catch (e) {
      logger.error(`failed to addUserToGitTypesMap ${e}`);
    }
  }

  addUser(newUser: User, type: string) {
    const org = newUser.org;

    this.addUserToGitTypesMap(newUser, type);

    const orgWithPrefix = `${type}_${org}`;

    if (!org) {
      return;
    }

    if (!this.users[orgWithPrefix]) {
      this.users[orgWithPrefix] = [newUser];
      return;
    }

    //Org already exist, the user should be checked
    const orgUsers: User[] = this.users[orgWithPrefix];

    const currentUser = orgUsers.find(i => i.id == newUser.id);
    //Check if user exist for this org
    if (currentUser == undefined) {
      //Not exist
      orgUsers.push(newUser);
    } else {
      //Update affiliation
      Array.from(newUser.affiliation).forEach(i => {
        currentUser.affiliation.add(i);
      });
      //Update twoFactorEnabled
      if (!newUser.twoFactorEnabled) {
        currentUser.twoFactorEnabled = false;
      }
      //Update roles
      Array.from(newUser.orgRole).forEach(i => {
        currentUser.orgRole.add(i);
      });
    }
  }

  updateOrg2faRepo(org: string) {
    try {
      const repos = this.repos.filter(r => r.organization === org);
      for (const repo of repos) {
        repo.isOrg2faEnabled = false;
      }
    } catch (e) {
      logger.error(`failed to updateOrg2faRepo: ${e}`);
    }
  }

  addCommit(commits: Commit[], repo: Repo) {
    try {
      for (const commit of commits) {
        if (this.UserCommitsRepo[repo.fullName]) {
          const users: UserCommit[] = this.UserCommitsRepo[repo.fullName];
          const singleUser = users.find(u => u.lastCommit.authorName === commit.authorName);

          if (singleUser) {
            singleUser.count++;
            if (new Date(singleUser.lastCommit.date).getTime() < new Date(commit.date).getTime()) {
              singleUser.lastCommit = commit;
            }
          } else {
            const userCommit: UserCommit = new UserCommit();
            userCommit.count = 1;
            userCommit.lastCommit = commit;
            this.UserCommitsRepo[repo.fullName].push(userCommit);
            userCommit.gitType = repo.type.toLowerCase() as repoType;
          }
        } else {
          const userCommit: UserCommit = new UserCommit();
          userCommit.count = 1;
          userCommit.lastCommit = commit;
          this.UserCommitsRepo[repo.fullName] = [userCommit];
          userCommit.gitType = repo.type.toLowerCase() as repoType;
        }
      }
    } catch (e) {
      StatesHelper.Instance.globalApisFails.add(resourceType.allCommits);
    }
  }

  addPulls(pulls: PullRequest[], repo: Repo) {
    try {
      for (const pull of pulls) {
        this.addPullsReviewers(pull, repo);

        //Repo based
        if (this.UserPullRequestRepo[repo.fullName]) {
          const users: UserPullRequest[] = this.UserPullRequestRepo[repo.fullName];
          const singleUser = users.find(u => u.lastPullRequest.author === pull.author);
          if (singleUser) {
            singleUser.count++;
            if (singleUser.lastPullRequest.createdAtData.getTime() < pull.createdAtData.getTime()) {
              singleUser.lastPullRequest = pull;
            }
          } else {
            const userPullRequest: UserPullRequest = new UserPullRequest();
            userPullRequest.count = 1;
            userPullRequest.lastPullRequest = pull;
            this.UserPullRequestRepo[repo.fullName].push(userPullRequest);
          }
        } else {
          const userPullRequest: UserPullRequest = new UserPullRequest();
          userPullRequest.count = 1;
          userPullRequest.lastPullRequest = pull;
          this.UserPullRequestRepo[repo.fullName] = [userPullRequest];
        }

        //User based
        if (this.UserPullRequest[pull.author]) {
          const userPullRequest: UserPullRequest = this.UserPullRequest[pull.author];
          userPullRequest.count++;
          if (userPullRequest.lastPullRequest.createdAtData.getTime() < pull.createdAtData.getTime()) {
            userPullRequest.lastPullRequest = pull;
          }
        } else {
          const userPullRequest: UserPullRequest = new UserPullRequest();
          userPullRequest.count = 1;
          userPullRequest.lastPullRequest = pull;
          this.UserPullRequest[pull.author] = userPullRequest;
        }
      }
    } catch (err) {
      logger.error(`failed add pulls: ${pulls.length}, err:${err}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.allPulls);
    }
  }

  addPullsReviewers(pulls: PullRequest, repo: Repo) {
    try {
      for (const reviewer of pulls.reviewers) {
        //Repo based
        if (this.UserReviewersRepo[repo.fullName]) {
          const userReviewer: UserReviewer[] = this.UserReviewersRepo[repo.fullName];
          const singleUser = userReviewer.find(u => u.lastReviewer.author === reviewer.author);
          if (singleUser) {
            singleUser.count++;
            if (singleUser.lastReviewerRequest.getTime() < pulls.createdAtData.getTime()) {
              singleUser.lastReviewer = reviewer;
              singleUser.lastReviewerRequest = pulls.createdAtData;
            }
          } else {
            const userReviewer: UserReviewer = new UserReviewer();
            userReviewer.count = 1;
            userReviewer.lastReviewer = reviewer;
            userReviewer.lastReviewerRequest = pulls.createdAtData;
            this.UserReviewersRepo[repo.fullName].push(userReviewer);
          }
        } else {
          const userReviewer: UserReviewer = new UserReviewer();
          userReviewer.count = 1;
          userReviewer.lastReviewer = reviewer;
          userReviewer.lastReviewerRequest = pulls.createdAtData;
          this.UserReviewersRepo[repo.fullName] = [userReviewer];
        }

        if (this.UserReviewers[reviewer.author]) {
          const userReviewer: UserReviewer = this.UserReviewers[reviewer.author];
          userReviewer.count++;

          if (userReviewer.lastReviewerRequest.getTime() < pulls.createdAtData.getTime()) {
            userReviewer.lastReviewer = reviewer;
            userReviewer.lastReviewerRequest = pulls.createdAtData;
          }
        } else {
          const userReviewer: UserReviewer = new UserReviewer();
          userReviewer.count = 1;
          userReviewer.lastReviewer = reviewer;
          userReviewer.lastReviewerRequest = pulls.createdAtData;
          this.UserReviewers[reviewer.author] = userReviewer;
        }
      }
    } catch (err) {
      logger.error(`failed add pulls reviewers, err:${err}`);
    }
  }

  async handleActions(semGrepResult, repo: Repo) {
    try {
      let orgName;
      let repoName;
      if (semGrepResult.metaVars) {
        orgName = semGrepResult.metaVars?.$1?.abstract_content;
        repoName = semGrepResult.metaVars?.$2?.abstract_content;
      } else {
        orgName = semGrepResult.extra?.metavars?.$1?.abstract_content;
        repoName = semGrepResult.extra?.metavars?.$2?.abstract_content;
      }

      const orgNameToQuery = `orgs/${orgName}`;
      const repoNameToQuery = `repos/${orgName}/${repoName}`;

      // whitelist of approved organizations, first one for example
      // is "actions" which is the original GitHub Actions organization, see(https://github.com/actions)
      // when list expands we should export list to json or something
      const whitelist = ["actions", "oxsecurity", "ox-security"];

      // adding current scanned organization to whitelist
      whitelist.push(repo.organization.toLowerCase());

      if (whitelist.includes(orgName.toLowerCase())) {
        return;
      }
      repo.unlistedActions.set(`${orgName}/${repoName}`, { stars: null, isVerified: null, orgNameToQuery, repoNameToQuery });
    } catch (e) {
      logger.error(`handleActions failed to add action repo to repo obj, err: ${e}`);
    }
  }
}

export default GlobalCodeRepoData;
