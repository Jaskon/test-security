//https://github.com/jlmorgan/node-stash-client
//https://docs.atlassian.com/DAC/rest/stash/3.11.3/stash-rest.html

import loggerImport from "../../logger";
import CodeRepoBase from "../base/codeRepoBase";
const logger = loggerImport.getDebugLogger();

import {
  Branch,
  CodeRepoTypes,
  Commit,
  File,
  MergeUser,
  PullRequest,
  Repo,
  repoResourceType,
  repoType,
  resourceType,
  Reviewer,
  setFileInfo,
  User,
  Webhook,
} from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import RepoImportanceCalcHelper from "../../helper/appPriority/repoImportanceCalcHelper";
import GitHelper from "../../helper/gitHelper";
import FileHelper from "../../helper/IO/fileHlper";
import StatesHelper from "../../helper/statesHelper";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";

const stash = require("stash-client");
const max_pages = 300;
let bitbucketStash = null;

class CodeRepoBitbucketStash extends CodeRepoBase {
  fileHelper: FileHelper;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);
    this.fileHelper = new FileHelper(this.uuid);
  }

  async initLib() {
    logger.info(`try init lib for: ${this.token.name}, url: ${this.token.host}`);

    const config = {
      url: this.token.host,
      password: this.token.password,
      username: this.token.userName,
    };

    bitbucketStash = stash(config).api();

    logger.info(`finish init lib for: ${this.token.name}, url: ${this.token.host}, password: ${this.token.password}`);
  }

  async setRepo(apiRepo, repoObj) {
    try {
      const pipelineScanInfo = this.getPipelineScanInfo(apiRepo.id.toString(), apiRepo.name);

      let repo = new Repo(
        this.uuid,
        this.orgName,
        this.token.name,
        apiRepo.name,
        apiRepo.id.toString(),
        apiRepo.project == undefined ? this.token.name : apiRepo.project.key + " / " + apiRepo.name,
        "",
        await this.getDefaultBrnahc(apiRepo),
        apiRepo?.project?.description,
        false,
        this.getCloneUrl(apiRepo),
        0,
        true,
        true,
        true,
        "",
        !apiRepo.public,
        [],
        0,
        0,
        apiRepo.slug,
        this.getHtmlUrl(apiRepo),
        0,
        apiRepo.lastCodeChange,
        apiRepo?.project?.key,
        this.getHtmlUrl(apiRepo) + "browse/",
        "#",
        0,
        this.getHtmlUrl(apiRepo) + "permissions",
        this.getHtmlUrl(apiRepo) + "commits/",
        "",
        "",
        "",
        apiRepo.id.toString(),
        false,
        apiRepo.name,
        pipelineScanInfo,
      );

      if (!apiRepo.lastCodeChange) {
        if (!repo.disable) {
          repo.lastPushTime = await this.getLastCodeChange(apiRepo);
        }
      }

      this.setClientConfiguredProps(repo);

      if (apiRepo.delta) {
        repo.isDelta = true;
      }

      const cal = new RepoImportanceCalcHelper(this.uuid, this.orgName);
      if (cal.isRepoImportanceAreZero(repo, 100).length > 0) {
        StatesHelper.Instance.skippedClone.add(repo.fullName);
      }

      if (repo.noneRelevantRepo) {
        this.fileHelper.createDir(repo.cloneDir);
      } else {
        //Must clone here
        const gitHelper: GitHelper = new GitHelper(this.uuid, this.orgName);
        const cloneRes = await gitHelper.cloneRepo(repo, this);
        if (!cloneRes) {
          repo.failedClone = true;
        } else {
          repo.successfulClone = true;
          repo.headSha = await this.getHeadSha(repo, gitHelper);
        }
      }

      const filesList: File[] = await this.files(repo);
      repoObj[CodeRepoTypes[CodeRepoTypes.files]] = filesList;
      repo.filesCount = filesList.length;

      await this.getAndSetRepoDevLanguagesKubernetesAndOrchestrator(repo, filesList);

      repo.deploymentFilesYmls = this.getDeploymentFilesYmls(filesList);

      repo.gitRoles = this.getGitRoles("bitbucketStash");

      return repo;
    } catch (err) {
      logger.error(`failed to create repo obj for: ${JSON.stringify(apiRepo)}, err: ${err}`);
    }
    return null;
  }

  async getAllRepos(callObj: RulesManager): Promise<Repo[]> {
    try {
      const allRepos = await this.getAllOrgRepos();

      logger.info(`stash all repos before checking exclusions and user selection count: ${allRepos.length}`);

      const monitored = allRepos.filter(apiRepo => this.repoSelectedByUser(apiRepo.id.toString(), apiRepo.name, undefined));

      return monitored;
    } catch (err) {
      logger.error(`failed to get repos list obj for: ${this.token.type}, err: ${err}, errStr: ${JSON.stringify(err)}`);
    }
    return [];
  }

  async allUsers() {
    let users = null;

    try {
      users = await bitbucketStash.users().list();
      const usersInfo: User[] = [];

      for (const user of users.body.values) {
        if (user.active == false) {
          continue;
        }

        const userInfo = new User(user.name, user.slug, user.id, "", "", "");

        usersInfo.push(userInfo);
      }

      return usersInfo;
    } catch (err) {
      logger.error(`failed get all users, err: ${err}, users output: ${JSON.stringify(users)}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.allUsers);
    }
    return [];
  }

  getCloneUrl(repo) {
    try {
      const res = repo.links.clone.filter(i => i.name.includes("http"));
      let cloneRepo = res[0].href;
      logger.info(`clone url before changing, repo: ${repo.name}, url: ${cloneRepo}`);

      const urlFriendlyPassword = encodeURIComponent(this.getTokenPassword()).replaceAll("!", "%21");

      if (!cloneRepo.includes("@")) {
        const index = cloneRepo.indexOf("://");
        if (index != -1) {
          const httpInfo = cloneRepo.substring(0, index);
          const res = cloneRepo.substring(index + "://".length, cloneRepo.length);
          let name = this.token.userName;
          cloneRepo = `${httpInfo}://${name}:${urlFriendlyPassword}@${res}`;
          //Example: https://username:password@github.com/username/repository.git
        }
      } else {
        cloneRepo = cloneRepo.replace("@", `:${urlFriendlyPassword}@`);
      }

      return cloneRepo;
    } catch (err) {
      logger.error(`failed to get clone url obj for: ${this.token.type}, repo: ${repo.name}, err: ${err}`);
    }
    return "";
  }

  getHtmlUrl(apiRepo) {
    try {
      const hrefInfo = apiRepo.links.self[0].href.replace("/browse", "/");
      return hrefInfo;
    } catch (err) {
      logger.error(`failed to get clone url obj for: ${this.token.type}, err: ${err}`);
    }
    return "";
  }

  async getAllOrgRepos() {
    //Get all project
    const projectFunc = bitbucketStash.projects().list;
    const projects = await this.handlePaging("projectFunc", projectFunc, true);

    //Repos By Project
    let reposFromProjects = [];
    for (const project of projects) {
      try {
        const repos = await this.getProjectRepos(project);
        if (repos == null) {
          continue;
        }
        reposFromProjects.push(repos);
      } catch (err) {
        logger.error(`failed err for get projects repos, err: ${err}`);
      }
    }
    const flattenRepos = reposFromProjects.flat();

    //Repos by user
    const userRepo = await this.getUserRepos();

    const r = [...userRepo, ...flattenRepos];
    const uniqueRepos = [];
    const u = new Set();
    r.forEach(i => {
      if (!i.id) {
        return;
      }
      if (u.has(i.id)) {
        return;
      }
      u.add(i.id);
      uniqueRepos.push(i);
    });

    return uniqueRepos;
  }

  async getProjectRepos(project) {
    try {
      const projectReposFunc = bitbucketStash.projects().repos(project.key).list;
      const projectRepos = await this.handlePaging("projectRepos", projectReposFunc, true);

      if (projectRepos.length == 0) {
        logger.error(`failed to get repos for project: ${project.key}`);
      } else {
        logger.info(`repos for project: ${project.key} count: ${projectRepos.length}`);
      }

      return projectRepos;
    } catch (err) {
      logger.debug(`get project repos failed project: ${project.key}, err: ${err}`);
    }
    return null;
  }

  async getUserRepos() {
    try {
      const userReposFunc = bitbucketStash.profile().recent().repos().list;
      const userRepos = await this.handlePaging("getUserRepos", userReposFunc, true);
      return userRepos;
    } catch (err) {
      logger.debug(`get user repos failed, err: ${err}`);
    }
    return [];
  }

  async webhooks(repo: Repo) {
    let webhooksList: Webhook[] = [];
    let res;
    try {
      const funcInfo = bitbucketStash.projects().repos(repo.project).settings(repo.ownerName).hooks().list;
      res = await this.handlePaging("getRepoWebHooks", funcInfo);
      if (!res) {
        return [];
      }

      for (const webhookInfo of res) {
        try {
          let webhook = new Webhook(
            webhookInfo?.details?.key,
            webhookInfo.created_at,
            "",
            "",
            true,
            true,
            true,
            webhookInfo?.details?.description,
            repo.link + "settings/hooks",
            webhookInfo.events,
            repoResourceType.webhooks,
          );

          webhooksList.push(webhook);
        } catch (err) {
          logger.error(`failed to create webhook obj for: ${repo.name}, webhook: ${JSON.stringify(webhookInfo, null, 4)}, err: ${err}`);
          // StatesHelper.Instance.addFailedTool(repoResourceType.webhooks, repo.id);
        }
      }
    } catch (err) {
      if (err.status != 404) {
        logger.error(`get webhooks failed repo: ${repo.name}, err: ${err}, res: ${JSON.stringify(res)}`);
      }
      logger.debug(`get webhooks failed repo: ${repo.name}, err: ${err}, res: ${JSON.stringify(res)}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.webhooks, repo.id);
    }
    return webhooksList;
  }

  async branches(repo: Repo) {
    let branchsList: Branch[] = [];

    try {
      const funcInfo = bitbucketStash.projects().repos(repo.project).branches(repo.ownerName).list;
      const res = await this.handlePaging("getAllBranch", funcInfo);
      if (!res) {
        return [];
      }

      for (const branchInfo of res) {
        try {
          let branch = new Branch(branchInfo.displayId);

          branchsList.push(branch);
        } catch (err) {
          logger.error(`failed to create branch obj for: ${repo.name}, branch: ${JSON.stringify(branchInfo, null, 4)}, err: ${err}`);
          StatesHelper.Instance.addFailedTool(repoResourceType.branches, repo.id);
        }
      }
    } catch (err) {
      logger.error(`get branches failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.branches, repo.id);
    }
    return branchsList;
  }

  async users(repoObj: any) {
    let repoName = "";
    try {
      const repo: Repo = repoObj.code_repo;

      const projectKey = repo.project;
      const repositorySlug = repo.ownerName;
      repoName = repo.name;

      const res = await bitbucketStash.projects().repos(projectKey).permissions(repositorySlug).users().none({});
      let usersInfo: User[] = [];

      if (!res?.body?.values) {
        return [];
      }

      for (const user of res.body.values) {
        try {
          if (user.active == false) {
            continue;
          }

          const userInfo = new User(user.name, user.slug, user.id, "", "", "");

          usersInfo.push(userInfo);
          this.globalCodeRepoData.addUser(userInfo, repoType.bitbucketStash);
        } catch (err) {
          logger.error(`failed to create branch obj for: ${repo.name}, user: ${JSON.stringify(user, null, 4)}, err: ${err}`);
          StatesHelper.Instance.addFailedTool(repoResourceType.users, repo.id);
        }
      }
      return usersInfo;
    } catch (err) {
      logger.error(`get branches failed repo: ${repoName}, err: ${err}`);
      const repo: Repo = repoObj.code_repo;
      StatesHelper.Instance.addFailedTool(repoResourceType.users, repo.id);
    }
    return [];
  }

  private async getDefaultBrnahc(repo) {
    try {
      logger.debug(`Try get default branch repo ${repo.name}`);

      const projectKey = repo.project.key;
      const repositorySlug = repo.slug;

      const res = await bitbucketStash.projects().repos(repo.project).branches(repositorySlug).default().list();
      return res.body?.displayId;
    } catch (err) {
      logger.error(`repo: ${repo.name}, err: ${err}`);
    }
    return "";
  }

  getAPICredentials() {
    return null;
  }

  getAPIRepoInfo(repo: Repo) {
    return null;
  }

  async findPullRequestIntroducingMergeCommit(repoObj: any, branch: string, sha: string) {
    return null;
  }

  async findFilesModifiedInPullRequest() {
    return null;
  }

  async pulls(repoObj: any): Promise<any> {
    let pullRequestList: PullRequest[] = [];
    const repo: Repo = repoObj.code_repo;
    const commits: Commit[] = repoObj.commits;
    let res;

    try {
      let parms = { start: 0, state: "merged" };

      res = await bitbucketStash.projects().repos(repo.project).pullRequests(repo.ownerName).list(parms);

      for (const pullInfo of res.body.values) {
        try {
          if (pullInfo.state == null || pullInfo.state == undefined) {
            continue;
          }
          if (pullInfo.state.toLowerCase() != "merged") {
            continue;
          }

          const reviewers: Reviewer[] = [];
          if (pullInfo.reviewers != undefined) {
            for (const rev of pullInfo.reviewers) {
              if (rev.user == undefined) {
                continue;
              }
              if (rev.user.active == undefined) {
                continue;
              }
              if (!rev.user.active) {
                continue;
              }
              reviewers.push(new Reviewer(rev.user.name, rev.user.displayName, rev.user.id));
            }
          }

          const pullRequest = new PullRequest(
            new Date(pullInfo.createdDate).toString(),
            repo.link + "/pull-requests/" + pullInfo.id + "/overview",
            pullInfo.description,
            pullInfo.fromRef?.latestChangeset ? pullInfo.fromRef?.latestChangeset : pullInfo.fromRef?.latestCommit,
            pullInfo.state === "MERGED" ? new Date(pullInfo.updatedDate).toString() : "",
            pullInfo.title,
            pullInfo.reviewers == undefined ? 0 : pullInfo.reviewers.length,
            pullInfo.author.user.name,
            pullInfo.id,
            CodeRepoTypes.pulls,
            reviewers,
            new MergeUser("", "", -1),
            true,
          );

          this.getCommitRelatedToPullReq(repo, pullInfo, pullRequest, commits);

          if (pullRequest.pullsCommitInfo.length == 0) {
            continue;
          }

          this.updateMailInfo(pullRequest);

          pullRequestList.push(pullRequest);
        } catch (err) {
          logger.error(`failed to create pull obj for: ${repo.name}, pull obj: ${JSON.stringify(pullInfo)}, err: ${err}`);
          StatesHelper.Instance.addFailedTool(repoResourceType.pulls, repo.id);
        }
      }
    } catch (err) {
      logger.error(`get pulls failed repo: ${repo.name}, err: ${err}, res: ${JSON.stringify(res)}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.pulls, repo.id);
    }
    return pullRequestList;
  }

  async getCommitRelatedToPullReq(repo: Repo, pullInfo: any, pullRequest: PullRequest, commitsFromDisk: Commit[]) {
    try {
      const res = [];
      if (pullInfo?.fromRef?.latestChangeset) {
        res.push({ id: pullInfo?.fromRef?.latestChangeset });
      }
      if (pullInfo?.toRef?.latestChangeset) {
        res.push({ id: pullInfo?.toRef?.latestChangeset });
      }
      for (const resCommit of res) {
        try {
          const commitInfoFromDisk = commitsFromDisk.filter(i => i.hash === resCommit.id);
          if (commitInfoFromDisk.length > 0) {
            pullRequest.pullsCommitInfo = [...pullRequest.pullsCommitInfo, ...commitInfoFromDisk];
          }
        } catch (err) {
          logger.error(`repo: ${repo.name}, get related single commit to pull request err: ${err}`);
        }
      }
      setFileInfo(pullRequest);
    } catch (err) {
      logger.error(`failed to get commit related to pull request for repo: ${repo.name}, err: ${err}`);
    }
  }

  async handlePaging(name: string, query: any, pagination: boolean = false) {
    let list = [];
    logger.debug(`try get query: ${name}, pagination: ${pagination}`);
    if (!pagination) {
      const res = await query();
      return res.body.values;
    }

    //Handle paging
    let parms = { start: 0 };
    while (parms.start <= max_pages) {
      try {
        const res = await query(parms);

        if (res.body.values) {
          list.push(res.body.values);

          if (res.body.isLastPage) {
            break;
          }
          parms.start++;
        } else {
          logger.error(`err: ${JSON.stringify(res.body, null, 4)} , statusMessage: ${res.statusMessage}, query: ${name}`);
          break;
        }
      } catch (err) {
        if (list.length == 0) {
          throw `err: ${err} query: ${name}`;
        }
        logger.error(`err: ${err} query: ${name}`);
        break;
      }
    }
    if (parms.start > max_pages) {
      logger.error(`bitbucket stash query: ${name} hit limit of max page: ${max_pages}`);
    }

    let flatten = list.flat();
    logger.debug(`finish get query: ${name}, pagination: ${pagination}, size: ${flatten.length}`);
    return flatten;
  }

  async getLastCodeChange(application: any) {
    // Get the last commit date to save as last code change
    try {
      const data = await bitbucketStash.projects().repos(application.project.key).commits(application.slug).list();
      const lastCodeChange = data?.body?.values[0]?.authorTimestamp
        ? data?.body?.values[0]?.authorTimestamp
        : data?.body?.values[0]?.committerTimestamp;
      if (lastCodeChange) {
        return new Date(lastCodeChange).toString();
      }
    } catch (error) {
      logger.error(`Can't get last code change bitbucket Stash: ${error}, appInfo: ${JSON.stringify(application)}`);
    }
  }

  getCodeRepoId(application) {
    return application.id;
  }

  async getCodeBaseLastCodeChange(application) {
    const lastCodeChange = await this.getLastCodeChange(application);
    if (lastCodeChange) {
      this.setLastCodeChange(application, lastCodeChange);
    }
    return application.lastCodeChange;
  }
}

export default CodeRepoBitbucketStash;
