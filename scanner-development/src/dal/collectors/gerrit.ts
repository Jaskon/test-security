import loggerImport from "../../logger";
import CodeRepoBase from "../base/codeRepoBase";
const logger = loggerImport.getDebugLogger();

import FeatureFlags from "@oxappsec/ox-feature-flag";
import axios, { AxiosInstance } from "axios";
import https from "https";
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
  Reviewer,
  setFileInfo,
  User,
} from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import RepoImportanceCalcHelper from "../../helper/appPriority/repoImportanceCalcHelper";
import GitHelper from "../../helper/gitHelper";
import FileHelper from "../../helper/IO/fileHlper";
import StatesHelper from "../../helper/statesHelper";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import { sleep } from "../../helper/commonUtils";

const max_api_calls = 10;
const per_page_max_res = 100;

class Gerrit extends CodeRepoBase {
  private axiosInstance: AxiosInstance = null;
  private cachedGerritUsers = {};
  private sshPort = 29418;
  private useKeyAsRepoName = false;
  private shouldBypassCertChecks;

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

    if (this.token.sshToken) {
      this.sshPort = 29418;

      const useAutoPortDiscovery = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxGerritAutoPortDiscovery"); // LD
      this.useKeyAsRepoName = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxGerritKeyAsRepoName"); // LD

      if (useAutoPortDiscovery) {
        // axios get port from url/ssh_info
        try {
          const { data }: any = await axios.get(`${this.token.host}/ssh_info`);

          // match the result against: url port
          const port = data.match(/.*\s+([0-9]*)/)[1];

          if (port) {
            this.sshPort = parseInt(port);
          }
        } catch (e) {
          logger.error(`Failed to get port from url/ssh_info for: ${this.token.name}, url: ${this.token.host}, err: ${e}`);
        }
      }
    }

    // If gerrit server is self certified signed
    this.shouldBypassCertChecks = process.env.IS_REMOTE_SITE;
    if (this.shouldBypassCertChecks) {
      this.axiosInstance = axios.create({
        baseURL: this.token.host,
        httpsAgent: new https.Agent({
          rejectUnauthorized: false,
        }),
        auth: {
          username: this.token.userName,
          password: this.token.password,
        },
      });
    } else {
      this.axiosInstance = axios.create({
        baseURL: this.token.host,
        auth: {
          username: this.token.userName,
          password: this.token.password,
        },
      });
    }

    await this.cacheAllGerritUsers();

    logger.info(`finish init lib for: ${this.token.name}, url: ${this.token.host}`);
  }

  async cacheAllGerritUsers() {
    try {
      const allGroups = await this.getAllGroups();
      logger.info(`Found total groups count: ${allGroups.length}, for: ${this.token.name} ${this.token.type}`);
      if (!allGroups.length) {
        return;
      }

      const getGroupMembersPromise = allGroups.map(group => this.getAllGroupsMembers(group.group_id || group.id));
      await Promise.allSettled(getGroupMembersPromise);
      logger.info(`Total cached users count ${Object.keys(this.cachedGerritUsers).length}, for: ${this.token.name} ${this.token.type}`);
    } catch (err) {
      logger.error(`failed to cache all gerrit users info: ${this.token.name} ${this.token.type}, err: ${err}`);
    }
    return;
  }

  async getAllGroups() {
    const allGroups = [];
    try {
      let page = 0;
      let apiIteration = 0;
      while (apiIteration < max_api_calls) {
        let reposFound = 0;
        const start = page * per_page_max_res;

        const getAllGroupsUrl = `/a/groups/?n=${per_page_max_res}&S=${start}`;
        const { data }: any = await this.axiosInstance.get(getAllGroupsUrl);
        const parseData = JSON.parse(data.substring(4));

        for (const key in parseData) {
          allGroups.push(parseData[key]);
          ++reposFound;
        }
        ++apiIteration;
        ++page;

        // If data count is less than per_page_max_res break loop
        if (reposFound < per_page_max_res) {
          break;
        }
      }
    } catch (err) {
      logger.error(`failed to get all groups: ${this.token.name} ${this.token.type}, err: ${err}`);
    }
    return allGroups;
  }

  async getAllGroupsMembers(groupId) {
    try {
      const getAllGroupMemberssUrl = `/a/groups/${groupId}/members/`;
      const { data }: any = await this.axiosInstance.get(getAllGroupMemberssUrl);
      const parseData = JSON.parse(data.substring(4));

      for (const user of parseData) {
        if (!this.cachedGerritUsers[user._account_id]) {
          this.cachedGerritUsers[user._account_id] = user;
          this.cachedGerritUsers[user.username] = user;
        }
      }
    } catch (err) {
      logger.error(`failed to get all groups members: ${this.token.name} ${this.token.type}, err: ${err}`);
    }
  }

  async getAllRepos() {
    const allRepos = [];
    try {
      let page = 0;
      let apiIteration = 0;
      while (apiIteration < max_api_calls) {
        let reposFound = 0;
        const start = page * per_page_max_res;

        const getAllRepoUrl = `/a/projects/?n=${per_page_max_res}&S=${start}`;
        const { data }: any = await this.axiosInstance.get(getAllRepoUrl);
        const parseData = JSON.parse(data.substring(4));

        for (const key in parseData) {
          if (key === "All-Projects" || key === "All-Users") {
            continue;
          }

          if (this.useKeyAsRepoName) {
            parseData[key].keyName = key;
          }

          allRepos.push(parseData[key]);
          ++reposFound;
        }
        ++apiIteration;
        ++page;

        // If data count is less than per_page_max_res break loop
        if (reposFound < per_page_max_res) {
          break;
        }
      }

      const monitored = allRepos.filter(apiRepo => this.repoSelectedByUser(apiRepo.id.toString(), apiRepo.id, ""));
      logger.info(
        `Found all repos before filter: ${allRepos.length}, after filter: ${monitored.length}, for: ${this.token.name} ${this.token.type}`,
      );

      await this.getSingleRepos(monitored[0]); // debugging single repo data.

      return monitored;
    } catch (err) {
      logger.error(`failed to get repos list obj for: ${this.token.name} ${this.token.type}, err: ${err}`);
    }
    return [];
  }

  // remove it after debug
  async getSingleRepos(apiRepo) {
    try {
      if (!apiRepo) {
        return;
      }
      const getSingleRepo = `/a/projects/${apiRepo.id}`;
      const { data }: any = await this.axiosInstance.get(getSingleRepo);
      const parseData = JSON.parse(data.substring(4));
      // sameer log
      logger.info(`${this.token.name}, get single repo details: ${JSON.stringify(parseData)}`);
    } catch (err) {
      logger.error(`failed to get single repo obj for: ${this.token.name} ${this.token.type}, err: ${err}`);
    }
  }

  async setRepo(apiRepo, repoObj) {
    try {
      const repoId = decodeURIComponent(apiRepo.id);
      const link = apiRepo?.web_links?.[0]?.url || "";
      let repoName = repoId.split("/").pop();

      if (this.useKeyAsRepoName) {
        repoName = apiRepo.keyName;
      }

      const cloneHeaders = [];
      if (this.shouldBypassCertChecks) {
        cloneHeaders.push(`-c`, `http.sslVerify=false`);
      }

      const pipelineScanInfo = this.getPipelineScanInfo(repoId, repoName);
      const isActive = apiRepo.state === "ACTIVE";

      let repo = new Repo(
        this.uuid,
        this.orgName,
        repoType.gerrit,
        repoName,
        repoId,
        repoId,
        "",
        apiRepo.mainbranch ? (apiRepo.mainbranch == null ? "main" : apiRepo.mainbranch.name) : "main",
        apiRepo.description ? apiRepo.description : "",
        !isActive,
        this.getCloneUrl(repoId),
        -1,
        true,
        false,
        false,
        "",
        true,
        [],
        0,
        0,
        "",
        link,
        0,
        apiRepo?.lastCodeChange, // Missing
        "",
        this.getFileLinkPrefix(apiRepo, repoId),
        "#lines-",
        0,
        link + "/admin",
        link + "/commits/",
        "",
        "",
        "",
        repoId,
        true,
        repoName,
        pipelineScanInfo,
        undefined,
        undefined,
        cloneHeaders,
      );

      if (!apiRepo.lastCodeChange) {
        if (!repo.disable) {
          //check - sammer
          //repo.lastPushTime = await this.getLastCodeChange(apiRepo);
        }
      }

      this.setClientConfiguredProps(repo);

      const cal = new RepoImportanceCalcHelper(this.uuid, this.orgName);
      if (cal.isRepoImportanceAreZero(repo, 100).length > 0) {
        StatesHelper.Instance.skippedClone.add(repo.fullName);
      }

      if (apiRepo.delta) {
        repo.isDelta = true;
      }

      //Must clone here
      if (repo.noneRelevantRepo) {
        this.fileHelper.createDir(repo.cloneDir);
      } else {
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

      return repo;
    } catch (err) {
      logger.error(`failed to create repo obj for: ${JSON.stringify(apiRepo)}, err: ${err}`);
    }
    return null;
  }

  async branches(repo: Repo): Promise<any> {
    let branchList: Branch[] = [];

    try {
      const encodedRepoName = encodeURIComponent(repo.name);
      const allBranches = [];
      let page = 0;
      let apiIteration = 0;
      while (apiIteration < max_api_calls) {
        const start = page * per_page_max_res;
        const getAllBranchesUrl = `/a/projects/${encodedRepoName}/branches/?n=${per_page_max_res}&S=${start}`;
        const { data }: any = await this.axiosInstance.get(getAllBranchesUrl);
        const parseData = JSON.parse(data.substring(4));
        if (parseData?.length) {
          allBranches.push(...parseData);
        }
        ++apiIteration;
        ++page;
        // If data count is less than per_page_max_res break loop
        if (parseData.length < per_page_max_res) {
          break;
        }
      }

      for (const branchInfo of allBranches) {
        try {
          const branchName = branchInfo.ref.replace("refs/heads/", "");
          let branch = new Branch(branchName);
          branchList.push(branch);
        } catch (err) {
          logger.error(`failed to create branch obj for: ${repo.name}, branch: ${JSON.stringify(branchInfo, null, 4)}, err: ${err}`);
        }
      }
      logger.info(
        `Found all branches before filter: ${allBranches.length}, after filter: ${branchList.length}, for: ${this.token.name} ${this.token.type}`,
      );
    } catch (err) {
      logger.error(`get branches failed repo: ${repo.name}, err: ${err}`);
    }
    return branchList;
  }

  getCloneUrl(repoName: string) {
    const url = new URL(this.token.host);
    if (this.token.sshToken) {
      return `ssh://${this.token.userName}@${url.host}:${this.sshPort}/${repoName}.git`;
    }

    const urlFriendlyPassword = encodeURIComponent(this.getTokenPassword()).replaceAll("!", "%21");
    return `https://${this.token.userName}:${urlFriendlyPassword}@${url.host}/${repoName}`;
  }

  async pulls(repoObj: any): Promise<any> {
    let pullRequestList: PullRequest[] = [];
    const repo: Repo = repoObj.code_repo;
    const commits: Commit[] = repoObj.commits;

    try {
      const res = [];

      const encodedRepoName = encodeURIComponent(repo.name);
      let page = 0;
      let apiIteration = 0;
      while (apiIteration < max_api_calls) {
        const start = page * per_page_max_res;
        const getAllChangesUrl = `/a/changes/?q=project:${encodedRepoName}&n=${per_page_max_res}&S=${start}`;
        const { data }: any = await this.axiosInstance.get(getAllChangesUrl);
        const parseData = JSON.parse(data.substring(4));
        res.push(...parseData);
        ++apiIteration;
        ++page;
        // If data count is less than per_page_max_res break loop
        if (parseData.length < per_page_max_res) {
          break;
        }
      }

      for (const pullInfo of res) {
        try {
          let owner = null;
          if (pullInfo?.owner?._account_id) {
            const userInfos = [];
            await this.getUserDetails(pullInfo?.owner?._account_id, userInfos);
            if (userInfos.length) {
              owner = userInfos[0];
            }
          }

          let user = "";
          if (owner?.name) {
            user = owner?.name;
          }

          const uniqueReviewers = new Set();
          const reviewers: Reviewer[] = [];
          if (pullInfo.reviewers) {
            for (const rev of pullInfo.reviewers) {
              if (uniqueReviewers.has(rev.name) || rev.name === user) {
                // continue;
              }
              if (rev.state != "active") {
                continue;
              }
              uniqueReviewers.add(rev.name);
              reviewers.push(new Reviewer(rev.name, rev.username, rev.id));
            }
          }

          let mergeUser;
          if (pullInfo?.merged_by?.name) {
            mergeUser = new MergeUser(pullInfo?.merged_by.name, pullInfo?.merged_by.username, pullInfo?.merged_by.id);
          } else if (pullInfo?.merge_user?.name) {
            mergeUser = new MergeUser(pullInfo?.merge_user.name, pullInfo?.merge_user.username, pullInfo?.merge_user.id);
          } else if (pullInfo?.author?.name) {
            mergeUser = new MergeUser(pullInfo?.author.name, pullInfo?.author.username, pullInfo?.author.id);
          }

          const isMerged = pullInfo.status.toLowerCase() === "merged" ? true : false;

          const pullRequest: PullRequest = new PullRequest(
            pullInfo.created,
            pullInfo.web_url,
            pullInfo.description,
            pullInfo.meta_rev_id,
            pullInfo.submitted,
            pullInfo.subject,
            reviewers.length,
            user,
            pullInfo.id,
            CodeRepoTypes.pulls,
            reviewers,
            mergeUser,
            isMerged,
          );
          pullRequest.authorUserName = owner?.username || "";

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
      this.globalCodeRepoData.addPulls(pullRequestList, repo);
    } catch (err) {
      logger.error(`get pulls failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.pulls, repo.id);
    }
    return pullRequestList;
  }

  async getCommitRelatedToPullReq(repo: Repo, pullInfo: any, pullRequest: PullRequest, commitsFromDisk: Commit[]) {
    try {
      const res = [];
      if (pullInfo?.push_data?.commit_from) {
        res.push({ id: pullInfo?.push_data?.commit_from });
      }
      if (pullInfo?.push_data?.commit_to) {
        res.push({ id: pullInfo?.push_data?.commit_to });
      }
      if (pullInfo?.meta_rev_id) {
        res.push({ id: pullInfo?.meta_rev_id });
      }
      if (pullInfo.merge_commit_sha) {
        res.push({ id: pullInfo?.merge_commit_sha });
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

  async users(repoObj: any) {
    let usersInfo: User[] = [];
    let repoName = "";
    try {
      const repo: Repo = repoObj.code_repo;
      repoName = repo.name;
      const encodedRepoName = encodeURIComponent(repoName);

      const getRepoAccessUrl = `/a/access/?project=${encodedRepoName}`;
      const { data }: any = await this.axiosInstance.get(getRepoAccessUrl);
      const parseData = JSON.parse(data.substring(4));
      const usersObjKeys = Object.keys(parseData[repoName].groups);
      if (!usersObjKeys.length) {
        return usersInfo;
      }

      const userInfos = [];
      const getUsersPromise = [];
      logger.info(`Fetching ${this.token.name} ${this.token.type} multi userDetails with Promise`);
      for (const user of usersObjKeys) {
        if (user.includes('"user:"')) {
          const username = user.replace("user:", "");
          getUsersPromise.push(this.getUserDetails(username, userInfos));
        }
      }

      await Promise.allSettled(getUsersPromise);
      logger.info(`Found total userDetails count: ${userInfos.length} for ${this.token.name} ${this.token.type}`);

      for (const user of userInfos) {
        try {
          if (user.inactive == true) {
            continue;
          }
          const userInfo = new User(user.name, user.username, user._account_id, "", "", "");

          if (user?.avatars?.length) {
            userInfo.avatarUrl = user.avatars[0].url;
          }
          usersInfo.push(userInfo);
          this.globalCodeRepoData.addUser(userInfo, repoType.gerrit);
        } catch (err) {
          logger.error(`failed to create branch obj for: ${repo.name}, user: ${JSON.stringify(user, null, 4)}, err: ${err}`);
          StatesHelper.Instance.addFailedTool(repoResourceType.users, repo.id);
        }
      }
      return usersInfo;
    } catch (err) {
      const repo: Repo = repoObj.code_repo;
      logger.error(`get branches failed repo: ${repoName}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.users, repo.id);
    }
    return usersInfo;
  }

  async getUserDetails(userId: string, userInfos: any[]) {
    try {
      if (this.cachedGerritUsers[userId]) {
        userInfos.push(this.cachedGerritUsers[userId]);
        return;
      }
      const getUserDetailsApi = `/a/accounts/${userId}`;
      const { data }: any = await this.axiosInstance.get(getUserDetailsApi);
      const parseData = JSON.parse(data.substring(4));
      userInfos.push(parseData);
      this.cachedGerritUsers[parseData._account_id] = parseData;
      this.cachedGerritUsers[parseData.username] = parseData;
    } catch (err) {
      logger.error(`get user details failed for: ${this.token.name} ${this.token.type}, err: ${err}`);
    }
  }

  // eg. https://test.com/plugins/gitiles/test/+/refs/heads/master/package.json
  getFileLinkPrefix(repo, repoId) {
    try {
      return `plugins/gitiles/${repoId}/+/refs/heads/master/`;
    } catch (err) {
      logger.error(`failed get file link repo name: ${repo.name}`);
    }
    return "";
  }

  async getCodeBaseLastCodeChange(application) {
    return null;
  }

  getCodeRepoId(application) {
    return application.id;
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
}

export default Gerrit;
