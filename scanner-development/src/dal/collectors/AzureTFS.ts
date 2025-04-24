import loggerImport from "../../logger";
import CodeRepoBase from "../base/codeRepoBase";
const logger = loggerImport.getDebugLogger();

import FeatureFlags from "@oxappsec/ox-feature-flag";
import axios from "axios";
import https from "https";
import lodash from "lodash";
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
import { TFS2018Types } from "../../entitis/connectorsSpecific/tfsTypes";
import RepoImportanceCalcHelper from "../../helper/appPriority/repoImportanceCalcHelper";
import { isIpAddress, removeUrlAndKeepOnlyIp } from "../../helper/commonUtils";
import GitHelper from "../../helper/gitHelper";
import FileHelper from "../../helper/IO/fileHlper";
import { RateLimitHelperFactory } from "../../helper/rateLimitHelper";
import StatesHelper from "../../helper/statesHelper";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";

const per_page_max_res = 100;
const max_pages = 5;
const retry_count = 4;
const timeout_to_wait_after_rate_limit_happen = 1000 * 60 * 1.5;

class AzureTeamFoundationServerRequest {
  query: any;
  page: number = 1;
  maxPage: number;
}

let axiosInstance = null;
class AzureTFS extends CodeRepoBase {
  fileHelper: FileHelper;
  accessToken: string;
  shouldBypassCertChecks: boolean;
  isUsingIp: boolean = false;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);
    this.fileHelper = new FileHelper(this.uuid);
    this.accessToken = Buffer.from(":" + this.token.password).toString("base64");

    this.rateLimitHelper = RateLimitHelperFactory.getRateLimitHelperPerToken(this.token.name, 200);
  }

  async initLib() {
    logger.info(`try init lib for: ${this.token.name}, url: ${this.token.host}`);

    this.shouldBypassCertChecks = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "ox-disable-tfs-cert-validation", true);

    const possibleIp = removeUrlAndKeepOnlyIp(this.token.host);
    if (isIpAddress(possibleIp)) {
      this.isUsingIp = true;
      logger.info(`set to true, isUsingIp: ${this.isUsingIp}`);
    }

    if (this.shouldBypassCertChecks) {
      axiosInstance = axios.create({
        baseURL: this.token.host,
        httpsAgent: new https.Agent({
          rejectUnauthorized: false,
        }),
        auth: {
          username: this.token.password,
          password: "",
        },
        params: { "api-version": 4.1 },
      });
    } else {
      axiosInstance = axios.create({
        baseURL: this.token.host,
        auth: {
          username: this.token.password,
          password: "",
        },
        params: { "api-version": 4.1 },
      });
    }

    logger.info(`finish init lib for: ${this.token.name}, url: ${this.token.host}`);
  }

  async setRepo(apiRepo, repoObj) {
    try {
      const pipelineScanInfo = this.getPipelineScanInfo(apiRepo.id.toString(), apiRepo.name);

      // Be on a cautions side
      let isPrivate = true;

      if ("visibility" in apiRepo) {
        isPrivate = apiRepo.visibility === "private";
      } else if (apiRepo.project) {
        if ("visibility" in apiRepo.project) {
          isPrivate = apiRepo.project.visibility === "private";
        }
      }

      const cloneUrl = this.getCloneUrl(apiRepo);
      const fileLink = this.getFileLinkPrefix(cloneUrl, apiRepo.name);
      const projectName = apiRepo.project == undefined ? this.token.name : apiRepo.project.name + " / " + apiRepo.name;
      const cloneHeaders = [`-c`, `http.extraHeader=Authorization: Basic ${this.accessToken}`];

      if (this.shouldBypassCertChecks) {
        cloneHeaders.push(`-c`, `http.sslVerify=false`);
      }

      let repo = new Repo(
        this.uuid,
        this.orgName,
        this.token.name,
        apiRepo.name,
        apiRepo.id,
        projectName,
        "",
        apiRepo.defaultBranch,
        apiRepo?.project?.description || "",
        false,
        cloneUrl,
        0,
        true,
        true,
        true,
        "",
        this.isUsingIp ? true : isPrivate,
        [],
        0,
        0,
        apiRepo.name,
        apiRepo.url,
        0,
        null,
        apiRepo?.project?.id,
        fileLink,
        "#",
        0,
        apiRepo.webUrl,
        apiRepo.webUrl + "/commit/",
        apiRepo.webUrl + "/pushes",
        apiRepo.webUrl + "/pullrequest",
        this.orgName,
        apiRepo.id,
        false,
        apiRepo.name,
        pipelineScanInfo,
        undefined,
        undefined,
        cloneHeaders,
      );

      if (!apiRepo.lastCodeChange) {
        if (!repo.disable) {
          repo.lastPushTime = await this.getLastCodeChange(apiRepo);
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

      return repo;
    } catch (err) {
      logger.error(`failed to create repo obj for: ${JSON.stringify(apiRepo)}, err: ${err}`);
    }
    return null;
  }

  async getAllRepos(callObj: RulesManager): Promise<Repo[]> {
    try {
      let projects: TFS2018Types.Projects[] = [];
      const collections = await this.invokeRequest({
        url: "/_apis/projectCollections",
      });

      if (collections.length === 0) {
        projects = await this.invokeRequest({
          url: "/DefaultCollection/_apis/projects",
        });
      } else {
        // Try go over all collections and fetch all projects
        projects = await this.getProjects(collections);
      }

      const allReposList = await this.getRepoList(projects);

      const monitored = allReposList.filter(apiRepo => this.repoSelectedByUser(apiRepo.id.toString(), apiRepo.name, apiRepo.created_at));

      return monitored;
    } catch (err) {
      logger.error(`failed to get repos list obj for: ${this.token.type}, err: ${err}`);
    }
    return [];
  }

  private async getRepoList(projects: TFS2018Types.Projects[]) {
    const repoCalls = projects.reduce((arr, { name: projectName, collectionName }) => {
      const repoUrl = `/${collectionName ?? "DefaultCollection"}/${projectName}/_apis/git/repositories`;
      const repoCalls = this.invokeRequest({ url: repoUrl, singleRequest: true });
      return [...arr, repoCalls];
    }, []);

    const allRepos = await Promise.all(repoCalls);
    return allRepos
      .flat()
      .filter(repo => repo)
      .reduce((arr, repo) => arr.concat(repo), []);
  }

  private async getProjects(collections: any) {
    const projectCalls = collections.map(collection => {
      const collectionName = collection.name;
      const projectUrl = `/${collectionName}/_apis/projects`;
      return this.invokeRequest({
        url: projectUrl,
        axiosConfig: {
          transformResponse: [
            function (data) {
              data = JSON.parse(data);
              return { ...data, value: data.value.map(data => ({ ...data, collectionName })) };
            },
          ],
        },
      });
    });

    const projects = await Promise.all(projectCalls);
    return projects.flat().filter(project => project);
  }

  getCloneUrl(repo) {
    try {
      // Remote url, not always equal to this.token.host
      // In such case we need to replace the remote host with
      // this.token.host
      const remoteHost = repo.remoteUrl.split("/")[2];
      const tokenHost = this.token.host.split("/")[2];

      if (remoteHost !== tokenHost) {
        repo.remoteUrl = repo.remoteUrl.replace(remoteHost, tokenHost);
      }

      const remoteUrl = new URL(repo.remoteUrl);
      const hostUrl = new URL(this.token.host);

      const cloneURL = repo.remoteUrl.replace(
        remoteUrl.protocol + "//" + remoteUrl.hostname + ":" + remoteUrl.port,
        `${hostUrl.protocol}//${hostUrl.hostname}:${hostUrl.port}`,
      );
      return cloneURL;
    } catch (err) {
      logger.error(`failed to get clone url obj for: ${this.token.type}, err: ${err}`);
    }
    return "";
  }

  getFileLinkPrefix(cloneURL, repo) {
    try {
      const res = cloneURL.replace("/_git/", "/_versionControl?path=$/");
      const splitted = res.split("/");
      const indexToAdd = splitted.indexOf("_versionControl?path=$");
      const app = splitted[indexToAdd - 1];
      splitted.splice(indexToAdd + 1, 0, app);
      splitted.push("");
      return splitted.join("/");
    } catch (err) {
      logger.error(`could not get file link for repo: ${repo}`);
    }
    return "";
  }

  async branches(repo: Repo) {
    let branchsList: Branch[] = [];

    try {
      const res = await this.invokeRequest({
        url: "/refs",
        singleRequest: true,
        axiosConfig: { baseURL: repo.link, params: { filter: "heads" } },
      });
      for (const branchInfo of res) {
        try {
          let branch = new Branch(branchInfo.name);
          branchsList.push(branch);
        } catch (err) {
          logger.error(`failed to create branch obj for: ${repo.name}, branch: ${JSON.stringify(branchInfo, null, 4)}, err: ${err}`);
        }
      }
    } catch (err) {
      logger.error(`get branches failed repo: ${repo.name}, err: ${err}`);
    }
    return branchsList;
  }

  async users(repoObj: any) {
    let repoName = "";
    try {
      const repo: Repo = repoObj.code_repo;

      repoName = repo.name;

      const teamsUrl = `/_apis/projects/${repo.project}/teams`;
      const baseURL = repo.link.substring(0, repo.link.indexOf("_apis"));

      const teams = await this.invokeRequest({
        url: teamsUrl,
        axiosConfig: { baseURL },
      });

      const allTeamMembersRequests = teams.map(team =>
        this.invokeRequest({ url: `${teamsUrl}/${team.id}/members`, axiosConfig: { baseURL } }),
      );
      const allTeamMembers = await Promise.all(allTeamMembersRequests);

      const teamMembersRequests = allTeamMembers.flat().reduce((arr, teamMembers) => {
        const res = this.invokeRequest({
          url: teamMembers.identity.url,
          singleRequest: true,
          axiosConfig: {
            baseURL: null,
            transformResponse: [
              function (data) {
                return { value: JSON.parse(data ? data : "[]") };
              },
            ],
          },
        });
        return [...arr, res];
      }, []);

      const teamMembersData = await Promise.all(teamMembersRequests);
      const uniqueProjectUsers = lodash.uniqBy(teamMembersData.flat(), "id");

      let usersInfo: User[] = [];

      for (const user of uniqueProjectUsers) {
        try {
          if (user.isActive == false) {
            continue;
          }

          const userInfo = new User(user.providerDisplayName, user.providerDisplayName, user.id, "", "", "");

          usersInfo.push(userInfo);
          this.globalCodeRepoData.addUser(userInfo, repoType.azureTFS);
        } catch (err) {
          logger.error(`failed to create branch obj for: ${repo.name}, user: ${JSON.stringify(user, null, 4)}, err: ${err}`);
        }
      }

      // We need to handle a case where, we don't have enough permissions for _api/Identities
      // And make best effort
      if (uniqueProjectUsers.length === 0 && allTeamMembers.length > 0) {
        const usersIdentities: TFS2018Types.Identities[] = allTeamMembers.flat();

        for (const user of usersIdentities) {
          try {
            const convertGuidToNumber = (guid: string) => {
              return parseInt(guid.replace(/-/g, "").substring(0, 8), 16);
            };

            const userInfo = new User(
              user.identity.displayName,
              user.identity.displayName,
              convertGuidToNumber(user.identity.id),
              "",
              "",
              "",
            );

            usersInfo.push(userInfo);
            this.globalCodeRepoData.addUser(userInfo, repoType.azureTFS);
          } catch (err) {
            logger.error(`failed to create branch obj for: ${repo.name}, user: ${JSON.stringify(user, null, 4)}, err: ${err}`);
            StatesHelper.Instance.addFailedTool(repoResourceType.users, repo.id);
          }
        }
      }

      return usersInfo;
    } catch (err) {
      const repo: Repo = repoObj.code_repo;
      logger.error(`get branches failed repo: ${repoName}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.users, repo.id);
    }
    return [];
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
      res = await this.invokeRequest({
        url: "/pullrequests",
        axiosConfig: {
          baseURL: repo.link,
          params: { "searchCriteria.status": "completed" },
        },
      });

      for (const pullInfo of res) {
        try {
          if (pullInfo.status == null || pullInfo.status == undefined) {
            continue;
          }

          if (pullInfo.status.toLowerCase() !== "completed") {
            continue;
          }

          const reviewers: Reviewer[] = [];
          if (pullInfo.reviewers != undefined) {
            for (const rev of pullInfo.reviewers) {
              reviewers.push(new Reviewer(rev.uniqueName, rev.displayName, rev.id));
            }
          }

          const pullRequest = new PullRequest(
            new Date(pullInfo.creationDate).toString(),
            pullInfo.url,
            pullInfo.description,
            pullInfo.closedDate,
            pullInfo.status.toLowerCase() === "completed" ? new Date(pullInfo.closedDate).toString() : "",
            pullInfo.title,
            pullInfo.reviewers == undefined ? 0 : pullInfo.reviewers.length,
            pullInfo.createdBy.displayName,
            pullInfo.pullRequestId,
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
      if (pullInfo?.lastMergeSourceCommit) {
        res.push({ id: pullInfo?.lastMergeSourceCommit.commitId });
      }
      if (pullInfo?.lastMergeTargetCommit) {
        res.push({ id: pullInfo?.lastMergeTargetCommit.commitId });
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

  async handlePaging(name: string, query: any, pagination: boolean = false) {}

  isRateLimitErrFunction(err: any) {
    try {
      if (err.toString().includes("rate limit")) {
        return true;
      }
      if (err.toString().includes("ECONNRESET".toLowerCase())) {
        return true;
      }
      if (err.toString().includes("timeout of")) {
        return true;
      }

      if (err.response?.status) {
        if (err.response.status == 429) {
          return true;
        }
      }
    } catch (e) {
      logger.error(`failed pare error output for: ${this.token.type}, err: ${e}, original err: ${err}`);
    }
    return false;
  }

  getQueryNextPage(r: AzureTeamFoundationServerRequest, singleRes: any) {
    if (r.query.singleRequest) {
      if (r.query.singleRequest) return false;
    }
    if (r.page > r.maxPage) return false;
    if (singleRes.length < per_page_max_res) return false;
    r.page++;
    return true;
  }

  async invokeRequest(query: any, maxPageCount: number = max_pages) {
    const r: AzureTeamFoundationServerRequest = new AzureTeamFoundationServerRequest();
    r.query = query;
    r.maxPage = maxPageCount;

    const res = await this.rateLimitHelper.sendApiRequest(
      r.query.url,
      r,
      this.isRateLimitErrFunction,
      this.axiosCall,
      this.getQueryNextPage,
      retry_count,
      this,
    );

    if (res) {
      return res.flat();
    }
    return [];
  }

  async axiosCall(r: AzureTeamFoundationServerRequest) {
    const top = r.query.axiosConfig?.params?.$top || per_page_max_res;
    const instance = axiosInstance
      .get(r.query.url, {
        ...r.query.axiosConfig,
        params: {
          ...r.query.axiosConfig?.params,
          $top: top,
          $skip: top * (r.page - 1),
        },
      })
      .catch(err => {
        logger.error(`failed to get tfs data for url ${r.query.url}, error: ${err}`);
      });
    const res: any = await instance;
    return res.data.value || {};
  }

  async getTimeToWait() {
    return timeout_to_wait_after_rate_limit_happen;
  }

  // check if u have from api when the last push to repo happen
  async getLastCodeChange(application: any) {
    // Get the last commit date to save as last code change
    try {
      const commits = await this.invokeRequest({
        url: "/commits",
        singleRequest: true,
        axiosConfig: { baseURL: application.url, params: { $top: 1 } },
      });
      if (commits.length) {
        const lastCodeChange = commits[0].author.date;
        if (lastCodeChange) {
          return new Date(lastCodeChange).toString();
        }
      }
    } catch (error) {
      logger.error(`Can't get last code change azure tfs: ${error}`);
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

export default AzureTFS;
