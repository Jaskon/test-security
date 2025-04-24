import { ProjectSchema } from "@gitbeaker/core/dist/types/types";
import { Gitlab } from "@gitbeaker/node";
import FeatureFlags from "@oxappsec/ox-feature-flag";
import axios from "axios";
import https from "https";
import { ApplicationManager } from "../../appmgr/AppManager";
import {
  addSeverityChangedReason,
  AlertSeverity,
  Branch,
  BranchSettings,
  CodeRepoTypes,
  Commit,
  CweObject,
  File,
  ForkedRepos,
  ForkReasons,
  GitlabRequest,
  MergeUser,
  Organization,
  PipelineScanInfo,
  PullRequest,
  PushRole,
  Repo,
  repoResourceType,
  repoType,
  resourceType,
  Reviewer,
  SecurityAlertType,
  SecurityEvent,
  setFileInfo,
  User,
  UserAuditLog,
  UserRole,
  Webhook,
  Workflow,
} from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { isJson } from "../../entitis/commonTypes";
import { GitLab, GitLabPipeline } from "../../entitis/connectorsSpecific/gitLabTypes";
import Constant from "../../entitis/constant";
import { severityReasons } from "../../entitis/service/blameTypes";
import RepoImportanceCalcHelper from "../../helper/appPriority/repoImportanceCalcHelper";
import {
  capitalizeFirstLetter,
  getGitlabRepoName,
  isIpAddress,
  removeUrlAndKeepOnlyIp,
  replaceUrlWithHostForOnPremGit,
  replaceUrlWithIpForOnPremGit,
} from "../../helper/commonUtils";
import { isDevelopment, isLocalDevelopment, isStaging } from "../../helper/envUtils";
import GeoLocationHelper from "../../helper/geoLocationHelper";
import GitHelper from "../../helper/gitHelper";
import { handleGitlabRequest } from "../../helper/github/gitlab-request";
import { Parallel, RateLimitHelperFactory } from "../../helper/rateLimitHelper";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import { isPolicyMainBranchDoesntRequireCodeReviewViolation } from "../../policy/rules/code/policyMainBranchDoesntRequireCodeReview";
import RulesManager from "../../policy/rules/ruleManager";
import CodeRepoBase from "../base/codeRepoBase";
import GlobalCodeRepoData from "../GolobalCollectorData/globalCodeRepoData";
import { SettingsService } from "../../helper/service/scan-settings-service/service/settings-service";
const timeHelper: TimeHelper = new TimeHelper("bitbucket");

const crypto = require("crypto");
export const default_per_page_max_res = 100;
const default_max_pages = 5;
const retry_count = 4;
const timeout_to_wait_after_rate_limit_happen = 1000 * 60 * 1.5;
let shouldEnableEtags: boolean = false;
let g_shouldLogRateLimitData = false;

const logger = loggerImport.getDebugLogger();
const roles = new Map<number, UserRole>();
roles.set(0, UserRole.NO_ACCESS);
roles.set(10, UserRole.GUEST);
roles.set(20, UserRole.REPORTER);
roles.set(30, UserRole.DEVELOPER);
roles.set(40, UserRole.MAINTAINER);
roles.set(50, UserRole.OWNER);

const pushRoles = new Map<number, PushRole>();
pushRoles.set(0, PushRole.NONE);
pushRoles.set(30, PushRole.DEVELOPER);
pushRoles.set(40, PushRole.MAINTAINER);

class CodeRepoGitLab extends CodeRepoBase {
  api: InstanceType<typeof Gitlab>;
  host: string;
  private_token: string;
  Based64_token: string;
  appMgr: ApplicationManager;
  sleepWasCalled = false;
  usingOathToken = false;
  isUsingIp: boolean = false;
  cal;
  orgs: Organization[] = [];
  geoLocationHelper: GeoLocationHelper;
  shouldUseBasicAuthChecks: boolean;
  shouldBypassCertChecks: boolean;
  shouldReplaceUrl: boolean = false;
  shouldUseBaseUrlFeature: boolean = false;
  shouldLogRateLimitData: boolean = true;
  userSelectedBranch: string = "";

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    let tempToken = token.password;
    const isIdpToken = isJson(token.password);
    this.cal = new RepoImportanceCalcHelper(this.uuid, this.orgName);

    this.rateLimitHelper = RateLimitHelperFactory.getRateLimitHelperPerToken(this.token.name, 200);

    if (isIdpToken) {
      const idpToken = JSON.parse(token.password);
      tempToken = idpToken.access_token;
    }

    this.host = token.host;
    this.private_token = tempToken;

    this.appMgr = new ApplicationManager(this.uuid);

    this.geoLocationHelper = new GeoLocationHelper();
  }

  getAllOrgs() {
    return this.orgs;
  }

  getTokenHeader() {
    if (this.Based64_token) {
      return {
        Authorization: `Basic ${this.Based64_token}`,
      };
    }
    if (this.usingOathToken) {
      return {
        Authorization: `Bearer ${this.private_token}`,
      };
    }
    return { "private-token": this.private_token };
  }

  async initLib() {
    logger.info(`try init lib for: ${this.token.name}, url: ${this.token.host}`);

    try {
      const shouldRepUrlWithHost = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "ox-replace-host-url-clone", true);
      this.shouldUseBaseUrlFeature = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxUseGitlabBaseUrl");
      this.shouldLogRateLimitData = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxLogRateLimitDataForGitlab");
      g_shouldLogRateLimitData = this.shouldLogRateLimitData;

      if (shouldRepUrlWithHost) {
        this.shouldReplaceUrl = true;
        logger.info(`shouldReplaceUrl for: ${this.token.name}, url: ${this.token.host}`);
      }

      const oauthTokenRegex = /[a-z0-9]{64}/g;
      const personalTokenRegex = /glpat-[0-9a-zA-Z\-]{20}/g;
      const oldPersonalTokenRegex = /[0-9a-zA-Z\-\_]{20}/g;

      this.shouldBypassCertChecks = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "ox-disable-gitlab-cert-validation", true);
      this.shouldUseBasicAuthChecks = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "ox-use-basic-auth-check", true);

      shouldEnableEtags =
        (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxGitlabEnableEtags")) || isDevelopment() || isStaging(); //LD-Only

      if (this.shouldUseBasicAuthChecks) {
        this.Based64_token = Buffer.from(`${this.private_token}:`).toString("base64");

        const possibleIp = removeUrlAndKeepOnlyIp(this.host);
        if (isIpAddress(possibleIp)) {
          this.isUsingIp = true;
        }

        logger.info(`shouldUseBaseAuthChecks for: ${this.token.name}, url: ${this.token.host} set to true, isUsingIp: ${this.isUsingIp}`);

        this.api = new Gitlab({
          host: this.token.host,
          token: this.private_token,
          rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          requesterFn: this.requesterFnc,
        });
      } else {
        if (this.private_token.match(oauthTokenRegex)) {
          this.api = new Gitlab({
            host: this.token.host,
            oauthToken: this.private_token,
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          });
          this.usingOathToken = true;
        } else if (this.private_token.match(personalTokenRegex) || this.private_token.match(oldPersonalTokenRegex)) {
          this.api = new Gitlab({
            host: this.token.host,
            token: this.token.password,
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          });
        } else {
          logger.error(`Got unfamiliar token type, trying to use personal token`);

          this.api = new Gitlab({
            host: this.token.host,
            token: this.token.password,
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          });
        }
      }
    } catch (err) {
      logger.error(err);
    }

    logger.info(`finish init lib for: ${this.token.name}, url: ${this.token.host}`);
  }

  getFileLink(apiRepo, pipelineScanInfo: PipelineScanInfo) {
    return [apiRepo.web_url, "-", "blob", pipelineScanInfo.sourceBranch ? pipelineScanInfo.sourceBranch : apiRepo.default_branch, ""].join(
      "/",
    );
  }

  requesterFnc(requestOptions) {
    const { url, headers, rejectUnauthorized, camelize, requestTimeout } = requestOptions;

    const privateToken = headers["private-token"] + ":";
    const authHeaders = {
      Authorization: `Basic ${Buffer.from(privateToken).toString("base64")}`,
    };

    return {
      get: route => {
        return new Promise((resolve, reject) => {
          axios({
            url: `${url}${route}?per_page=100&page=1`,
            method: "GET",
            headers: authHeaders,
            httpsAgent: new https.Agent({
              rejectUnauthorized,
            }),
          })
            .then(response => {
              resolve({
                body: response.data,
                headers: response.headers,
                status: response.status,
              });
            })
            .catch(error => {
              reject(error);
            });
        });
      },
      post: () => {
        return new Promise((resolve, reject) => {
          axios({
            url,
            method: "POST",
            headers,
            httpsAgent: new https.Agent({
              rejectUnauthorized: false,
            }),
          })
            .then(response => {
              console.log("response.data post", response.data);
              resolve(response.data);
            })
            .catch(error => {
              reject(error);
            });
        });
      },
      put: () => {
        return new Promise((resolve, reject) => {
          axios({
            url,
            method: "PUT",
            headers,
            httpsAgent: new https.Agent({
              rejectUnauthorized: false,
            }),
          })
            .then(response => {
              console.log("response.data put", response.data);
              resolve(response.data);
            })
            .catch(error => {
              reject(error);
            });
        });
      },
      delete: () => {
        return new Promise((resolve, reject) => {
          axios({
            url,
            method: "DELETE",
            headers,
            httpsAgent: new https.Agent({
              rejectUnauthorized: false,
            }),
          })
            .then(response => {
              console.log("response.data delete", response.data);
              resolve(response.data);
            })
            .catch(error => {
              reject(error);
            });
        });
      },
    };
  }

  createRepo(apiRepo) {
    const pipelineScanInfo = this.getPipelineScanInfo(apiRepo.id.toString(), apiRepo.name_with_namespace);

    const cloneHeaders = [];

    if (this.shouldBypassCertChecks) {
      cloneHeaders.push(`-c`, `http.sslVerify=false`);
    }

    const repo = new Repo(
      this.uuid,
      this.orgName,
      this.token.name,
      apiRepo.name,
      apiRepo.id.toString(),
      getGitlabRepoName(apiRepo.name_with_namespace),
      apiRepo.created_at,
      apiRepo.default_branch,
      apiRepo.description,
      apiRepo.archived || apiRepo.empty_repo,
      this.getCloneUrl(apiRepo),
      0, // GitLab does not have this stat: apiRepo.has_downloads,
      true, //apiRepo.has_pages,
      apiRepo.wiki_enabled, //apiRepo.has_wiki,
      apiRepo.open_issues_count > 0, //apiRepo.has_issues,
      apiRepo.readme_url,
      this.isUsingIp ? true : apiRepo.visibility === "private",
      null,
      0, //set bellow,
      0, //apiRepo.watchers_count,
      "", //apiRepo.owner.login,
      apiRepo.web_url,
      apiRepo.forks_count, //apiRepo.forks_count,
      apiRepo.last_activity_at, //apiRepo.pushed_at
      "",
      this.getFileLink(apiRepo, pipelineScanInfo),
      "#L",
      apiRepo.tag_list.length,
      apiRepo.web_url + "/edit",
      apiRepo.web_url + "/commit/",
      "",
      "",
      "",
      apiRepo.id.toString(),
      true,
      apiRepo.name,
      pipelineScanInfo,
      undefined,
      undefined,
      cloneHeaders,
    );
    this.setOrganization(repo, apiRepo);
    repo.fullPath = apiRepo.path_with_namespace;
    return repo;
  }

  async setRepo(apiRepo, repoObj) {
    try {
      const pipelineScanInfo = this.getPipelineScanInfo(apiRepo.id.toString(), apiRepo.name_with_namespace);
      const cloneHeaders = [];

      if (this.shouldBypassCertChecks) {
        cloneHeaders.push(`-c`, `http.sslVerify=false`);
      }

      let repo = new Repo(
        this.uuid,
        this.orgName,
        this.token.name,
        apiRepo.name,
        apiRepo.id.toString(),
        getGitlabRepoName(apiRepo.name_with_namespace),
        apiRepo.created_at,
        apiRepo.default_branch,
        apiRepo.description,
        apiRepo.archived || apiRepo.empty_repo,
        this.getCloneUrl(apiRepo),
        0, // GitLab does not have this stat: apiRepo.has_downloads,
        true, //apiRepo.has_pages,
        apiRepo.wiki_enabled, //apiRepo.has_wiki,
        apiRepo.open_issues_count > 0, //apiRepo.has_issues,
        apiRepo.readme_url,
        this.isUsingIp ? true : apiRepo.visibility === "private",
        null,
        0, //set bellow,
        0, //apiRepo.watchers_count,
        "", //apiRepo.owner.login,
        apiRepo.web_url,
        apiRepo.forks_count, //apiRepo.forks_count,
        apiRepo.last_activity_at, //apiRepo.pushed_at
        "",
        this.getFileLink(apiRepo, pipelineScanInfo),
        "#L",
        apiRepo.tag_list.length,
        apiRepo.web_url + "/edit",
        apiRepo.web_url + "/commit/",
        "",
        "",
        "",
        apiRepo.id.toString(),
        true,
        apiRepo.name,
        pipelineScanInfo,
        undefined,
        undefined,
        cloneHeaders,
      );
      this.setOrganization(repo, apiRepo);
      repo.fullPath = apiRepo.path_with_namespace;
      repo.forksCount = apiRepo.forks_count ? apiRepo.forks_count : 0;

      if (this.userSelectedBranch) {
        repo.sourceBranch = this.userSelectedBranch;
      }

      this.setClientConfiguredProps(repo);

      if (this.cal.isRepoImportanceAreZero(repo, 100).length > 0) {
        StatesHelper.Instance.skippedClone.add(repo.fullName);
      }

      if (apiRepo.delta) {
        repo.isDelta = true;
      }

      // Must clone here
      if (repo.noneRelevantRepo) {
        this.fileHelper.createDir(repo.cloneDir);
      } else {
        repo.filesModifiedInPullRequest = await this.tryFindingFilesModifiedInPullRequest(repo);
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

      repo.gitRoles = this.getGitRoles("gitlab");

      const promise = await this.appMgr.CreateRepoNode({
        repo_name: getGitlabRepoName(apiRepo.name_with_namespace.trim()).trim(),
        repo_id: apiRepo.id,
        vcs_type: "gitlab",
        url: apiRepo.web_url,
        default_branch: apiRepo.default_branch,
      });

      return repo;
    } catch (err) {
      logger.error(`failed to create repo obj for: ${JSON.stringify(apiRepo)}, err: ${err}`);
    }
    return null;
  }

  setOrganization(repo, apiRepo) {
    try {
      repo.organization = apiRepo.path_with_namespace.split("/")[0];
    } catch (err) {
      logger.error(`failed to get oranization name for repo: ${apiRepo.path_with_namespace}, err: ${err}`);
    }
  }

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

  getQueryNextPage(r: GitlabRequest, singleRes: any) {
    if (r.query.singleRequest) return false;
    if (r.page > r.maxPage) return false;
    if (singleRes.length < (r.perPage || default_per_page_max_res)) return false;
    r.page++;
    return true;
  }

  async invokeRequest(
    query: any,
    repoName: string,
    maxPageCount: number = default_max_pages,
    maxPageSize: number = default_per_page_max_res,
    parallel?: Parallel,
  ) {
    const r: GitlabRequest = new GitlabRequest();
    r.query = query;
    r.maxPage = maxPageCount;
    r.perPage = maxPageSize;

    const splitted = r.query?.url?.split("/");
    const relevant = [splitted[splitted.length - 2], splitted[splitted.length - 1]];
    const apiName = relevant.join("/");
    const key = `${repoName}_${apiName}`;

    if (this.uniqueRequestAPIs.has(key)) {
      this.uniqueRequestAPIs.set(key, this.uniqueRequestAPIs.get(key) + 1);
    } else {
      this.uniqueRequestAPIs.set(key, 1);
    }

    const res = await this.rateLimitHelper.sendApiRequest(
      r.query.url,
      r,
      this.isRateLimitErrFunction,
      this.axiosCall,
      this.getQueryNextPage,
      retry_count,
      this,
      false,
      undefined,
      parallel,
    );

    return res.flat();
  }

  async axiosCall(r: GitlabRequest, page: number) {
    if (shouldEnableEtags) {
      return await handleGitlabRequest(r);
    } else {
      const instance = axios.get(r.query.url + `?per_page=${r.perPage || default_per_page_max_res}&page=${page || r.page}`, r.query.params);
      const res: any = await instance;

      if (g_shouldLogRateLimitData && res.headers["ratelimit-remaining"]) {
        try {
          const remaining = res.headers["ratelimit-remaining"];
          const reset = res.headers["ratelimit-reset"];
          const total = res.headers["ratelimit-limit"];
          const observed = res.headers["ratelimit-observed"];
          const used = total - remaining;
          const resetDate = new Date(reset * 1000);

          //Debug
          // logger.info(
          //   `Gitlab rate limit stats: used: ${used}, remaining: ${remaining} (observed: ${observed}), total: ${total}, reset: ${resetDate}, url: ${
          //     r.query.url
          //   }, reset in: ${Math.round((reset - Date.now() / 1000) / 60)} minutes`,
          // );

          // Show gitlab etag information
          if (res.headers.etag) {
            //Debug
            //logger.info(`Gitlab etag: ${res.headers.etag} for url: ${r.query.url}`);
          }
        } catch (e) {
          // Be extra safe here
        }
      }

      return res.data;
    }
  }

  async getTimeToWait() {
    return timeout_to_wait_after_rate_limit_happen;
  }

  async getSingleRepositoryById(repoId: string): Promise<ProjectSchema> {
    try {
      const repo = await this.api.Projects.show(repoId);
      return repo;
    } catch (e) {
      logger.error(`failed to get single repository by id ${repoId} for: ${this.token.type}`, e);
      return null;
    }
  }

  async getAllRepos(callObj: RulesManager): Promise<ProjectSchema[]> {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        const repoId = this.getPipelineScanRepoId();
        if (repoId === null) return [];
        const repo = await this.getSingleRepositoryById(repoId);
        return repo === null ? [] : [repo];
      }

      const allRepos = await this.api.Projects.all({
        maxPages: 100000,
        perPage: 100,
        membership: true,
      });

      const monitoredBeforeBranch = allRepos.filter(apiRepo =>
        this.repoSelectedByUser(apiRepo.id.toString(), apiRepo.name_with_namespace, apiRepo.created_at),
      );
      logger.info(`${this.token.name}, all repos before filter: ${allRepos.length} after filter: ${monitoredBeforeBranch.length}`);

      let monitored = monitoredBeforeBranch;
      this.userSelectedBranch = SettingsService.Instance.defineBranch(this.token.name);
      if (this.userSelectedBranch) {
        logger.info(`${this.token.name}, customer chose a specific branch for ${this.token.name} repos: ${this.userSelectedBranch}`);
        monitored = await this.getReposWithSelectedBranch(monitoredBeforeBranch, this.userSelectedBranch);
      } else {
        logger.info(`${this.token.name}, customer didn't chose a specific branch for ${this.token.name} repos`);
      }
      logger.info(
        `${this.token.name}, all repos before branch filter: ${monitoredBeforeBranch.length} after branch filter: ${monitored.length}`,
      );
      return monitored;
    } catch (err) {
      logger.error(`failed to get repos list obj for: ${this.token.type}, err: ${err}`);
    }
    return [];
  }

  // Here we filter repos with specific branch that user has provided
  async getReposWithSelectedBranch(allRepos: any[], sourceBranch: string) {
    const reposWithSelectedBranch = [];
    try {
      for (const repo of allRepos) {
        try {
          const query = {
            url: `${this.host}/api/v4/projects/${repo.id}/repository/branches`,
            params: {
              timeout: 30000,
              headers: this.getTokenHeader(),
              httpsAgent: new https.Agent({
                rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
              }),
            },
          };
          const branches = await this.invokeRequest(query, repo.name, 10);

          if (branches.find(branch => branch?.name === sourceBranch)) {
            // check case sensitive match
            reposWithSelectedBranch.push(repo);
            logger.info(`${this.token.name}, repo ${repo.name} contains the ${sourceBranch} branch, will be included in scan`);
            continue;
          }
          logger.info(`${this.token.name}, repo ${repo.name} doesn't contain the ${sourceBranch} branch, will be excluded from scan`);
        } catch (error) {
          logger.error(`${this.token.name}, failed to get branch for repo ${repo.name} while getReposWithSelectedBranch, err: ${error}`);
        }
      }
      return reposWithSelectedBranch;
    } catch (err) {
      logger.error(`${this.token.name}, failed to getReposWithSelectedBranch, err: ${err}`);
    }
    return reposWithSelectedBranch;
  }

  getCloneUrl(repo): string {
    let url: string = repo.http_url_to_repo.replace(/(^\w+:|^)\/\//, "");

    if (this.shouldUseBaseUrlFeature) {
      try {
        const hostname = url.split("/")[0];
        url = url.replace(hostname, this.host.replace(/(^\w+:|^)\/\//, ""));
      } catch (err) {
        logger.error(`failed to replace hostname for: ${this.token.type}, err: ${err}`);
      }
    }

    const user = this.usingOathToken ? "oauth2" : "personal";
    let res = `https://${user}:${this.getTokenPassword()}@${url}`;
    if (this.shouldReplaceUrl) {
      res = replaceUrlWithHostForOnPremGit(res, this.host);
      return res;
    }
    if (this.Based64_token) {
      res = replaceUrlWithIpForOnPremGit(res, this.host);
    }
    return res;
  }

  async getAuthenticatedRepos() {
    try {
      const query = {
        url: "GET /user/repos",
        params: {
          page: 1,
          per_page: default_per_page_max_res,
          timeout: 30000,
          headers: this.getTokenHeader(),
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };

      const res = await this.invokeRequest(query, "");
      return res;
    } catch (err) {
      logger.error(err);
    }
    return [];
  }

  getWebhooksEvents(webhookInfo) {
    try {
      const events = Object.keys(webhookInfo).filter(x => {
        return x.includes("_event") && webhookInfo[x] == true;
      });
      return [events];
    } catch (err) {
      logger.error(`uuid: ${this.uuid}, failed to create webhook obj: ${JSON.stringify(webhookInfo.url)}, err: ${err}`);
    }
    return [];
  }

  async webhooks(repo: Repo): Promise<any> {
    let webhooksList: Webhook[] = [];

    try {
      const query = {
        url: `${this.host}/api/v4/projects/${repo.id}/hooks`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };

      const res: any = await this.invokeRequest(query, repo.name);

      for (const webhookInfo of res) {
        try {
          let webhook = new Webhook(
            webhookInfo.url,
            webhookInfo.created_at,
            "", //webhookInfo.lastResponseCode,
            "", //webhookInfo.lastResponseMsg,
            true,
            webhookInfo.enable_ssl_verification,
            true,
            "",
            repo.link + "/hooks/" + webhookInfo.id + "/edit",
            this.getWebhooksEvents(webhookInfo),
            repoResourceType.webhooks,
          );

          const promise = await this.appMgr.CreateNode("Webhook", {
            repo_name: repo.name,
            repo_id: repo.id,
            vcs_type: "gitlab",
            url: webhookInfo.web_url,
            created: webhookInfo.created_at,
          });

          webhooksList.push(webhook);
        } catch (err) {
          logger.error(`failed to create webhook obj for: ${repo.name}, webhook: ${JSON.stringify(webhookInfo, null, 4)}, err: ${err}`);
          // StatesHelper.Instance.addFailedTool(repoResourceType.webhooks, repo.id);
        }
      }
    } catch (err) {
      logger.error(`failed to get webhooks, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.webhooks, repo.id);
    }

    return webhooksList;
  }

  async workflows(repo: Repo): Promise<any> {
    let workflowsList: Workflow[] = [];

    try {
      const query = {
        url: `${this.host}/api/v4/projects/${repo.id}/pipelines`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };

      const pipeline: GitLabPipeline[] = await this.invokeRequest(query, repo.name);
      if (pipeline && pipeline.length > 0) {
        try {
          // Read yaml file (file data on it)
          let workflow = new Workflow("", pipeline[0].web_url, true, pipeline[0].sha, pipeline[0].ref, pipeline[0].id.toString());

          const promise = await this.appMgr.CreateNode("Workflow", {
            repo_name: repo.name,
            repo_id: repo.id,
            vcs_type: "gitlab",
            url: pipeline[0].web_url,
            id: pipeline[0].id.toString(),
            sha: pipeline[0].sha,
          });

          workflowsList.push(workflow);
        } catch (err) {
          logger.error(`failed to create workflow obj for: ${repo.name}, workflow: ${JSON.stringify(pipeline, null, 4)}, err: ${err}`);
        }
      }
    } catch (err) {
      logger.error(`get workflows failed repo: ${repo.name}, err: ${err}`);
    }
    return workflowsList;
  }

  getAPICredentials() {
    const auth = this.usingOathToken
      ? { authType: "oauthToken", oauthToken: this.private_token }
      : { authType: "token", token: this.private_token };

    return {
      ...auth,
      host: this.host,
      shouldUseBasicAuthChecks: this.shouldUseBasicAuthChecks,
      shouldBypassCertChecks: this.shouldBypassCertChecks,
    };
  }

  getAPIRepoInfo(repo: Repo) {
    return {
      projectId: repo.id,
    };
  }

  async findPullRequestIntroducingMergeCommit(repoObj: any, branch: string, sha: string) {
    const repo: Repo = repoObj.code_repo;
    try {
      // first fetch commit information
      const commitsQuery = {
        url: `${this.host}/api/v4/projects/${repo.id}/repository/commits/${sha}`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };

      const commitsResponse = await this.invokeRequest(commitsQuery, repo.name);
      const commit = commitsResponse[0];
      if (!commit) return null;

      // avoid fetching all merge_requests, only fetch ones around the date commit was introduced
      let updatedTimeframeQueryParams: {
        updated_after?: string;
        updated_before?: string;
      } = {};

      const pivotDateString = commit.authored_date ?? commit.commited_date ?? commit.created_at;
      if (pivotDateString) {
        const pivotDate = new Date(pivotDateString);
        updatedTimeframeQueryParams.updated_after = timeHelper.addDaysToDate(pivotDate, -3).toISOString();
        updatedTimeframeQueryParams.updated_before = timeHelper.addDaysToDate(pivotDate, 3).toISOString();
      }

      const mergeRequestQuery = {
        url: `${this.host}/api/v4/projects/${repo.id}/merge_requests`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          params: {
            state: "merged",
            target_branch: branch,
            ...updatedTimeframeQueryParams, // fetch merge requests with date information
            httpsAgent: new https.Agent({
              rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
            }),
          },
        },
      };

      const mergeRequestsResponse: GitLab.MergeRequest[] = await this.invokeRequest(mergeRequestQuery, repo.name);

      // try finding
      const found = mergeRequestsResponse.find(mr => mr.merge_commit_sha === sha || mr.squash_commit_sha === sha);
      if (!found) return null;

      const pullRequest = new PullRequest(
        found.created_at,
        found.web_url,
        found.description,
        sha,
        found.merged_at,
        found.title,
        0,
        found.author?.name ?? found.author?.username ?? found.author?.id?.toString(),
        found.iid,
        CodeRepoTypes.pulls,
        [],
        new MergeUser(found.merge_user?.name, found.merge_user?.username, found.merge_user?.id),
        true,
      );
      return pullRequest;
    } catch (e) {
      logger.error(
        `[gitlab] failed to find pull request introducing merge commit repo: ${repo.name}, branch: ${branch}, sha: ${sha}, e: ${e}`,
      );
      return null;
    }
  }

  async findFilesModifiedInPullRequest(
    repo: Repo,
    sourceBranch: string,
    targetBranch: string,
    sha: string | null,
    pullRequestId: string | null,
  ) {
    try {
      const shouldFindFilesModifiedInPrViaApi = isLocalDevelopment()
        ? true
        : await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxShouldFindFilesModifiedInPrViaApiGitLab");

      if (!shouldFindFilesModifiedInPrViaApi) return null;
      StatesHelper.Instance.pipelineScanInfo.filesModifiedInPullRequest.enabled = true;

      let usedPullRequestId = pullRequestId;
      let pullRequestDetailed: GitLab.MergeRequestDetailed = null;

      if (!usedPullRequestId) {
        const pullRequest = await this.getOpenPullRequestForBranches(repo.repoId, sourceBranch, targetBranch, repo.name);
        usedPullRequestId = pullRequest?.iid ?? null;
      }

      if (!usedPullRequestId) {
        logger.warn(
          `[gitlab][findFilesModifiedInPullRequest] no pull request ID provided and found for repoId: ${repo.repoId}, repoName: ${repo.name}, sourceBranch: ${sourceBranch}, targetBranch: ${targetBranch}, usedPullRequestId: ${usedPullRequestId}`,
        );
        return null;
      }

      pullRequestDetailed = await this.getPullRequestDetails(repo.repoId, usedPullRequestId, repo.name);

      const changesCount = parseInt(pullRequestDetailed.changes_count);
      const changesCountLimitReached = pullRequestDetailed.changes_count.endsWith("+");
      const perPage = 30;

      if (changesCountLimitReached) {
        logger.warn(
          `[gitlab][findFilesModifiedInPullRequest] ${changesCount} files limit reached. pullRequest.changes_count: ${pullRequestDetailed.changes_count} for repo: ${repo.name}, repoId: ${repo.repoId}, sourceBranch: ${sourceBranch}, targetBranch: ${targetBranch}, usedPullRequestId: ${usedPullRequestId}`,
        );
        return null;
      }

      const query = {
        url: `${this.host}/api/v4/projects/${repo.repoId}/merge_requests/${usedPullRequestId}/diffs`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          httpsAgent: new https.Agent({
            rejectUnauthorized: !this.shouldBypassCertChecks,
          }),
        },
      };

      const pages = Math.ceil(changesCount / perPage);

      const pullRequestFilesResponse: GitLab.CompareRequestDiff[] = await this.invokeRequest(query, repo.name, 100, perPage, {
        concurrency: 5,
        pages: pages,
      });

      const files = [
        ...new Set(
          pullRequestFilesResponse
            .filter(item => !item.deleted_file)
            .map(item => item.new_path)
            .filter(Boolean),
        ),
      ];

      return files;
    } catch (e) {
      logger.error(`[gitlab][findFilesModifiedInPullRequest] e: ${e}`);
      return null;
    }
  }

  async getOpenPullRequestForBranches(repoId: string, sourceBranch: string, targetBranch: string, repoName: string) {
    try {
      const query = {
        url: `${this.host}/api/v4/projects/${repoId}/merge_requests`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          params: {
            state: "opened",
            target_branch: targetBranch,
            source_branch: sourceBranch,
            httpsAgent: new https.Agent({
              rejectUnauthorized: !this.shouldBypassCertChecks,
            }),
          },
        },
        singleRequest: true,
      };

      const res: GitLab.MergeRequest[] = await this.invokeRequest(query, repoName, 1);
      if (!res || res.length === 0) return null;

      return res[0];
    } catch (e) {
      logger.error(`[gitlab][getOpenPullRequestForBranches] e: ${e}`);
      return null;
    }
  }

  async getPullRequestDetails(repoId: string, pullRequestId: string, repoName: string) {
    try {
      const query = {
        url: `${this.host}/api/v4/projects/${repoId}/merge_requests/${pullRequestId}`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          httpsAgent: new https.Agent({
            rejectUnauthorized: !this.shouldBypassCertChecks,
          }),
        },
        singleRequest: true,
      };

      const res: GitLab.MergeRequestDetailed[] = await this.invokeRequest(query, repoName, 1);
      if (!res) {
        logger.error(`[gitlab][getPullRequestDetails] pr with id: ${pullRequestId} not found`);
        return null;
      }

      return res[0];
    } catch (e) {
      logger.error(`[gitlab][getPullRequestDetails] e: ${e}`);
      return null;
    }
  }

  async pulls(repoObj: any): Promise<any> {
    let pullRequestList: PullRequest[] = [];
    const repo: Repo = repoObj.code_repo;
    const commits: Commit[] = repoObj.commits;

    try {
      const query = {
        url: `${this.host}/api/v4/projects/${repo.id}/merge_requests`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };

      const res = await this.invokeRequest(query, repo.name);

      for (const pullInfo of res) {
        try {
          if (pullInfo.merged_at == null || pullInfo.merged_at == undefined || pullInfo.state !== "merged") {
            continue;
          }

          let user = "";
          if (pullInfo?.author?.name) {
            user = pullInfo.author.name;
          }

          const uniqueReviewers = new Set();
          const reviewers: Reviewer[] = [];
          if (pullInfo.reviewers) {
            //in case of PR was assigned to / merged by other user
            if (pullInfo.reviewers.length === 0) {
              if (pullInfo.merge_user && pullInfo.merge_user.name != pullInfo.author.name) {
                const reviewer = new Reviewer(pullInfo.merge_user.name, pullInfo.merge_user.username, pullInfo.merge_user.id);
                reviewers.push(reviewer);
                uniqueReviewers.add(reviewer.author);
              }
              if (pullInfo.assignee && pullInfo.reviewers.length === 0 && pullInfo.assignee.name != pullInfo.author.name) {
                const reviewer = new Reviewer(pullInfo.assignee.name, pullInfo.assignee.username, pullInfo.assignee.id);
                reviewers.push(reviewer);
                uniqueReviewers.add(reviewer.author);
              }
            }
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

          const isMerged = pullInfo.state.toLowerCase() === "merged" ? true : false;

          const pullRequest: PullRequest = new PullRequest(
            pullInfo.created_at,
            pullInfo.web_url,
            pullInfo.description,
            pullInfo.sha,
            pullInfo.merged_at,
            pullInfo.title,
            reviewers.length,
            user,
            pullInfo.iid,
            CodeRepoTypes.pulls,
            reviewers,
            mergeUser,
            isMerged,
          );
          pullRequest.authorUserName = pullInfo.author.username;

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

  async pushedCommits(repoObj: any): Promise<any> {
    let pullRequestList: PullRequest[] = [];

    const repo: Repo = repoObj.code_repo;
    const commits: Commit[] = repoObj.commits;

    try {
      const query = {
        url: `${this.host}/api/v4/projects/${repo.id}/events`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          per_page: default_per_page_max_res,
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };

      const res = await this.invokeRequest(query, repo.name);

      for (const pullInfo of res) {
        try {
          if (pullInfo.push_data == undefined) {
            continue;
          }
          if (pullInfo.push_data.action != "pushed") {
            continue;
          }
          if (pullInfo.push_data.ref != repo.defaultBranch) {
            continue;
          }
          if (pullInfo.push_data.commit_title == null) {
            continue;
          }
          if (pullInfo.push_data.commit_title.startsWith("Merge branch ")) {
            continue;
          }
          const selfMergeUser = new MergeUser(pullInfo.author.name, pullInfo.author_username, pullInfo.author_id);

          let directCodePush = new PullRequest(
            pullInfo.created_at,
            repo.commitLink + pullInfo.push_data.commit_to,
            pullInfo.push_data.commit_title,
            pullInfo.push_data.commit_to,
            pullInfo.created_at,
            pullInfo.push_data.commit_title,
            0,
            pullInfo.author.name,
            "",
            CodeRepoTypes.pushedCommits,
            [],
            selfMergeUser,
            true,
          );

          directCodePush.authorUserName = pullInfo.author.username;

          this.getCommitRelatedToPullReq(repo, pullInfo, directCodePush, commits);

          if (directCodePush.pullsCommitInfo.length == 0) {
            continue;
          }

          this.updateMailInfo(directCodePush);
          pullRequestList.push(directCodePush);
        } catch (err) {
          logger.error(`failed to create pushed code obj, err: ${err},  for: ${repo.name}, push: ${JSON.stringify(pullInfo, null, 4)}`);
          StatesHelper.Instance.addFailedTool(repoResourceType.pushedCommits, repo.id);
        }
      }
      this.globalCodeRepoData.addPulls(pullRequestList, repo);
    } catch (err) {
      logger.error(`get pushed code failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.pushedCommits, repo.id);
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
      if (pullInfo?.sha) {
        res.push({ id: pullInfo?.sha });
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

  async branches(repo: Repo): Promise<any> {
    let branchList: Branch[] = [];

    try {
      const query = {
        url: `${this.host}/api/v4/projects/${repo.id}/repository/branches`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };

      const res = await this.invokeRequest(query, repo.name);
      for (const branchInfo of res) {
        try {
          let branch = new Branch(branchInfo.name);

          branchList.push(branch);
        } catch (err) {
          logger.error(`failed to create branch obj for: ${repo.name}, branch: ${JSON.stringify(branchInfo, null, 4)}, err: ${err}`);
          StatesHelper.Instance.addFailedTool(repoResourceType.branches, repo.id);
        }
      }
    } catch (err) {
      logger.error(`get branches failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.branches, repo.id);
    }
    return branchList;
  }

  async branchSettings(repoObj: any) {
    const repo: Repo = repoObj.code_repo;

    let MRWithoutReviewEnabled = false;
    let pushEventsEnabled = false;
    let forceDeleteAllowed = false;
    let branchProtection = true;
    let requiredSignedCommits = false;
    let restrictions = [];
    let enforceAdmins = false;
    let dissmisalRestrictions = {};
    let bypassPullReqAllowances = [];
    let pushAccessLevel = PushRole.NONE;

    try {
      const approvalRulesQuery = {
        url: `${this.host}/api/v4/projects/${repo.id}/approval_rules`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
        singleRequest: true,
      };

      const pushRuleQuery = {
        url: `${this.host}/api/v4/projects/${repo.id}/push_rule`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
        singleRequest: true,
      };

      const mainBranchQuery = {
        url: `${this.host}/api/v4/projects/${repo.id}/protected_branches/${repo.defaultBranch}`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
        singleRequest: true,
      };

      const userMap = new Map<string, User>();

      repoObj.users.forEach(user => {
        userMap.set(user.id, user);
      });

      const mainRules = [];
      let mainBranchProtected;

      const approvalRules = await this.invokeRequest(approvalRulesQuery, repo.name);
      const pushRules = await this.invokeRequest(pushRuleQuery, repo.name);
      const mainBranchRes = await this.invokeRequest(mainBranchQuery, repo.name);

      if (mainBranchRes) {
        mainBranchProtected = mainBranchRes[0];
      }

      let pushRule;

      if (pushRules) {
        pushRule = pushRules[0];
      }

      approvalRules.forEach(rule => {
        // in case the rule apply for all branches (include unprotected)
        if (rule.protected_branches.length === 0) {
          mainRules.push(rule);
        } else {
          for (const branch of rule.protected_branches) {
            if (branch.name === repo.defaultBranch) {
              mainRules.push(rule);
            }
          }
        }
      });

      if (pushRule) {
        if (pushRule.hasOwnProperty("reject_unsigned_commits")) {
          // logger.error('found push rule porperty: reject_unsigned_commits')
          if (pushRule.reject_unsigned_commits) {
            requiredSignedCommits = true;
          }
        }
      }

      // in case default branch is not protected
      if (!mainBranchProtected) {
        branchProtection = false;
        pushEventsEnabled = true;
        forceDeleteAllowed = true;
      } else {
        if (mainBranchProtected.hasOwnProperty("push_access_levels")) {
          // logger.error('found main branch porperty: push_access_levelss')
          pushAccessLevel = this.getPushAccessLevel(mainBranchProtected);
          const restrictedUsers = this.findRestrictedUsers(mainBranchProtected, userMap);

          restrictedUsers.forEach(user => {
            restrictions.push(userMap.get(user.user_id));
          });

          bypassPullReqAllowances = restrictions;

          // in case push is allowed
          if (pushAccessLevel != PushRole.NONE || restrictions.length > 0) {
            pushEventsEnabled = true;

            // no one can push, and there are no restrictions
          } else {
            enforceAdmins = true;
          }
        }
      }

      // in case there aren't any approval rules for default branch
      if (mainRules.length == 0) {
        MRWithoutReviewEnabled = true;
      } else {
        for (const rule of mainRules) {
          MRWithoutReviewEnabled = true;
          if (rule?.hasOwnProperty("approvals_required")) {
            // logger.error('found rule porperty: approvals_required')
            if (rule.approvals_required > 0) {
              MRWithoutReviewEnabled = false;
              break;
            }
          }
        }
      }

      const settings = new BranchSettings(
        pushEventsEnabled,
        MRWithoutReviewEnabled,
        forceDeleteAllowed,
        requiredSignedCommits,
        restrictions,
        enforceAdmins,
        dissmisalRestrictions,
        bypassPullReqAllowances,
        branchProtection,
      );

      settings.pushRole = pushAccessLevel;

      const res = isPolicyMainBranchDoesntRequireCodeReviewViolation(settings);
      if (res) {
        StatesHelper.Instance.reposMainBranchDoesntRequireCodeReviewViolationCount++;
      } else {
        StatesHelper.Instance.noReposMainBranchDoesntRequireCodeReviewViolationCount++;
      }

      return settings;
    } catch (err) {
      logger.error(`failed get repo: ${repo.name} branch settings, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.branchSettings, repo.id);
    }
  }

  findRestrictedUsers(branch: any, userMap: Map<string, User>) {
    try {
      let restrictedUsers = [];
      const pushAccessLevels = branch.push_access_levels.filter(i => i.user_id == null);

      if (pushAccessLevels.length > 0) {
        const accesLevel = this.getPushAccessLevel(branch);

        if (accesLevel === PushRole.NONE) {
          restrictedUsers = branch.push_access_levels.filter(i => i.user_id != null);

          return restrictedUsers;
        }

        if (accesLevel === PushRole.DEVELOPER) {
          return [];
        }

        // only maintainers/owners can push except restricted users
        restrictedUsers = branch.push_access_levels.filter(i => i.user_id != null && userMap.get(i.user_id).role == UserRole.DEVELOPER);
      }

      // no one can push except restricted users
      else {
        restrictedUsers = branch.push_access_levels.filter(i => i.user_id != null);
      }

      return restrictedUsers;
    } catch (err) {
      logger.error(`failed get restricted users of rule: ${branch.id}, err: ${err}`);
    }
  }

  getPushAccessLevel(branch: any) {
    let accesLevel;

    try {
      const pushAccessLevels = branch.push_access_levels.filter(i => i.user_id == null);
      if (pushAccessLevels.length > 0) {
        accesLevel = pushAccessLevels[0];

        for (const pushAccesLevel of pushAccessLevels) {
          if (pushRoles.get(pushAccesLevel.access_level) == PushRole.NONE) {
            accesLevel = pushAccesLevel;
            break;
          }
          if (pushRoles.get(pushAccesLevel.access_level) == PushRole.DEVELOPER) {
            return PushRole.DEVELOPER;
          }
          accesLevel = pushAccesLevel;
        }
      }
      if (accesLevel) {
        return pushRoles.get(accesLevel.access_level);
      }
      return PushRole.NONE;
    } catch (err) {
      logger.error(`failed get push access level for branch: ${branch.id}, err: ${err}`);
    }
  }

  async auditLog(): Promise<any> {
    try {
      logger.info(`try parse audit logs`);
      const startTime = new Date().getTime();
      await Promise.all([this.auditLogByGroup()]);
      let elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));
      StatesHelper.Instance.scanInfoStats.audiLogTime = elapsedTime;
      logger.info(`finish parse audit logs, audit logs count: ${StatesHelper.Instance.scanInfoStats.auditLogsCount}`);
    } catch (err) {
      logger.error(`get audit all logs failed, err: ${err}`);
    }
  }

  async getGroups() {
    const query = {
      url: `${this.host}/api/v4/groups`,
      params: {
        timeout: 30000,
        headers: this.getTokenHeader(),
        page: 1,
        per_page: default_per_page_max_res,
        httpsAgent: new https.Agent({
          rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
        }),
      },
    };
    const res = await this.invokeRequest(query, "getGroups_global", 10);
    // save orgs
    const orgsFromRes = res.filter(i => i.parent_id === null);
    for (const org of orgsFromRes) {
      let orgObj = new Organization(org.name, org.id, null, null);
      if (this.orgs.filter(i => i.name == org.name).length == 0) {
        this.orgs.push(orgObj);
      }
    }

    return res;
  }

  async allUsers(reposObj: any) {
    await this.getGroups();
    for (const org of this.orgs) {
      try {
        const query = {
          // url: `${this.host}/api/v4/groups/60583029/provisioned_users`,
          url: `${this.host}/api/v4/groups/${org.id}/members`,
          params: {
            timeout: 30000,
            headers: this.getTokenHeader(),
            page: 1,
            per_page: default_per_page_max_res,
            httpsAgent: new https.Agent({
              rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
            }),
          },
        };
        const res = await this.invokeRequest(query, `${org.name}_org`);

        for (const user of res) {
          if (user.active == false) {
            continue;
          }

          const role = roles.get(user.access_level) || UserRole.NO_ACCESS;

          const userInfo = new User(user.name, user.username, user.id, user.avatar_url, user.expires_at, user.created_at);
          userInfo.createdAtDays = timeHelper.getTimeIntervalFronNowInDays(user.created_at);
          userInfo.orgRole = new Set();
          userInfo.orgRole.add(role);
          userInfo.org = org.name;
          // users.push(userInfo);
          GlobalCodeRepoData.Instance.addUser(userInfo, repoType.gitlab);
          // await Promise.all(res.map((i) => this.check2fa(i)));
        }
        const orgWithPrefix = `${repoType.gitlab}_${org.name}`;
        GlobalCodeRepoData.Instance.updateOrgCollaborators(orgWithPrefix);
      } catch (err) {
        logger.error(`failed get members of group ${org.id}, err: ${err}`);
        StatesHelper.Instance.globalApisFails.add(resourceType.allUsers);
      }
    }
  }

  async auditLogByGroup() {
    try {
      const groups = await this.getGroups();
      const orgs = this.orgs;
      for (const org of orgs) {
        await this.auditByOrgGroups(org);
      }
    } catch (err) {
      logger.error(`failed get audit all logs for all group, err: ${err}`);
    }
  }
  async auditByOrgGroups(org) {
    try {
      const query = {
        url: `${this.host}/api/v4/groups/${org.id}/descendant_groups`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          page: 1,
          per_page: default_per_page_max_res,
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };
      const res = await this.invokeRequest(query, `${org.name}_org`);
      const p1 = res.map(i => this.auditLogBySingleGroup(i, org));
      const p2 = res.map(i => this.ProjectsAuditLog(i, org));
      await Promise.all(p1);
      await Promise.all(p2);
    } catch (err) {
      logger.error(`failed get audit logs of org ${org.id}: ${err}`);
    }
  }

  async auditLogBySingleGroup(group, org) {
    try {
      const query = {
        url: `${this.host}/api/v4/groups/${group.id}/audit_events`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          page: 1,
          per_page: default_per_page_max_res,
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };

      const res = await this.invokeRequest(query, `${org.name}_org`);
      for (const logInfo of res) {
        this.processAuditEvent(logInfo, org, false);
      }
    } catch (err) {
      logger.error(`failed get audit all logs for single group, err: ${err}`);
    }
  }

  async processAuditEvent(logInfo, org, isRepo: boolean) {
    try {
      StatesHelper.Instance.scanInfoStats.auditLogsCount++;

      StatesHelper.Instance.orgsWithAuditLogs.add(org.name);
      const details = logInfo.details;
      const userAuditLog: UserAuditLog = new UserAuditLog();

      userAuditLog.action = details.add;
      userAuditLog.ip_address = details.ip_address;
      if (details.ip_address != undefined) {
        const location = await this.geoLocationHelper.findCountryByIP(details.ip_address);
        if (location) {
          userAuditLog.actorLocation = location;
        }
      }
      userAuditLog.name = details.author_name
        ? details.author_name
        : //
          logInfo.runner_name;
      //
      if (details.add) {
        userAuditLog.action = `add_${details.add}`;
        if (details.add === "user_access") {
          userAuditLog.actionInfo = `Add ${details.add} of ${details.as} to ${details.target_details} in ${details.entity_path}`;
        } else {
          userAuditLog.actionInfo = `Add ${details.add}: ${details.target_details}`;
        }
      }
      if (details.change) {
        userAuditLog.action = `change_${details.change}`;
        if (details.from == "") {
          details.from = `None`;
        }
        if (details.to == "") {
          details.to = `None`;
        }
        userAuditLog.actionInfo = `Change ${details.change} of ${details.target_details} from ${details.from} to ${details.to}`;
      }

      if (details.remove) {
        userAuditLog.action = `remove_${details.remove}`;
        userAuditLog.actionInfo = `Remove ${details.remove} of ${details.target_details} in ${details.entity_path}`;
      }

      if (!userAuditLog.action && details.custom_message) {
        userAuditLog.action = details.custom_message;
      }

      if (!userAuditLog.action) {
        userAuditLog.action = "AuditLog";
      }
      userAuditLog.actionFriendly = userAuditLog.action;
      userAuditLog.actionFriendly = userAuditLog.action.replaceAll("_", " ");
      userAuditLog.actionFriendly = userAuditLog.actionFriendly.replaceAll("\\.", " ");
      userAuditLog.timestamp = new Date(logInfo.created_at);
      userAuditLog.org = org.name;

      if (isRepo) {
        userAuditLog.isRepo = true;
        userAuditLog.repo = details.entity_path;
      } else {
        userAuditLog.isOrg = true;
      }
      const auditLogFilters = ["ci_", "Created Release", "Repository Download Started"];
      if (this.isAdminOperation(userAuditLog.action, auditLogFilters)) {
        if (!GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name]) {
          GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name] = [userAuditLog];
        } else {
          GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name].push(userAuditLog);
        }
      }
    } catch (err) {
      logger.error(`failed to get audit log: ${org.name}, logInfo: ${JSON.stringify(logInfo)}, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.auditLog);
    }
  }

  isAdminOperation(action: string, filters: any) {
    for (const filter of filters) {
      if (action.includes(filter)) {
        return false;
      }
    }
    return true;
  }

  async ProjectsAuditLog(group, org) {
    try {
      const query = {
        url: `${this.host}/api/v4/groups/${group.id}/projects`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          page: 10,
          per_page: default_per_page_max_res,
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };

      const res = await this.invokeRequest(query, `${org.name}_org`);
      await Promise.all(res.map(i => this.auditLogByProject(i, org)));
    } catch (err) {
      logger.error(`failed get projects for single group, err: ${err}`);
    }
  }

  async auditLogByProject(project: any, org: any) {
    try {
      const query = {
        url: `${this.host}/api/v4/projects/${project.id}/audit_events`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          page: 1,
          per_page: default_per_page_max_res,
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };
      const res = await this.invokeRequest(query, `${org.name}_org`);
      for (const logInfo of res) {
        this.processAuditEvent(logInfo, org, true);
      }
    } catch (err) {
      logger.error(`failed get audits for project ${project.id}, err: ${err}`);
    }
  }

  isReadWrite(permission) {
    if (permission >= 30) {
      return ["write", "read"];
    }
    return ["read"];
  }

  async securityEvents(repo: Repo) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return [];
      }

      if (
        StatesHelper.Instance.gitLabDependencyScanningEnable ||
        StatesHelper.Instance.gitlabSastEnable ||
        StatesHelper.Instance.gitlabSecretDetectionEnable ||
        isLocalDevelopment()
      ) {
        //No need to collect from api same alerts if this is delta
        if (repo.isDelta || repo.disable) {
          return [];
        }

        const p1 = this.getRepoSecurityIssues(repo);
        //const p2 = this.getRepoSecretScanningAlerts(repo);
        //const p3 = this.getRepoCodeScanningAlerts(repo);
        const p4 = this.getRepoDependabotAlerts(repo);

        const res = await Promise.all([p1, p4]);
        const flatten = res.flat();
        return flatten;
      }
    } catch (err) {
      logger.error(`get security alerts failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.securityEvents, repo.id);
    }
    return [];
  }

  async getRepoSecurityIssues(repo: Repo) {
    let securityEventList: SecurityEvent[] = [];
    let failedCollect = 0;
    let sca = 0;
    let sast = 0;
    let secrets = 0;
    const otherTypes = new Set();

    try {
      const query = {
        url: `${this.host}/api/v4/projects/${repo.id}/vulnerability_findings`,
        params: {
          timeout: 30000,
          headers: { "private-token": this.private_token },
        },
      };

      const res: any = await this.invokeRequest(query, repo.name);

      for (const securityIssue of res) {
        try {
          if (securityIssue?.false_positive) {
            continue;
          }

          const scannerName = capitalizeFirstLetter(securityIssue.scanner.name);

          const issusName = securityIssue.name;
          let type = securityIssue.report_type;
          if (issusName && scannerName.toLowerCase() === "semgrep") {
            if (
              issusName.toLowerCase().includes(" password") ||
              issusName.toLowerCase().includes(" secret") ||
              issusName.toLowerCase().includes(" hardcoded")
            ) {
              type = "secret_detection";
            }
          }

          if (type === "sast" && StatesHelper.Instance.gitlabSastEnable) {
            let fileName = "";
            if (securityIssue?.location?.file) {
              fileName = securityIssue?.location?.file;
            }

            let violationInfo = securityIssue.description;
            let title = securityIssue.name;
            if (scannerName.toLowerCase() === "semgrep") {
              violationInfo = securityIssue.name;
              title = securityIssue.description;
            }

            const securityEvent = new SecurityEvent(
              `${Constant.gitlabSast} - ${scannerName}`,
              securityIssue.state === "detected",
              repo.fileLink + "/" + fileName + repo.linkFilePreffix + securityIssue.location.start_line,
              securityIssue.scan.start_time,
              "",
              "",
              "",
              violationInfo,
              title,
              fileName,
              securityIssue.severity,
              "",
              securityIssue.location.start_line,
              securityIssue.confidence,
              SecurityAlertType.sast,
              securityIssue.solution ? securityIssue.solution : ``,
              securityIssue.description_html,
              securityIssue.description_html,
              securityIssue.location.end_line,
              false,
              false,
              "",
              "",
              "",
              "",
              securityIssue.name,
              "",
              repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
              repo.fullName,
              repo.insideFolder,
              repo.monoRepoChild ? repo.name.substring(1) + "/" + fileName : fileName,
              "gitlab-sec-issues",
            );

            securityEvent.version = repo.defaultBranch;

            const cwes = securityIssue?.identifiers?.filter(item => item.external_type == "cwe");
            cwes?.forEach(i => {
              securityEvent.blame.cwe.push(i.name);
              const c = new CweObject();
              c.name = i.name;
              c.shortName = i.name;
              c.url = i.url;
              securityEvent.blame.cweList.push(c);
            });

            securityEvent.realMatch = securityIssue.uuid;
            securityEvent.collectedAsPartOfRepos = true;
            sast++;
            securityEventList.push(securityEvent);
          } else if (type == "dependency_scanning" && StatesHelper.Instance.gitLabDependencyScanningEnable) {
            let fileName = "";
            if (securityIssue?.location?.file) {
              fileName = securityIssue?.location?.file;
            }

            let securityEvent = new SecurityEvent(
              `${Constant.gitLabDependencyScanning} - ${scannerName}`,
              securityIssue.state === "detected",
              repo.fileLink + "/" + fileName + repo.linkFilePreffix + securityIssue.location.start_line,
              securityIssue.scan.start_time,
              "",
              "",
              "",
              securityIssue.description,
              securityIssue.name,
              fileName,
              securityIssue.severity,
              "",
              securityIssue.location.start_line,
              securityIssue.confidence,
              SecurityAlertType.sca,
              securityIssue.solution ? securityIssue.solution : ``,
              "",
              securityIssue.details.vulnerable_package.value,
              securityIssue.location.end_line,
              false,
              false,
              "",
              "",
              "",
              "",
              securityIssue.name,
              "",
              repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
              repo.fullName,
              repo.insideFolder,
              repo.monoRepoChild ? repo.name.substring(1) + "/" + fileName : fileName,
              "gitlab-dependency-scanning",
            );

            securityEvent.version = repo.defaultBranch;

            const cves = securityIssue.identifiers.filter(item => item.external_type == "cve");
            if (cves.length > 0) {
              const cve = cves[0];
              securityEvent.blame.cve = cve.external_id;
              securityEvent.cves.push(securityEvent.blame.cve);
            }

            securityEvent.pkgName = securityIssue.location.dependency.package.name;
            if ("Gemnasium-maven".toLowerCase() === scannerName.toLowerCase()) {
              if (securityEvent.pkgName.includes("/")) {
                securityEvent.pkgName = securityEvent.pkgName.replace("/", ":");
              }
            }
            securityEvent.installedVersion = securityIssue.location.dependency.version;

            if (securityIssue.solution && securityIssue.solution.toLowerCase().search("upgrade to version") > -1) {
              securityEvent.fixedVersion = securityIssue.solution.replace("Upgrade to versions", "").replace("Upgrade to version", "");
            }

            securityEvent.realMatch = `${securityEvent.pkgName}@${securityEvent.installedVersion}`;
            securityEvent.collectedAsPartOfRepos = true;
            sca++;
            securityEventList.push(securityEvent);
          } else if (type == "secret_detection" && StatesHelper.Instance.gitlabSecretDetectionEnable) {
            let fileName = "";
            if (securityIssue?.location?.file) {
              fileName = securityIssue?.location?.file;
            }

            let securityEvent = new SecurityEvent(
              `${Constant.gitlabSecretDetection} - ${scannerName}`,
              true,
              repo.fileLink + "/" + securityIssue.location.file + repo.linkFilePreffix + securityIssue.location.start_line,
              securityIssue?.scan?.created_at,
              "",
              "",
              "",
              securityIssue.description,
              securityIssue.description,
              securityIssue?.location?.file,
              securityIssue.severity,
              fileName,
              securityIssue?.location?.start_line,
              "high",
              SecurityAlertType.secrets,
              "",
              securityIssue.description_html,
              securityIssue.description_html,
              -1,
              false,
              false,
              "",
              "",
              "",
              "",
              securityIssue.name,
              "",
              repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
              repo.fullName,
              repo.insideFolder,
              repo.monoRepoChild ? repo.name.substring(1) + "/" + fileName : fileName,
              "gitlab-secret",
            );

            //Overwrite severity for secrets of public repos
            if (repo.privateVisability) {
              addSeverityChangedReason(severityReasons.secretInPrivateRepo, securityEvent, repo);
            } else {
              addSeverityChangedReason(severityReasons.secretInPublicRepo, securityEvent, repo);
            }

            securityEvent.version = repo.defaultBranch;
            securityEvent.realMatch = securityIssue.uuid;
            securityEvent.lineContent = securityEvent.lineContent.trim().replace(/\s+/g, " ");
            securityEvent.collectedAsPartOfRepos = true;
            secrets++;
            securityEventList.push(securityEvent);
          } else {
            otherTypes.add(securityIssue.scanner.name);
          }
        } catch (err) {
          StatesHelper.Instance.addFailedTool("gitlab-dependency-scanning", repo.id);
          StatesHelper.Instance.addFailedTool("gitlab-sec-issues", repo.id);
          StatesHelper.Instance.addFailedTool("gitlab-secret", repo.id);
          logger.error(`failed to create security issue obj for: ${repo.name}, data: ${JSON.stringify(alert, null, 4)}, err: ${err}`, err);
        }
      }
    } catch (err) {
      if (err.status != 403 && err.status != 404) {
        logger.debug(`get repo security issues failed repo: ${repo.name}, err: ${err}`);
      } else {
        failedCollect++;
        logger.error(`get repo security issues failed repo: ${repo.name}, err: ${err}`);
      }
      StatesHelper.Instance.addFailedTool("gitlab-dependency-scanning", repo.id);
      StatesHelper.Instance.addFailedTool("gitlab-sec-issues", repo.id);
      StatesHelper.Instance.addFailedTool("gitlab-secret", repo.id);
    }

    logger.info(
      `finish getRepoCodeScanningAlerts collect gitlab security events: ${
        securityEventList.length
      }, failedCollect: ${failedCollect}, counts secrets: ${secrets}, sca: ${sca}, sast: ${sast}, otherTypes: ${Array.from(otherTypes).join(
        ", ",
      )}`,
    );

    return securityEventList;
  }

  async getRepoCodeScanningAlerts(repo: Repo) {
    let securityEventList: SecurityEvent[] = [];
    let failedCollect = 0;
    let notOpen = 0;

    try {
      const query = {
        url: "GET /repos/{owner}/{repo}/code-scanning/alerts",
        parms: {
          owner: repo.ownerName,
          repo: repo.name,
          page: 1,
          per_page: default_per_page_max_res,
        },
      };

      const res = await this.invokeRequest(query, repo.name);

      for (const codeScanAlert of res) {
        try {
          if (codeScanAlert.state.toLowerCase() !== "open") {
            notOpen++;
            continue;
          }

          let securityEvent = new SecurityEvent(
            Constant.gitlabSecurityCenter,
            codeScanAlert.state.toLowerCase() === "open",
            codeScanAlert.html_url,
            codeScanAlert.created_at,
            codeScanAlert.dismissed_at,
            codeScanAlert.dismisser?.login,
            codeScanAlert.dismissed_reason,
            codeScanAlert?.rule?.description,
            codeScanAlert?.rule?.name,
            codeScanAlert.most_recent_instance?.location?.path,
            codeScanAlert.rule?.severity,
            "",
            -1,
            AlertSeverity[AlertSeverity.Unknown],
            SecurityAlertType.sast,
            "",
            "",
            "",
            0,
            false,
            false,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "gitlab-security-center",
            "",
          );

          securityEvent.version = repo.defaultBranch;
          securityEvent.collectedAsPartOfRepos = true;
          securityEventList.push(securityEvent);
        } catch (err) {
          failedCollect++;
          logger.error(`failed to create code scan obj for: ${repo.name}, data: ${JSON.stringify(codeScanAlert, null, 4)}, err: ${err}`);
        }
      }
    } catch (err) {
      if (err.status != 403 && err.status != 404) {
        logger.debug(`get repo code scan failed repo: ${repo.name}, err: ${err}`);
      } else logger.debug(`get repo code scan failed repo: ${repo.name}, err: ${err}`);
    }

    logger.info(
      `finish getRepoCodeScanningAlerts collect gitlab security events: ${securityEventList.length}, failedCollect: ${failedCollect}, notOpen: ${notOpen}`,
    );

    return securityEventList;
  }

  async getRepoDependabotAlerts(repo: Repo) {
    let securityEventList: SecurityEvent[] = [];

    try {
      const query = {
        url: `${this.host}/api/v4/projects/${repo.id}/dependencies`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
        },
      };

      const res: any = await this.invokeRequest(query, repo.name);

      for (const securityIssue of res) {
        if (securityIssue.vulnerabilities.length === 0) continue;

        try {
          let securityEvent = new SecurityEvent(
            `${Constant.gitlabSecurityCenter}`,
            true,
            securityIssue.vulnerabilities[0].url,
            Date(),
            "",
            "",
            "",
            "Vulnerable Dependency",
            securityIssue.name,
            securityIssue.dependency_file_path,
            securityIssue.vulnerabilities[0].severity,
            "",
            -1,
            AlertSeverity[AlertSeverity.Unknown],
            SecurityAlertType.sca,
            "",
            "",
            "",
            0,
            false,
            false,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "gitlab-security-center",
            "",
          );

          securityEvent.version = repo.defaultBranch;
          securityEvent.collectedAsPartOfRepos = true;
          securityEventList.push(securityEvent);
        } catch (err) {
          StatesHelper.Instance.addFailedTool("gitlab-security-center", repo.id);
          logger.error(`failed to create security issue obj for: ${repo.name}, data: ${JSON.stringify(alert, null, 4)}, err: ${err}`, err);
        }
      }
    } catch (err) {
      if (err.status != 403 && err.status != 404) {
        logger.debug(`get repo security issues failed repo: ${repo.name}, err: ${err}`);
      } else {
        logger.error(`get repo security issues failed repo: ${repo.name}, err: ${err}`);
      }
      StatesHelper.Instance.addFailedTool("gitlab-security-center", repo.id);
    }

    return securityEventList;
  }

  async getRepoSecretScanningAlerts(repo: Repo) {
    let securityEventList: SecurityEvent[] = [];

    try {
      const query = {
        url: "GET /repos/{owner}/{repo}/secret-scanning/alerts",
        parms: {
          owner: repo.ownerName,
          repo: repo.name,
          page: 1,
          per_page: default_per_page_max_res,
        },
      };

      const res = await this.invokeRequest(query, repo.name);

      for (const alert of res) {
        try {
          let securityEvent = new SecurityEvent(
            Constant.gitlabSecurityCenter,
            alert.state.toLowerCase() === "open",
            alert.html_url,
            alert.created_at,
            alert.resolved_at,
            alert.resolved_by?.login,
            alert.resolution?.description,
            "",
            "Secret " + alert.secret_type + " detected",
            "",
            "",
            "",
            -1,
            AlertSeverity[AlertSeverity.Unknown],
            SecurityAlertType.secrets,
            "",
            "",
            "",
            0,
            false,
            false,
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            "gitlab-security-center",
            "",
          );

          securityEvent.version = repo.defaultBranch;
          securityEvent.collectedAsPartOfRepos = true;
          securityEventList.push(securityEvent);
        } catch (err) {
          logger.error(`failed to create secret scan obj for: ${repo.name}, data: ${JSON.stringify(alert, null, 4)}, err: ${err}`);
          StatesHelper.Instance.addFailedTool("gitlab-security-center", repo.id);
        }
      }
    } catch (err) {
      if (err.status != 404) {
        logger.error(`get repo secret scan failed repo: ${repo.name}, err: ${err}`);
      }
      logger.debug(`get repo secret scan failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool("gitlab-security-center", repo.id);
    }
    return securityEventList;
  }

  async users(repoObj: any) {
    let users: User[] = [];
    let repoName = "";

    try {
      const repo: Repo = repoObj.code_repo;
      let orgName = repo.organization;
      repoName = repo.fullName;
      const query = {
        url: `${this.host}/api/v4/projects/${repo.id}/members/all`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          page: 1,
          per_page: default_per_page_max_res,
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };
      const directUsersRes = await this.getDirectMembers(repo.id, repo.name);
      const allMembersRes = await this.invokeRequest(query, repo.name);
      const directMembers = this.proccessMembers(directUsersRes, false, orgName);
      const allMembers = this.proccessMembers(allMembersRes, true, orgName);
      const users = [];
      const usersFound = new Set();

      directMembers.forEach(i => {
        users.push(i);
        usersFound.add(i.id);
      });

      allMembers.forEach(i => {
        if (usersFound.has(i.id)) {
          return;
        }
        users.push(i);
      });

      users.forEach(i => {
        GlobalCodeRepoData.Instance.addUser(i, repoType.gitlab);
      });

      return users;
    } catch (err) {
      const repo: Repo = repoObj.code_repo;
      logger.error(`get users failed repo: ${repoName}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.users, repo.id);
    }
    return users;
  }

  proccessMembers(members: any, isInherited: boolean, orgName: string) {
    let users: User[] = [];
    for (const user of members) {
      if (user.state != "active") {
        continue;
      }

      const role = roles.get(user.access_level) || UserRole.NO_ACCESS;
      const userInfo = new User(user.name, user.username, user.id, user.avatar_url, user.expires_at, user.created_at);
      userInfo.isOwnerInherited = isInherited && role == UserRole.OWNER;
      userInfo.createdAtDays = timeHelper.getTimeIntervalFronNowInDays(user.created_at);
      userInfo.role = role;
      userInfo.orgRole.add(role);
      userInfo.repoRolesRaw.push(role);
      userInfo.org = orgName;
      userInfo.repoRoleName = role;
      //find if already exist
      const userExist = users.find(i => i.id === user.id);
      if (userExist) {
        const existDate = new Date(userExist.createdAt);
        const newDate = new Date(user.created_at);
        if (newDate < existDate) {
          users.push(userInfo);
        }
      } else {
        users.push(userInfo);
      }
    }
    return users;
  }

  async getDirectMembers(repoId: string, repoName: string) {
    try {
      const query = {
        url: `${this.host}/api/v4/projects/${repoId}/members`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          page: 1,
          per_page: default_per_page_max_res,
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };
      const res = await this.invokeRequest(query, repoName);
      return res;
    } catch (err) {
      logger.error(`failed get direct users of repo: ${repoId}, err: ${err}`);
    }
  }

  // @override method for idpToken support
  getTokenPassword(): string {
    return this.private_token.trim();
  }

  getCodeRepoId(application) {
    return application.id.toString();
  }

  async getCodeBaseLastCodeChange(application) {
    return new Date(application.last_activity_at);
  }
}

export default CodeRepoGitLab;
