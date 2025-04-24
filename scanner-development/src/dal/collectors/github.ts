//https://docs.github.com/en/rest/reference/repos
import { Octokit } from "@octokit/core";
import { OxTagTypes } from "@oxappsec/ox-consolidated-tags";
import * as OXGitHubApp from "@oxappsec/ox-github-app";
import { ApplicationManager } from "../../appmgr/AppManager";
import {
  AffiliationType,
  AlertSeverity,
  Branch,
  BranchSettings,
  CodeRepoTypes,
  Commit,
  CweObject,
  File,
  ForkedRepos as ForkedRepo,
  ForkedRepos,
  ForkReasons,
  GitHubRequest,
  MergeUser,
  OrgRoles,
  PipelineScanInfo,
  PullRequest,
  Repo,
  repoResourceType,
  repoType,
  resourceType,
  Reviewer,
  SecurityAlertType,
  SecurityEvent,
  setFileInfo,
  Topic,
  User,
  UserAuditLog,
  UserRole,
  Webhook,
  Workflow,
} from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { GitHub } from "../../entitis/connectorsSpecific/GitHubTypes";
import Constant from "../../entitis/constant";
import RepoImportanceCalcHelper from "../../helper/appPriority/repoImportanceCalcHelper";
import { capitalizeFirstLetter, checkObjectSize, getLanFromPkgManager } from "../../helper/commonUtils";
import { GithubHelper } from "../../helper/connectorsSpecific/githubHelper";
import { isDevelopment, isLocalDevelopment } from "../../helper/envUtils";
import GitHelper from "../../helper/gitHelper";
import {
  GitHubCredentials,
  GitHubCredentialsType,
  GITHUB_APP_INSTALLATION_TOKEN_REFRESH_INTERVAL,
  resolveGitHubCredentials,
} from "../../helper/github/credentials";
import { handleGithubRequest } from "../../helper/github/requests";
import VTHelper from "../../helper/policy/vtHelper";
import { RateLimitHelperFactory } from "../../helper/rateLimitHelper";
import { RedisHelper } from "../../helper/redis/redisHelper";
import RoleHelper from "../../helper/roleHelper";
import { cleanVer } from "../../helper/sbom/sbomHelper";
import { SettingsService } from "../../helper/service/scan-settings-service/service/settings-service";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import { CveToolsService } from "../../mongo/cve-tools.service";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import { isPolicyMainBranchDoesntRequireCodeReviewViolation } from "../../policy/rules/code/policyMainBranchDoesntRequireCodeReview";
import RulesManager from "../../policy/rules/ruleManager";
import CodeRepoBase from "../base/codeRepoBase";
import GlobalCodeRepoData from "../GolobalCollectorData/globalCodeRepoData";
import { GithubGraphQL } from "./github-graphql";
const fs = require("fs");
const { graphql } = require("@octokit/graphql");

const per_page_max_res = 100;
const max_pages = 5;
const retry_count = 4;
const timeout_to_wait_after_rate_limit_happen = 1000 * 60 * 3;
const logger = loggerImport.getDebugLogger();
const stringSimilarity = require("string-similarity");

export enum OrgWorkflowAPIResponse {
  ALL = "all",
  NONE = "none",
  SELECTED = "selected",
}

class CodeRepoGithub extends CodeRepoBase {
  octokit: Octokit;
  appMgr: ApplicationManager;
  credentials: GitHubCredentials;
  githubHelper: GithubHelper;
  timeHelper: TimeHelper;
  roleHelper: RoleHelper;
  graphQL: GithubGraphQL;
  userSelectedBranch: string = "";

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.credentials = resolveGitHubCredentials(token);

    this.initCredentialsRefresh();
    this.initGitHubApp();

    this.appMgr = new ApplicationManager(this.uuid);

    this.rateLimitHelper = RateLimitHelperFactory.getRateLimitHelperPerToken(this.token.name, 200);

    this.timeHelper = new TimeHelper("github");
    this.roleHelper = new RoleHelper("github");
  }

  async initLib() {
    logger.info(`try init lib for: ${this.token.name}, url: ${this.token.host}`);

    this.initGitHubAPI();

    this.githubHelper = new GithubHelper(per_page_max_res, this);
    const res = await this.githubHelper.getGithubRateLimitInfo();
    if (res) {
      this.rateLimitHelper.totalRequestAllowed = res.remaining;
      StatesHelper.Instance.numberOfAllowedRequests = res.remaining;
    }

    logger.info(
      `finish init lib for: ${this.token.name}, url: ${this.token.host}, total request allowed: ${this.rateLimitHelper.totalRequestAllowed}`,
    );
  }

  initGitHubAPI() {
    logger.info(`try init Octokit for: ${this.token.name}, url: ${this.token.host}`);

    this.octokit = new Octokit({
      auth: this.credentials.token,
      baseUrl: this.token.host ? this.token.host : null,
    });
    this.graphQL = new GithubGraphQL(this.credentials.token);
  }

  async initCredentialsRefresh() {
    if (!this.credentials) {
      logger.warn(`[initCredentialsRefresh] no credentials object initialized`);
      return;
    }
    // set interval only in case GitHubApp
    if (this.credentials.type !== GitHubCredentialsType.App) return;

    setInterval(async () => {
      // check to satisfy typechecking
      if (this.credentials.type !== GitHubCredentialsType.App) return;

      const installationToken = await OXGitHubApp.getInstallationToken(this.credentials.gitHubAppId, this.credentials.installationId);

      if (installationToken) this.credentials.token = installationToken.token;

      // re-init octokit and graphql lib since token changed
      this.initGitHubAPI();
    }, GITHUB_APP_INSTALLATION_TOKEN_REFRESH_INTERVAL);
  }

  async initGitHubApp() {
    if (!this.credentials) {
      logger.warn(`[initGitHubApp] no credentials object initialized`);
      return;
    }
    // set interval only in case GitHubApp
    if (this.credentials.type !== GitHubCredentialsType.App) return;

    const {
      GITHUB_APP_ID,
      GITHUB_APP_PRIVATE_KEY,
      GITHUB_APP_RO_ID,
      GITHUB_APP_RO_PRIVATE_KEY,
      GITHUB_APP_PRODUCTION_ID,
      GITHUB_APP_PRODUCTION_PRIVATE_KEY,
    } = process.env;

    const options = [
      {
        appId: GITHUB_APP_ID,
        privateKey: GITHUB_APP_PRIVATE_KEY,
      },
      {
        appId: GITHUB_APP_RO_ID,
        privateKey: GITHUB_APP_RO_PRIVATE_KEY,
      },
    ];

    // Gady/Yury
    const shouldInitProdGitHubApp =
      isDevelopment() &&
      GITHUB_APP_PRODUCTION_ID &&
      GITHUB_APP_PRODUCTION_PRIVATE_KEY &&
      this.credentials.gitHubAppId === GITHUB_APP_PRODUCTION_ID;

    if (shouldInitProdGitHubApp) {
      options.push({
        appId: GITHUB_APP_PRODUCTION_ID,
        privateKey: GITHUB_APP_PRODUCTION_PRIVATE_KEY,
      });
    }

    const appIds = options.map(o => o.appId);
    logger.info(`[github-app] initializing ${appIds.length} GitHub Apps: [${appIds}]`);

    OXGitHubApp.init(options);
  }

  createRepo(apiRepo, pipelineScanInfo: PipelineScanInfo): Repo {
    const r = new Repo(
      this.uuid,
      this.orgName,
      this.token.name,
      apiRepo.name,
      apiRepo.id.toString(),
      apiRepo.full_name,
      apiRepo.created_at,
      apiRepo.default_branch,
      apiRepo.description,
      apiRepo.disabled || apiRepo.archived,
      this.getCloneUrl(apiRepo),
      apiRepo.has_downloads,
      apiRepo.has_pages,
      apiRepo.has_wiki,
      apiRepo.has_issues,
      apiRepo.homepage,
      apiRepo.private,
      null,
      0,
      apiRepo.watchers_count,
      apiRepo.owner.login,
      apiRepo.html_url,
      apiRepo.forks_count,
      apiRepo.pushed_at,
      "",
      this.getFileLinkPrefix(apiRepo, pipelineScanInfo),
      "#L",
      0,
      apiRepo.html_url + "/settings",
      apiRepo.html_url + "/commit/",
      "",
      "",
      apiRepo.owner.login,
      apiRepo.id.toString(),
      this.isOrgRepo(apiRepo.owner),
      apiRepo.name,
      pipelineScanInfo,
      apiRepo.teams,
    );

    if (this.userSelectedBranch) {
      r.sourceBranch = this.userSelectedBranch;
    }

    // topics
    r.topics = apiRepo.topics.map(
      topic => new Topic(`${topic}_${r.name}`, OxTagTypes.simple, false, topic, topic, r.type, r.type, "topic", true),
    );

    // github secret scanning
    if (apiRepo.security_and_analysis) {
      r.securityAndAnalysis = apiRepo.security_and_analysis;
      r.isAdvancedSecurityEnabled = apiRepo.security_and_analysis.advanced_security?.status === "enabled";
      r.isSecretScanningEnabled = apiRepo.security_and_analysis.secret_scanning?.status === "enabled";
    }

    r.issueCount = apiRepo.open_issues_count;

    return r;
  }

  isOrgRepo(owner) {
    try {
      if (owner.type.toLowerCase() === "organization") {
        return true;
      }
    } catch (e) {
      logger.error(e, e);
    }
    return false;
  }

  async setRepo(apiRepo, repoObj) {
    try {
      const pipelineScanInfo = this.getPipelineScanInfo(apiRepo.id.toString(), apiRepo.full_name);

      let repo = this.createRepo(apiRepo, pipelineScanInfo);
      repo.allowForking = apiRepo.allow_forking;
      if (repo.allowForking == undefined) {
        repo.allowForking = false;
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

      repo.gitRoles = this.getGitRoles("github");

      const promise = await this.appMgr.CreateRepoNode({
        repo_name: apiRepo.full_name,
        repo_id: apiRepo.id.toString(),
        vcs_type: "github",
        url: apiRepo.html_url,
        default_branch: apiRepo.default_branch,
      });

      return repo;
    } catch (err) {
      logger.error(`failed to create repo obj for: ${JSON.stringify(apiRepo)}`, err);
    }
    return null;
  }

  getGitRoles(git) {
    try {
      return this.roleHelper.getGitRoles(git);
    } catch (e) {
      logger.error(`getGitRoles err`, e);
    }
    return {};
  }

  async isDependabotEnabled(repo: Repo) {
    try {
      const query = {
        url: "/repos/{owner}/{repo}/vulnerability-alerts",
        parms: {
          owner: repo.ownerNameApi,
          repo: repo.name,
        },
        singleRequest: true,
        throwErr: true,
      };

      repo.isDependabotEnabled = !!(await this.invokeRequest(query));
    } catch (e) {
      if (e?.response?.status === 404 && e?.response?.data?.message === "Vulnerability alerts are disabled.") {
        logger.info(`Vulnerability alerts are disabled (Dependabot) for repo ${repo.name}`);
      } else {
        logger.error(`failed to check if dependabot is enabled for repo ${repo.name}`, e);
      }
    }
  }

  async setRepoApiInfo(repo: Repo) {
    this.isDependabotEnabled(repo);

    try {
      for (const org of this.githubHelper.orgs) {
        if (org.workflowPermissions === null) {
          org.workflowPermissions = await this.getOrgWorkflowPermissions(org);
        }
      }

      const currentOrg = this.githubHelper.orgs.find(o => o.name === repo.organization);

      if (currentOrg) {
        // if GH ACTIONS disabled for all org, no need to check the repo.
        if (currentOrg.workflowPermissions?.enabled === false) {
          repo.workflowPermissions = false;
          return;
        }

        if (!currentOrg.workflowPermissions?.hasOwnProperty("enabled")) {
          // token doesnt have admin rights
        }
      }

      // if GH ACTIONS enabled for all org OR enabled for selected repos
      repo.workflowPermissions = await this.getRepoWorkflowPermissions(repo);

      // if GH ACTIONS is enabled for repo, we continue and check for specific setting
      if (!repo.workflowPermissions || repo.workflowPermissions?.enabled === false) {
        return;
      }

      // checking if GH ACTIONS is allowed to review PR
      repo.defaultWorkflowPermissions = await this.getDefaultRepoWorkflowPermissions(repo);

      // Setting repo teams
      if (!repo.organization || repo.organization === "") {
        repo.teams = [];
      } else {
        repo.teams = await this.getRepoTeams(repo.name, repo.organization);
      }
    } catch (e) {
      logger.error(`failed to setRepoApiInfo for: ${repo.fullName}`, e);
    }
  }

  async getOrgWorkflowPermissions(org) {
    try {
      const query = {
        url: "/orgs/{org}/actions/permissions",
        parms: {
          org: org.name,
        },
        singleRequest: true,
      };

      const res = await this.invokeRequest(query);

      if (!res.length) {
        return null;
      }

      if (res[0].enabled_repositories === OrgWorkflowAPIResponse.NONE) {
        // disabled - no need to check for specific repo
        return false;
      }

      if (res[0].enabled_repositories === OrgWorkflowAPIResponse.SELECTED || res[0].allowed_actions === OrgWorkflowAPIResponse.SELECTED) {
        // check if this repo is selected
        // check if this action is selected
      }

      if (res[0].enabled_repositories === OrgWorkflowAPIResponse.ALL) {
        const bp = "all enabled";
        // enabled - now lets check specific repo
      }

      return res[0];
    } catch (e) {
      logger.error(`getOrgWorkflowPermissions failed. org: ${org}`, e);
    }
  }

  async getRepoWorkflowPermissions(repo) {
    try {
      const query = {
        url: "GET /repos/{owner}/{repo}/actions/permissions",
        parms: {
          owner: repo.organization,
          repo: repo.name,
        },
        singleRequest: true,
      };

      const res = await this.invokeRequest(query);

      return res[0];
    } catch (e) {
      logger.error(`getRepoWorkflowPermissions failed`, e);
    }
  }

  async getDefaultRepoWorkflowPermissions(repo: Repo) {
    try {
      const query = {
        url: "GET /repos/{owner}/{repo}/actions/permissions/workflow",
        parms: {
          owner: repo.organization,
          repo: repo.name,
        },
        singleRequest: true,
      };

      const res = await this.invokeRequest(query, 5, repo);

      return res[0];
    } catch (e) {
      logger.error(`getDefaultRepoWorkflowPermissions failed`, e);
      StatesHelper.Instance.addFailedTool("min-permissions", repo.id);
    }
  }

  getAllOrgs() {
    return this.githubHelper.orgs;
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
      logger.error(`failed pare error, err: ${e}, original err: ${err}`, e);
    }
    return false;
  }

  getQueryNextPage(r: GitHubRequest, singleRes: any) {
    // checks not depending on `singleRes` param
    if (r.query.singleRequest) {
      if (r.query.singleRequest) return false;
    }
    if (!r?.query?.parms?.page) return false;
    if (r.query.parms.page > r.maxPage) return false;

    // "GET /installation/repositories" GitHub App query has queried repositories nested in the response.repositories
    if ("total_count" in singleRes && "repositories" in singleRes) {
      if (singleRes.repositories.length < per_page_max_res) return false;
    } else {
      if (!Array.isArray(singleRes)) return false;
      if (singleRes.length < per_page_max_res) return false;
    }

    r.query.parms.page++;
    return true;
  }

  async getTimeToWait() {
    return this.githubHelper.getTimeToWait(this.rateLimitHelper, timeout_to_wait_after_rate_limit_happen);
  }

  async invokeRequest(query: any, maxPage = max_pages, repo?: Repo) {
    const r: GitHubRequest = new GitHubRequest();
    r.query = query;
    r.maxPage = maxPage;

    const key = `${query.parms.repo ? `${query.parms.repo}_` : ""}${query.url.replace(/^(GET )?\//, "")}`;
    if (this.uniqueRequestAPIs.has(key)) {
      this.uniqueRequestAPIs.set(key, this.uniqueRequestAPIs.get(key) + 1);
    } else {
      this.uniqueRequestAPIs.set(key, 1);
    }

    const res = await this.rateLimitHelper.sendApiRequest(
      r.query.url,
      r,
      this.isRateLimitErrFunction,
      this.handleRequest.bind(this),
      this.getQueryNextPage,
      retry_count,
      this,
      r.query.throwErr,
      repo,
    );

    return res.flat();
  }

  async getAllRepos(callObj: RulesManager): Promise<Repo[]> {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        const repoId = this.getPipelineScanRepoId();
        if (repoId === null) return [];
        const repo = await this.githubHelper.getSingleRepositoryById(repoId);
        return repo === null ? [] : [repo];
      }

      logger.info(`try get all repos, token: ${this.token.name}`);

      let allRepos =
        this.credentials.type === GitHubCredentialsType.App
          ? await this.githubHelper.getAllInstallationRepos()
          : await this.githubHelper.getAllReposOfOrg();

      // let allRepos =
      //   this.credentials.type === GitHubCredentialsType.App
      //     ? await this.githubHelper.getAllInstallationRepos()
      //     : await this.githubHelper.getAuthenticatedRepos();

      //Retry;
      if (allRepos.length == 0) {
        logger.info(`retry getAuthenticatedRepos, token: ${this.token.name}`);
        allRepos = await this.githubHelper.getAuthenticatedRepos();
        logger.info(`after retry getAuthenticatedRepos, token: ${this.token.name}, allRepos: ${allRepos.length}`);
      }

      //On prem
      if ("https://api.github.com" !== this.token.host) {
        if (allRepos.length > 0) {
          StatesHelper.Instance.allReposOfGitlabOnPrem = allRepos;
        } else {
          if (StatesHelper.Instance.allReposOfGitlabOnPrem.length > 0) {
            allRepos = StatesHelper.Instance.allReposOfGitlabOnPrem;
            logger.info(`using allReposOfGitlabOnPrem: ${this.token.name}, allRepos: ${allRepos.length}`);
          }
        }
      }

      logger.info(`finish get all repos, token: ${this.token.name}, allRepos: ${allRepos.length}`);

      const monitoredBeforeBranch = allRepos.filter(apiRepo =>
        this.repoSelectedByUser(apiRepo.id.toString(), apiRepo.full_name, apiRepo.created_at),
      );

      let monitored = monitoredBeforeBranch;
      this.userSelectedBranch = SettingsService.Instance.defineBranch(this.token.name);
      if (this.userSelectedBranch) {
        logger.info(`customer chose a specific branch for ${this.token.name} repos: ${this.userSelectedBranch}`);
        monitored = await this.getReposWithSelectedBranch(monitoredBeforeBranch, this.userSelectedBranch);
      } else {
        logger.info(`customer didn't chose a specific branch for ${this.token.name} repos`);
      }

      logger.info(
        `finish get all repos after filter, token: ${this.token.name}, monitored: ${monitored.length}, allRepos: ${allRepos.length}`,
      );

      return monitored;
    } catch (err) {
      logger.error(`failed to get repos list obj for: ${this.token.type}`, err);
    }
    return [];
  }

  getFileLinkPrefix(repo, pipelineScanInfo: PipelineScanInfo) {
    try {
      const res = [repo.html_url, "blob", pipelineScanInfo.sourceBranch ?? repo.default_branch, ""].join("/");

      return res;
    } catch (err) {
      logger.error(`get file link repo name: ${repo.name}`, err);
    }
    return "";
  }

  getCloneUrl(repo) {
    let cred = `//${repo.owner.login}:${this.getTokenPassword()}@`;
    if (this.token.globalRepositories) {
      repo.clone_url = `${repo.html_url}.git`;
    }
    const pos = repo.clone_url.indexOf("//");
    let strBeforeSlash = repo.clone_url.substring(0, pos);
    let strAfterSlash = repo.clone_url.substring(pos + "//".length);
    const res = strBeforeSlash + cred + strAfterSlash;
    return res;
  }

  async getMembers(org: string, roleFilter: string = "", type: OrgRoles = undefined, filter: string = "") {
    const members = [];

    try {
      const query = {
        url: "GET /orgs/{org}/members",
        parms: {
          org: org,
          page: 1,
          filter: filter,
          per_page: per_page_max_res,
          role: roleFilter,
        },
      };

      const res = await this.invokeRequest(query, 10);
      for (const user of res) {
        const newUser = new User(
          user.name == null || user.name == undefined ? user.login : user.name,
          user.login,
          user.id,
          user.avatar_url,
          "",
          user.created_at,
          user.role,
        );

        //In this case org role can be any type including to the inout
        //But there are not repo owner in this stage
        if (type) {
          newUser.orgRole.add(type);
        }
        if (filter) {
          newUser.twoFactorEnabled = filter === "2fa_disabled" ? false : true;
        }
        newUser.htmlLink = user.html_url;
        newUser.org = org;

        this.globalCodeRepoData.addUser(newUser, repoType.github);
      }
    } catch (err) {
      logger.error(`failed to get members, type: ${type}`, err);
    }
    return members;
  }

  async getOutsideCollaborators(org: string, filter: string = "") {
    try {
      const query = {
        url: "/orgs/{org}/outside_collaborators",
        parms: {
          org: org,
          page: 1,
          per_page: per_page_max_res,
          filter: filter,
        },
      };

      const res = await this.invokeRequest(query, 10);
      for (const user of res) {
        const newUser = new User(
          user.name == null || user.name == undefined ? user.login : user.name,
          user.login,
          user.id,
          user.avatar_url,
          "",
          user.created_at,
          user.role,
        );

        newUser.affiliation.add(AffiliationType.outside);
        newUser.htmlLink = user.html_url;
        newUser.orgRole.add(OrgRoles.COLLABORATORS);
        newUser.twoFactorEnabled = filter === "2fa_disabled" ? false : true;

        newUser.org = org;

        this.globalCodeRepoData.addUser(newUser, repoType.github);
      }
    } catch (err) {
      logger.error(`failed to get members, type: ${filter}`, err);
    }
  }

  getCVE(alert: any, repo: Repo) {
    try {
      const data = alert?.securityVulnerability?.advisory?.identifiers;
      if (!data) {
        return "Generic";
      }
      const cveExist = data.find(i => i.type === "CVE");
      if (cveExist) {
        return cveExist.value;
      }
      data[0].value;
    } catch (err) {
      logger.error(`failed getCVE, repo: ${repo.fullName}`, err);
    }
  }

  setDependabotEvent(alert: any, repo: Repo, securityEventList: SecurityEvent[]) {
    if (alert?.state?.toLowerCase() == "open") {
      try {
        let cve = this.getCVE(alert, repo);
        if (!cve) {
          cve = "Generic";
        }

        const securityEvent = new SecurityEvent(
          `GitHub - ${Constant.Dependabot}`,
          true,
          repo.fileLink + "/" + alert.vulnerableManifestPath,
          alert.createdAt,
          alert.dismissedAt == null ? "" : alert.dismissedAt,
          alert.dismissReason == null ? "" : alert.dismissReason,
          "",
          alert.securityVulnerability.advisory.summary,
          alert.securityVulnerability.advisory.description,
          alert.vulnerableManifestPath,
          alert.securityVulnerability.severity,
          `Rule name: ${cve}`,
          -1,
          AlertSeverity[AlertSeverity.High],
          SecurityAlertType.sca,
          "",
          "",
          "",
          -1,
          false,
          false,
          "",
          "",
          "",
          "",
          cve,
          "",
          repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
          repo.fullName,
          repo.insideFolder,
          repo.monoRepoChild ? repo.name.substring(1) + "/" + alert.vulnerableManifestPath : alert.vulnerableManifestPath,
          "dependabot",
        );

        securityEvent.installedVersion = cleanVer(alert.vulnerableRequirements, repo.fullName);

        securityEvent.version = repo.defaultBranch;
        securityEvent.pkgManager = alert.securityVulnerability.package.ecosystem;
        if (securityEvent.pkgManager) {
          securityEvent.language = getLanFromPkgManager(securityEvent.pkgManager).toLowerCase();
          securityEvent.language = capitalizeFirstLetter(securityEvent.language);
        }
        if (alert?.securityVulnerability?.firstPatchedVersion?.identifier) {
          securityEvent.fixedVersion = alert?.securityVulnerability?.firstPatchedVersion?.identifier;
          if (securityEvent.installedVersion === securityEvent.fixedVersion) {
            securityEvent.fixedVersion = "";
          }
        }

        if (alert.securityVulnerability.advisory.cwes?.nodes) {
          for (const cwe of alert.securityVulnerability.advisory.cwes.nodes) {
            const cweObject: CweObject = new CweObject();
            cweObject.name = cwe.name;
            cweObject.shortName = cwe.name;
            cweObject.description = cwe.description;
            securityEvent.blame.cwe.push(cwe.cweId);
            securityEvent.blame.cweList.push(cweObject);
          }
        }

        if (alert?.securityVulnerability.advisory?.cvss?.score) {
          securityEvent.blame.cvssScore = alert?.securityVulnerability.advisory?.cvss?.score;
        }
        securityEvent.blame.cveDescription = alert?.securityVulnerability.advisory?.description;

        securityEvent.pkgName = alert.securityVulnerability.package.name;
        securityEvent.lineContent = securityEvent.pkgName;
        securityEvent.blame.cve = alert?.securityVulnerability?.advisory.cve_id;
        if (!securityEvent.blame.cve) {
          if (alert?.securityVulnerability?.advisory?.identifiers) {
            const cve = alert?.securityVulnerability?.advisory?.identifiers.find(i => i.type === "CVE");
            if (cve) {
              securityEvent.blame.cve = cve.value;
              securityEvent.ruleId = cve.value;
            } else {
              if (Array.isArray(alert?.securityVulnerability?.advisory.identifiers)) {
                if (alert?.securityVulnerability?.advisory.identifiers.length > 0) {
                  securityEvent.blame.cve = alert?.securityVulnerability?.advisory.identifiers[0].value;
                  securityEvent.ruleId = securityEvent.blame.cve;
                }
              }
            }
          }
        }

        if (securityEvent.blame.cve) {
          securityEvent.cves.push(securityEvent.blame.cve);
        }

        securityEvent.linkToExternalProduct = `${repo.link}/security/dependabot/${alert.number}`;
        securityEvent.realMatch = `${securityEvent.pkgName}@${securityEvent.installedVersion}`;

        if (!securityEvent.realMatch) {
          logger.error(`failed add dependabot Security Event for repo: ${repo.name}, no match`);
          return;
        }

        securityEvent.collectedAsPartOfRepos = true;

        securityEventList.push(securityEvent);
      } catch (err) {
        logger.error(`dependabot - Error in set SecurityEvent for ${repo.name} : Item - ${alert.number}`, err);
      }
    }
  }

  async securityEvents(repo: Repo) {
    const securityEventList: SecurityEvent[] = [];
    try {
      //No need to collect from api same alerts if this is delta
      if (repo.disable || repo.isDelta) {
        return [];
      }
      if (StatesHelper.Instance.isPipelineScan) {
        return [];
      }

      //await this.getRepoSecurityIssues(repo, securityEventList);
      await this.getRepoSecretScanningAlerts(repo, securityEventList);
      await this.getRepoCodeScanningAlerts(repo, securityEventList);
      await this.getRepoDependabotAlerts(repo, securityEventList);

      if (!repo.noneRelevantRepo || repo.markedAsRelevant) {
        securityEventList.forEach(secEvent => CveToolsService.instance.addToCveTools(secEvent.repoFullName, secEvent));
      }

      return securityEventList;
    } catch (err) {
      logger.error(`get security alerts failed repo: ${repo.name}`, err);
      StatesHelper.Instance.addFailedTool(repoResourceType.securityEvents, repo.id);
    }
    return [];
  }

  async getRepoDependabotAlerts(repo: Repo, securityEventList: SecurityEvent[]) {
    try {
      const shouldRun = StatesHelper.Instance.dependabotEnable || isLocalDevelopment();
      if (!shouldRun) {
        return;
      }

      const res = await this.graphQL.getAlerts({
        owner: repo.ownerNameApi,
        repository: repo.name,
      });

      for (const alert of res) {
        try {
          this.setDependabotEvent(alert, repo, securityEventList);
        } catch (err) {
          logger.error(`failed to create dependabot obj for: ${repo.name}`, err);
        }
      }

      logger.info(`getRepoDependabotAlerts repo: ${repo.name}, info: ${res?.length}`);
    } catch (err) {
      logger.error(`failed getRepoDependabotAlerts for: ${repo.name}`, err);
    }
  }

  async getRepoSecretScanningAlerts(repo: Repo, securityEventList: SecurityEvent[]) {
    let count = 0;
    try {
      const shouldRun = StatesHelper.Instance.githubSecretDetectionEnable || isLocalDevelopment();
      if (!shouldRun) {
        return;
      }

      const query = {
        url: "GET /repos/{owner}/{repo}/secret-scanning/alerts?state=open",
        parms: {
          owner: repo.ownerName,
          repo: repo.name,
          page: 1,
          per_page: per_page_max_res,
        },
      };

      const res = await this.invokeRequest(query, 10);

      for (const alert of res) {
        try {
          const querySecretInfo = {
            url: "GET /repos/{owner}/{repo}/secret-scanning/alerts/{alert_number}/locations",
            parms: {
              owner: repo.ownerName,
              repo: repo.name,
              alert_number: alert.number,
            },
            singleRequest: true,
          };
          const resSecretInfo = await this.invokeRequest(querySecretInfo);

          const lineNumber = resSecretInfo?.length > 0 ? resSecretInfo[0].details.start_line : -1;
          const filePath = resSecretInfo?.length > 0 ? resSecretInfo[0].details.path : "";

          const securityEvent = new SecurityEvent(
            Constant.githubSecretsDetection,
            true,
            repo.fileLink + "/" + filePath + repo.linkFilePreffix + lineNumber,
            alert.created_at,
            "",
            "",
            "",
            alert.secret_type_display_name,
            alert.secret_type_display_name,
            filePath,
            "high",
            "",
            lineNumber,
            AlertSeverity[AlertSeverity.High],
            SecurityAlertType.secrets,
            "",
            alert.secret,
            alert.secret,
            -1,
            false,
            false,
            "",
            "",
            "",
            "",
            alert.secret_type,
            "",
            repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
            repo.fullName,
            repo.insideFolder,
            repo.monoRepoChild ? repo.name.substring(1) + "/" + alert.vulnerableManifestPath : alert.vulnerableManifestPath,
            "dependabot",
          );

          securityEvent.version = repo.defaultBranch;
          securityEvent.linkToExternalProduct = alert.html_url;
          securityEvent.filePath = filePath;
          securityEvent.realMatch = securityEvent.lineContent;
          securityEvent.collectedAsPartOfRepos = true;

          securityEventList.push(securityEvent);
          count++;

          if (StatesHelper.Instance.orgName === "org_dorAnqmk8zLcBYRw") {
            logger.info(`found secret in github secrets for: ${repo.name}, item: ${JSON.stringify(alert)}`);
          }
        } catch (err) {
          logger.error(`failed to create secret scan obj for: ${repo.name}`, err);
        }
      }

      logger.info(`getRepoSecretScanningAlerts repo: ${repo.name}, info: ${res?.length}`);
    } catch (err) {
      if (err.status != 404) {
        logger.error(`get repo secret scan failed repo: ${repo.name}`, err);
      } else {
        logger.info(`get repo secret scan failed repo: ${repo.name}`, err);
      }
    }

    return securityEventList;
  }

  async getRepoCodeScanningAlerts(repo: Repo, securityEventList: SecurityEvent[]) {
    let count = 0;
    const codeScanningSecurityEventList: SecurityEvent[] = [];
    try {
      const shouldRun = StatesHelper.Instance.githubSastEnable || isLocalDevelopment();
      if (!shouldRun) {
        return;
      }

      let query;

      if (repo.sourceBranch) {
        query = {
          url: "GET /repos/{owner}/{repo}/code-scanning/alerts?state=open",
          parms: {
            owner: repo.ownerName,
            repo: repo.name,
            page: 1,
            per_page: per_page_max_res,
            ref: repo.sourceBranch,
          },
        };
      } else {
        query = {
          url: "GET /repos/{owner}/{repo}/code-scanning/alerts?state=open",
          parms: {
            owner: repo.ownerName,
            repo: repo.name,
            page: 1,
            per_page: per_page_max_res,
          },
        };
      }

      const res = await this.invokeRequest(query, 10);

      for (const codeScanAlert of res) {
        try {
          const securityEvent = new SecurityEvent(
            codeScanAlert?.tool?.name ? `${Constant.githubSast} - ${codeScanAlert?.tool?.name}` : Constant.githubSast,
            true,
            repo.fileLink +
              "/" +
              codeScanAlert.most_recent_instance.location.path +
              repo.linkFilePreffix +
              codeScanAlert.most_recent_instance.location.start_line,
            codeScanAlert.created_at,
            "",
            "",
            "",
            codeScanAlert.most_recent_instance.message.text,
            codeScanAlert.rule.name,
            codeScanAlert.most_recent_instance.location.path,
            codeScanAlert?.rule?.security_severity_level ? codeScanAlert?.rule?.security_severity_level : codeScanAlert.rule?.severity,
            "",
            codeScanAlert.most_recent_instance.location.start_line,
            AlertSeverity[AlertSeverity.High],
            SecurityAlertType.sast,
            `Please consider fix the code at file ${codeScanAlert.most_recent_instance.location.path} line ${codeScanAlert.most_recent_instance.location.start_line}`,
            "",
            "",
            codeScanAlert.most_recent_instance.location.end_line,
            false,
            false,
            "",
            "",
            "",
            "",
            codeScanAlert.rule.name,
            codeScanAlert.html_url,
            repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
            repo.fullName,
            repo.insideFolder,
            repo.monoRepoChild ? repo.name.substring(1) + "/" + codeScanAlert.vulnerableManifestPath : codeScanAlert.vulnerableManifestPath,
            "dependabot",
          );

          securityEvent.version = repo.defaultBranch;
          securityEvent.linkToExternalProduct = codeScanAlert.html_url;
          securityEvent.realMatch = codeScanAlert.url;
          securityEvent.collectedAsPartOfRepos = true;

          codeScanningSecurityEventList.push(securityEvent);
          count++;
        } catch (err) {
          logger.error(`failed to create code scan obj for: ${repo.name}, data: ${JSON.stringify(codeScanAlert, null, 4)}`, err);
        }
      }

      logger.info(`getRepoCodeScanningAlerts repo: ${repo.name}, info: ${res?.length}`);
    } catch (err) {
      if (
        err.response?.status === 403 &&
        err.response?.data?.message?.includes("Advanced Security must be enabled for this repository to use code scanning")
      ) {
        logger.info(`get repo code scan failed repo: ${repo.name}, err: ${err.response?.data?.message}`);
      } else {
        logger.error(`get repo code scan failed repo: ${repo.name}`, err);
      }
    }

    const proms = codeScanningSecurityEventList.map(i => this.setCodeScanningRecommendation(repo, i));
    await Promise.all(proms);

    codeScanningSecurityEventList.forEach(i => securityEventList.push(i));

    return securityEventList;
  }

  async getRepoCodeScanningDetails(repo: Repo, id) {
    try {
      const query = {
        url: "GET /repos/{owner}/{repo}/code-scanning/alerts/{id}",
        parms: {
          owner: repo.organization,
          repo: repo.name,
          id: id,
        },
        singleRequest: true,
      };

      const res = await this.invokeRequest(query);
      if (res) {
        return res[0].rule;
      }
    } catch (e) {
      logger.error(`getRepoCodeScanningDetails failed for repo: ${repo.name} with code scanning alert id : ${id}`, e);
    }
  }

  getRecommendationFromRuleHelp(help: string) {
    let recommendation = "";
    const ruleHelpArr = help.split("\n\n\n");
    for (const rule of ruleHelpArr) {
      if (rule.startsWith("## Recommendation")) {
        recommendation = rule.replace("## Recommendation\n", "");
        break;
      }
    }
    return recommendation;
  }

  async setCodeScanningRecommendation(repo: Repo, securityEvent: SecurityEvent) {
    try {
      if (securityEvent.realMatch.search("code-scanning/alerts") > -1) {
        const ruleId = securityEvent.realMatch.substring(securityEvent.realMatch.lastIndexOf("/") + 1);
        const rule = await this.getRepoCodeScanningDetails(repo, ruleId);
        const recommendation = this.getRecommendationFromRuleHelp(rule.help);

        if (recommendation !== "") {
          securityEvent.recommendation = recommendation;
        }
      }
    } catch (err) {
      logger.error(`Error in setCodeScanningRecommendation Repo : ${repo.name}`, err);
    }
  }

  dumpEventsToFile(res: any, dir: string, fileName: string) {
    try {
      fs.writeFile(`${dir}/${fileName}`, JSON.stringify(res), err => {
        if (err) {
          console.log(`dependabot res written failed: ${err}`);
        } else {
          console.log("dependabot res written successfully");
        }
      });
    } catch (err) {
      logger.error(`dumpEventsToFile err`, err);
    }
  }

  async auditLog(): Promise<any> {
    try {
      logger.info(`try parse audit logs`);

      const startTime = new Date().getTime();

      await Promise.all([
        this.auditLogByAction("action:account"),
        this.auditLogByAction("action:advisory_credit"),
        this.auditLogByAction("action:auto_approve_personal_access_token_requests"),
        this.auditLogByAction("action:codespaces"),
        this.auditLogByAction("action:dependabot_alerts"),
        this.auditLogByAction("action:dependabot_alerts_new_repos"),
        this.auditLogByAction("action:dependabot_security_updates"),
        this.auditLogByAction("action:dependabot_security_updates_new_repos"),
        this.auditLogByAction("action:dependency_graph"),
        this.auditLogByAction("action:dependency_graph_new_repos"),
        //this.auditLogByType("action:enterprise"),
        this.auditLogByAction("action:hook"),
        this.auditLogByAction("action:integration_installation"),
        this.auditLogByAction("action:integration_installation_request"),
        this.auditLogByAction("action:marketplace_agreement_signature"),
        this.auditLogByAction("action:marketplace_listing"),
        this.auditLogByAction("action:members_can_create_pages"),
        this.auditLogByAction("action:payment_method"),
        this.auditLogByAction("action:personal_access_token"),
        this.auditLogByAction("action:project"),
        this.auditLogByAction("action:protected_branch"),
        this.auditLogByAction("action:repository_advisory"),
        this.auditLogByAction("action:repository_content_analysis"),
        this.auditLogByAction("action:repository_dependency_graph"),
        this.auditLogByAction("action:repository_vulnerability_alerts"),
        this.auditLogByAction(
          "-action:org.sso_response -action:org.add_member -action:org.block_user -action:org.invite_member -action:org.remove_member -action:org.unblock_user -action:org.update_member action:org",
        ),
        this.auditLogByAction("action:repo.add_member"),
        this.auditLogByAction("action:org.add_member"),
        this.auditLogByAction("action:org.block_user"),
        this.auditLogByAction("action:org.invite_member"),
        this.auditLogByAction("action:org.remove_member"),
        this.auditLogByAction("action:org.unblock_user"),
        this.auditLogByAction("action:org.update_member"),
        this.auditLogByAction("-action:team.add_repository -action:team.add_member action:team"),
        this.auditLogByAction("action:team.add_repository"),
        this.auditLogByAction("action:team.add_member"),
        this.auditLogByAction("action:workflows.enable_workflow action:workflows.disable_workflow"),
      ]);

      let elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));
      StatesHelper.Instance.scanInfoStats.audiLogTime = elapsedTime;

      logger.info(`finish parse audit logs, audit logs count: ${StatesHelper.Instance.scanInfoStats.auditLogsCount}`);
    } catch (err) {
      logger.error(`get audit all logs failed`, err);
    }
  }

  async auditLogByAction(action: string, page = max_pages): Promise<any> {
    try {
      const proms = this.githubHelper.orgs.map(i => this.auditLogByTypeAndOrg(action, i.name, page));
      await Promise.all(proms);
    } catch (err) {
      logger.error(`get audit log failed for ${this.githubHelper.orgs.length} orgs, action: ${action}`, err);
    }
  }

  async auditLogByTypeAndOrg(action: string, org: string, page = max_pages): Promise<any> {
    const orgName = org;
    try {
      const query = {
        url: "GET /orgs/{orgName}/audit-log",
        parms: {
          orgName: orgName,
          per_page: per_page_max_res,
          page: 1,
          phrase: action,
        },
      };

      const res = (await this.invokeRequest(query, page)) as any;
      for (const logInfo of res) {
        try {
          StatesHelper.Instance.scanInfoStats.auditLogsCount++;

          StatesHelper.Instance.orgsWithAuditLogs.add(org);

          const userAuditLog: UserAuditLog = new UserAuditLog();
          userAuditLog.repo = logInfo.repo;

          userAuditLog.name = logInfo.actor ? logInfo.actor : logInfo.runner_name;
          if (!userAuditLog.name || action === "action:repo.add_member") {
            userAuditLog.name = logInfo.user;
            userAuditLog.actionInfo = logInfo.created_at;
          }
          userAuditLog.action = logInfo.action;
          userAuditLog.actionFriendly = logInfo.action;
          userAuditLog.actionFriendly = logInfo.action.replaceAll("_", " ");
          userAuditLog.actionFriendly = userAuditLog.actionFriendly.replaceAll("\\.", " ");
          userAuditLog.timestamp = new Date(logInfo["@timestamp"]);
          userAuditLog.org = logInfo.org ? logInfo.org : "";
          userAuditLog.actorLocation = logInfo?.actor_location?.country_code;
          if (!userAuditLog.actorLocation) {
            userAuditLog.actorLocation = "";
          }

          if (!userAuditLog.name || !userAuditLog.action) {
            throw "incorrect audit log info";
          }

          if (!GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name]) {
            GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name] = [userAuditLog];
          } else {
            GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name].push(userAuditLog);
          }
        } catch (err) {
          logger.error(`failed to get audit log: ${orgName}, logInfo: ${JSON.stringify(logInfo)}`, err);
          StatesHelper.Instance.globalApisFails.add(resourceType.auditLog);
        }
      }
    } catch (err) {
      logger.error(`get audit log failed orgName: ${orgName}, type: ${action}`, err);
      StatesHelper.Instance.globalApisFails.add(resourceType.auditLog);
    }
  }

  async allUsers(reposObj: any) {
    try {
      if (process.env.SKIP_SCM_AUDIT) {
        return;
      }
      logger.info(`start get all users`);

      //Get org ADMIN and MEMBER, members with 2fa_disabled configuration
      const resMembers = this.githubHelper.orgs.map(org => {
        return Promise.all([
          this.getMembers(org.name, "admin", OrgRoles.OWNER, "all"),
          this.getMembers(org.name, "member", OrgRoles.MEMBER, "all"),
          this.getMembers(org.name, "admin", OrgRoles.OWNER, "2fa_disabled"),
          this.getMembers(org.name, "member", OrgRoles.MEMBER, "2fa_disabled"),
        ]);
      });
      await Promise.all(resMembers);

      //Get org collaborators that have 2fa disabled
      const resCollaborators = this.githubHelper.orgs.map(org => {
        return Promise.all([this.getOutsideCollaborators(org.name, "2fa_disabled")]);
      });
      await Promise.all(resCollaborators);

      //Get all collaborators
      const allResMembers = this.githubHelper.orgs.map(org => {
        return this.getMembers(org.name);
      });
      await Promise.all(allResMembers);

      //Get all users
      const resAllCollaborators = this.githubHelper.orgs.map(org => {
        return this.getOutsideCollaborators(org.name);
      });
      await Promise.all(resAllCollaborators);

      const allUsers: User[] = Object.values(GlobalCodeRepoData.Instance.getUsers()).flat() as any;
      const unique = new Set();
      const uniqueUsers = [];
      const usersMap = {};
      allUsers.forEach(i => {
        if (!unique.has(i.id)) {
          uniqueUsers.push(i);
          unique.add(i.id);
        }
        usersMap[i.name] = i;
      });

      this.setFormerUsers(usersMap);

      logger.info(`finish get all users count: ${allUsers.length}, former users: ${this.globalCodeRepoData.formerUsers.length}`);

      const stats = {
        forkedInsideOrgRepos: [],
      };
      stats.forkedInsideOrgRepos = [];
      const uniqueReposThatWasAdded: Set<string> = new Set<string>();

      const forkedProms = reposObj.map(repo => this.getForks(repo.code_repo, usersMap, stats));
      await Promise.all(forkedProms);

      const promsUsers = uniqueUsers.map(i => this.setUserRepos(i, reposObj, uniqueReposThatWasAdded, stats));
      await Promise.all(promsUsers);

      const promsFormerUsers = this.globalCodeRepoData.formerUsers.map(i => this.setUserRepos(i, reposObj, uniqueReposThatWasAdded, stats));
      await Promise.all(promsFormerUsers);

      logger.info(
        `finish calc forks, forked repos added to user: ${
          uniqueReposThatWasAdded.size
        }, forked forked repos because they forked inside the org count: ${
          stats.forkedInsideOrgRepos.length
        }, info: ${stats.forkedInsideOrgRepos.join(", ")}`,
      );
    } catch (e) {
      logger.error(`failed get all users`, e);
      StatesHelper.Instance.globalApisFails.add(resourceType.allUsers);
    }
  }

  isReadWrite(permission) {
    if (permission == undefined) {
      return ["none"];
    }
    const perms = Object.entries(permission);
    for (const [key, perm] of perms) {
      if (key === ("admin" || "maintain" || "push") && perm === true) {
        return ["read", "write"];
      }
    }
    return ["read"];
  }

  async getForks(repo: Repo, usersMap: any, stats: any) {
    try {
      if (!repo.privateVisability) {
        return [];
      }
      if (repo.forksCount == 0) {
        return [];
      }

      const query = {
        url: "GET /repos/{owner}/{repo}/forks",
        parms: {
          owner: repo.ownerNameApi,
          per_page: per_page_max_res,
          repo: repo.name,
          page: 1,
        },
        singleRequest: true,
      };

      const res = await this.invokeRequest(query);
      for (const forked of res) {
        const forkedRepo = new ForkedRepo();

        try {
          //Check timeline of forking
          if (new Date(repo.createdAt).getTime() >= new Date(forked.created_at).getTime()) {
            continue;
          }

          //Dont add forked inside org
          const orgRepo = this.githubHelper.orgs.find(i => forked.git_url.includes(`/${i.name}/`));
          if (orgRepo) {
            stats.forkedInsideOrgRepos.push(forked.git_url);
            continue;
          }

          if (forked?.owner?.type !== "User") {
            forkedRepo.destinationOrgName = forked?.owner.login;

            const query = {
              url: "GET /orgs/{org}/members",
              parms: {
                org: forked?.owner.login,
                page: 1,
                per_page: per_page_max_res,
              },
              singleRequest: true,
            };

            const res = await this.invokeRequest(query, 1);
            for (const user of res) {
              if (user?.login) {
                const r = usersMap[user.login];
                if (r) {
                  forkedRepo.destinationUserName = user.login;
                  forkedRepo.user = r;
                  break;
                }
              }
            }

            logger.info(
              `found forked repo from: ${repo.fullName} to: ${forked.full_name}, user type: ${forked?.owner?.type}, name: ${forked?.owner.login}`,
            );
          }
        } catch (err) {
          logger.error(`failed get single forks repo: ${repo.fullName}`, err);
        }

        const pipelineScanInfo = this.getPipelineScanInfo(forked.id.toString(), forked.full_name);
        const destination = this.createRepo(forked, pipelineScanInfo);
        forkedRepo.destination = destination;
        forkedRepo.source = repo;
        forkedRepo.reasons.push(ForkReasons.fork);

        repo.forkedRepos.push(forkedRepo);

        //Set if forked user exist in org
        if (!forkedRepo.user) {
          let ownerName = forkedRepo.destination.ownerName;
          //Using org
          if (forkedRepo.destinationOrgName) {
            ownerName = forkedRepo.destinationUserName;
          }
          if (ownerName) {
            const r = usersMap[ownerName];
            if (r) {
              forkedRepo.user = r;
            } else {
              const u: User = new User(
                forked?.owner?.login,
                forked?.owner?.login,
                Constant.formerUserId,
                forked?.owner?.avatar_url,
                "",
                new Date().toString(),
              );
              u.htmlLink = forked?.owner?.html_url;
              forkedRepo.user = u;
              forkedRepo.reasons.push(ForkReasons.forkNoneExitUser);
              logger.info(`cannot find ownerName: ${ownerName} for forked repo: ${repo.fullName} inside the organization`);
            }
          } else {
            forkedRepo.checkedUser = false;
          }
        }
      }
    } catch (err) {
      logger.error(`failed get forks repo: ${repo.fullName}`, err);
    }
  }

  async setUserRepos(user: User, reposObj: any[], uniqueReposThatWasAdded: Set<string>, stats) {
    try {
      if (process.env.SKIP_SCM_AUDIT) {
        return;
      }
      const query = {
        url: "GET /users/{owner}/repos",
        parms: {
          owner: user.name,
          per_page: per_page_max_res,
          page: 1,
        },
      };

      const isFormerUser = user.id === Constant.formerUserId;

      const res = await this.invokeRequest(query);
      for (const apiRepo of res) {
        try {
          //check if its not an current org repp
          const orgRepo = this.githubHelper.orgs.find(i => apiRepo.git_url.includes(`/${i.name}/`));
          if (orgRepo) {
            stats.forkedInsideOrgRepos.push(apiRepo.git_url);
            continue;
          }
          //Dont save duplication, this is just safty should happen
          if (uniqueReposThatWasAdded.has(apiRepo.full_name)) {
            continue;
          }

          //Check if forked
          let forked = false;
          const query = {
            url: "GET /repos/{owner}/{repo}",
            parms: {
              owner: user.name,
              per_page: per_page_max_res,
              repo: apiRepo.name,
              page: 1,
            },
            singleRequest: true,
          };

          const repoInfo = await this.invokeRequest(query);
          if (repoInfo?.length > 0) {
            if (repoInfo[0].parent) {
              forked = true;
            }
          }

          //Add based on name similarity
          if (!forked) {
            let bestMatch;
            for (const i of reposObj) {
              const r: Repo = i.code_repo;
              const score = stringSimilarity.compareTwoStrings(apiRepo.name, r.name);
              if (score < 0.75) {
                continue;
              }
              //Update best match
              if (bestMatch) {
                if (bestMatch.score < score) {
                  bestMatch = {
                    score: score,
                    source: r,
                  };
                }
              } else {
                bestMatch = {
                  score: score,
                  source: r,
                };
              }
            }

            if (bestMatch) {
              const pipelineScanInfo = this.getPipelineScanInfo(apiRepo.id.toString(), apiRepo.full_name);
              const destination: Repo = this.createRepo(apiRepo, pipelineScanInfo);
              const source: Repo = bestMatch.source;

              //Check timeline of forking
              if (new Date(source.createdAt).getTime() < new Date(destination.createdAt).getTime() && source.privateVisability) {
                const forkedRepo = new ForkedRepo();
                forkedRepo.destination = destination;
                forkedRepo.source = source;
                forkedRepo.user = user;
                forkedRepo.reasons.push(ForkReasons.sameName);

                source.forkedRepos.push(forkedRepo);
                uniqueReposThatWasAdded.add(apiRepo.full_name);
                // Debug
                // logger.info(
                //   `found connection, isFormerUser: ${isFormerUser}, best match score: ${bestMatch.score} between public repos of user: ${user.name}, by name, source:${source.fullName}, destination: ${destination.fullName}`,
                // );
                continue;
              }
            }
          }

          //This is based on policy for admins that want to see all public repos of there org users
          const skipForkedRepoForPublicRepo = StatesHelper.Instance.includeForkedPublicRepos == false;
          let shouldRun = true;
          if (forked) {
            if (skipForkedRepoForPublicRepo) {
              shouldRun = false;
            }
          }
          if (shouldRun) {
            const pipelineScanInfo = this.getPipelineScanInfo(apiRepo.id.toString(), apiRepo.full_name);
            const destination = this.createRepo(apiRepo, pipelineScanInfo);
            const forkedRepo: ForkedRepo = new ForkedRepo();
            forkedRepo.destination = destination;
            forkedRepo.user = user;
            forkedRepo.reasons.push(ForkReasons.public);
            // Debug
            // logger.info(
            //   `found connection, isFormerUser: ${isFormerUser} between public repos of user: ${user.name}, by public repo, source: no source, destination: ${destination.fullName}`,
            // );
            user.forkedReposFromOrg.push(forkedRepo);
            uniqueReposThatWasAdded.add(apiRepo.full_name);
          }
        } catch (err) {
          logger.error(`failed set, isFormerUser: ${isFormerUser} single user: ${user.username} forked repo: ${apiRepo.full_name}`, err);
        }
      }
    } catch (err) {
      logger.error(`failed set all user: ${user.username} repo`, err);
    }
  }

  async webhooks(repo: Repo): Promise<any> {
    let webhooksList: Webhook[] = [];

    try {
      const query = {
        url: "GET /repos/{owner}/{repo}/hooks",
        parms: {
          owner: repo.ownerNameApi,
          per_page: per_page_max_res,
          repo: repo.name,
          page: 1,
        },
      };

      const res = await this.invokeRequest(query);

      for (const webhookInfo of res) {
        try {
          let webhook = new Webhook(
            webhookInfo.config.url,
            webhookInfo.createdAt,
            webhookInfo.lastResponseCode,
            webhookInfo.lastResponseMsg,
            webhookInfo.config.secret != undefined && webhookInfo.config.secret === "",
            webhookInfo.config.insecure_ssl === "0",
            webhookInfo.active,
            "",
            repo.link + "/settings/hooks/" + webhookInfo.id,
            webhookInfo.events == "*" ? ["All"] : webhookInfo.events,
            repoResourceType.webhooks,
            webhookInfo.id,
          );

          const domain = VTHelper.getInstance().getDomainFromUrl(webhook.url);
          webhook.domain = domain;
          if (domain != null) {
            if (GlobalCodeRepoData.Instance.domainWebhooksToRepo[domain]) {
              GlobalCodeRepoData.Instance.domainWebhooksToRepo[domain].add(repo.id);
            } else {
              GlobalCodeRepoData.Instance.domainWebhooksToRepo[domain] = new Set();
              GlobalCodeRepoData.Instance.domainWebhooksToRepo[domain].add(repo.id);
            }
          }

          const promise = await this.appMgr.CreateNode("Webhook", {
            repo_name: repo.name,
            repo_id: repo.id,
            vcs_type: "github",
            url: webhookInfo.config.url,
            created: webhookInfo.createdAt,
          });

          webhooksList.push(webhook);
        } catch (err) {
          logger.error(`failed to create webhook obj for: ${repo.name}, webhook: ${JSON.stringify(webhookInfo, null, 4)}`, err);
          // StatesHelper.Instance.addFailedTool(repoResourceType.webhooks, repo.id);
        }
      }
    } catch (err) {
      if (err.status != 404) {
        logger.error(`get webhooks failed repo: ${repo.name}`, err);
      }
      logger.debug(`get webhooks failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.webhooks, repo.id);
    }

    return webhooksList;
  }

  async workflows(repo: Repo): Promise<any> {
    let workflowsList: Workflow[] = [];

    try {
      const query = {
        url: "GET /repos/{owner}/{repo}/actions/workflows",
        parms: {
          owner: repo.ownerNameApi,
          per_page: per_page_max_res,
          repo: repo.name,
          page: 1,
        },
        singleRequest: true,
      };

      const res = await this.invokeRequest(query);
      const workflows = res.map(i => i.workflows);
      const flatWorkflows = workflows.flat();
      for (const workflowInfo of flatWorkflows) {
        try {
          let workflow = new Workflow(
            workflowInfo.created_at,
            workflowInfo.html_url,
            workflowInfo.state === "active",
            workflowInfo.path,
            workflowInfo.name,
            workflowInfo.id.toString(),
          );

          const promise = await this.appMgr.CreateNode("Workflows", {
            repo_name: repo.name,
            repo_id: repo.id,
            vcs_type: "github",
            url: workflowInfo.html_url,
            created: workflowInfo.created_at,
          });

          workflowsList.push(workflow);
        } catch (err) {
          logger.error(`failed to create workflow obj for: ${repo.name}, workflow: ${JSON.stringify(workflowInfo, null, 4)}`, err);
        }
      }
    } catch (err) {
      logger.error(`get workflows failed repo: ${repo.name}`, err);
    }
    return workflowsList;
  }

  getAPICredentials() {
    return {
      authType: "token",
      baseUrl: this.token.host ?? "https://api.github.com",
      token: this.credentials.token,
    };
  }

  getAPIRepoInfo(repo: Repo) {
    return {
      owner: repo.ownerName,
      repo: repo.name,
    };
  }

  async findPullRequestIntroducingMergeCommit(repoObj: any, branch: string, sha: string) {
    const repo: Repo = repoObj.code_repo;
    try {
      const pullRequestsAssociatedWithACommitQuery = {
        url: "GET /repos/{owner}/{repo}/commits/{commit_sha}/pulls",
        parms: {
          per_page: per_page_max_res,
          page: 1,
          owner: repo.ownerNameApi,
          repo: repo.name,
          commit_sha: sha,
        },
        singleRequest: true,
      };

      const response: GitHub.MergeRequest[] = await this.invokeRequest(pullRequestsAssociatedWithACommitQuery);

      const found = response
        .filter(r => r.state === "closed")
        .filter(r => r.base?.ref === branch)
        .find(r => r?.merge_commit_sha === sha);

      if (!found) return null;

      const mergeUser = new MergeUser(
        found.merged_by?.login ?? found.user?.login ?? found.base?.user?.login,
        found.merged_by?.login ?? found.user?.login ?? found.base?.user?.login,
        found.merged_by?.id ?? found.user?.id ?? found.base?.user?.id,
      );

      const pullRequest = new PullRequest(
        found.created_at,
        found.html_url,
        found.body,
        sha,
        found.merged_at ?? found.closed_at,
        found.title,
        0,
        found.user?.login ?? found.base?.user?.login,
        found.number.toString(),
        CodeRepoTypes.pulls,
        [],
        mergeUser,
        true,
      );

      return pullRequest;
    } catch (e) {
      logger.error(`[github] failed to find pull request introducing merge commit repo: ${repo.name}, branch: ${branch}, sha: ${sha}`, e);
      return null;
    }
  }

  async findFilesModifiedInPullRequest(repo: Repo, sourceBranch: string, targetBranch: string, sha: string, pullRequestId: string | null) {
    try {
      // open in production for all orgs
      StatesHelper.Instance.pipelineScanInfo.filesModifiedInPullRequest.enabled = true;

      let usedPullRequestId = pullRequestId;

      // if pullRequestId wasn't provided (i.e. Jenkins integration triggered the job, try to find a matching PR)
      if (!usedPullRequestId) {
        const pullRequest = await this.graphQL.getOpenPullRequestForBranches(repo.organization, repo.name, sourceBranch, targetBranch);
        usedPullRequestId = pullRequest?.number?.toString() ?? null;
      }

      if (!usedPullRequestId) {
        logger.warn(
          `[github][findFilesModifiedInPullRequest] no pull request ID provided and found for repo: ${repo.name}, sourceBranch: ${sourceBranch}, targetBranch: ${targetBranch}, usedPullRequestId: ${usedPullRequestId}`,
        );
        return null;
      }

      const query = {
        url: "GET /repos/{owner}/{repo}/pulls/{pull_number}/files",
        parms: {
          owner: repo.organization,
          repo: repo.name,
          pull_number: usedPullRequestId,
          page: 1,
          per_page: 100,
        },
      };

      // Responses include a maximum of 3000 files
      // so we are fetching max 30 pages of 100 files per page
      const pullRequestFilesResponse = await this.invokeRequest(query, 30);
      // we can't risk PR including over 3000 files and us not analyzing all of them
      if (pullRequestFilesResponse.length === 3000) {
        logger.warn(
          `[github][findFilesModifiedInPullRequest] pullRequestFilesResponse.length: ${pullRequestFilesResponse.length} for repo: ${repo.name}, sourceBranch: ${sourceBranch}, targetBranch: ${targetBranch}, usedPullRequestId: ${usedPullRequestId}`,
        );
        return null;
      }

      const files = [
        ...new Set(
          pullRequestFilesResponse
            // can be one of "added", "removed", "modified", "renamed", "copied", "changed", "unchanged"
            .filter(item => item.status !== "removed")
            .map(item => item.filename)
            .filter(Boolean),
        ),
      ];

      return files;
    } catch (e) {
      logger.error(`[github][findFilesModifiedInPullRequest]`, e);
    }
  }

  async pulls(repoObj: any): Promise<PullRequest[]> {
    const repo: Repo = repoObj.code_repo;
    const commits: Commit[] = repoObj.commits;

    await this.setRepoApiInfo(repo);
    return await this.getPullsAndReviews(repo, commits);
  }

  private async getPullsAndReviews(repo: Repo, commits: Commit[]): Promise<PullRequest[]> {
    let pullRequestList: PullRequest[] = [];
    try {
      if (StatesHelper.Instance.orgName === "org_3FaIb7kmXGVol1Vu") {
        return;
      }

      const pulls = await this.graphQL.getPullsAndReviews({
        owner: repo.ownerNameApi,
        repository: repo.name,
        defaultBranch: repo.sourceBranch ? repo.sourceBranch : repo.defaultBranch,
      });

      StatesHelper.Instance.scanInfoStats.githubGraphqlTotalPullRequests += pulls.length;

      for (const pull of pulls) {
        try {
          if (!pull.mergeCommit?.oid) {
            continue;
          }

          if (!pull.author?.login) {
            pull.author = { login: "ghost" }; // This is a github placeholder for deleted users (https://github.com/ghost)
          }

          const reviewers = [...new Set(pull.reviews.nodes.map(reviewer => reviewer.author?.login).filter(Boolean))];

          const pullRequest = new PullRequest(
            pull.createdAt,
            pull.url,
            pull.body,
            pull.mergeCommit.oid,
            pull.mergedAt,
            pull.title,
            reviewers.length || -1,
            pull.author.login,
            String(pull.number),
            CodeRepoTypes.pulls,
            reviewers.map(reviewer => new Reviewer(reviewer, reviewer)),
            new MergeUser(pull.author.login, pull.author.login),
            true,
          );
          pullRequest.authorUserName = pull.author.login;
          pullRequest.reviewerCount = pullRequest.reviewers.length;

          if (StatesHelper.Instance.policyForQueryPullsByDays) {
            if (pullRequest.diffFromNowToCreatedAtInDays > StatesHelper.Instance.policyForQueryPullsByDays) {
              StatesHelper.Instance.policyForQueryPullsByDaysSkippedRequests++;
              continue;
            }
          }

          this.getCommitRelatedToPullReq(repo, pullRequest, commits, {
            headSha: pull.headRefOid,
            baseSha: pull.baseRefOid,
            mergeCommmitSha: pull.mergeCommit.oid,
          });
          if (pullRequest.pullsCommitInfo.length == 0) {
            continue;
          }
          this.updateMailInfo(pullRequest);
          pullRequestList.push(pullRequest);
        } catch (err) {
          logger.error(
            `failed to create pull err: ${err} for: ${repo.ownerNameApi}/${repo.name} branch ${repo.defaultBranch}, pull obj: ${pull.title}`,
            err,
          );
          StatesHelper.Instance.addFailedTool(repoResourceType.pulls, repo.id);
        }
      }
    } catch (err) {
      logger.error(`get pulls failed repo: ${repo.ownerNameApi}/${repo.name} branch ${repo.defaultBranch}`, err);
      StatesHelper.Instance.addFailedTool(repoResourceType.pulls, repo.id);
    }

    pullRequestList.forEach(pullRequest => {
      GlobalCodeRepoData.Instance.addPulls([pullRequest], repo);
    });

    return pullRequestList;
  }

  async setReviews(pullRequest: PullRequest, repo: Repo): Promise<void> {
    try {
      if (pullRequest.reviewers.length > 0) {
        return;
      }

      //Set default before check
      pullRequest.reviewerCount = -1;

      const reviwersQuery = {
        url: "GET /repos/{owner}/{repo}/pulls/{pull_number}/reviews",
        parms: {
          owner: repo.ownerNameApi,
          per_page: per_page_max_res,
          state: "closed",
          repo: repo.name,
          pull_number: pullRequest.id,
          page: 1,
        },
        error: false,
        singleRequest: true,
      };

      const reviews = await this.invokeRequest(reviwersQuery);
      reviews.forEach(rev => {
        pullRequest.reviewers.push(new Reviewer(rev.user.login, rev.user.login, rev.user.id));
      });
      pullRequest.reviewerCount = pullRequest.reviewers.length;
    } catch (err) {
      logger.error(`get pulls reviews failed repo: ${repo.name}`, err);
      pullRequest.reviewerCount = -1;
    }
  }

  shouldAttachCommitToPull(commitFromDisk, resCommit): boolean {
    return commitFromDisk.hash === resCommit.sha;
  }

  async getCommitRelatedToPullReq(
    repo: Repo,
    pullRequest: PullRequest,
    commitsFromDisk: Commit[],
    pull: { headSha?: string; baseSha?: string; mergeCommmitSha?: string },
  ) {
    try {
      const res = [];
      if (pull?.headSha) {
        res.push({ sha: pull.headSha });
      }
      if (pull?.baseSha) {
        res.push({ sha: pull.baseSha });
      }
      if (pull?.mergeCommmitSha) {
        res.push({ sha: pull.mergeCommmitSha });
      }

      for (const resCommit of res) {
        try {
          let commitInfoFromDisk = commitsFromDisk.filter(i => this.shouldAttachCommitToPull(i, resCommit));

          if (commitInfoFromDisk.length > 0) {
            pullRequest.pullsCommitInfo = [...pullRequest.pullsCommitInfo, ...commitInfoFromDisk];
          }
        } catch (err) {
          logger.error(`repo: ${repo.name}, get related single commit to pull request`, err);
        }
      }

      if (pullRequest.pullsCommitInfo.length == 0 && commitsFromDisk.length > 0) {
        return;
      }

      setFileInfo(pullRequest);
    } catch (err) {
      logger.error(`repo: ${repo.name}, get related commit to pull request`, err);
    }
  }

  async getRepoTeams(repo: string, owner: string) {
    try {
      let dataToReturn = [];

      const query = {
        url: "GET /repos/{owner}/{repo}/teams",
        parms: {
          owner: owner,
          repo: repo,
          per_page: per_page_max_res,
        },
      };

      const res = (await this.invokeRequest(query)) as any;

      if (res) {
        for (const team of res) {
          const members = await this.getTeamMembers(owner, team.slug);

          const teamData = {
            slug: team.slug,
            permission: team.permission,
            members: members,
          };
          dataToReturn.push(teamData);
        }
      }
      return dataToReturn;
    } catch (e) {
      logger.error(`Could not get Teams of the repo ${repo}`, e);
    }
  }

  async getTeamMembers(org: string, teamName: string) {
    try {
      let data = [];
      const query = {
        url: "GET /orgs/{org}/teams/{team_slug}/members",
        parms: {
          org: org,
          team_slug: teamName,
          per_page: per_page_max_res,
        },
      };

      const res = (await this.invokeRequest(query)) as any;
      if (res) {
        for (const member of res) {
          data.push(member.login);
        }
      }

      return data;
    } catch (e) {
      logger.error(`Could not get Team members of the team ${teamName}`, e);
    }
  }

  async getReposWithSelectedBranch(apiRepos: any[], sourceBranch: string) {
    try {
      const reposWithSelectedBranch = [];

      for (const apiRepo of apiRepos) {
        const query = {
          url: "GET /repos/{owner}/{repo}/branches",
          parms: {
            owner: apiRepo.owner.login,
            repo: apiRepo.name,
            per_page: per_page_max_res,
          },
        };

        const res = (await this.invokeRequest(query)) as any;
        if (res.find(branch => branch.name === sourceBranch)) {
          reposWithSelectedBranch.push(apiRepo);
          logger.info(`repo ${apiRepo.name} contains the ${sourceBranch} branch, will be included in scan`);
          continue;
        }
        logger.info(`repo ${apiRepo.name} doesn't contain the ${sourceBranch} branch, will be excluded from scan`);
      }
      return reposWithSelectedBranch;
    } catch (err) {
      logger.error(`failed getReposWithSelectedBranch`, err);
    }
    return [];
  }

  async branches(repo: Repo): Promise<any> {
    let branchsList: Branch[] = [];

    try {
      const query = {
        url: "GET /repos/{owner}/{repo}/branches",
        parms: {
          owner: repo.ownerNameApi,
          repo: repo.name,
          per_page: per_page_max_res,
        },
      };

      const res = (await this.invokeRequest(query)) as any;

      for (const branchInfo of res) {
        try {
          let branch = new Branch(branchInfo.name);

          branchsList.push(branch);
        } catch (err) {
          logger.error(`failed to create branch obj for: ${repo.name}, branch: ${JSON.stringify(branchInfo, null, 4)}`, err);
          StatesHelper.Instance.addFailedTool(repoResourceType.branches, repo.id);
        }
      }
    } catch (err) {
      logger.error(`get branches failed repo: ${repo.name}`, err);
      StatesHelper.Instance.addFailedTool(repoResourceType.branches, repo.id);
    }
    return branchsList;
  }

  private getRole(permissions) {
    try {
      if (permissions.admin) {
        return UserRole.OWNER;
      }
      if (permissions.maintain) {
        return UserRole.MAINTAINER;
      }
      if (permissions.push && permissions.pull) {
        return UserRole.DEVELOPER;
      }
      return UserRole.GUEST;
    } catch (e) {
      logger.error(`failed to get user role`, e);
    }
    return UserRole.GUEST;
  }

  private getAllRole(permissions) {
    const rolls = [];
    try {
      if (permissions.admin) {
        rolls.push(UserRole.OWNER);
      }
      if (permissions.maintain) {
        rolls.push(UserRole.MAINTAINER);
      }
      if (permissions.push && permissions.pull) {
        rolls.push(UserRole.DEVELOPER);
      }
      rolls.push(UserRole.GUEST);
    } catch (e) {
      logger.error(`failed to get user role`, e);
    }
    return rolls;
  }

  private getRepoRolesRaw(permissions) {
    const roles = [];
    try {
      for (const [perm, isTrue] of Object.entries(permissions)) {
        if (isTrue) {
          roles.push(perm);
        }
      }
    } catch (e) {
      logger.error(`getRolesRaw failed`, e);
    }
    return roles;
  }

  async getCollaboratorsBasedOnRepo(repo: Repo, type: string) {
    const users = [];
    try {
      const query = {
        url: "GET /repos/{owner}/{repo}/collaborators",
        parms: {
          owner: repo.ownerNameApi,
          repo: repo.name,
          per_page: per_page_max_res,
          affiliation: type,
          page: 1,
        },
      };

      const res = await this.invokeRequest(query, 10);

      for (const user of res) {
        const userInfo = new User(user.login, user.login, user.id, user.avatar_url, "", "");

        //In this case org rule will be always OrgRoles.COLLABORATORS
        //For repo rules it can be admin, owner or any other role
        userInfo.role = this.getRole(user.permissions);

        if (type === AffiliationType.outside) {
          userInfo.orgRole.add(OrgRoles.COLLABORATORS);
        }

        userInfo.allRoles = this.getAllRole(user.permissions);
        userInfo.repoRolesRaw = this.getRepoRolesRaw(user.permissions);

        userInfo.affiliation.add(type);
        userInfo.htmlLink = user.html_url;
        userInfo.org = repo.organization;
        userInfo.repoRoleName = user.role_name;

        users.push(userInfo);
      }
    } catch (err) {
      logger.error(`failed to get collaborators, type: ${type}`, err);
    }
    return users;
  }

  async users(repoObj: any) {
    let users: User[] = [];
    let repoName = "";
    if (!this.token.globalRepositories) {
      try {
        const repo: Repo = repoObj.code_repo;
        repoName = repo.name;

        //Collaborators
        const res = await Promise.all([
          this.getCollaboratorsBasedOnRepo(repo, AffiliationType.outside),
          this.getCollaboratorsBasedOnRepo(repo, AffiliationType.all),
        ]);
        const allUsers: User[] = res.flat();

        const map = {};
        allUsers.forEach(i => {
          if (map[i.id]) {
            const u: User = map[i.id];
            const allAffiliation = Array.from(i.affiliation);
            allAffiliation.forEach(j => {
              u.affiliation.add(j);
            });
          } else {
            map[i.id] = i;
          }
        });

        users = Object.values(map);
      } catch (err) {
        const repo: Repo = repoObj.code_repo;
        logger.error(`get users failed repo: ${repoName}`, err);
        StatesHelper.Instance.addFailedTool(repoResourceType.users, repo.id);
      }
    }
    return users;
  }

  async handleRequest(gitHubRequest: GitHubRequest) {
    if ("https://api.github.com" !== this.token.host) {
      const res = await this.octokit.request(gitHubRequest.query.url, gitHubRequest.query.parms);
      return res.data;
    }

    const token = this.getTokenPassword();
    const host = this.getHost();
    return handleGithubRequest(gitHubRequest, token, host);
  }

  async getCodeBaseLastCodeChange(application) {
    return new Date(application.pushed_at);
  }

  getCodeRepoId(application) {
    return application.id.toString();
  }

  getTokenPassword(): string {
    return this.credentials.token;
  }

  getHost(): string {
    return this.token.host;
  }

  async branchSettings(repoObj: any) {
    try {
      const repo: Repo = repoObj.code_repo;
      const query = {
        url: "GET /repos/{owner}/{repo}/branches/{branch}/protection",
        parms: {
          owner: repo.ownerNameApi,
          repo: repo.name,
          branch: repo.sourceBranch ? repo.sourceBranch : repo.defaultBranch,
        },
      };
      const resData = await this.invokeRequest(query);

      let MRWithoutReviewEnabled = false;
      let pushEventsEnabled = false;
      let forceDeleteAllowed = false;
      let branchProtection = true;
      let requiredSignedCommits = true;
      let restrictions = {};
      let enforceAdmins = false;
      let dissmisalRestrictions = {};
      let bypassPullReqAllowances = {};
      let branchSettings;
      let codeOwnerApproval;

      // in case we don't have a protected branch rule
      if (resData.length == 0) {
        branchProtection = false;
        MRWithoutReviewEnabled = true;
        pushEventsEnabled = true;
        branchSettings = {};
      } else {
        branchSettings = resData[0];
        // checking if the owner allowed deletions

        if (branchSettings.hasOwnProperty("allow_deletions")) {
          const deletionsSettings = branchSettings.allow_deletions;
          forceDeleteAllowed = deletionsSettings.enabled;
        }

        if (branchSettings.hasOwnProperty("enforce_admins")) {
          enforceAdmins = branchSettings["enforce_admins"].enable;
        }

        requiredSignedCommits = branchSettings.hasOwnProperty("required_signatures")
          ? branchSettings["required_signatures"]["enabled"]
          : false;

        // In case we don't have this property PR are allowed w.o review and push events to main are allowed
        if (!branchSettings.hasOwnProperty("required_pull_request_reviews")) {
          MRWithoutReviewEnabled = true;
          pushEventsEnabled = true;
        } else {
          if (branchSettings.hasOwnProperty("restrictions") && branchSettings.restrictions) {
            restrictions = branchSettings.restrictions;
          }

          let pullReqReviewSettings = branchSettings.required_pull_request_reviews;

          // in case of null
          if (!pullReqReviewSettings) {
            MRWithoutReviewEnabled = true;
            pushEventsEnabled = true;
          } else {
            if (pullReqReviewSettings.require_code_owner_reviews === true) {
              codeOwnerApproval = true;
            }
            if (pullReqReviewSettings.required_approving_review_count === 0) {
              MRWithoutReviewEnabled = true;
            }

            if (
              pullReqReviewSettings.hasOwnProperty("dismissal_restrictions") &&
              Object.keys(pullReqReviewSettings.dismissal_restrictions).length != 0
            ) {
              dissmisalRestrictions = pullReqReviewSettings.dismissal_restrictions;
            }
            if (
              pullReqReviewSettings.hasOwnProperty("bypass_pull_request_allowances") &&
              Object.keys(pullReqReviewSettings.bypass_pull_request_allowances).length != 0
            ) {
              bypassPullReqAllowances = pullReqReviewSettings.bypass_pull_request_allowances;
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
        branchSettings,
        codeOwnerApproval,
      );

      const res = isPolicyMainBranchDoesntRequireCodeReviewViolation(settings);
      if (res) {
        StatesHelper.Instance.reposMainBranchDoesntRequireCodeReviewViolationCount++;
      } else {
        StatesHelper.Instance.noReposMainBranchDoesntRequireCodeReviewViolationCount++;
      }

      return settings;
    } catch (err) {
      const repo: Repo = repoObj.code_repo;
      logger.error(`failed get protected branch info`, err);
      StatesHelper.Instance.addFailedTool(repoResourceType.branchSettings, repo.id);
    }
    const defaultSettings = new BranchSettings();
    return defaultSettings;
  }
}

export default CodeRepoGithub;
