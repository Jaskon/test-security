//https://bitbucketjs.netlify.app/
// const { Bitbucket } = require("bitbucket");
import { APIClient, Bitbucket } from "bitbucket";
import qs from "qs";
import { IdentityProviderToken } from "../../entitis/IdentityProvider";
import { getInstallationOauthToken } from "@oxappsec/ox-bitbucket-app";
import axios from "axios";
import {
  Branch,
  BranchSettings,
  CodeRepoTypes,
  Commit,
  File,
  MergeUser,
  Organization,
  PullRequest,
  Repo,
  repoResourceType,
  repoType,
  resourceType,
  Reviewer,
  User,
  UserAuditLog,
  UserRole,
  Webhook,
} from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { isJson } from "../../entitis/commonTypes";
import RepoImportanceCalcHelper from "../../helper/appPriority/repoImportanceCalcHelper";
import {
  axiosCall,
  BitbucketRequest,
  max_pages,
  per_page_max_res,
  retry_count,
  timeout_to_wait_after_rate_limit_happen,
} from "../../helper/connectorsSpecific/bitbucketHelper";
import CheckmarxCLIparser from "../../helper/connectorsSpecific/checkmarxCLIparser";
import GitHelper from "../../helper/gitHelper";
import { RateLimitHelperFactory } from "../../helper/rateLimitHelper";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";
import CodeRepoBase from "../base/codeRepoBase";
import { isPolicyMainBranchDoesntRequireCodeReviewViolation } from "../../policy/rules/code/policyMainBranchDoesntRequireCodeReview";
import GeoLocationHelper from "../../helper/geoLocationHelper";
import GlobalCodeRepoData from "../GolobalCollectorData/globalCodeRepoData";
import { PipeLineHelper } from "../../helper/pipelineHelper";
import { millis } from "../../helper/time-unit-utils";

const BITBUCKET_APP_TOKEN_REFRESH_INTERVAL = millis.from.minutes(110);
let bitbucket: APIClient = null;
let keyPrefix = null;
const logger = loggerImport.getDebugLogger();
const timeHelper: TimeHelper = new TimeHelper("bitbucket");

class CodeRepoBitbucket extends CodeRepoBase {
  workspaces = [];
  private_token: string;
  refresh_token: string;
  // IDP or BitbucketApp
  usingOathToken = false;
  allUsersInfo: User[] = [];
  allPermissions = [];
  geoLocationHelper: GeoLocationHelper;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.rateLimitHelper = RateLimitHelperFactory.getRateLimitHelperPerToken(this.token.name, 200);

    let tempToken = token.password;
    const isIdpToken = isJson(token.password);
    if (isIdpToken) {
      const idpToken = JSON.parse(token.password);
      tempToken = idpToken.access_token;
      this.refresh_token = idpToken.refresh_token;
      this.usingOathToken = true;
    }
    if (this.isBitbucketAppToken) {
      this.usingOathToken = true;
    }

    this.private_token = tempToken;

    this.geoLocationHelper = new GeoLocationHelper();
  }

  async initLib() {
    try {
      logger.info(`try init lib for: ${this.token.name}, url: ${this.token.host}`);

      if (this.usingOathToken) {
        if (this.isBitbucketAppToken) {
          await this.refreshBBAClientToken();
          this.setBBATokenRefreshInterval();
        } else {
          // Refresh token first
          const refreshToken = await this.refreshToken(
            process.env.BITBUCKET_IDP_CLIENT_ID,
            process.env.BITBUCKET_IDP_CLIENT_SECRET,
            this.refresh_token,
          );
          this.private_token = refreshToken.access_token;

          bitbucket = new Bitbucket({
            baseUrl: this.token.host,
            auth: {
              token: this.private_token,
            },
            request: {
              timeout: 30000,
            },
          });
        }
      } else {
        bitbucket = new Bitbucket({
          baseUrl: this.token.host,
          auth: {
            username: this.token.userName,
            password: this.private_token,
          },
          request: {
            timeout: 30000,
          },
        });
      }

      const workspacesFunc = bitbucket.workspaces.getWorkspaces;
      const workspaces = await this.invokeRequest({
        func: workspacesFunc,
        parms: {
          funcName: "getAllWorkspaces",
          pagelen: per_page_max_res,
          page: 1,
        },
      });

      for (const workspace of workspaces) {
        let orgObj = new Organization(workspace.slug, workspace.uuid, null, null);
        this.workspaces.push(orgObj);
      }

      this.allUsersInfo = await this.allUsers(null);

      logger.info(`finish init lib for: ${this.token.name}, url: ${this.token.host}, workspaces: ${this.workspaces.length}`);
    } catch (err) {
      logger.error(`failed init lib for: ${this.token.name}, url: ${this.token.host}, err: ${err}`);
    }
    return [];
  }

  async setBBATokenRefreshInterval() {
    setInterval(async () => {
      await this.refreshBBAClientToken();
    }, BITBUCKET_APP_TOKEN_REFRESH_INTERVAL);
  }

  async refreshBBAClientToken() {
    const { sharedSecret, clientKey, appKey } = this.token;
    const installationToken = await getInstallationOauthToken(appKey, clientKey, sharedSecret);
    this.private_token = installationToken.access_token;

    bitbucket = new Bitbucket({
      baseUrl: this.token.host,
      auth: {
        token: this.private_token,
      },
      request: {
        timeout: 30000,
      },
    });
  }

  getAllOrgs() {
    return this.workspaces;
  }

  async setRepo(apiRepo, repoObj) {
    try {
      const pipelineScanInfo = this.getPipelineScanInfo(apiRepo.uuid, apiRepo.full_name);

      let repo = new Repo(
        this.uuid,
        this.orgName,
        this.token.name,
        apiRepo.name,
        apiRepo.uuid,
        apiRepo.full_name,
        apiRepo.created_on,
        apiRepo.mainbranch == null ? "main" : apiRepo.mainbranch.name,
        apiRepo.description,
        false,
        this.getCloneUrl(apiRepo),
        -1,
        true,
        apiRepo.has_wiki,
        apiRepo.has_issues,
        "",
        apiRepo.is_private,
        [],
        0,
        0,
        apiRepo.owner == null ? "" : apiRepo.owner.display_name,
        apiRepo.links.html.href,
        0,
        apiRepo.lastCodeChange,
        "",
        this.getFileLinkPrefix(apiRepo),
        "#lines-",
        0,
        apiRepo.links.html.href + "/admin",
        apiRepo.links.html.href + "/commits/",
        "",
        "",
        apiRepo.workspace.slug,
        apiRepo.uuid,
        true,
        apiRepo.name,
        pipelineScanInfo,
      );

      repo.workspace = apiRepo.workspace.uuid;

      if (!apiRepo.lastCodeChange) {
        if (!repo.disable) {
          repo.lastPushTime = await this.getLastCodeChange(apiRepo);
          logger.error(`roman: ${repo.lastPushTime}`);
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

      repo.gitRoles = this.getGitRoles("bitbucket");

      await this.getAndSetRepoDevLanguagesKubernetesAndOrchestrator(repo, filesList);

      repo.deploymentFilesYmls = this.getDeploymentFilesYmls(filesList);

      return repo;
    } catch (err) {
      logger.error(`failed to create repo obj for: ${JSON.stringify(apiRepo)}, err: ${err}`);
    }
    return null;
  }

  isRateLimitErrFunction(err: any) {
    try {
      if (err.toString().includes("rate limit")) {
        return true;
      }
      if (err.toString().includes("too many calls".toLowerCase())) {
        return true;
      }
      if (err.toString().includes("timeout of")) {
        return true;
      }
      if (err.toString().includes("network timeout")) {
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

  getQueryNextPage(r: BitbucketRequest, singleRes: any) {
    if (r.query.singleRequest) {
      if (r.query.singleRequest) return false;
    }
    if (r.query.parms.page > r.maxPage) return false;
    if (singleRes.length < per_page_max_res) return false;
    r.query.parms.page++;
    return true;
  }

  async invokeRequest(query: any, maxPage = max_pages) {
    const r: BitbucketRequest = new BitbucketRequest();
    r.query = query;
    r.maxPage = maxPage;

    const res = await this.rateLimitHelper.sendApiRequest(
      r.query.url,
      r,
      this.isRateLimitErrFunction,
      this.handleRequest,
      this.getQueryNextPage,
      retry_count,
      this,
    );
    return res.flat();
  }

  async getAllRepos(callObj: RulesManager): Promise<Repo[]> {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        const repo = this.getPipelineScanRepo();
        if (repo === null) return [];

        const repoByName = await this.getSingleRepositoryByName(repo.name);
        if (repoByName) return [repoByName];

        const repoById = await this.getSingleRepositoryById(repo.id);
        if (repoById) return [repoById];

        const allRepos = await this.getAllOrgRepos();
        return allRepos.filter(r => r.uuid === repo.id);
      }

      const allRepos = await this.getAllOrgRepos();

      const monitored = allRepos.filter(apiRepo => this.repoSelectedByUser(apiRepo.uuid, apiRepo.full_name, apiRepo.created_on));

      return monitored;
    } catch (err) {
      logger.error(`failed to get repos list obj for: ${this.token.type}, err: ${err}`);
    }
    return [];
  }

  async allUsers(apiRepos: any) {
    try {
      //We already asked for this data in init as we needed for
      //the rest of the flow due to the fact bitbucket not have api for users per repo
      if (this.allUsersInfo.length > 0) {
        return this.allUsersInfo;
      }

      const usersInfo: User[] = [];
      for (const workspace of this.workspaces) {
        const query = {
          func: bitbucket.workspaces.getMembersForWorkspace,
          parms: {
            funcName: "allUsers",
            workspace: workspace.name,
            page: 1,
          },
        };

        const users = await this.invokeRequest(query);
        // let users = [];
        // if (usersRes.length > 0) {
        //   users = usersRes[0];
        // }

        const request = {
          func: bitbucket.workspaces.listPermissions,
          parms: {
            funcName: "allUsers",
            workspace: workspace.name,
            pagelen: 100,
          },
          singleRequest: true,
        };

        const permissions = await this.invokeRequest(request);
        // let permissions = [];
        if (!permissions.length) {
          logger.info(`no permissions found for workspace ${workspace.name}`);
        }

        for (const user of users) {
          const userInfo = new User(user.user.display_name, user.user.nickname, user.user.uuid, user.user.links.avatar.href, "", "");

          const userPermissions = permissions.find(i => i.user.uuid === user.user.uuid);
          if (userPermissions) {
            userInfo.orgRole.add(userPermissions.permission);
          }
          userInfo.org = workspace.name;
          await this.getUserCreatedAt(userInfo);
          usersInfo.push(userInfo);
          GlobalCodeRepoData.Instance.addUser(userInfo, repoType.bitbucket);
        }
      }
      return usersInfo;
    } catch (err) {
      logger.error(`failed get all users, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.allUsers);
    }
    return [];
  }

  async auditLog(): Promise<any> {
    try {
      if (!this.token.organizationId || !this.token.apiKey) {
        logger.info(`cannot get audit logs for: ${this.token.name}, due to organizationId or apiKey empty`);
        return;
      }

      let allAuditLogs = [];
      const workspacesWithAuditLogs = new Set();
      const query = {
        url: `https://api.atlassian.com/admin/v1/orgs/${this.token.organizationId}/events`,
        method: "GET",
        headers: {
          Authorization: `Bearer ${this.token.apiKey}`,
        },
        isHttp: true,
      };
      const res = await this.invokeRequest(query);
      if (res.length > 0) {
        allAuditLogs = res[0].data;
      }
      const auditLogs = allAuditLogs.filter(i => i.attributes.action.includes("bitbucket"));

      for (const auditLog of auditLogs) {
        try {
          StatesHelper.Instance.scanInfoStats.auditLogsCount++;
          const userAuditLog: UserAuditLog = new UserAuditLog();
          const attributes = auditLog.attributes;
          const message = auditLog.message;
          const workspace = this.getAuditWorkspace(attributes);
          userAuditLog.action = attributes.action;
          userAuditLog.actionFriendly = message.content;
          userAuditLog.actionInfo = message.content;
          userAuditLog.name = this.getAuditActor(attributes);
          userAuditLog.org = workspace;
          workspacesWithAuditLogs.add(workspace);
          userAuditLog.timestamp = new Date(attributes.time);
          if (attributes.hasOwnProperty("location")) {
            const location = attributes.location;
            if (location) {
              // in case we want in future to get country code by country name
              // if (location.countryName) {
              //   userAuditLog.actorLocation = location.countryName;
              // }
              if (location.ip) {
                const actorLocation = await this.geoLocationHelper.findCountryByIP(location.ip);
                userAuditLog.ip_address = location.ip;
                userAuditLog.actorLocation = actorLocation;
              }
            }
          }
          const auditRepo = this.getAuditRepo(attributes);
          if (auditRepo) {
            userAuditLog.isRepo = true;
            userAuditLog.repo = auditRepo;
          } else {
            userAuditLog.isOrg = true;
          }

          if (!GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name]) {
            GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name] = [userAuditLog];
          } else {
            GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name].push(userAuditLog);
          }
        } catch (err) {
          logger.error(`failed procceing auditlog:${auditLog}, err:${err}`);
          StatesHelper.Instance.globalApisFails.add(resourceType.auditLog);
        }
      }

      for (const workspace of workspacesWithAuditLogs) {
        StatesHelper.Instance.orgsWithAuditLogs.add(workspace);
      }

      return res;
    } catch (err) {
      logger.error(`failed getting audit logs, err:${err}`);
    }
  }

  getAuditWorkspace(auditAttributes: any) {
    try {
      let workspace = "";
      if (auditAttributes.hasOwnProperty("container")) {
        const containers = auditAttributes.container;
        if (containers.length > 0) {
          const container = containers[0];
          if (container.hasOwnProperty("attributes")) {
            workspace = container.attributes.slug;
          }
        }
      }
      return workspace;
    } catch (err) {
      logger.error(`failed getting audit actor, err: ${err}`);
    }
  }

  getAuditRepo(auditAttributes: any) {
    try {
      let repository = "";
      if (auditAttributes.hasOwnProperty("context")) {
        const auditContexts = auditAttributes.context;
        for (const context of auditContexts) {
          if (context.type === "repository") {
            repository = context.attributes.slug;
          }
        }
      }
      return repository;
    } catch (err) {
      logger.error(`failed getting audit repo, err:${err}`);
    }
  }

  getAuditActor(auditAttributes: any) {
    try {
      let actorName = "";
      if (auditAttributes.hasOwnProperty("actor")) {
        const actor = auditAttributes.actor;
        if (actor.hasOwnProperty("name")) {
          actorName = actor.name;
        }
      }
      return actorName;
    } catch (err) {
      logger.error(`failed getting audit actor, err: ${err}`);
    }
  }

  private getUserRole(userData) {
    const { permission } = userData;
    if (permission === "admin") {
      return UserRole.OWNER;
    } else if (permission === "read") {
      return UserRole.GUEST;
    } else if (permission === "write") {
      return UserRole.DEVELOPER;
    }
    return UserRole.GUEST;
  }

  async users(repoObj: any) {
    try {
      const repo: Repo = repoObj.code_repo;
      const usersInfo: User[] = [];
      const userPremmisions = await this.getUserPrivileges(repo);
      for (const userData of userPremmisions) {
        const userRole = this.getUserRole(userData);

        const userItem = this.allUsersInfo.find(i => i.id === userData.user.uuid);
        if (userItem) {
          const userInfo = new User(userItem.name, userItem.username, userItem.id, userItem.avatarUrl, "", userItem.createdAt);
          userInfo.createdAtDays = userItem.createdAtDays;
          if (userData.permission) {
            userInfo.repoRolesRaw.push(userData.permission);
            userInfo.repoRoleName = userData.permission;
          }
          userInfo.org = userItem.org;
          userInfo.orgRole = userItem.orgRole;
          userInfo.repoRolesRaw.push(userRole);
          userInfo.role = userRole;
          usersInfo.push(userInfo);
          GlobalCodeRepoData.Instance.addUser(userInfo, repoType.bitbucket);
        }
      }
      return usersInfo;
    } catch (err) {
      logger.error(`failed get all users, err: ${err}`);
      const repo: Repo = repoObj.code_repo;
      StatesHelper.Instance.addFailedTool(repoResourceType.users, repo.id);
      return [];
    }
  }

  async getUserCreatedAt(user: User) {
    try {
      const userApi = await bitbucket.users.get({
        selected_user: user.id.toString(),
      });

      if (userApi) {
        user.createdAt = userApi.data.created_on || "";
        user.createdAtDays = timeHelper.getTimeIntervalFronNowInDays(user.createdAt);
      }
    } catch (err) {
      logger.error(`uuid: ${this.uuid}, failed to get user creation date for ${user.name}, err: ${err}`);
    }
  }

  getTokenHeader() {
    if (this.usingOathToken) {
      return {
        Authorization: `Bearer ${this.private_token}`,
      };
    }

    return { "private-token": this.private_token };
  }

  async getUserPrivileges(repo: Repo) {
    try {
      const query = {
        func: bitbucket.workspaces.listPermissionsForRepository,
        parms: {
          funcName: "getUserPrivileges",
          repo_slug: repo.id,
          workspace: repo.organization,
          pagelen: 100,
        },
        singleRequest: true,
      };

      const res = await this.invokeRequest(query);

      return res;
    } catch (err) {
      logger.error(`uuid: ${this.uuid}, failed to get all users permissions for ${repo.workspace}, err: ${err}`);
    }
  }

  getFileLinkPrefix(repo) {
    try {
      const str = repo.links.html.href + "/src/" + repo.mainbranch.name + "/";
      return str;
    } catch (err) {
      logger.error(`get file link repo name: ${repo.name}`);
    }
    return "";
  }

  getCloneUrl(repo) {
    try {
      const res = repo.links.clone.filter(i => i.name.includes("http"));
      let cloneRepo = res[0].href;
      cloneRepo = cloneRepo.replace("@", `:${this.usingOathToken ? this.private_token : this.getTokenPassword()}@`);
      return cloneRepo;
    } catch (err) {
      logger.error(`failed to get clone url for ${repo.name}, err: ${err}`);
    }

    return "";
  }

  async getSingleRepositoryByName(fullRepoName: string): Promise<any | null> {
    const [wpName, repoName] = fullRepoName.split("/");

    // unable to query otherwise
    if (!wpName || !repoName) return null;

    try {
      const query = {
        func: bitbucket.repositories.get,
        parms: {
          funcName: "getSingleRepositoryByName",
          workspace: wpName,
          pagelen: 1,
          repo_slug: repoName,
          page: 1,
        },
        singleRequest: true,
      };

      const response = await this.invokeRequest(query);

      return response.find(repo => repo.slug === repoName) ?? null;
    } catch (e) {
      logger.error(`[bitbucket] unable to find ${repoName} in getSingleRepositoryByName, e: ${e}`);
    }

    return null;
  }

  async getSingleRepositoryById(repoId: string): Promise<any | null> {
    for (const wp of this.workspaces) {
      try {
        const query = {
          func: bitbucket.repositories.get,
          parms: {
            funcName: "getSingleRepositoryById",
            workspace: wp.id,
            pagelen: 1,
            repo_slug: repoId,
            page: 1,
          },
          singleRequest: true,
        };

        const response = await this.invokeRequest(query);

        return response.find(repo => repo.uuid === repoId) ?? null;
      } catch (e) {
        logger.error(`[bitbucket] unable to find ${repoId} in workspace ${wp} in getSingleRepositoryById, e: ${e}`);
      }
    }

    return null;
  }

  async getAllOrgRepos(): Promise<any> {
    const reposPromises = this.workspaces.map(workspace => {
      logger.info(`trying getting repo for workspace: ${workspace.name}`);

      CheckmarxCLIparser.Instance.scanOrgs.push(workspace.name);

      const query = {
        func: bitbucket.repositories.list,
        parms: {
          funcName: "getAllOrgRepos",
          workspace: workspace.id,
          pagelen: per_page_max_res,
          page: 1,
        },
      };

      const res = this.invokeRequest(query);

      return res;
    });

    const workspacesRepos = await Promise.all(reposPromises);
    const allRepos = [];

    const ws = workspacesRepos.flat();

    for (const repo of ws) {
      allRepos.push(repo);
    }

    logger.info(`getAllOrgRepos for bitbucket return ${allRepos.length}`);

    return allRepos;
  }

  async webhooks(repo: Repo): Promise<any> {
    let webhooksList: Webhook[] = [];

    try {
      const query = {
        func: bitbucket.repositories.listWebhooks,
        parms: {
          funcName: "webhooks",
          workspace: repo.workspace,
          pagelen: per_page_max_res,
          repo_slug: repo.id,
          page: 1,
        },
      };

      const webhooks = await this.invokeRequest(query);
      if (!webhooks) {
        return [];
      }

      for (const webhookInfo of webhooks) {
        try {
          let webhook = new Webhook(
            webhookInfo.url,
            webhookInfo.created_at,
            "",
            "",
            true,
            webhookInfo.skip_cert_verification == false,
            webhookInfo.active,
            "",
            repo.link + "/admin/webhooks/" + webhookInfo.uuid.replace("{", "").replace("}", ""),
            webhookInfo.events,
            repoResourceType.webhooks,
          );

          webhooksList.push(webhook);
        } catch (err) {
          logger.error(`failed to create webhook obj for: ${repo.name}, webhook: ${JSON.stringify(webhookInfo, null, 4)}, err: ${err}`);
        }
      }
    } catch (err) {
      if (err.status != 404) {
        logger.error(`get webhooks failed repo: ${repo.name}, err: ${err}`);
      }
      StatesHelper.Instance.addFailedTool(repoResourceType.webhooks, repo.id);
      logger.debug(`get webhooks failed repo: ${repo.name}, err: ${err}`);
    }
    return webhooksList;
  }

  async branches(repo: Repo): Promise<any> {
    let branchsList: Branch[] = [];

    try {
      const query = {
        func: bitbucket.repositories.listBranches,
        parms: {
          funcName: "branches",
          repo_slug: repo.id,
          workspace: repo.workspace,
        },
        singleRequest: true,
      };

      const branches = await this.invokeRequest(query);
      if (!branches) {
        return [];
      }

      for (const branchInfo of branches) {
        try {
          let branch = new Branch(branchInfo.name);

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

  async branchSettings(repoObj: any) {
    const repo: Repo = repoObj.code_repo;

    const defaultBranch = repo.defaultBranch;
    let MRWithoutReviewEnabled = true;
    let pushEventsEnabled = false;
    let forceDeleteAllowed = true;
    let branchProtection = true;
    let requiredSignedCommits = false;
    let enforceAdmins = false;
    let dissmisalRestrictions = {};
    let bypassPullReqAllowances = [];

    try {
      const restrictionsQuery = {
        func: bitbucket.branchrestrictions.list,
        parms: {
          funcName: "branchSettings",
          repo_slug: repo.id,
          workspace: repo.workspace,
        },
        singleRequest: true,
      };

      const restrictions = await this.invokeRequest(restrictionsQuery);

      const branchModelQuery = {
        func: bitbucket.repositories.getBranchingModel,
        parms: {
          funcName: "branchModelQuery",
          repo_slug: repo.id,
          workspace: repo.workspace,
        },
        singleRequest: true,
      };

      const branchModelsRes = await this.invokeRequest(branchModelQuery);
      let branchModel;
      if (branchModelsRes.length > 0) {
        branchModel = branchModelsRes[0];
      }
      let isDefaultInDev = false;
      let isDefaultInProd = false;

      if (branchModel.hasOwnProperty("production")) {
        if (branchModel.production.name === defaultBranch) {
          isDefaultInProd = true;
        }
      }

      if (branchModel.hasOwnProperty("development")) {
        if (branchModel.development.name === defaultBranch) {
          isDefaultInDev = true;
        }
      }

      const restrictionUsers = [];
      const restrictedUsers = [];
      let foundPushRestriction = false;

      const relevnatRestrictions = this.getRelevantRestrictions(defaultBranch, restrictions, isDefaultInDev, isDefaultInProd);

      for (const restriction of relevnatRestrictions) {
        if (restriction.hasOwnProperty("kind")) {
          switch (restriction.kind) {
            case "push":
              foundPushRestriction = true;
              for (const user of restriction.users) {
                pushEventsEnabled = true;
                restrictionUsers.push(user);
              }

              for (const group of restriction.groups) {
                pushEventsEnabled = true;
                const groupMembers = await this.getGroupMembers(group.slug, this.token, repo.workspace);
                for (const member of groupMembers) {
                  restrictionUsers.push(member);
                }
              }
              break;

            case "delete":
              forceDeleteAllowed = false;
              break;

            case "require_approvals_to_merge":
              MRWithoutReviewEnabled = false;
          }
        }
      }

      if (!foundPushRestriction) {
        pushEventsEnabled = true;
      }

      const userMap = new Map<string, User>();

      repoObj.users.forEach(user => {
        userMap.set(user.id, user);
      });

      restrictionUsers.forEach(user => {
        restrictedUsers.push(userMap.get(user.uuid));
      });

      if (!MRWithoutReviewEnabled && !pushEventsEnabled && !forceDeleteAllowed) {
        branchProtection = false;
      }

      const settings = new BranchSettings(
        pushEventsEnabled,
        MRWithoutReviewEnabled,
        forceDeleteAllowed,
        requiredSignedCommits,
        restrictedUsers,
        enforceAdmins,
        dissmisalRestrictions,
        bypassPullReqAllowances,
        branchProtection,
      );

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

  async getGroupMembers(group: string, token: any, workspace: string) {
    // Bitbucket Cloud REST API version 1.0 is deprecated effective 30 June 2018, except certain endpoints such as groups and invitations
    // The 2.0 REST API will rely on the Atlassian Cloud Admin API for user and group management, but those API endpoints are not yet available.
    // https://support.atlassian.com/bitbucket-cloud/docs/groups-endpoint/
    try {
      const tokenAuth = `${token.userName}:${token.password}`;
      const query = {
        url: `https://api.bitbucket.org/1.0/groups/${workspace}/${group}/members`,
        method: "GET",
        headers: {
          Authorization: `Basic ${Buffer.from(tokenAuth, "utf8").toString("base64")}`,
        },
        isHttp: true,
      };
      const res = await this.invokeRequest(query);

      return res;
    } catch (err) {
      logger.error(`failed to get group:${group} members, err:${err}`);
    }
  }

  getRelevantRestrictions(defaultBranch: string, restrictions: any, isDefaultInDev: boolean, isDefaultInProd: boolean) {
    try {
      const relevantRestrictions = restrictions.filter(
        restriction =>
          restriction.pattern === defaultBranch ||
          (restriction.branch_type === "development" && isDefaultInDev) ||
          (restriction.branch_type === "production" && isDefaultInProd),
      );
      return relevantRestrictions;
    } catch (err) {
      logger.error(`failed filtering relevant restrictions, err:${err}`);
      return [];
    }
  }

  // for pipeline scan cloner feature: fetching files via API
  getAPICredentials() {
    return this.usingOathToken
      ? {
          authType: "token",
          baseUrl: this.token.host,
          token: this.private_token,
        }
      : {
          authType: "usernamePassword",
          baseUrl: this.token.host,
          username: this.token.userName,
          password: this.private_token,
        };
  }

  // for pipeline scan cloner feature: fetching files via API
  getAPIRepoInfo(repo: Repo) {
    return {
      repo: repo.id,
      workspace: repo.workspace,
    };
  }

  async findPullRequestIntroducingMergeCommit(repoObj: any, branch: string, sha: string) {
    return null;
  }

  async findFilesModifiedInPullRequest(
    repo: Repo,
    sourceBranch: string,
    targetBranch: string,
    sha: string | null,
    pullRequestId: string | null,
  ) {
    try {
      // open in production for all orgs
      StatesHelper.Instance.pipelineScanInfo.filesModifiedInPullRequest.enabled = true;

      let usedPullRequestId = pullRequestId;

      // if pullRequestId wasn't provided (i.e. Jenkins integration triggered the job, try to find a matching PR)
      if (!usedPullRequestId) {
        const pullRequestQuery = {
          func: bitbucket.repositories.listPullRequests,
          parms: {
            funcName: "getPullRequest",
            workspace: repo.workspace,
            repo_slug: repo.id,
            q: [`source.branch.name="${sourceBranch}"`, `destination.branch.name="${targetBranch}"`, 'state="OPEN"'].join(" AND "),
            page: 1,
          },
          singleRequest: true,
        };

        const pullRequestResponse = await this.invokeRequest(pullRequestQuery);
        usedPullRequestId = pullRequestResponse?.[0]?.id ?? null;
      }

      if (!usedPullRequestId) {
        logger.warn(
          `[bitbucket][findFilesModifiedInPullRequest] no pull request ID provided and found for repo: ${repo.name}, sourceBranch: ${sourceBranch}, targetBranch: ${targetBranch}, usedPullRequestId: ${usedPullRequestId}`,
        );
        return null;
      }

      const diffStatQuery = {
        func: bitbucket.repositories.getPullRequestDiffStat,
        parms: {
          funcName: "getPullRequestDiffStat",
          workspace: repo.workspace,
          repo_slug: repo.id,
          pull_request_id: usedPullRequestId,
          pagelen: 500,
          page: 1,
        },
      };

      const diffStatResponse = await this.invokeRequest(diffStatQuery);
      if (!diffStatResponse) {
        logger.warn(
          `[bitbucket][findFilesModifiedInPullRequest] diffStatResponse: ${diffStatResponse} for repo: ${repo.name}, sourceBranch: ${sourceBranch}, targetBranch: ${targetBranch}, usedPullRequestId: ${usedPullRequestId}`,
        );
        return null;
      }

      return [...new Set(diffStatResponse.map(diff => diff?.new?.path).filter(Boolean))];
    } catch (e) {
      logger.error(`[bitbucket][findFilesModifiedInPullRequest] e: ${e}`);
      return null;
    }
  }

  async tryFindingJobTriggeredBy(): Promise<string | null> {
    if (!StatesHelper.Instance.isPipelineScan) return null;

    const user = this.allUsersInfo.find(u => u.id.toString() === PipeLineHelper.Instance.pipelineScanJobInfo.jobTriggeredBy);

    if (!user) return null;

    return user.name ?? user.username ?? null;
  }

  async pulls(repoObj: any): Promise<any> {
    let pullRequestList: PullRequest[] = [];
    const repo: Repo = repoObj.code_repo;
    const commits: Commit[] = repoObj.commits;

    try {
      const query = {
        func: bitbucket.repositories.listPullRequests,
        parms: {
          funcName: "pulls",
          workspace: repo.workspace,
          repo_slug: repo.id,
          state: "MERGED",
          pagelen: 50,
          page: 1,
        },
      };

      const pulls = await this.invokeRequest(query);

      for (const pullInfo of pulls) {
        try {
          const reviewers: Reviewer[] = [];
          let pullRequest = new PullRequest(
            pullInfo.created_on,
            pullInfo.links.html.href,
            pullInfo.title,
            pullInfo.merge_commit.hash,
            pullInfo.updated_on,
            pullInfo.title,
            0,
            pullInfo.author.display_name,
            pullInfo.id,
            CodeRepoTypes.pulls,
            reviewers,
            new MergeUser(pullInfo.closed_by.display_name, pullInfo.closed_by.nickname, pullInfo.closed_by.account_id),
            true,
          );

          if (StatesHelper.Instance.policyForQueryPullsByDays) {
            if (
              pullRequest.diffFromNowToCreatedAtInDays > // the policy was modified to work with months - so we multiply
              StatesHelper.Instance.policyForQueryPullsByDays
            ) {
              StatesHelper.Instance.policyForQueryPullsByDaysSkippedRequests++;
              continue;
            }
          }

          const activitiesQuery = {
            func: bitbucket.pullrequests.listActivities,
            parms: {
              funcName: "pulls",
              workspace: repo.workspace,
              repo_slug: repo.id,
              pull_request_id: pullRequest.id,
              pagelen: 50,
              page: 1,
            },
          };

          const prHistoryActivity = await this.invokeRequest(activitiesQuery);

          const itemWithState = prHistoryActivity.filter(i => i?.update?.state);

          const mergeActivity = itemWithState.find(i => i.update.state === "MERGED");

          if (mergeActivity) {
            for (const rev of mergeActivity.update.reviewers) {
              reviewers.push(new Reviewer(rev.display_name, rev.display_name, rev.account_id));
              pullRequest.reviewerCount++;
            }
          }
          if (reviewers.length === 0) {
            const approvalActivity = prHistoryActivity.find(i => i.approval);
            if (approvalActivity) {
              reviewers.push(
                new Reviewer(
                  approvalActivity.approval.user.display_name,
                  approvalActivity.approval.user.nickname,
                  approvalActivity.approval.user.account_id,
                ),
              );
              pullRequest.reviewerCount = 1;
            }
          }

          pullRequestList.push(pullRequest);
        } catch (err) {
          logger.error(`err: ${err}, failed to create pull obj for: ${repo.name}, pull obj: ${JSON.stringify(pullInfo)}`);
          StatesHelper.Instance.addFailedTool(repoResourceType.pulls, repo.id);
        }
      }

      const proms = pullRequestList.map(i => this.getCommitRelatedToPullReq(repo, i, commits));
      await Promise.all(proms);

      pullRequestList = pullRequestList.filter(i => i.pullsCommitInfo.length > 0);

      pullRequestList.forEach(i => this.updateMailInfo(i));
    } catch (err) {
      logger.error(`get pulls failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.pulls, repo.id);
    }
    this.globalCodeRepoData.addPulls(pullRequestList, repo);
    return pullRequestList;
  }

  async getCommitRelatedToPullReq(repo: Repo, pullRequest: PullRequest, commitsFromDisk: Commit[]) {
    try {
      const query = {
        func: bitbucket.repositories.getCommit,
        parms: {
          funcName: "getCommitRelatedToPullReq",
          workspace: repo.workspace,
          repo_slug: repo.id,
          commit: pullRequest.sha,
        },
        singleRequest: true,
      };

      let commitsFromPull = [];
      const res = await this.invokeRequest(query);
      let commit;
      for (const resCommit of res) {
        try {
          let filesChanged = new Set();
          const commitInfoFromDisk = commitsFromDisk.filter(i => i.hash === resCommit.hash);
          if (commitInfoFromDisk.length > 0) {
            filesChanged = this.getFilesChangedFromCommit(res, commitsFromDisk, commitInfoFromDisk);
          } else {
            filesChanged = this.getCommitFileFromParent(resCommit, commitsFromDisk);
          }
          pullRequest.uniqueFilesChanged.push(...Array.from(filesChanged));
          commitsFromPull = [...commitsFromPull, ...commitInfoFromDisk];
          commit = resCommit;
        } catch (err) {
          logger.error(`repo: ${repo.name}, get related single commit to pull request err: ${err}`);
        }
      }

      if (commitsFromPull.length == 0) {
        pullRequest.pullsCommitInfo.push(
          new Commit(
            commit?.links?.html?.href || null,
            commit.date,
            "",
            commit?.author?.user?.display_name || "",
            commit.message,
            commit.hash,
            [],
            [],
            [],
            [],
          ),
        );
      } else {
        pullRequest.pullsCommitInfo = [...pullRequest.pullsCommitInfo, ...commitsFromPull];
      }
    } catch (err) {
      logger.error(`repo: ${repo.name}, get related commit to pull request err: ${err}`);
    }
  }

  getFilesChangedFromCommit(commits, commitsFromDisk: Commit[], relatedCommits: Commit[]) {
    const filesChanges = [];
    for (const [index, relatedCommit] of relatedCommits.entries()) {
      const commitFromAPI = commits[index];
      if (relatedCommit.uniqueFiles.length == 0) {
        filesChanges.push(this.getCommitFileFromParent(commitFromAPI, commitsFromDisk));
      } else {
        filesChanges.push(relatedCommit.uniqueFiles);
      }
    }
    return new Set(filesChanges.flat());
  }

  getCommitFileFromParent(commitFromAPI, commitsFromDisk: Commit[]) {
    const parents = commitFromAPI.parents;
    const filesChanged = [];
    for (const parent of parents) {
      const commitInfoFromDisk = commitsFromDisk.find(i => i.hash === parent.hash);
      if (commitInfoFromDisk) {
        filesChanged.push(commitInfoFromDisk.uniqueFiles);
      }
    }
    return new Set(filesChanged.flat());
  }

  async handleRequest(r: BitbucketRequest) {
    try {
      const query = r.query;

      if (query.isHttp) {
        const instance = await axiosCall(r);
        return instance;
      }

      const res = await query.func(query.parms);

      if (Array.isArray(res.data?.values)) return res.data.values;
      // covers cases when res.data is an array and when it's not expected to be one
      return res.data;
    } catch (err) {
      logger.error(`failed sending request for query: ${JSON.stringify(r.query)}, err: ${err}`);
    }
  }

  async refreshToken(clientId: string, clientSecret: string, refreshToken: string) {
    try {
      const url = `https://bitbucket.org/site/oauth2/access_token`;
      const response = await axios.post(
        url,
        qs.stringify({
          client_id: clientId,
          client_secret: clientSecret,
          grant_type: "refresh_token",
          refresh_token: refreshToken,
        }),
        {
          headers: {
            Accept: `application/json`,
            ContentType: "application/x-www-form-urlencoded",
          },
        },
      );
      if (response.status !== 200) {
        return null;
      }
      return response.data as IdentityProviderToken;
    } catch (error) {
      logger.error("failed to create identity provider token", error);
      return null;
    }
  }

  async getTimeToWait() {
    return timeout_to_wait_after_rate_limit_happen;
  }

  async getCodeBaseLastCodeChange(application) {
    const lastCodeChange = await this.getLastCodeChange(application);
    if (lastCodeChange) {
      this.setLastCodeChange(application, lastCodeChange);
    }
    return application.lastCodeChange;
  }

  getCodeRepoId(application) {
    return application.id;
  }

  async getLastCodeChange(application: any) {
    try {
      const lastCodeChangeQuery = {
        func: bitbucket.commits.list,
        parms: {
          funcName: "getLastCodeChange",
          repo_slug: application.slug,
          workspace: application.workspace.slug,
          pagelen: 1, // Get only the most recent commit
          fields: "values.date",
        },
        singleRequest: true,
      };

      const commits = await this.invokeRequest(lastCodeChangeQuery);

      if (commits.length > 0) {
        const lastCodeChange = commits[0].date;
        return lastCodeChange;
      }
    } catch (error) {
      logger.error(`Can't get last code change bitbucket Stash: ${error}`);
    }
  }

  get isBitbucketAppToken() {
    const { sharedSecret, clientKey, appKey } = this.token;
    return sharedSecret && clientKey && appKey;
  }
}

export default CodeRepoBitbucket;
