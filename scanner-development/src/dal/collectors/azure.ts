import axios from "axios";
import * as azdev from "azure-devops-node-api";
import * as ba from "azure-devops-node-api/BuildApi";
import * as gitA from "azure-devops-node-api/GitApi";
import pRetry from "p-retry";
import qs from "qs";
import RepoImportanceCalcHelper from "../../helper/appPriority/repoImportanceCalcHelper";
import loggerImport from "../../logger";
import CodeRepoBase from "../base/codeRepoBase";

const Timeout = require("await-timeout");
const logger = loggerImport.getDebugLogger();

import { ICoreApi } from "azure-devops-node-api/CoreApi";
import { IRequestHandler } from "azure-devops-node-api/interfaces/common/VsoBaseInterfaces";
import { TeamProjectReference } from "azure-devops-node-api/interfaces/CoreInterfaces";
import {
  GitCommitDiffs,
  GitCommitRef,
  GitPullRequest,
  GitPullRequestQuery,
  GitPullRequestQueryType,
  GitRepository,
  VersionControlChangeType,
} from "azure-devops-node-api/interfaces/GitInterfaces";
import { TfvcItem } from "azure-devops-node-api/interfaces/TfvcInterfaces";
import { INotificationApi } from "azure-devops-node-api/NotificationApi";
import { ITfvcApi } from "azure-devops-node-api/TfvcApi";
import { ApplicationManager } from "../../appmgr/AppManager";
import {
  Branch,
  BranchSettingAPI,
  BranchSettings,
  CodeRepoTypes,
  Commit,
  File,
  getTFSRepo,
  MergeUser,
  Organization,
  OrgRoles,
  PipelineScanInfo,
  PullRequest,
  Repo,
  repoResourceType,
  repoType,
  resourceType,
  Reviewer,
  setFileInfo,
  User,
  UserAuditLog,
  VCSType,
  Webhook,
} from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { IdentityProviderToken } from "../../entitis/IdentityProvider";
import { isDevelopment, isLocalDevelopment, isStaging } from "../../helper/envUtils";
import GeoLocationHelper from "../../helper/geoLocationHelper";
import GitHelper from "../../helper/gitHelper";
import FileHelper from "../../helper/IO/fileHlper";
import { RateLimitHelperFactory } from "../../helper/rateLimitHelper";
import StatesHelper from "../../helper/statesHelper";
import { millisToMinutesAndSeconds } from "../../helper/telemetry-utils";
import TimeHelper from "../../helper/timeHelper";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";
import GlobalCodeRepoData from "../GolobalCollectorData/globalCodeRepoData";

import { isPolicyMainBranchDoesntRequireCodeReviewViolation } from "../../policy/rules/code/policyMainBranchDoesntRequireCodeReview";
import FeatureFlags from "@oxappsec/ox-feature-flag";

const util = require("util");
const AZURE_DEV_URL = "https://dev.azure.com/";
enum Roles {
  READ = 1,
  WRITE = 2,
  ADMIN = 3,
  OWNER = 4,
}

type RoleKeys = keyof typeof Roles;

const exec = util.promisify(require("child_process").exec);
interface OrganizationClient {
  connection: azdev.WebApi;
  git: gitA.IGitApi;
  notification: INotificationApi;
  build: ba.IBuildApi;
  core: ICoreApi;
  tfs: ITfvcApi;
}

class AzureRepoRequest {
  repo: Repo;
  query: any;
  orgsClient: OrganizationClient;
  needNextPage: boolean = false;
}

const TOP = 1000;
const retry_count = 4;
const timeout_to_wait_after_rate_limit_happen = 1000 * 60 * 3;

interface TfvcRepository extends TfvcItem {
  org: string;
  id: string;
  name: string;
  webUrl: string;
  tfvc: true;
  project: TeamProjectReference;
}

let git: gitA.IGitApi;
let tfsSingleOrg: ITfvcApi;
let notification: INotificationApi;
let build: ba.IBuildApi;
let core: ICoreApi;
let authHandler: IRequestHandler;
let connection: azdev.WebApi;
const client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";

const max_pages = 5;
const refreshInterval = 1000 * 60 * 45;

const projectsMap = new Map();
const teamsRolesMap = new Map();
const groupsMap = new Map();
const groupSidMap = new Map();
const repoGroupsMap = new Map();
const groupsNameIdMap = new Map();

class CodeRepoAzureRepoes extends CodeRepoBase {
  fileHelper: FileHelper;
  refresh_token: string;
  usingOathToken: boolean = false;
  private_token: string;
  organizations: string[];
  orgsClients = new Map<string, OrganizationClient>();
  appMgr: ApplicationManager;
  orgNameToLastUpdate = {};
  tokenExpirationInMinutes: number = 30;
  timeHelper: TimeHelper;
  geoLocationHelper: GeoLocationHelper;
  orgs = [];
  accessToken: string;
  isCustomHost: boolean;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.fileHelper = new FileHelper(this.uuid);
    this.rateLimitHelper = RateLimitHelperFactory.getRateLimitHelperPerToken(this.token.name, 500);

    let tempToken = token.password;
    const isIdpToken = this.isJson(token.password);

    if (isIdpToken) {
      const idpToken = JSON.parse(token.password);
      tempToken = idpToken.access_token;
      this.refresh_token = idpToken.refresh_token;
      this.usingOathToken = true;

      setInterval(this.refreshTokenAndSetToken, refreshInterval, this);
    }

    this.private_token = tempToken;
    this.appMgr = new ApplicationManager(this.uuid);
    this.timeHelper = new TimeHelper("");
    this.geoLocationHelper = new GeoLocationHelper();
    this.accessToken = Buffer.from(":" + this.token.password).toString("base64");

    this.isCustomHost = false;

    if (!this.token.host.includes(AZURE_DEV_URL)) {
      this.isCustomHost = true;
    }
  }

  async initLib() {
    // logger.info(`try init lib for: ${this.token.name}, url: ${this.token.host}`);

    if (this.usingOathToken) {
      logger.info(`try init lib for: ${this.token.name}, url: ${this.token.host}, connection type: 0auth`);
      // Refresh token first
      const refreshToken = (await this.refreshToken()) as any;
      this.private_token = refreshToken.access_token;
      if (refreshToken.expires_in) {
        this.tokenExpirationInMinutes = Number(refreshToken.expires_in) / 60 / 2;
        logger.info(`setting refresh token for: ${this.tokenExpirationInMinutes} minutes`);
      } else {
        logger.info(`cannot find refresh token time using default: ${this.tokenExpirationInMinutes} minutes`);
      }
      logger.info(`try to connect to azure via 0auth`);
      authHandler = azdev.getPersonalAccessTokenHandler(this.private_token);
      logger.info(`Azure 0auth connected succefully`);
      const organizations = await this.getAzureDevOpsOrganizationNames(this.private_token);
      this.organizations = organizations;
      this.orgs = organizations.map(org => new Organization(org, "", null, null));
    } else {
      logger.info(`try init lib for: ${this.token.name}, url: ${this.token.host}, connection type: PAT`);
      let isRunningOnVisualStudio = false;

      authHandler = azdev.getPersonalAccessTokenHandler(this.token.password);

      // Microsoft on-premise
      if (this.token.host.includes(".visualstudio.com")) {
        logger.info(
          `identify visualstudio for for: ${this.token.name}, url: ${this.token.host}, using the host as org: ${this.token.host}`,
        );
        this.orgs = [new Organization(this.token.host, "", null, null)];
        isRunningOnVisualStudio = true;
      }

      // if default host, no suffix, get all orgs that account has access to
      else if (this.token.host === AZURE_DEV_URL) {
        this.orgs = await this.getOrgs();
        logger.info(`identify AZURE_DEV_URL for for: ${this.token.name}, url: ${this.token.host}, asking for orgs`);
      } else {
        let orgName = new URL(this.token.host).pathname.replace("/", "");
        logger.info(`identify orgName: ${orgName} for for: ${this.token.name}, url: ${this.token.host}, using as org: ${orgName}`);

        //Fix for MS
        if (orgName === "") {
          orgName = this.token.host;
        }

        if (orgName == "") {
          // non default host, and no suffix as orgname
          this.orgs = await this.getOrgs();
        } else {
          // we have default host with org name as suffix
          this.orgs = [new Organization(orgName, "", null, null)];
        }
      }

      for (const org of this.orgs) {
        const hostName = new URL("/", this.token.host).href;

        if (isRunningOnVisualStudio) {
          connection = new azdev.WebApi(`${this.token.host}`, authHandler, {
            socketTimeout: 10 * 60 * 1000,
          });
        } else {
          connection = new azdev.WebApi(`${hostName}${org.name}`, authHandler, {
            socketTimeout: 10 * 60 * 1000,
          });
        }

        git = await connection.getGitApi();
        tfsSingleOrg = await connection.getTfvcApi();
        notification = await connection.getNotificationApi();
        build = await connection.getBuildApi();
        core = await connection.getCoreApi();
        this.orgsClients.set(org.name, {
          connection,
          git,
          notification,
          build,
          core,
          tfs: tfsSingleOrg,
        });
      }

      // const organizations = await this.getAzureDevOpsOrganizationNames(this.private_token);
      // this.organizations = organizations;
    }

    logger.info(`finish init lib for: ${this.token.name}, url: ${this.token.host}`);
  }

  async getOrgs() {
    try {
      let orgs: Organization[] = [];

      let uri = `https://app.vssps.visualstudio.com/_apis/profile/profiles/me/?api-version=7.0`;

      if (this.isCustomHost) {
        uri = `${this.token.host}_apis/profile/profiles/me/?api-version=7.0`;
      }

      const query = {
        functionName: "getAuthedUser",
        params: {
          options: this.getDefaultOptions(),
          uri,
        },
      };
      const req = axios.get<any>(query.params.uri, query.params.options);
      const res = await req;
      const data = res.data;

      let acountId;
      if (data.hasOwnProperty("publicAlias")) {
        acountId = data.publicAlias;
      } else if (data.id) {
        acountId = data.id;
      }

      if (acountId) {
        uri = `https://app.vssps.visualstudio.com/_apis/accounts?memberId=${acountId}&api-version=7.0`;
        if (this.isCustomHost) {
          uri = `${this.token.host}_apis/profile/profiles/me/?api-version=7.0`;
        }

        const request = {
          functionName: "getAccounts",
          params: {
            options: this.getDefaultOptions(),
            uri,
          },
        };
        const req2 = axios.get<any>(request.params.uri, request.params.options);
        const res2 = await req2;
        const orgsJson = res2.data.value;

        orgs = orgsJson.map(org => new Organization(org.accountName, org.accountId, null, null));
      }
      return orgs;
    } catch (err) {
      logger.error(`failed getting all orgs related to verified account, err: ${err}`);
    }
    return [];
  }

  getAuth() {
    return {
      username: "",
      password: this.private_token,
    };
  }

  getAllOrgs() {
    return this.orgs;
  }

  getLinkFilePreffix(apiRepo, pipelineScanInfo: PipelineScanInfo) {
    if (apiRepo.tfvc == true) {
      return "&lineStartColumn=1&line=";
    }

    let branchValueForParam = null;

    if (apiRepo.defaultBranch) {
      branchValueForParam = apiRepo.defaultBranch.replace("refs/heads/", "");
    }

    if (pipelineScanInfo.sourceBranch) {
      branchValueForParam = pipelineScanInfo.sourceBranch;
    }

    const branchParam = branchValueForParam ? `&version=GB${branchValueForParam}` : "";

    return `${branchParam}&lineStartColumn=1&line=`;
  }

  getRepo(apiRepo) {
    const isTfvc = apiRepo.tfvc == true;
    const pipelineScanInfo = this.getPipelineScanInfo(apiRepo.id, apiRepo.name);
    const linkFilePreffix = this.getLinkFilePreffix(apiRepo, pipelineScanInfo);
    const defaultBranch = apiRepo.defaultBranch ? this.getBranchFromRef(apiRepo.defaultBranch) : "main";
    const cloneUrl = this.getCloneUrl(apiRepo.remoteUrl);

    let cloneHeaders = [];
    if (!isTfvc && cloneUrl && !cloneUrl.includes("@")) {
      // In case we don't have an associated user and password, we need to pass the token as a header
      if (this.usingOathToken) {
        cloneHeaders = [`-c`, `http.extraHeader=Authorization: Bearer ${this.private_token}`];
      } else {
        cloneHeaders = [`-c`, `http.extraHeader=Authorization: Basic ${this.accessToken}`];
      }
    }

    let isPrivate = true;

    if (apiRepo?.project?.visibility) {
      isPrivate = apiRepo?.project?.visibility == "private" ? true : false;
    }

    let fullName = apiRepo.name;
    if (apiRepo?.project?.name) {
      fullName = `${apiRepo.project.name} / ${apiRepo.name}`;
    }

    let repo = new Repo(
      this.uuid,
      this.orgName,
      this.token.name,
      apiRepo.name,
      isTfvc ? apiRepo.name : apiRepo.id,
      fullName,
      isTfvc ? apiRepo.changeDate : "",
      defaultBranch,
      apiRepo.description || "",
      isTfvc ? false : apiRepo.isDisabled,
      isTfvc ? this.token.host : cloneUrl,
      0,
      true,
      true,
      true,
      "",
      isPrivate,
      [],
      0,
      0,
      "",
      apiRepo.webUrl,
      0,
      isTfvc ? apiRepo.changeDate : apiRepo.lastCodeChange,
      apiRepo?.project?.id,
      apiRepo.webUrl + "?path=",
      linkFilePreffix,
      0,
      isTfvc ? "" : apiRepo.webUrl,
      isTfvc ? "" : apiRepo.webUrl + "/commit/",
      isTfvc ? "" : apiRepo.webUrl + "/pushes",
      isTfvc ? "" : apiRepo.webUrl + "/pullrequest",
      isTfvc ? apiRepo.org : this.getOrganizationFromUrl(apiRepo.webUrl),
      isTfvc ? apiRepo.name : apiRepo.id,
      false,
      apiRepo.name,
      pipelineScanInfo,
      isTfvc ? VCSType.tfvc : VCSType.git,
      undefined,
      cloneHeaders,
    );
    repo.projectName = apiRepo?.project?.name;
    return repo;
  }

  getBranchFromRef(ref: string) {
    return ref.split("refs/heads/")[1];
  }

  async setRepo(apiRepo, repoObj) {
    try {
      const isTfvc = apiRepo.tfvc == true;
      const repo: Repo = this.getRepo(apiRepo);

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

      const promise = await this.appMgr.CreateRepoNode({
        repo_name: apiRepo.name,
        repo_id: apiRepo.id,
        vcs_type: "azure",
        url: apiRepo.webUrl,
        default_branch: apiRepo.defaultBranch,
      });

      if (apiRepo.delta) {
        repo.isDelta = true;
      }

      //Must clone here
      if (repo.noneRelevantRepo) {
        this.fileHelper.createDir(repo.cloneDir);
      } else {
        if (isTfvc) {
          const token = this.usingOathToken ? this.private_token : this.token.password;
          const path = apiRepo.path ?? "$/";
          const url = this.token.host;

          repo.tfsUrl = url;
          repo.tfsRepoClonePath = path;
          repo.tfsToken = token;
        }
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
      repo.gitRoles = this.getGitRoles(repoType.azureGit.toLowerCase());
      await this.getAndSetRepoDevLanguagesKubernetesAndOrchestrator(repo, filesList);

      repo.deploymentFilesYmls = this.getDeploymentFilesYmls(filesList);

      return repo;
    } catch (err) {
      logger.error(`failed to create repo obj for: ${JSON.stringify(apiRepo)}, err: ${err}`);
    }
    return null;
  }

  getOwnerName() {
    const res = connection.vsoClient.basePath.split("/")[1];
    return res;
  }

  getCloneUrl(url: string) {
    try {
      if (!url) {
        return;
      }

      const cloneRepo = url.replace("@", `:${this.usingOathToken ? this.private_token : this.getTokenPassword()}@`);
      return cloneRepo;
    } catch (err) {
      logger.error(`failed to get clone url obj for: ${this.token.type}, err: ${err}`);
    }
    return "";
  }

  async getSingleRepositoryByIdInOrganizations(repositoryId: string) {
    for (const org of this.organizations) {
      try {
        await this.validateToken(org);
      } catch (e) {
        logger.error(`failed to validate token for ${org}`, e);
        continue;
      }
      try {
        const repository = await this.orgsClients.get(org).git.getRepository(repositoryId);
        if (!repository) {
          logger.warn(`repository ${repositoryId} wasn't found in ${org}`);
          continue;
        }

        logger.info(`repository ${repositoryId} was found in ${org}`);
        return repository;
      } catch (e) {
        logger.error(`failed to fetch repository ${repositoryId} for ${org}`, e);
        continue;
      }
    }
    logger.warn(`repository ${repositoryId} wasn't found in any available orgs when usingOathToken === true`);
    return null;
  }

  async getSingleRepositoryByIdInSingleOrganization(repositoryId: string) {
    try {
      const repository = await git.getRepository(repositoryId);

      if (!repository) {
        logger.warn(`repository ${repositoryId} wasn't found`);
      }

      return repository;
    } catch (e) {
      logger.error(`failed to fetch repository ${repositoryId}`, e);
    }
    return null;
  }

  async getSingleRepositoryById(repositoryId: string) {
    if (this.usingOathToken) {
      return this.getSingleRepositoryByIdInOrganizations(repositoryId);
    }

    return this.getSingleRepositoryByIdInSingleOrganization(repositoryId);
  }

  async getAllRepos(callObj: RulesManager) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        const repoId = this.getPipelineScanRepoId();
        if (repoId === null) return [];
        const repo = await this.getSingleRepositoryById(repoId);
        return repo === null ? [] : [repo];
      }

      let allRepos = [];
      if (this.usingOathToken) {
        allRepos = await this.getOrginizationsRepositories();
        let tfsRepos = await this.getOrganizationsTfvcRepositories();
        tfsRepos = tfsRepos.filter(i => i.name != undefined && i.name !== "$/");
        allRepos = [...tfsRepos, ...allRepos];
      } else {
        for (const org of this.orgs) {
          allRepos = [...allRepos, ...(await this.getSingleOrginizationRepositories(org.name))];
        }
      }

      let monitored = allRepos.filter(apiRepo => this.repoSelectedByUser(apiRepo.id, apiRepo.name, apiRepo.changeDate));
      //monitored = monitored.slice(0, 2);

      return monitored;
    } catch (err) {
      logger.error(`failed to get repos list obj for: ${this.token.type}, err: ${err}`);
    }
    return [];
  }

  async getOrginizationsRepositories() {
    let totalRepos: GitRepository[] = [];
    for (const org of this.organizations) {
      try {
        await this.validateToken(org);
      } catch (e) {
        logger.error("failed to validate token");
        return [];
      }
      try {
        const res = await this.orgsClients.get(org).git.getRepositories(null, true);

        totalRepos.push(...res);
      } catch (e) {
        logger.error(`failed to fetch repos for ${org}`, e);
        return [];
      }
    }

    return totalRepos;
  }

  async getOrganizationsTfvcRepositories() {
    let totalRepos: TfvcRepository[] = [];
    for (const org of this.organizations) {
      try {
        await this.validateToken(org);
      } catch (e) {
        logger.error("failed to validate token");
        return [];
      }
      try {
        const projects = await this.orgsClients.get(org).core.getProjects();
        const items = await this.orgsClients.get(org).tfs.getItems();

        const tfsRepos = items.filter(i => i.isFolder && i.path != undefined && i.path !== "$/");

        const repos = tfsRepos.map(i => {
          const name = getTFSRepo(i.path);
          const projectName = projects.find(i => i.name === getTFSRepo(name));
          if (!projectName) {
            logger.warn(`cannot find project name for repo name: ${name}`);
          }
          const item = i as TfvcRepository;
          item.org = org;
          item.id = name;
          item.name = name;
          item.webUrl = i.url ?? "";
          item.tfvc = true;
          item.project = projectName;
          return item;
        });

        totalRepos.push(...repos);
      } catch (e) {
        logger.error(`failed to fetch tfs repos for ${org}`, e);
        return [];
      }
    }
    return totalRepos;
  }

  async groups(repoObj) {
    try {
      const repo: Repo = repoObj.code_repo;
      const res = await this.getRepoGroupsACL(repoObj);
      const accessControlList = res[0].acesDictionary;

      for (const [g, group] of Object.entries(accessControlList) as any) {
        const sid = g.split(";")[1];
        if (sid) {
          groupSidMap.set(`${repo.name}_${sid}`, group.extendedInfo.effectiveAllow);
        }
      }

      const groups = await this.getGroupsIdentities(repoObj, accessControlList);

      groups.map(group => groupsMap.set(group.id, group));
      groups.map(group => groupsNameIdMap.set(`${repo.name}_${group.id}`, group.providerDisplayName));

      await this.calcRepoGroupsEffectivePermissions(repoObj);
      this.setRolesForGroups(repo);
    } catch (e) {
      logger.error(`groups failed, err: ${e}`);
    }
  }
  async calcRepoGroupsEffectivePermissions(repoObj) {
    const repo: Repo = repoObj.code_repo;
    const map = new Map();
    try {
      const gitPermissions = await this.getNameSpacePermissions(repo);
      for (const [groupId, group] of groupsMap.entries()) {
        const sid = group.descriptor.split(";")[1];
        const acl = groupSidMap.get(`${repo.name}_${sid}`);
        const effectiveArray = [];
        // for (const bit of Object.values(gitPermissionsMap.get(repo.organization)) as any) {
        for (const bit of Object.values(gitPermissions) as any) {
          const action = { displayName: "", effective: null }; // todo typed obj
          action.displayName = bit.displayName;
          if (acl & bit.bit) {
            action.effective = true;
          } else {
            action.effective = false;
          }
          effectiveArray.push(action);
        }
        const groupPerms = map.set(`${repo.name}_${group.id}`, effectiveArray);
        //
        repoGroupsMap.set(repo.name, groupPerms);
      }
    } catch (e) {
      logger.error(`calcRepoGroupsEffectivePermissions failed, err: ${e}`);
    }
  }

  setRolesForGroups(repo) {
    const map = new Map();
    logger.info(`start setRolesForTeams for repo: ${repo.name}`);
    try {
      const repoGroups = repoGroupsMap.get(repo.name);
      for (const [groupId, permissions] of repoGroups) {
        for (const permission of permissions) {
          if (permission.displayName === "Read") {
            if (permission.effective) {
              if (teamsRolesMap.get(groupId) !== "write") {
                teamsRolesMap.set(groupId, "read");
              }
            }
          }

          if (permission.displayName === "Contribute") {
            if (permission.effective) {
              teamsRolesMap.set(groupId, "write");
            }
          }

          if (permission.displayName === "Administer") {
            if (permission.effective) {
              teamsRolesMap.set(groupId, "admin");
            }
          }
        }

        try {
          const groupName = groupsNameIdMap.get(groupId);

          if (groupName) {
            if (groupName.toLowerCase().includes("project collection administrators")) {
              teamsRolesMap.set(groupId, "owner");
            }

            if (groupName.toLowerCase().includes("project collection valid users")) {
              teamsRolesMap.set(groupId, "member");
            }

            if (groupName.toLowerCase().includes("project administrators")) {
              teamsRolesMap.set(groupId, "admin");
              continue;
            }
          }
        } catch (e) {
          logger.error(e);
        }
      }
      logger.info(`finish setRolesForTeams for repo: ${repo.name}`);
    } catch (e) {
      logger.error(`setRolesForGroups failed, err: ${e}`);
    }
  }

  async getRepoGroupsACL(repoObj) {
    const repo: Repo = repoObj.code_repo;
    const { organization: org } = repo;

    let uri = `https://dev.azure.com/${org}/_apis/AccessControlLists/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87?token=repoV2/${repo.project}/${repo.id}&includeExtendedInfo=true&recurse=false`;

    if (this.isCustomHost) {
      uri = `${this.token.host}/_apis/AccessControlLists/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87?token=repoV2/${repo.project}/${repo.id}&includeExtendedInfo=true&recurse=false`;
    }

    try {
      const query = {
        functionName: "acl",
        params: {
          options: this.usingOathToken
            ? {
                auth: {
                  username: "",
                  password: this.private_token,
                },
                headers: {
                  "Content-Type": "application/json",
                },
              }
            : {
                auth: {
                  username: "",
                  password: this.token.password,
                },
                headers: {
                  "Content-Type": "application/json",
                },
              },
          uri,
        },
        isHttp: true,
      };

      const res = await this.invokeRequest(repo, query);

      // const res = axios.get<any>(query.params.uri, query.params.options);

      return res;
    } catch (e) {
      logger.error(`getACL failed, err: ${e}, repo: ${repoObj.code_repo.name}`);
    }
  }

  async getNameSpacePermissions(repo) {
    try {
      const { organization: org } = repo;

      let uri = `https://dev.azure.com/${org}/_apis/SecurityNamespaces/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87?api-version=7.0`;
      if (this.isCustomHost) {
        uri = `${this.token.host}/_apis/SecurityNamespaces/2e9eb7ed-3c0a-47d4-87c1-0ffdd275fd87?api-version=7.0`;
      }
      const query = {
        functionName: "getNameSpacePermissions",
        params: {
          options: this.usingOathToken
            ? {
                auth: {
                  username: "",
                  password: this.private_token,
                },
                headers: {
                  "Content-Type": "application/json",
                },
              }
            : {
                auth: {
                  username: "",
                  password: this.token.password,
                },
                headers: {
                  "Content-Type": "application/json",
                },
              },
          uri,
        },
        isHttp: true,
      };

      const res = await this.invokeRequest(repo, query);

      return res[0].actions;
    } catch (e) {
      logger.error(`getNameSpacePermissions failed. err: ${e}`);
    }
  }

  async getGroupsIdentities(repoObj, groups) {
    const repo: Repo = repoObj.code_repo;
    const { organization: org } = repo;
    try {
      const identities = (Object.values(groups) as any).map(group => group.descriptor);
      const identitiesString = identities.join(",");
      let uri = `https://vssps.dev.azure.com/${org}/_apis/identities?descriptors=${identitiesString}&queryMembership=Direct&api-version=7.0`;
      if (this.isCustomHost) {
        uri = `${this.token.host}/_apis/identities?descriptors=${identitiesString}&queryMembership=Direct&api-version=7.0`;
      }
      const query = {
        functionName: "getGroupsIdentities",
        params: {
          uri,
          options: this.usingOathToken
            ? {
                auth: {
                  username: "",
                  password: this.private_token,
                },
                headers: {
                  "Content-Type": "application/json",
                },
              }
            : {
                auth: {
                  username: "",
                  password: this.token.password,
                },
                headers: {
                  "Content-Type": "application/json",
                },
              },
        },
        // data,
        isHttp: true,
      };

      const res = await this.invokeRequest(repo, query);

      return res;
    } catch (e) {
      logger.error(`getGroupsIdentities failed. err: ${e}`);
    }
  }

  async assignPermToUser(user: User, repo: Repo) {
    try {
      const roles = [];

      for (const [groupId, group] of groupsMap.entries()) {
        try {
          let users = group.members?.map(user => user.split("\\")[1]);

          if (users?.includes(user.email)) {
            let role = (teamsRolesMap.get(`${repo.name}_${groupId}`) || teamsRolesMap.get(group.providerDisplayName))?.toUpperCase();

            if (role === "OWNER") {
              user.orgRole.add("owner");
              continue;
            } else if (!role) {
              continue;
            }
            roles.push(Roles[role]);
          }
        } catch (e) {
          logger.error(`assignPermToUser for group ${groupId} failed, err :${e}`);
        }
      }
      const highestRole = Roles[Math.max(...Object.values(roles))];
      user.repoPermissions = highestRole;
      user.repoRolesRaw.push(highestRole);
      user.repoRoleName = highestRole;
    } catch (e) {
      logger.error(`assignPermToUser failed, err :${e}`);
    }
  }

  async getSingleOrginizationRepositories(org: string) {
    logger.info(`try to get all repos for org : ${org}`);
    try {
      // let uri = `https://dev.azure.com/${org}/_apis/git/repositories?api-version=7.0`;
      // if (this.isCustomHost) {
      //   uri = `${this.token.host}/_apis/git/repositories?api-version=6.1`;
      // }

      // const query = {
      //   functionName: "getOrgRepos",
      //   params: {
      //     options: this.getDefaultOptions(),
      //     uri,
      //   },
      // };
      // const req = axios.get<any>(query.params.uri, query.params.options);
      // const res = await req;
      const gitRepos = (await this.orgsClients.get(org).git.getRepositories(null, true)) as any;

      gitRepos.forEach(i => (i.tfvc = false));

      logger.info(`finish get all repos for org : ${org}`);
      for (const repo of gitRepos) {
        projectsMap.set(repo.name, repo);
      }

      const projects = (await tfsSingleOrg.getItems()) as any;
      const tfsRepos = projects.filter(i => i.isFolder && i.path != undefined && i.path !== "$/");
      const repos = tfsRepos.map(i => {
        const name = getTFSRepo(i.path);
        const projectName = projects.find(i => i.name === getTFSRepo(name));
        if (!projectName) {
          logger.warn(`cannot find project name for repo name: ${name}`);
        }
        const item = i as TfvcRepository;
        item.org = "";
        item.id = name;
        item.name = name;
        item.webUrl = i.url ?? "";
        item.tfvc = true;
        item.project = projectName;
        return item;
      });

      const tfsReposNew = repos.filter(i => i.name != undefined && i.name !== "$/");

      return [...gitRepos, ...tfsReposNew];
    } catch (e) {
      logger.error("failed to fetch repos", e);
      return [];
    }
  }

  async webhooks(repo: Repo) {
    if (repo.vcsType === VCSType.tfvc) return [];

    let webhooksList: Webhook[] = [];
    const { organization } = repo;
    if (this.usingOathToken) {
      try {
        await this.validateToken(organization);
      } catch (e) {
        logger.error(`failed to validate token for ${organization}`);
        StatesHelper.Instance.addFailedTool(repoResourceType.webhooks, repo.id);
      }
    }

    const org = this.usingOathToken ? organization : this.token.userName;
    let uri = `https://dev.azure.com/${org}/_apis/hooks/subscriptions?api-version=6.0`;
    let webhookUri = `https://dev.azure.com/${org}/${repo.name}/_settings/serviceHooks`;
    if (this.isCustomHost) {
      uri = `${this.token.host}/_apis/hooks/subscriptions?api-version=6.0`;
      webhookUri = `${this.token.host}/${repo.name}/_settings/serviceHooks`;
    }

    try {
      const query = {
        functionName: "webhooks",
        params: {
          options: this.getDefaultOptions(),
          uri,
        },
      };

      const res = await this.invokeRequest(repo, query);

      for (const webhookInfo of res) {
        if (webhookInfo.publisherInputs.projectId !== repo.project) continue;
        try {
          let webhook = new Webhook(
            webhookInfo.consumerInputs.url,
            webhookInfo.createdDate,
            "",
            "",
            webhookInfo.consumerInputs.basicAuthPassword ? true : false,
            webhookInfo.consumerInputs.url.startsWith("https") ? true : false,
            webhookInfo.status === "enabled" ? true : false,
            webhookInfo.actionDescription,
            webhookUri,
            [webhookInfo.eventType],
            repoResourceType.webhooks,
          );
          webhooksList.push(webhook);
        } catch (err) {
          logger.error(
            `uuid: ${this.uuid}, failed to create webhook obj for: ${repo.name}, webhook: ${JSON.stringify(webhookInfo)}, err: ${err}`,
          );
        }
      }
    } catch (err) {
      if (err.status != 404) {
        logger.error(`uuid: ${this.uuid}, get webhooks failed repo: ${repo.name}, err: ${err}`);
      }
      logger.debug(`uuid: ${this.uuid}, get webhooks failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.webhooks, repo.id);
    }

    return webhooksList;
  }

  async auditLog(reposObj: any): Promise<any> {
    try {
      logger.info(`try parse audit logs`);
      const startTime = new Date().getTime();
      // await Promise.all([this.auditLogByOrg()]);
      await this.auditLogByOrg(reposObj);

      let elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));
      StatesHelper.Instance.scanInfoStats.audiLogTime = elapsedTime;
      logger.info(`finish parse audit logs, audit logs count: ${StatesHelper.Instance.scanInfoStats.auditLogsCount}`);
    } catch (err) {
      logger.error(`get audit all logs failed, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.auditLog);
    }
  }

  async auditLogByOrg(reposObj: any) {
    for (const org of this.orgs) {
      try {
        let uri = `https://auditservice.dev.azure.com/${org.name}/_apis/audit/auditlog?api-version=7.0-preview.1`;

        if (this.isCustomHost) {
          uri = `${this.token.host}/_apis/audit/auditlog?api-version=7.0-preview.1`;
        }

        const query = {
          functionName: "auditLogByOrg",
          params: {
            options: this.getDefaultOptions(),
            uri,
          },
        };

        const req = axios.get<any>(query.params.uri, query.params.options);
        const res = await req;
        const auditLogs = res.data.decoratedAuditLogEntries;
        if (auditLogs.length > 0) {
          StatesHelper.Instance.orgsWithAuditLogs.add(org.name);
        }
        const auditRelevantTypes = ["Git", "Group", "Licensing", "Organization", "Permissions", "Project", "Token", "Security"];
        let relevatnAuditLogs = [];
        const repos = reposObj.map(i => i.code_repo);
        for (const event of auditLogs) {
          const auditLogType = event.actionId.split(".")[0];
          if (auditRelevantTypes.find(i => i === auditLogType)) {
            relevatnAuditLogs.push(event);
          }
        }
        relevatnAuditLogs = relevatnAuditLogs.filter(i => i.actorDisplayName != "Azure DevOps Service");
        const auditMap = new Map();
        for (const event of relevatnAuditLogs) {
          const correlationId = event.correlationId;
          if (!auditMap.has(correlationId)) {
            auditMap.set(correlationId, []);
          }
          auditMap.get(correlationId).push(event);
        }
        const auditLogProms = [];
        for (const [key, audits] of auditMap.entries()) {
          try {
            const apiAuditLog = audits[0];
            auditLogProms.push(this.processAuditLog(apiAuditLog, org, repos));
          } catch (e) {
            logger.error(`processAuditLog failed, err :${e}`);
          }
        }
        await Promise.all(auditLogProms);
        logger.info(`finish process all sudit Logs`);
      } catch (err) {
        logger.error(`failed getting audit logs, err: ${err}`);
      }
    }
  }

  async processAuditLog(apiAuditLog: any, org: string, repos: Repo[]) {
    try {
      const userAuditLog: UserAuditLog = new UserAuditLog();
      StatesHelper.Instance.scanInfoStats.auditLogsCount++;

      const data = apiAuditLog.data;
      userAuditLog.action = apiAuditLog.actionId;
      userAuditLog.actionFriendly = apiAuditLog.details;
      userAuditLog.name = apiAuditLog.actorDisplayName;
      userAuditLog.org = org;
      userAuditLog.ip_address = apiAuditLog.ipAddress;
      userAuditLog.timestamp = new Date(apiAuditLog.timestamp);
      const location = await this.geoLocationHelper.findCountryByIP(apiAuditLog.ipAddress);
      if (location) {
        userAuditLog.actorLocation = location;
      }
      const auditArea = apiAuditLog.area;
      if (data.hasOwnProperty("RepoName")) {
        userAuditLog.isRepo = true;
        userAuditLog.repo = data.RepoName;
      }

      if (auditArea === "Group" || auditArea === "Permissions") {
        let groupName;

        if (data.hasOwnProperty("GroupId")) {
          groupName = this.getGroupNameFromAPIResult(data.GroupName);
        }

        if (auditArea === "Permissions") {
          const details: string = apiAuditLog.details;
          if (!details.includes(org)) {
            groupName = this.getGroupNameFromAPIResult(apiAuditLog.details);
          }
        }

        if (groupName) {
          if (groupName === org) {
            userAuditLog.isOrg = true;
          } else {
            const relevantRepos = repos.filter(i => i.projectName === groupName);
            for (const repo of relevantRepos) {
              this.createAuditForRepo(userAuditLog, repo);
            }
            return;
          }
        }
      }

      if (!userAuditLog.isRepo) {
        userAuditLog.isOrg = true;
      }

      if (!GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name]) {
        GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name] = [userAuditLog];
      } else {
        GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name].push(userAuditLog);
      }
    } catch (err) {
      logger.error(`failed audit log, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.auditLog);
    }
  }

  createAuditForRepo(userAuditLog: UserAuditLog, repo: Repo) {
    try {
      userAuditLog.isRepo = true;
      userAuditLog.repo = repo.name;
      if (!GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name]) {
        GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name] = [userAuditLog];
      } else {
        GlobalCodeRepoData.Instance.auditLogBasedOnUser[userAuditLog.name].push(userAuditLog);
      }
    } catch (e) {
      logger.error(`createAuditForRepo failed, err: ${e}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.auditLog);
    }
  }

  getGroupNameFromAPIResult(apiResult: string) {
    try {
      const groupNameArr = apiResult.split("]\\");
      const groupName = groupNameArr[0].split("[")[1];
      return groupName;
    } catch (e) {
      logger.error(`getGroupNameFromAPIResult failed, err: ${e}, ${apiResult}`);
    }
  }

  async branches(repo: Repo) {
    let branchsList: Branch[] = [];
    try {
      if (repo.vcsType === VCSType.tfvc) {
        let branches = [];
        if (this.usingOathToken) {
          branches = await this.orgsClients.get(repo.organization).tfs.getBranches(repo.name);
        } else {
          branches = await tfsSingleOrg.getBranches(repo.name);
        }
        for (const branchInfo of branches) {
          try {
            const bPath = branchInfo.path;
            const index = bPath.lastIndexOf("/");
            if (index == -1) {
              continue;
            }
            const bName = bPath.substring(index + 1, bPath.length);
            let branch = new Branch(bName);
            branchsList.push(branch);
          } catch (err) {
            logger.error(`failed get single branches repo: ${repo.name}, err: ${err}`);
            StatesHelper.Instance.addFailedTool(repoResourceType.branches, repo.id);
          }
        }
        return branchsList;
      }

      const { organization } = repo;
      if (this.usingOathToken) {
        try {
          await this.validateToken(organization);
        } catch (e) {
          logger.error(`failed to validate token for ${organization}`);
          StatesHelper.Instance.addFailedTool(repoResourceType.branches, repo.id);
        }
      }
      try {
        const query = {
          functionName: "branches",
          params: {},
        };

        const res = await this.invokeRequest(repo, query);

        for (const branchInfo of res) {
          try {
            let branch = new Branch(branchInfo.name || "");

            branchsList.push(branch);
          } catch (err) {
            logger.error(`failed to create branch obj for: ${repo.name}, branch: ${JSON.stringify(branchInfo, null, 4)}, err: ${err}`);
            StatesHelper.Instance.addFailedTool(repoResourceType.branches, repo.id);
          }
        }
      } catch (err) {
        if (!err.result.message.startsWith("VS403403")) {
          logger.error(`get branches failed repo: ${repo.name}, err: ${err}`);
        }
        StatesHelper.Instance.addFailedTool(repoResourceType.branches, repo.id);
      }
    } catch (err) {
      logger.error(`failed get all branches repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.branches, repo.id);
    }
    return branchsList;
  }

  async users(repoObj: any) {
    const usersInfo: User[] = [];
    const repo: Repo = repoObj.code_repo;

    const { organization } = repo;
    if (this.usingOathToken) {
      try {
        await this.validateToken(organization);
      } catch (e) {
        logger.error(`failed to validate token for ${organization}`);
        StatesHelper.Instance.addFailedTool(repoResourceType.users, repo.id);
      }
    }
    try {
      let uri = `https://vssps.dev.azure.com/${organization}/_apis/graph/users?api-version=6.0-preview.1`;
      if (this.isCustomHost) {
        uri = `${this.token.host}/_apis/graph/users?api-version=6.0-preview.1`;
      }
      const query = {
        functionName: "users",
        params: {
          options: this.getDefaultOptions(),
          uri,
        },
      };

      const res = await this.invokeRequest(repo, query);

      if (res.length == 0) {
        return usersInfo;
      } else {
        for (const user of res) {
          if (user.mailAddress == "") {
            continue;
          }
          try {
            const username = user.displayName;
            const userInfo = new User(username, "", user.originId, "", "", "");

            userInfo.org = organization;
            userInfo.email = user.mailAddress;
            userInfo.domain = userInfo.email.substring(userInfo.email.indexOf("@") + 1);
            userInfo.diffFromNowToCreatedAtInDays = this.timeHelper.getTimeIntervalFronNowInDays(userInfo.createdAt);
            userInfo.descriptor = user.descriptor;

            await this.assignPermToUser(userInfo, repo);
            if (user?.directoryAlias?.includes("#EXT#")) {
              userInfo.orgRole.add(OrgRoles.COLLABORATORS);
            }
            GlobalCodeRepoData.Instance.addUser(userInfo, "azure repos (git)");

            usersInfo.push(userInfo);
          } catch (err) {
            logger.error(`failed to get users, err: ${err}`);
            StatesHelper.Instance.addFailedTool(repoResourceType.users, repo.id);
          }
        }
      }
    } catch (err) {
      logger.error(`failed to get users, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.users, repo.id);
    }
    return usersInfo;
  }

  //Fix
  async getUserCreatedAt(user: any, repo: Repo) {
    const { organization } = repo;
    if (this.usingOathToken) {
      try {
        await this.validateToken(organization);
      } catch (e) {
        logger.error(`failed to validate token for ${organization}`);
      }
    }
    try {
      let uri = `https://vsaex.dev.azure.com/${organization}/_apis/userentitlements?api-version=6.1-preview.1`;

      if (this.isCustomHost) {
        uri = `${this.token.host}/_apis/userentitlements?api-version=6.1-preview.1`;
      }

      const query = {
        functionName: "getUserCreatedAt",
        params: {
          options: this.getDefaultOptions(),
          uri,
        },
      };

      const res = await this.invokeRequest(repo, query);

      if (res.length > 0) {
        // by name until we have id
        const userRes = res.find(i => i.user.displayName === user.name);
        if (userRes != undefined) {
          user.createdAt = userRes.dateCreated;
        }
      }
    } catch (err) {
      logger.error(`uuid: ${this.uuid}, failed to get user creation date for ${user.name}, err: ${err}`);
    }
  }

  async commits(repo: Repo): Promise<any> {
    try {
      if (repo.vcsType === VCSType.git) {
        return super.commits(repo);
      }

      const c = await Timeout.wrap(this.getCommitsFromDiskForTfs(repo), 1000 * 60 * 15, `timeout set commits`);
      return c;
    } catch (err) {
      logger.error(`get commits failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.commits, repo.id);
      return [];
    }
  }

  async getCommitsFromDiskForTfs(repo: Repo): Promise<any> {
    try {
      logger.info(`try get commits fro repo: ${repo.fullName}`);

      // for tfvc repositories, we fetch `changesets` and map them to commits
      // Results are sorted by ID in descending order by default; newest come first
      let changesets = [];

      if (this.usingOathToken) {
        changesets = await this.orgsClients.get(repo.organization).tfs.getChangesets(
          repo.name, // corresponds to `project`
          null,
          0,
          9999, // can't fetch 10.000, ignored and reset to a default of 100
        );
      } else {
        changesets = await tfsSingleOrg.getChangesets(
          repo.name, // corresponds to `project`
          null,
          0,
          9999, // can't fetch 10.000, ignored and reset to a default of 100
        );
      }

      logger.info(`finish get commits fro repo: ${repo.fullName}`);

      const commits = changesets.map(
        changeset =>
          new Commit(
            changeset.url,
            changeset?.createdDate?.toString() ?? "",
            changeset?.author?.uniqueName ?? "",
            changeset?.author?.displayName ?? "",
            changeset.comment ?? "",
            changeset.changesetId.toString(), // not actually a hash
            [],
            [],
            [],
            [],
          ),
      );

      return commits;
    } catch (e) {
      logger.error(`unable to fetch commits for a tfvc repo ${repo.organization} ${repo.name}`, e);
      return [];
    }
  }

  async getAPICredentials(repo: Repo) {
    try {
      if (this.usingOathToken) {
        await this.validateToken(repo.organization);
      }

      return {
        token: this.private_token,
        isOAuth: this.usingOathToken,
        customHost: this.isCustomHost ? this.token.host : null,
      };
    } catch (e) {
      logger.error(`[azure][getAPICredentials] e: ${e}`);
      return null;
    }
  }

  getAPIRepoInfo(repo: Repo) {
    return {
      org: repo.organization,
      project: repo.projectName,
      repo: repo.name,
    };
  }

  async findPullRequestIntroducingMergeCommit(repoObj: any, branch: string, sha: string) {
    const repo: Repo = repoObj.code_repo;
    try {
      const getPullRequestQueryInput: GitPullRequestQuery = {
        queries: [
          {
            items: [sha],
            type: GitPullRequestQueryType.LastMergeCommit,
          },
        ],
      };

      const pullRequestQueryQuery = {
        functionName: "getPullRequestQuery",
        params: { getPullRequestQueryInput },
      };

      const pullRequestQueryResponse: GitPullRequestQuery[] = await this.invokeRequest(repo, pullRequestQueryQuery);

      const query = pullRequestQueryResponse[0];
      if (!query) return null;
      // from https://learn.microsoft.com/en-us/rest/api/azure/devops/git/pull-request-query/get?view=azure-devops-rest-7.0
      // The results of the queries.
      // This matches the QueryInputs list so Results[n] are the results of QueryInputs[n].
      // Each entry in the list is a dictionary of commit->pull requests.
      // since we only provide one query, we can grab the first result
      const result = query.results?.[0];
      if (!result) return null;
      const pullRequestsForSha = result[sha];
      if (!pullRequestsForSha) return null;
      const targetRefName = branch.startsWith("refs/heads/") ? branch : `refs/heads/${branch}`; // should never be provided with `refs/heads`, double checking
      const found = pullRequestsForSha.filter(pr => pr.targetRefName === targetRefName).find(pr => pr.lastMergeCommit?.commitId === sha);
      if (!found) return null;

      const pullRequest = new PullRequest(
        found.creationDate?.toString() ?? found.closedDate?.toString(),
        `${repo.pullsLink}/${found.pullRequestId}`,
        found.description,
        sha,
        found.closedDate?.toString(),
        found.title,
        0,
        found.createdBy?.displayName,
        found.pullRequestId?.toString(),
        CodeRepoTypes.pulls,
        [],
        new MergeUser(
          found.closedBy?.displayName || found.createdBy?.displayName,
          found.closedBy?.displayName || found.createdBy?.displayName,
          -1,
        ),
        true,
      );

      return pullRequest;
    } catch (e) {
      logger.error(
        `[azure] failed to find pull request introducing merge commit repo: ${repo.name}, branch: ${branch}, sha: ${sha}, e: ${e}`,
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
    const getQuery = (targetBranch: string, sourceBranch: string, limit: number) => {
      return {
        functionName: "diffs",
        target: targetBranch,
        source: sourceBranch,
        limit,
      };
    };

    try {
      // Tested: Azure has no limitation on diffs count. But just to be sure: check the count and actual diffs for equality

      const shouldFindFilesModifiedInPrViaApi = isLocalDevelopment()
        ? true
        : await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxShouldFindFilesModifiedInPrViaApiAzure");

      if (!shouldFindFilesModifiedInPrViaApi) return null;

      // Get changes count
      const query1 = getQuery(targetBranch, sourceBranch, 1);
      const res1 = (await this.invokeRequest(repo, query1)) as GitCommitDiffs[];
      if (!res1.length) return null;
      const changesCount = Object.values(res1[0].changeCounts).reduce((a, b) => a + b, 0);

      // Get diffs
      const query2 = getQuery(targetBranch, sourceBranch, changesCount);
      const res2 = (await this.invokeRequest(repo, query2)) as GitCommitDiffs[];
      if (!res2.length) return null;
      const changes = res2[0].changes;

      if (changes.length !== changesCount) {
        logger.error(
          `[azure][findFilesModifiedInPullRequest] changes count and actual change list are different for some reason. return null: ${repo.name}, sourceBranch: ${sourceBranch}, targetBranch: ${targetBranch}, sha: ${sha}, pullRequestId: ${pullRequestId}`,
        );
        return null;
      }

      const files = [
        ...new Set(
          changes
            .filter(change => !change.item.isFolder)
            .filter(change => change.changeType !== VersionControlChangeType.Delete)
            .map(change => change.item.path),
        ),
      ];

      return files;
    } catch (e) {
      logger.error(`[azure][findFilesModifiedInPullRequest] e: ${e}`);
    }
  }

  async pulls(repoObj: any): Promise<any> {
    let pullRequestList: PullRequest[] = [];
    const repo: Repo = repoObj.code_repo;
    const commits: Commit[] = repoObj.commits;
    const refName = `refs/heads/${repo.defaultBranch}`;

    try {
      if (repo.vcsType === VCSType.tfvc) {
        for (const commit of commits) {
          try {
            const reviewers: Reviewer[] = [];
            const r: Reviewer = new Reviewer(commit.authorName, commit.authorName, -1);
            reviewers.push(r);

            const mergeUser = new MergeUser(commit.authorName, commit.authorName, -1);

            let pullRequest = new PullRequest(
              commit.date.toString(),
              commit.link,
              commit.description,
              commit.hash.toString(),
              commit.date.toString(),
              commit.description,
              reviewers.length,
              commit.authorName,
              commit.hash.toString(),
              CodeRepoTypes.pulls,
              reviewers,
              mergeUser,
              true,
            );

            this.updateMailInfo(pullRequest);

            pullRequestList.push(pullRequest);
          } catch (err) {
            logger.error(`failed to create pull tfs obj for: ${repo.name}, pull obj: ${JSON.stringify(commit)}, err: ${err}`);
          }
        }
        return pullRequestList;
      }

      const { organization } = repo;
      let uri = `https://dev.azure.com/${organization}/${repo.projectName}/_apis/git/repositories/${repo.name}/pullrequests?api-version=7.0&searchCriteria.status=completed`;

      if (this.isCustomHost) {
        uri = `${this.token.host}/${repo.projectName}/_apis/git/repositories/${repo.name}/pullrequests?api-version=7.0&searchCriteria.status=completed`;
      }
      const query = {
        functionName: "pulls",
        params: {
          uri,
          options: this.getDefaultOptions(),
        },
        isHttp: true,
      };

      const res = (await this.invokeRequest(repo, query)) as GitPullRequest[];
      const pulls = res;

      for (const pullInfo of pulls) {
        try {
          const reviewers: Reviewer[] = [];
          if (pullInfo.reviewers != undefined) {
            for (const rev of pullInfo.reviewers) {
              reviewers.push(new Reviewer(rev.uniqueName, rev.displayName, rev.id));
            }
          }
          const mergeUser = new MergeUser(
            pullInfo.closedBy?.displayName || pullInfo.createdBy.displayName,
            pullInfo.closedBy?.displayName || pullInfo.createdBy.displayName,
            -1,
          );

          let pullRequest = new PullRequest(
            pullInfo.creationDate.toString() === "" ? pullInfo.closedDate.toString() : pullInfo.creationDate.toString(),
            `${repo.pullsLink}/${pullInfo.pullRequestId}`,
            pullInfo.description,
            pullInfo.mergeId,
            pullInfo.closedDate.toString(),
            pullInfo.title,
            reviewers.length,
            pullInfo.createdBy.displayName,
            pullInfo.pullRequestId.toString(),
            CodeRepoTypes.pulls,
            reviewers,
            mergeUser,
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
      logger.error(`get pulls failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.pulls, repo.id);
    }
    GlobalCodeRepoData.Instance.addPulls(pullRequestList, repo);
    return pullRequestList;
  }

  async pushedCommits(repoObj: any): Promise<any> {
    let pullRequestList: PullRequest[] = [];
    const repo: Repo = repoObj.code_repo;

    if (repo.vcsType === VCSType.tfvc) return [];

    const commits: Commit[] = repoObj.commits;
    try {
      const options = this.usingOathToken
        ? {
            headers: {
              Authorization: `Bearer ${this.private_token}`,
            },
          }
        : {
            auth: {
              username: "",
              password: this.token.password,
            },
          };

      let uri = `https://dev.azure.com/${repo.organization}/${repo.project}/_apis/git/repositories/${repo.name}/pushes?api-version=7.0`;

      if (this.isCustomHost) {
        uri = `${this.token.host}/${repo.project}_apis/git/repositories/${repo.name}/pushes?api-version=7.0`;
      }

      const query = {
        functionName: "users",
        params: {
          options: options,
          uri,
        },
      };

      const req = axios.get<any>(query.params.uri, query.params.options);
      const res = await req;
      const pulls = res.data.value;

      // const res = await this.invokeRequest(repo, query);
      for (const pullInfo of pulls) {
        try {
          const selfMergeUser = new MergeUser(pullInfo.pushedBy.displayName, pullInfo.pushedBy.uniqueName, pullInfo.pushedBy.id);

          let directCodePush = new PullRequest(
            pullInfo.date.toString(),
            `${repo.pushesLink}/${pullInfo.pushId}`,
            "",
            "",
            pullInfo.date.toString(),
            "",
            0,
            pullInfo.pushedBy.displayName,
            pullInfo.pushId.toString(),
            CodeRepoTypes.pushedCommits,
            [],
            selfMergeUser,
            true,
          );

          this.getCommitRelatedToPullReq(repo, pullInfo, directCodePush, commits);

          if (directCodePush.pullsCommitInfo.length == 0) {
            continue;
          }

          this.updateMailInfo(directCodePush);
          pullRequestList.push(directCodePush);
        } catch (err) {
          logger.error(`failed to create pushed code obj, err: ${err}, for: ${repo.name}, push: ${JSON.stringify(pullInfo)}`);
          StatesHelper.Instance.addFailedTool(repoResourceType.pushedCommits, repo.id);
        }
      }
    } catch (err) {
      logger.error(`get pushed code failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.pushedCommits, repo.id);
    }

    return pullRequestList;
  }

  async getCommitRelatedToPullReq(repo: Repo, pullInfo: any, pullRequest: PullRequest, commitsFromDisk: Commit[]) {
    try {
      const res = [];
      if (pullInfo?.lastMergeSourceCommit?.commitId) {
        res.push({ id: pullInfo?.lastMergeSourceCommit?.commitId });
      }
      if (pullInfo?.lastMergeTargetCommit?.commitId) {
        res.push({ id: pullInfo?.lastMergeTargetCommit?.commitId });
      }
      if (pullInfo?.mergeId) {
        res.push({ id: pullInfo?.mergeId });
      }
      if (pullInfo?.lastMergeCommit?.commitId) {
        res.push({ id: pullInfo?.lastMergeCommit?.commitId });
      }
      if (pullInfo?.refUpdates) {
        pullInfo?.refUpdates.forEach(i => {
          res.push({ id: i.newObjectId });
          res.push({ id: i.oldObjectId });
        });
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

  async getCommitRelatedToPush(repo: Repo, pullRequest: PullRequest, commitsFromDisk: Commit[]) {
    const pushId = pullRequest.id;

    const query = {
      functionName: "getPushCommits",
      params: {
        pushId: +pullRequest.id,
      },
    };

    const commits: GitCommitRef[] = await this.invokeRequest(repo, query);
    commits.sort((a, b) => {
      if (a.committer.date.getTime() > b.committer.date.getTime()) return 1;
      return -1;
    });

    for (const resCommit of commits) {
      try {
        const commitInfoFromDisk = commitsFromDisk.filter(i => i.hash === resCommit.commitId);
        if (commitInfoFromDisk.length > 0) {
          pullRequest.pullsCommitInfo = [...pullRequest.pullsCommitInfo, ...commitInfoFromDisk];
        } else {
          pullRequest.pullsCommitInfo.push(
            new Commit(
              resCommit.remoteUrl,
              pullRequest.createdAt,
              resCommit.author.email,
              resCommit.author.name,
              resCommit.comment,
              resCommit.commitId,
              [],
              [],
              [],
              [],
            ),
          );
        }
      } catch (err) {
        logger.error(`repo: ${repo.name}, get related single commit to pull request err: ${err}`);
      }
    }
    setFileInfo(pullRequest);

    if (commits.length > 0) {
      this.fillPush(pullRequest, commits);
    }
  }

  fillPush(pullRequest: PullRequest, commits: GitCommitRef[]) {
    pullRequest.createdAt = commits[commits.length - 1].committer.date.toString();
    pullRequest.description = commits[commits.length - 1].comment;
    pullRequest.sha = commits[commits.length - 1].commitId;
    pullRequest.title = commits[commits.length - 1].comment;
  }

  async invokeRequest(repo: Repo, query: any) {
    let organization = "";
    if (repo) {
      organization = repo.organization;
    }

    const r: AzureRepoRequest = new AzureRepoRequest();
    r.repo = repo;
    r.query = query;
    r.orgsClient = this.orgsClients.get(organization);
    r.query.skip = 0;
    r.query.maxPages = max_pages;

    if (this.usingOathToken) {
      try {
        await this.validateToken(organization);
      } catch (e) {
        logger.error("failed to validate token");
        return [];
      }
    }

    const res = await this.rateLimitHelper.sendApiRequest(
      r.query.functionName,
      r,
      this.isRateLimitErrFunction,
      this.handlePaging,
      this.getQueryNextPage,
      retry_count,
      this,
    );

    return res.flat();
  }

  getQueryNextPage(r: AzureRepoRequest, singleRes: any) {
    r.query.maxPages--;
    if (!r.needNextPage) return false;
    if (r.query.maxPages <= 0) return false;
    if (singleRes.length < TOP) return false;
    r.query.skip = r.query.skip + TOP;
    return true;
  }

  async handlePaging(r: AzureRepoRequest) {
    const repo: Repo = r.repo;
    const query = r.query;
    const params = query.params;
    const orgsClient = r.orgsClient;

    let resProm;

    switch (query.functionName) {
      case "getCommitRelatedToPullReq":
        resProm = orgsClient.git.getPullRequestCommits(repo.id, query.pullRequestId, repo.project);
        break;

      case "getUserCreatedAt":
        resProm = orgsClient.git.getBranches(repo.id, repo.project);
        break;

      case "branches":
        resProm = orgsClient.git.getBranches(repo.id, repo.project);
        break;

      case "webhooks":
        query.isHttp = true;
        resProm = axios.get<any>(params.uri, params.options);
        break;

      case "users":
        query.isHttp = true;
        resProm = axios.get<any>(params.uri, params.options);
        break;

      case "getPushCommits":
        r.needNextPage = true;
        const { pushId } = params;
        resProm = orgsClient.git.getPushCommits(repo.id, pushId, null, TOP, query.skip, true);
        break;

      case "getPullRequestQuery":
        const { getPullRequestQueryInput } = params;
        resProm = orgsClient.git.getPullRequestQuery(getPullRequestQueryInput, repo.id, repo.project);
        break;

      case "getPullRequests":
        r.needNextPage = true;
        const { gitPullRequestSearchCriteriaConfig } = params;
        resProm = orgsClient.git.getPullRequests(repo.id, gitPullRequestSearchCriteriaConfig, null, 10, query.skip, TOP);
        break;

      case "commits":
        resProm = orgsClient.git.getCommits(repo.id, { $top: 1 }, repo.project);
        break;

      case "getPushes":
        r.needNextPage = true;
        const { gitPushSearchCriteriaConfig } = params;
        resProm = orgsClient.git.getPushes(repo.id, null, query.skip, TOP, gitPushSearchCriteriaConfig);
        break;

      case "getPullRequestCommits":
        const { pullRequestId } = params;
        resProm = orgsClient.git.getPullRequestCommits(repo.id, pullRequestId, repo.project);
        break;

      case "getTeams":
        query.isHttp = true;
        resProm = axios.get<any>(params.uri, params.options);
        break;

      case "diffs":
        resProm = orgsClient.git.getCommitDiffs(
          repo.id,
          repo.project,
          false,
          query.limit,
          query.skip,
          { version: query.target },
          { version: query.source },
        );
        break;

      case "getAccounts":
        query.isHttp = true;
        resProm = axios.get<any>(params.uri, params.options);
        break;

      case "getTeamMembersWithExtendedProperties":
        r.needNextPage = true;
        const { teamId } = params;
        resProm = orgsClient.core.getTeamMembersWithExtendedProperties(repo.project, teamId, TOP, query.skip);
        break;

      case "branchSettings":
        r.needNextPage = true;
        resProm = axios.get<any>(params.uri, params.options);
        break;

      case "groups":
        r.needNextPage = true;
        resProm = axios.get<any>(params.uri, params.options);
        break;

      case "auditLogByOrg":
        // r.needNextPage = true;
        resProm = axios.get<any>(params.uri, params.options);
        break;

      case "pulls":
        r.needNextPage = true;
        resProm = axios.get<any>(params.uri, params.options);
        break;

      case "getGroupUsers":
        // r.needNextPage = true;
        resProm = axios.post<any>(params.uri, query.data, params.options);
        break;

      case "getGroupPermissions":
        // r.needNextPage = true;
        resProm = axios.post<any>(params.uri, query.data, params.options);
        break;

      case "getGroupBranchPolicies":
        // r.needNextPage = true;
        resProm = axios.post<any>(params.uri, query.data, params.options);
        break;

      case "getGroups":
        // r.needNextPage = true;
        resProm = axios.get<any>(params.uri, params.options);
        break;

      case "getPermissionsReport":
        resProm = axios.get<any>(params.uri, params.options);
        break;

      case "acl":
        resProm = axios.get<any>(params.uri, params.options);
        break;

      case "getNameSpacePermissions":
        resProm = axios.get<any>(params.uri, params.options);
        break;

      case "getGroupsIdentities":
        resProm = axios.get<any>(params.uri, params.options);
        break;

      default:
        logger.error("no function name provided");
        break;
    }

    let res = await resProm;
    if (query.isHttp != undefined) {
      res = res.data.value || res.data;
      return res;
    }
    return res;
  }

  isRateLimitErrFunction(err: any) {
    try {
      if (err.toString().includes("due to exceeding usage")) {
        return true;
      }
      if (err.toString().includes("ECONNRESET".toLowerCase())) {
        return true;
      }
      if (err.toString().includes("timeout of")) {
        return true;
      }
      if (err.response) {
        if (err.response.status == 429) {
          return true;
        }
      }
    } catch (err) {}
    return false;
  }

  async getTimeToWait() {
    return timeout_to_wait_after_rate_limit_happen;
  }

  isJson(str) {
    try {
      JSON.parse(str);
    } catch (e) {
      return false;
    }
    return true;
  }

  async refreshToken() {
    try {
      logger.info(
        `using refresh_token: ${this.refresh_token} AZURE_IDP_CLIENT_SECRET: ${process.env.AZURE_IDP_CLIENT_SECRET}, REDIRECT_URI: ${process.env.REDIRECT_URI}`,
      );

      const url = `https://app.vssps.visualstudio.com/oauth2/token`;

      let redirect_uri = "https://app.ox.security/identity-provider-configure";

      if (isDevelopment() || process.env.DEBUG) {
        redirect_uri = "https://dev.app.ox.security/identity-provider-configure";
      } else if (isStaging()) {
        redirect_uri = "https://stg.app.ox.security/identity-provider-configure";
      } else {
        redirect_uri = "https://app.ox.security/identity-provider-configure";
      }
      const response = await axios.post(
        url,
        qs.stringify({
          client_id: process.env.AZURE_IDP_CLIENT_ID,
          grant_type: "refresh_token",
          client_assertion: process.env.AZURE_IDP_CLIENT_SECRET,
          client_assertion_type: client_assertion_type,
          assertion: this.refresh_token,
          redirect_uri,
        }),
        {
          headers: {
            Accept: `application/json`,
            "Content-Type": "application/x-www-form-urlencoded",
          },
        },
      );
      if (response.status !== 200) {
        return null;
      }

      logger.info(`azure status: ${response.status}, REDIRECT_URI: ${process.env.IDP_REDIRECT_URI}`);
      return response.data as IdentityProviderToken;
    } catch (error) {
      logger.error("failed to create access token from refresh token", error);
      return null;
    }
  }

  async setAuthHandler() {
    authHandler = azdev.getPersonalAccessTokenHandler(this.private_token);
  }

  async getAzureDevOpsOrganizationNames(accessToken: string) {
    try {
      logger.info("getting organizations");
      const url = "https://app.vssps.visualstudio.com/_apis/accounts";
      const orgList = await axios.get<any>(url, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });
      return orgList.data.map(org => org.AccountName);
    } catch (e) {
      logger.error(`failed to get organizations: ${e}`);
    }

    return [];
  }

  async setClients(org: string) {
    try {
      logger.info(`set client host: ${this.token.host} org: ${org}`);
      const connection = new azdev.WebApi(`${AZURE_DEV_URL}${org}`, authHandler, {
        socketTimeout: 10 * 60 * 1000,
      });
      const git = await connection.getGitApi();
      const notification = await connection.getNotificationApi();
      const build = await connection.getBuildApi();
      const core = await connection.getCoreApi();
      const tfs = await connection.getTfvcApi();
      this.orgsClients.set(org, {
        connection,
        git,
        notification,
        build,
        core,
        tfs,
      });
    } catch (e) {
      logger.error("failed to init clients: ", e);
      throw e;
    }
  }

  async validateToken(org: string) {
    if (this.orgNameToLastUpdate.hasOwnProperty(org)) {
      const time: Date = this.orgNameToLastUpdate[org];
      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - time.getTime());
      if (elapsedTime < this.tokenExpirationInMinutes) {
        return;
      }
    }

    this.orgNameToLastUpdate[org] = new Date();

    await pRetry(
      async () => {
        await this.setClients(org);
      },
      {
        retries: 1,
        onFailedAttempt: async fail => {
          const error = fail as any;
          if (error.statusCode === 401) {
            await this.refreshTokenAndSetToken(this);
          } else {
            logger.error("faild to set clients: ", fail.message);
          }
        },
      },
    );
  }

  async refreshTokenAndSetToken(azureRepos: CodeRepoAzureRepoes) {
    try {
      if (!azureRepos.usingOathToken) {
        return;
      }

      logger.info("token expired, trying to get refresh token");
      const refreshToken = await azureRepos.refreshToken();
      azureRepos.private_token = refreshToken.access_token;
      azureRepos.setAuthHandler();
    } catch (err) {
      logger.error(`failed to refresh token, err: ${err}`);
    }
  }

  getOrganizationFromUrl(webUrl: string) {
    if (!webUrl) {
      return "";
    }

    const splitted = webUrl.split("/");
    return splitted[3];
  }

  async getCodeBaseLastCodeChange(application) {
    const lastCodeChange = await this.getLastCodeChange(application);
    if (lastCodeChange) {
      this.setLastCodeChange(application, lastCodeChange);
    }
    return application.lastCodeChange;
  }

  getCodeRepoId(application) {
    const isTfvc = application.tfvc == true;
    if (isTfvc) return application.name;
    return application.uuid;
  }

  async getLastCodeChange(application: any) {
    try {
      return application.changeDate;
    } catch (err) {
      logger.error(`getCodeBaseLastCodeChange Azure Can't get commits for ${application.name}, error: ${err}`);
    }
  }

  getDefaultOptions() {
    const options = this.usingOathToken
      ? {
          headers: {
            Authorization: `Bearer ${this.private_token}`,
            "Content-Type": "application/json",
          },
        }
      : {
          auth: {
            username: "",
            password: this.token.password,
          },
          headers: {
            "Content-Type": "application/json",
          },
        };
    return options;
  }

  async branchSettings(repoObj: any) {
    try {
      const repo: Repo = repoObj.code_repo;
      const { organization } = repo;
      let uri = `https://dev.azure.com/${organization}/${repo.projectName}/_apis/git/policy/configurations?repositoryId=${repo.id}&refName=refs/heads/${repo.defaultBranch}&api-version=5.0-preview.1`;

      if (this.isCustomHost) {
        uri = `${this.token.host}/${repo.projectName}/_apis/git/policy/configurations?repositoryId=${repo.id}&refName=refs/heads/${repo.defaultBranch}&api-version=5.0-preview.1`;
      }

      const query = {
        functionName: "branchSettings",
        params: {
          options: this.getDefaultOptions(),
          uri,
        },
        isHttp: true,
      };

      const res = await this.invokeRequest(repo, query);

      let repoBranchSettings = [];

      repoBranchSettings = res.map(i => new BranchSettingAPI(i.type.displayName, i.settings));

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

      const mergeSettings = repoBranchSettings.filter(i => i.settings.hasOwnProperty("minimumApproverCount"));

      if (repoBranchSettings.length == 0) {
        pushEventsEnabled = true;
        forceDeleteAllowed = true;
        branchProtection = false;
      }

      if (mergeSettings.length == 0) {
        MRWithoutReviewEnabled = true;
      }

      const settings = new BranchSettings(
        pushEventsEnabled,
        MRWithoutReviewEnabled, //bool
        forceDeleteAllowed,
        requiredSignedCommits,
        restrictions, // can bypass to main
        enforceAdmins, //
        dissmisalRestrictions, // bypass only pullreq review rule
        bypassPullReqAllowances, // bypass all pullreq rules
        branchProtection, // has at least 1 rule
        branchSettings, // object
      );

      const result = isPolicyMainBranchDoesntRequireCodeReviewViolation(settings);
      if (result) {
        StatesHelper.Instance.reposMainBranchDoesntRequireCodeReviewViolationCount++;
      } else {
        StatesHelper.Instance.noReposMainBranchDoesntRequireCodeReviewViolationCount++;
      }

      return settings;
    } catch (err) {
      const repo: Repo = repoObj.code_repo;
      logger.error(`failed get protected branch info, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.branchSettings, repo.id);
    }
    const defaultSettings = new BranchSettings();
    return defaultSettings;
  }
}

export default CodeRepoAzureRepoes;
