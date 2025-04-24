import { GitCommit, gitToJs } from "@oxappsec/ox-git-parse";
import crypto from "crypto";
import { startOfDay } from "date-fns";
import fs from "fs";
import _ from "lodash";
import LRU from "lru-cache";
import { AsyncTracker } from "../../async-tracker.service";
import ToolsCreatorBase from "../../codeOpenSourceTools/base/toolsCreatorBase";
import codeToolsCreator from "../../codeOpenSourceTools/codeTools/codeToolsCreator";
import CodeToolsManager from "../../codeOpenSourceTools/codeTools/codeToolsManager";
import { ApiSecurityItem } from "../../entitis/apiTypes";
import { AppFlowType, HahsType } from "../../entitis/applicationsFlowTypes";
import { ArtifactoryTypes, SbomEvent } from "../../entitis/artifactoryTypes";
import {
  CodeRepoTypes,
  Commit,
  DevLanguages,
  File,
  FileWithLanguage,
  GitInfoJSON,
  Organization,
  PipelineScanInfo,
  PullRequest,
  Repo,
  RepoImportanceInfo,
  repoResourceType,
  RepositoryInfo,
  RepositoryInfoJSON,
  repoType,
  resourceType,
  SecurityAlertType,
  SecurityEvent,
  setSecEventFromDelta,
  User,
  UserAuditLog,
  UserRole,
  VCSType,
} from "../../entitis/codeRepoTypes";
import { ResourceType, Token } from "../../entitis/collectorEntitisTypes";
import Constant from "../../entitis/constant";
import { getKubernetesSubSystem, KubernetesFile } from "../../entitis/kubernetesTypes";
import { OrchestratorFile, OrchestratorSystem } from "../../entitis/orchestratorTypes";
import { Resource } from "../../entitis/orgPolicyTypes";
import { Resource as ConnectorResource } from "../../entitis/service/connector-message-types";
import { CliToolsImage } from "../../entitis/service/pip2PoetryTypes";
import AppConfigHelper, { appOverrideRelevance, setConfiguredProps } from "../../helper/appConfigHelper";
import RepoImportanceCalcHelper from "../../helper/appPriority/repoImportanceCalcHelper";
import { CacheResolver } from "../../helper/cache/cache.resolver";
import { Cache } from "../../helper/cache/cache.types";
import { deleteFolderAfterDoneWorkingForOnPrem, getPkgManagerPretty } from "../../helper/commonUtils";
import CicdHelper from "../../helper/connectorsSpecific/cicdHelper";
import { PerformanceTelemetry } from "../../helper/decorators/PerformanceTelemetry";
import { isLocalDevelopment } from "../../helper/envUtils";
import { isRepoInfoJsonFeatureEnabled } from "../../helper/featureFlags/isRepoInfoJsonFeatureEnabledForOrg";
import { getDevLanBasedOnFileName } from "../../helper/generalUtils";
import GitHelper from "../../helper/gitHelper";
import { default as FileHelpe, default as FileHelper } from "../../helper/IO/fileHlper";
import MemoryMonitorHelper from "../../helper/IO/memoryMonitorHelper";
import { PipeLineHelper } from "../../helper/pipelineHelper";
import PromisePoolHelper from "../../helper/promisePoolHelper";
import getAFC from "../../helper/repository-matching/artifact-family-cache";
import { RepositoryMatcher } from "../../helper/repository-matching/RepositoryMatcher";
import RoleHelper from "../../helper/roleHelper";
import { OrgManagementService } from "../../helper/service";
import APIDiscoveryHelper from "../../helper/service/apiDiscoveryHelper";
import CallGraphHelper from "../../helper/service/callGraphHelper";
import DependencyGraphHelper from "../../helper/service/dependencyGraphHelper";
import DockerfileScannerHelper from "../../helper/service/dockerfileScannerHelper";
import Pip2poetryHelper from "../../helper/service/pip2poetryHelper";
import { TagsService } from "../../helper/service/tags-service/tags-service.service";
import VerificationAndStarsHelper from "../../helper/service/verificationAndStarsHelper";
import StatesHelper from "../../helper/statesHelper";
import StringHelper from "../../helper/stringHelper";
import {
  millisToMinutesAndSeconds,
  ScanPhaseTime,
  sendScannerFailedProcessSingleRepoTelemetry,
  sendScannerPhaseTimeTelemetry,
} from "../../helper/telemetry-utils";
import { millis } from "../../helper/time-unit-utils";
import TimeHelper from "../../helper/timeHelper";
import { ToolsExecutionStats } from "../../helper/toolExecutionStats";
import SecurityToolsHelper from "../../helper/tools/securityToolsHelper";
import loggerImport from "../../logger";
import MongoConnect from "../../mongo/mongoConnect";
import MongoDBApplications from "../../mongo/mongoDBapplications";
import MongoDBapplicationsConfigurations from "../../mongo/mongoDBapplicationsConfigurations";
import { InterceptHelper } from "../../orgSpecificTools/StandardChartered/InterceptHelper";
import { severityReasons } from "../../package-index";
import dependencyFiles from "../../policy/org/config/dependencyFiles.json";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";
import GlobalCodeRepoData, { UserCommit, UserPullRequest, UserReviewer } from "../GolobalCollectorData/globalCodeRepoData";
import CollectorBase from "./collectorBase";

const logger = loggerImport.getDebugLogger();
const Timeout = require("await-timeout");
const detect = require("language-detect");
const map = require("language-map");
const path = require("path");

abstract class CodeRepoBase extends CollectorBase {
  fileHelper: FileHelpe;
  apiAllRepos = [];
  reposObj = [];
  totalFinish = 0;
  totalStarted = 0;
  globalCodeRepoData: GlobalCodeRepoData;
  timeHelper: TimeHelper;
  roleHelper: RoleHelper;
  gitHelper: GitHelper;
  verificationAndStarsHelper: VerificationAndStarsHelper;
  //applicationsConfig: Application[] = [];
  callObj: RulesManager;
  promisePoolHelper: PromisePoolHelper;
  repoInfoJSONCache = new LRU<string, RepositoryInfoJSON>({
    max: StatesHelper.Instance.concurrentRepoScans,
  });
  isRepoInfoJsonFeatureEnabled: boolean = false;
  toolProgressBaseNotSet: boolean = false;
  mongoDBApplications: MongoDBApplications;
  toolsCreator: ToolsCreatorBase;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, ResourceType[ResourceType.code_repo], policyConfiguration, jsonApplicationDiscoveryOverview);
    this.fileHelper = new FileHelpe(uuid);
    this.globalCodeRepoData = GlobalCodeRepoData.Instance;
    this.gitHelper = new GitHelper(this.uuid, this.orgName);
    this.timeHelper = new TimeHelper(this.uuid);
    this.roleHelper = new RoleHelper(this.uuid);
    // this.verificationAndStarsHelper = new VerificationAndStarsHelper(this.uuid);
  }

  //Resource to collected
  resourcesToCollect: Resource[] = [];
  secondEnrichResourcesToCollect: Resource[] = [];
  thirdEnrichResourcesToCollect: Resource[] = [];
  forthEnrichResourcesToCollect: Resource[] = [];
  globalEnrichResourcesToCollect: Resource[] = [];

  //Should be collected regardless to the policy resources
  mandatoryResources: CodeRepoTypes[] = [
    CodeRepoTypes.webhooks,
    CodeRepoTypes.workflows,
    CodeRepoTypes.branches,
    CodeRepoTypes.pulls,
    CodeRepoTypes.pushedCommits,
    CodeRepoTypes.securityEvents,
    CodeRepoTypes.branchSettings,
    CodeRepoTypes.groups,
  ];

  //Should be collected after first level resources collected, any resource that is
  //not enrich type count as first level resource
  secondEnrichResources: CodeRepoTypes[] = [CodeRepoTypes.pulls, CodeRepoTypes.groups];
  thirdEnrichResources: CodeRepoTypes[] = [CodeRepoTypes.pushedCommits, CodeRepoTypes.users];
  forthEnrichResources: CodeRepoTypes[] = [CodeRepoTypes.branchSettings];

  cacheResovler: CacheResolver;

  async codeRepoInit(callObj: RulesManager) {
    this.isRepoInfoJsonFeatureEnabled = await isRepoInfoJsonFeatureEnabled.isEnabled(this.orgName);

    //Order is important
    await this.initLib();
    await this.initApplicationsFromDB(callObj.mongoConnect);
    this.initSelectedRepos(callObj);
    this.cacheResovler = new CacheResolver(this.orgName, callObj.mongoConnect);
    await this.setRepos(callObj);
  }

  //To implement methods
  abstract getAllRepos(callObj: RulesManager);
  abstract setRepo(apiRepo, repoObj);
  abstract initLib();
  abstract getCodeBaseLastCodeChange(app);
  abstract getCodeRepoId(app);

  async setRepos(callObj: RulesManager) {
    logger.info(`try set repos for: ${this.token.name}, url: ${this.token.host} to collect`);

    this.apiAllRepos = await this.getAllRepos(callObj);

    if (process.env.DEBUG || process.env.DOCKER_DEBUG) {
      // this.apiAllRepos = this.apiAllRepos.filter(i => i.name.includes("vuln-comp"));
      // this.apiAllRepos = this.apiAllRepos.filter(i => i.name_with_namespace.includes(" services / sites"));
      // this.apiAllRepos = this.apiAllRepos.filter(i => i.name === "sast-node-js-001");
      // this.apiAllRepos = this.apiAllRepos.filter(i => i.name.toLowerCase().includes("hudi"));
      // this.apiAllRepos = this.apiAllRepos.filter(repo => repo.name === "scanner");
      this.apiAllRepos = this.apiAllRepos.filter(repo => repo.name === "scanner");
      // this.apiAllRepos = this.apiAllRepos.filter(repo => repo.full_name === "python-popular-repos/yt-dlp");
      // this.apiAllRepos = this.apiAllRepos.filter(repo => repo.name_with_namespace.includes("cloner"));
      // this.apiAllRepos = this.apiAllRepos.slice(0, 1);
      // this.apiAllRepos = this.apiAllRepos.slice(23, 24);
      // this.apiAllRepos[0].id = 82;
      // this.apiAllRepos[0].name_with_namespace = "dev / ps";
    }

    logger.info(`Found ${this.apiAllRepos.length} repos`);

    if (this.token.sshToken && this.token.name === "gerrit") {
      StatesHelper.Instance.pathToSSHKeyGerrit = this.token.sshToken;
      logger.info(`using ${this.token.name} for ssh command`);
    }

    StatesHelper.Instance.addToAppsCount(this.apiAllRepos.length);
    await this.jsonApplicationDiscoveryOverview.updateInitState(StatesHelper.Instance.numberOfApps);

    callObj.resultsHandler.setTotalApps(StatesHelper.Instance.numberOfApps);

    this.mongoDBApplications = new MongoDBApplications(this.uuid, this.orgName, callObj.mongoConnect);
    await callObj.deltaScansHelper.markUnchangedApplications(callObj, this.apiAllRepos, this);

    logger.info(
      `scanning repos count: ${this.apiAllRepos.length}, finish set repos for: ${this.token.name}, url: ${this.token.host}, repos count: ${this.apiAllRepos.length}`,
    );

    //In case no repos and its not aws code commit, because aws code commit maybe not be enable but aws cloud scan will be
    //So in case we have other source control with aws code commit we cannot fail the scan
    if (this.apiAllRepos.length == 0 && this.token.name.toLowerCase() !== "awsCodeCommit".toLowerCase()) {
      throw `cannot set repos for: ${this.token.name}, url: ${this.token.host}`;
    }
  }

  getAllOrgs() {
    return [];
  }

  // to remove ?
  getSingleOrgName() {
    try {
      const index = this.token.host.indexOf("https://dev.azure.com/");
      const orgName = this.token.host.substring(index);
      return orgName;
    } catch (e) {
      logger.error(`[${this.token.name}] failed getting single org name`, e);
    }
  }

  isOrgMail(email) {
    try {
      let domain = email.split("@");

      if (!domain[1]) {
        return false;
      }

      domain = domain[1];
      const match = domain.match(/\./g);

      if (!match) {
        return false;
      }

      const isOrgDomain = match.length;
      return isOrgDomain === 1 ? true : false;
    } catch (err) {
      logger.error(`[${this.token.name}] failed is org mail, email: ${email}`, err);
    }
    return false;
  }

  updateMailInfo(pullRequest: PullRequest) {
    try {
      // by name
      let email = this.globalCodeRepoData.userMailMap.get(pullRequest.author);

      // by username
      if (!email) {
        email = this.globalCodeRepoData.userMailMap.get(pullRequest.authorUserName);
      }

      // by commit
      if (!email) {
        const commitInfo = pullRequest.pullsCommitInfo.reverse().find(i => i.authorEmail && i.authorName && this.isOrgMail(i.authorEmail));
        if (!commitInfo) {
          return;
        }
        email = commitInfo.authorEmail;
      }

      pullRequest.email = email;
      pullRequest.emailDomain = email.substring(email.lastIndexOf("@") + 1);
      const lastIndex = pullRequest.emailDomain.lastIndexOf(".");
      if (lastIndex != -1) {
        pullRequest.emailDomain = pullRequest.emailDomain.substring(0, lastIndex);
      }
    } catch (err) {
      logger.error(`[${this.token.name}] failed to update all mail info for all pull request`, err);
    }
  }

  @PerformanceTelemetry()
  async collect(resources: Resource[], callObj: RulesManager): Promise<boolean[]> {
    let res = [];

    const startTime = new Date().getTime();
    this.callObj = callObj;

    //keep this outside of the catch to make sure scan failed if this failed
    await this.codeRepoInit(callObj);

    try {
      this.setAndExtendWithMandatoryResources(resources);

      logger.info(`${this.token.name} start promisees poll to collect all ${resources.length} resources`);

      //Keep it for cloner as legacy
      this.toolsCreator = new codeToolsCreator(this.uuid, this.orgPolicyParser, this.orgName, this.securityToolsQueue, this.token);
      this.toolsCreator.setTools();

      //Run single repo collection
      await this.evalAllRepos(callObj, this.apiAllRepos);

      this.throwIfUnsuccessfulPipelineScanRepoEval();

      //Wait and after it enrich global data, when done run policy eval
      //(some policy can run only when we have the global repo data)
      if (this.globalEnrichResourcesToCollect.length > 0 && !StatesHelper.Instance.isPipelineScan) {
        await this.collectGlobalReposInfo();
        await this.attachGlobalDataToRepo();
      }

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "after finish repo scanning");

      let elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));
      await sendScannerPhaseTimeTelemetry(ScanPhaseTime.ScanRepoPhaseTime, this.orgName, this.uuid, elapsedTime);
      logger.info(`${this.token.name} finish collect promisees, resources for code repo, execution time in minutes: ${elapsedTime}`);

      StatesHelper.Instance.scanInfoStats.repoScanTime = `${elapsedTime} minutes, ${new Date().toTimeString()}`;
    } catch (err) {
      logger.error(`[${this.token.name}] failed collect all resources for code repo`, err);
      // throw further to fail the whole scan
      if (this.isUnsuccessfulPipelineScanRepoEvalError(err)) throw err;
    }

    //Free memory
    this.apiAllRepos = [];
    return res;
  }

  private async attachGlobalDataToRepo() {
    if (process.env.SKIP_SCM_AUDIT) {
      return;
    }
    logger.info(`start attach repos to global data`);
    await MemoryMonitorHelper.Instance.printSnapshot(
      this.orgName,
      this.uuid,
      "attachGlobalDataToRepo before start attach repos to global data",
    );

    try {
      //org
      const orgUsers: User[] = Object.values(this.globalCodeRepoData.getUsers()).flat() as User[];
      orgUsers.forEach(u => {
        this.setUserActivityBasedOnLogs(this.globalCodeRepoData.auditLogBasedOnUser, u);
        this.setUserActivityBasedOnDevOperation(this.globalCodeRepoData.UserPullRequest, u);
        this.setUserActivityBasedOnReviewOperation(this.globalCodeRepoData.UserReviewers, u);
      });

      const userAdminToRepo = {};
      let orgWithPrefix;
      this.reposObj.forEach(repoObj => {
        try {
          const gitType = repoObj.code_repo.type.toLowerCase();

          orgWithPrefix = `${gitType}_${repoObj.code_repo.organization}`;

          repoObj.allUsers = this.globalCodeRepoData.getUsersByOrg(orgWithPrefix) || [];
          repoObj.auditLog = this.globalCodeRepoData.auditLogBasedOnUser;
          repoObj.allPulls = this.globalCodeRepoData.UserPullRequest;
          repoObj.allPullsRepo = this.globalCodeRepoData.UserPullRequestRepo;

          const repo: Repo = repoObj.code_repo;
          repo.totalRepos = this.reposObj.length;

          const org: Organization = GlobalCodeRepoData.Instance.orgs.get(repo.organization);
          repo.isOrg2faEnabled = org ? org?.twoFactorEnabled : null;
          repo.isOrgVerified = org ? org?.isVerified : null;

          if (!repo.monoRepoChild) {
            GlobalCodeRepoData.Instance.updateRepoWebhookInfo(repoObj, this.reposObj.length);
          }

          //Attach to repo user, org rolls from an org user and additional data
          GlobalCodeRepoData.Instance.updateUsersRepoWithOrgOperation(repoObj, userAdminToRepo);

          //Update repo items
          GlobalCodeRepoData.Instance.updateUsersRepoWithDevOperation(repoObj);
          GlobalCodeRepoData.Instance.updateUsersRepoWithReviewOperation(repoObj);
          GlobalCodeRepoData.Instance.updateUsersRepoWithAdminOperation(repoObj);
          GlobalCodeRepoData.Instance.updateRepoUserWithCreatedAt(repoObj);
        } catch (err) {
          logger.error(`[${this.token.name}] failed to update and attach users to repo`, err);
        }
      });

      //update developers count for org
      await this.updateDevelopersCount();

      logger.info(`start calc common user prefix suffix info`);
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "start calc common user prefix suffix info");

      let count = 0;
      const commonUserPrefixSuffix = {};
      let totalUsers = 0;
      for (const repoObj of this.reposObj) {
        try {
          count++;

          if (count === 1000) {
            logger.info(`during calc common user prefix suffix info, count: ${count}`);
            await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "during calc common user prefix suffix");
            count = 0;
          }

          const repoUsers: User[] = repoObj[CodeRepoTypes[CodeRepoTypes.users]];
          if (!repoUsers) {
            continue;
          }

          repoUsers.forEach(user => {
            try {
              totalUsers++;
              let prefix = "";
              let suffix = "";

              //Handle '-'
              let prefixIndex = user.username.indexOf("-");
              if (prefixIndex != -1) {
                prefix = user.username.substring(0, prefixIndex) + "-";
              }
              let suffixIndex = user.username.lastIndexOf("-");
              if (suffixIndex != -1) {
                suffix = user.username.substring(suffixIndex, user.username.length);
              }

              //Handle '_'
              if (prefixIndex == -1) {
                prefixIndex = user.username.indexOf("_");
                if (prefixIndex != -1) {
                  prefix = user.username.substring(0, prefixIndex) + "_";
                }
              }
              if (suffixIndex == -1) {
                suffixIndex = user.username.lastIndexOf("_");
                if (suffixIndex != -1) {
                  suffix = user.username.substring(suffixIndex, user.username.length);
                }
              }

              //Skip double update
              if (prefix == suffix) {
                suffix = undefined;
              }

              if (prefix) {
                if (commonUserPrefixSuffix[prefix]) {
                  commonUserPrefixSuffix[prefix]++;
                } else {
                  commonUserPrefixSuffix[prefix] = 1;
                }
              }
              if (suffix) {
                if (commonUserPrefixSuffix[suffix]) {
                  commonUserPrefixSuffix[suffix]++;
                } else {
                  commonUserPrefixSuffix[suffix] = 1;
                }
              }

              const allReposWithAdminRole = userAdminToRepo[user.name];
              if (!allReposWithAdminRole) {
                return;
              }
              user.repoThatTheUserIsAdmin = allReposWithAdminRole.size;
            } catch (err) {
              logger.error(`[${this.token.name}] failed to update single user to repo`, err);
            }
          });
        } catch (err) {
          logger.error(`[${this.token.name}] failed to update users to repo`, err);
        }
      }

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "finish calc common user prefix suffix info");

      const finalCommonUserPrefixSuffix = {};
      if (totalUsers > 0) {
        for (const [name, entry] of Object.entries(commonUserPrefixSuffix)) {
          const entryCount = entry as number;
          if (entryCount / totalUsers >= 0.15) {
            finalCommonUserPrefixSuffix[name] = entry;
          }
        }
      }

      StatesHelper.Instance.commonUserPrefixSuffix = finalCommonUserPrefixSuffix;

      logger.info(
        `finish attach repos to global data, finalCommonUserPrefixSuffix count: ${
          Object.keys(finalCommonUserPrefixSuffix).length
        }, info: ${JSON.stringify(finalCommonUserPrefixSuffix)}`,
      );
    } catch (err) {
      logger.error(`[${this.token.name}] failed update app manager with all global info`, err);
    }
  }

  hackGitTypeNames(gitType: string) {
    if (gitType === repoType.azureGit) {
      return repoType.azure;
    }
    if (gitType.toLowerCase() === "bitbucket-stash") {
      return repoType.bitbucketStash;
    }
    if (gitType.toLowerCase() === "aws-codecommit") {
      return repoType.awsCodeCommit;
    }
    if (gitType.toLowerCase() === "gerrit") {
      return repoType.gerrit;
    }
    return gitType;
  }

  async updateDevelopersCount() {
    try {
      logger.info(`trying to update developers count for orgId: ${this.orgName}`);

      // all users
      const allOrgUsers = Object.values(GlobalCodeRepoData.Instance.getUsers()).flat();

      // all commits
      const allCommits = Object.values(GlobalCodeRepoData.Instance.UserCommitsRepo).flat();

      // users segregated by git type (not unique!!)
      const usersByType = GlobalCodeRepoData.Instance.usersGitTypeMap;

      // commits by git type
      const commitsByGit = _.groupBy(allCommits, "gitType");

      // org users count from api
      const usersCountFromApi = _.uniqBy(allOrgUsers, "id");

      const maxCountPerGitType = new Map();
      const totalUsersSet = new Set();
      const membersByGitArr = [];

      let totalDevCountResult = 0;

      // let skipCalc = true;

      // if (!allOrgUsers.length) {
      //   skipCalc = false;
      // }

      // for (const collector of this.callObj.collectorManager.collectors) {
      //   if (collector.userSelectedRepos?.monitorAllResources !== null) {
      //     skipCalc = false;
      //   }
      // }

      // if (skipCalc) {
      //   totalDevCountResult = usersCountFromApi;
      // }

      // set max for each git type
      for (let [gitType, users] of usersByType.entries()) {
        const u = _.uniqBy(users, "id");
        gitType = this.hackGitTypeNames(gitType);
        maxCountPerGitType.set(gitType, u);
      }

      // if (!skipCalc) {
      // calc users based on commits
      for (let [gitType, usersCommits] of Object.entries(commitsByGit)) {
        let result = 0;
        const usersSet = new Set();
        for (const userCommit of usersCommits as any) {
          if (userCommit.lastCommit.diffFromNowToCreatedAtInDays <= 90) {
            if (this.isValidDevCountMail(userCommit.lastCommit.authorEmail)) {
              usersSet.add(userCommit.lastCommit.authorEmail);
            }
          }
        }
        gitType = this.hackGitTypeNames(gitType);

        // set to max from api if count from commits exeeds max
        const max = maxCountPerGitType.get(gitType.toLowerCase())?.length;

        if (max) {
          if (usersSet.size > max) {
            result = max;
          } else {
            result = usersSet.size;
          }
        } else {
          result = usersSet.size;
        }

        membersByGitArr.push({ repoType: gitType, count: result });
      }

      // get total
      for (const commit of Object.values(commitsByGit).flat() as any) {
        if (commit.lastCommit.diffFromNowToCreatedAtInDays <= 90) {
          if (this.isValidDevCountMail(commit.lastCommit.authorEmail)) {
            totalUsersSet.add(commit.lastCommit.authorEmail);
          }
        }
      }

      let resourceType = "";
      let users = [];
      if ((totalUsersSet.size > usersCountFromApi.length && allOrgUsers.length) || totalUsersSet.size === 0) {
        totalDevCountResult = usersCountFromApi.length;
        resourceType = "api";
        users = (usersCountFromApi as User[]).map(u => u.name);
      } else {
        totalDevCountResult = totalUsersSet.size;
        resourceType = "commits";
        users = Array.from(totalUsersSet);
      }

      // debug
      try {
        if (StatesHelper.Instance.orgName === "org_w8nn4X7KDuNvdfr6") {
          const apiUsersNames = (usersCountFromApi as User[]).map(u => u.name);
          const logemails = Array.from(totalUsersSet);
          const allCountableCommits = (allCommits as UserCommit[]).filter(commit => commit.lastCommit.diffFromNowToCreatedAtInDays <= 90);

          logger.info(
            `developersCount totalDevCountResult: ${totalDevCountResult}, email list from commits : ${JSON.stringify(
              logemails,
            )}, total commits count: ${allCommits.length}, 90 days commits count : ${
              allCountableCommits.length
            } names list from api : ${JSON.stringify(apiUsersNames)}`,
          );
        }
      } catch (e) {
        logger.error(`[${this.token.name}] failed to log dev count`, e);
      }

      const updated = await OrgManagementService.Instance.updateDevelopersCount(
        this.orgName,
        totalDevCountResult,
        membersByGitArr,
        users,
        resourceType,
      );

      if (!updated) {
        logger.error(`[${this.token.name}] failed to update developers count`);
      } else {
        logger.info(`updated developers count successfully: ${totalDevCountResult}, orgId: ${this.orgName}`);
      }
    } catch (e) {
      logger.error(`[${this.token.name}] failed to update developers count`, e);
    }
  }

  isValidDevCountMail(email: string) {
    try {
      const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;

      const isValidEmail = emailRegex.test(email);
      if (!isValidEmail) {
        return false;
      }

      if (email.length > 70) {
        return false;
      }

      return true;
    } catch (e) {
      logger.error(`[${this.token.name}] failed to validate devCountEmail for ${email}`, e);
    }
    return false;
  }

  setUserActivityBasedOnDevOperation(allPulls: any, user: User) {
    try {
      if (!allPulls) {
        return;
      }
      //Get all user activity
      const userPullRequest: UserPullRequest = allPulls[user.name];
      if (!userPullRequest) {
        return;
      }

      user.devOperation = userPullRequest.count;
      user.devOperationDate = userPullRequest.lastPullRequest.createdAtData;
      user.foundDevData = true;

      if (!user.lastActivityData) {
        user.lastActivityData = user.devOperationDate;
      } else {
        if (user.lastActivityData.getTime() < userPullRequest.lastPullRequest.createdAtData.getTime()) {
          user.lastActivityData = userPullRequest.lastPullRequest.createdAtData;
        }
      }
    } catch (err) {
      logger.error(`[${this.token.name}] failed get user activity based on dev operation`, err);
    }
  }

  setUserActivityBasedOnReviewOperation(allReviews: any, user: User) {
    try {
      if (!allReviews) {
        return;
      }
      //Get all user activity
      const userReviewer: UserReviewer = allReviews[user.name];
      if (!userReviewer) {
        return;
      }

      user.reviewOperation = userReviewer.count;
      user.reviewOperationDate = userReviewer.lastReviewerRequest;
      user.foundReviewData = true;

      if (!user.lastActivityData) {
        user.lastActivityData = user.reviewOperationDate;
      } else {
        if (user.lastActivityData.getTime() < userReviewer.lastReviewerRequest.getTime()) {
          user.lastActivityData = userReviewer.lastReviewerRequest;
        }
      }
    } catch (err) {
      logger.error(`[${this.token.name}] failed get user activity based on review operation`, err);
    }
  }

  setUserActivityBasedOnLogs(auditLog: any, user: User) {
    try {
      if (!auditLog) {
        return;
      }
      //Get all user activity
      const usersAuditLogInfo: UserAuditLog[] = auditLog[user.name];
      if (!usersAuditLogInfo) {
        return;
      }

      const sortedItems = usersAuditLogInfo.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

      for (const action of usersAuditLogInfo) {
        if (action.repo && action.action.startsWith("repo")) {
          if (!user.repoAdminActivity.includes(action.repo)) {
            user.repoAdminActivity.push(action.repo);
          }
        }
      }
      user.adminOperation = usersAuditLogInfo.length;
      user.adminLocation = sortedItems[0].actorLocation;
      if (!user.adminLocation) {
        sortedItems.forEach(i => {
          if (!user.adminLocation && i.actorLocation) {
            user.adminLocation = i.actorLocation;
          }
        });
      }
      user.adminOperationDate = sortedItems[0].timestamp;
      user.foundAdminData = true;
      user.lastAdminOperation = sortedItems[0].actionFriendly;

      if (!user.lastActivityData) {
        user.lastActivityData = user.adminOperationDate;
      } else {
        if (user.lastActivityData.getTime() < sortedItems[0].timestamp.getTime()) {
          user.lastActivityData = sortedItems[0].timestamp;
        }
      }
    } catch (err) {
      logger.error(`[${this.token.name}] failed get user activity based on logs, user: ${JSON.stringify(user)}`, err);
    }
  }

  private getOwnerRepoBasedOnUsers(repo: Repo, users: User[]) {
    let res = {
      owner: "N/A",
      email: "N/A",
    };
    try {
      users.sort((a, b) => {
        return new Date(a.createdAt).getTime() > new Date(b.createdAt).getTime() ? 1 : -1;
      });
      if (users.length > 0) {
        let owner = users.find(u => u.role === UserRole.OWNER);

        if (owner) {
          res.owner = owner.name;
          res.email = owner.email;
          return res;
        }
        owner = users.find(u => u.role === UserRole.MAINTAINER);
        if (owner) {
          res.owner = users[0].name;
          res.email = users[0].email;
          return res;
        }

        owner = users.find(u => u.role === UserRole.DEVELOPER);
        if (owner) {
          res.owner = users[0].name;
          res.email = users[0].email;
          return res;
        }

        owner = users.find(u => u.role === UserRole.GUEST);
        if (owner) {
          res.owner = users[0].name;
          res.email = users[0].email;
          return res;
        }
      }

      return res;
    } catch (e) {
      logger.error(`[${this.token.name}] failed to get repo owner, repo: ${repo.name}`, e);
    }

    return res;
  }

  getOwnerRepoBasedOnCommits(repo: Repo, commits: Commit[]) {
    try {
      if (commits.length == 0) {
        return null;
      }

      const commitsWithAuthor = commits.filter(i => i.authorName);
      const sorted = this.sortCommitsByDates(commitsWithAuthor, repo);
      if (sorted.length == 0) {
        return null;
      }
      return { owner: sorted[0].authorName, email: sorted[0].authorEmail };
    } catch (err) {
      logger.error(`failed get first commit for repo: ${repo.name}, ${this.token.name}, err: ${err}`);
    }
    return null;
  }

  async allOrgsRepos() {
    return GlobalCodeRepoData.Instance.repos;
  }

  async collectGlobalReposInfo() {
    try {
      const proms = this.globalEnrichResourcesToCollect.map(i => this.runGlobalRepoFunc(i));

      if (proms.length > 0) {
        logger.info(`${this.token.name} start collect global repos info count: ${proms.length}`);
      }

      return Promise.all(proms);
    } catch (err) {
      logger.error(`failed collect all global info, err: ${err}`);
    }
    return [];
  }

  async runGlobalRepoFunc(resource: Resource) {
    try {
      if (!this.funcNames.has(resource.name)) {
        return;
      }
      await this[resource.name](this.reposObj);
    } catch (err) {
      logger.error(`failed wait for single global info: ${resource.name}, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async evalAllRepos(ruleManager: RulesManager, allRepos: any) {
    logger.info(
      `${this.token.name} start collect and run policy for each single repo, concurrent repo scans: ${StatesHelper.Instance.concurrentRepoScans}`,
    );

    const repoImportanceCalcHelper: RepoImportanceCalcHelper = new RepoImportanceCalcHelper(this.uuid, this.orgName);

    let defaultTimeoutPerApp = 1000 * 60 * 60 + 1000 * 60 * 25;
    const timeoutBasedOnApi = StatesHelper.Instance.getTimeoutForProcessRepoBasedOnAPIlimits();
    if (timeoutBasedOnApi) {
      defaultTimeoutPerApp = timeoutBasedOnApi + 1000 * 60 * 45;
      logger.info(`set default timeout to process: ${this.token.name} from API is: ${defaultTimeoutPerApp}`);
    } else {
      logger.info(`set default timeout to process: ${this.token.name} is: ${defaultTimeoutPerApp}`);
    }

    //Specific for tfs 1 org where it take very long to scan
    if (StatesHelper.Instance.orgName === "org_3FaIb7kmXGVol1Vu") {
      defaultTimeoutPerApp = defaultTimeoutPerApp * 3;
    }

    let concurrentRepoScans = StatesHelper.Instance.concurrentRepoScans;
    this.promisePoolHelper = new PromisePoolHelper(
      concurrentRepoScans,
      async (repoApi: any) => {
        return await AsyncTracker.runWithAsyncTracker(async () => {
          AsyncTracker.setValue("ox-app-id", repoApi.id);
          AsyncTracker.setValue("ox-app-name", repoApi.name);
          getAFC().associateRepoIdToName(`${repoApi.id}`, `${repoApi.name}`);

          if (repoApi.monoRepo) {
            return await this.processMonoRepo(repoApi, ruleManager, defaultTimeoutPerApp, allRepos, repoImportanceCalcHelper);
          } else {
            return await this.processRegularRepo(repoApi, ruleManager, defaultTimeoutPerApp, allRepos, repoImportanceCalcHelper);
          }
        });
      },
      "repo_queue",
    );

    this.promisePoolHelper.addRange(allRepos);
    await this.promisePoolHelper.runQueue();

    logger.info(`${this.token.name} finish collect and run all repos`);
  }

  async processRegularRepo(
    repoApi: any,
    ruleManager: RulesManager,
    defaultTimeoutPerApp: number,
    allRepos: any,
    repoImportanceCalcHelper: RepoImportanceCalcHelper,
  ) {
    this.totalStarted++;
    const id = this.totalStarted;
    try {
      let repoObj = {};
      let repo: Repo;

      const startTime = new Date().getTime();

      //Set repo
      const timeoutInterval = repoApi.tfvc || this.token.name === "gerrit" ? 80 : 45;
      repo = await Timeout.wrap(this.setRepo(repoApi, repoObj), 1000 * 60 * timeoutInterval, `timeout set repo, id: ${id}`);
      if (repo == null) {
        logger.error(`cannot set repo for: ${JSON.stringify(repoApi)}, id: ${id}, all: ${allRepos.length}`);
        return false;
      }

      if (StatesHelper.Instance.isPipelineScan && repo.failedClone) {
        logger.error(`cannot run processRegularRepo since running a pipeline scan and failed to clone ${repo.name}`);
        return false;
      }

      if (!repo.privateVisability) {
        StatesHelper.Instance.publicReposCount++;
      }

      //Update UI for each repo as soon as possible
      await this.jsonApplicationDiscoveryOverview.updateReposItem(repo);

      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);

      logger.info(`finish set repo for: ${repo.fullName} in ${elapsedTime} minutes, repo id: ${id}, all: ${allRepos.length}`);

      //process repo
      const startTimeProcessRepo = new Date().getTime();

      await Timeout.wrap(
        this.processRepo(repoObj, repoImportanceCalcHelper, ruleManager, repo),
        defaultTimeoutPerApp,
        `timeout process repo, id: ${id}, defaultTimeoutPerApp: ${defaultTimeoutPerApp}`,
      );
      let elapsedTimeProcessRepo = millisToMinutesAndSeconds(new Date().getTime() - startTimeProcessRepo);

      this.totalFinish++;

      logger.info(
        `finish process repo for: ${repo.fullName} in ${elapsedTimeProcessRepo} minutes, id: ${id}, total finish: ${this.totalFinish} all: ${allRepos.length}`,
      );

      this.setLastApplicationFinishTime();
      deleteFolderAfterDoneWorkingForOnPrem(repo.fullName, repo.mainFolder);

      return true;
    } catch (err) {
      this.totalFinish++;
      this.setLastApplicationFinishTime();

      StatesHelper.Instance.scanInfoStats.failedProcessSingleRepo++;

      await sendScannerFailedProcessSingleRepoTelemetry(this.orgName, this.uuid, repoApi.name);

      logger.error(
        `[${this.token.name}] failed collect resources, finish process repo id: ${id}, repoInfo: ${repoApi.name}, finish: ${this.totalFinish}, all: ${allRepos.length}`,
        err,
      );
      return false;
    }
  }

  async processMonoRepo(
    repoApi: any,
    ruleManager: RulesManager,
    defaultTimeoutPerApp: number,
    allRepos: any,
    repoImportanceCalcHelper: RepoImportanceCalcHelper,
  ) {
    this.totalStarted++;
    const id = this.totalStarted;

    try {
      const repo: Repo = repoApi[ResourceType[ResourceType.code_repo]];

      await this.jsonApplicationDiscoveryOverview.updateReposItem(repo);

      //Process mono repo
      const startTime = new Date().getTime();
      await Timeout.wrap(
        this.processRepoOnMonoRepo(repoApi, repoImportanceCalcHelper, ruleManager, repo),
        defaultTimeoutPerApp,
        `timeout process monorepo, ${repo.fullName}, defaultTimeoutPerApp: ${defaultTimeoutPerApp}`,
      );

      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);

      this.totalFinish++;

      logger.info(
        `finish process monorepo for: ${repo.fullName} in ${elapsedTime} minutes, id: ${id}, total finish: ${this.totalFinish} all: ${allRepos.length}`,
      );

      this.setLastApplicationFinishTime();
      deleteFolderAfterDoneWorkingForOnPrem(repo.fullName, repo.mainFolder);

      return true;
    } catch (err) {
      this.totalFinish++;
      this.setLastApplicationFinishTime();

      logger.error(
        `failed collect resources, finish process monorepo id: ${id}, finish: ${this.totalFinish}, all: ${allRepos.length}, err: ${err}`,
      );
      return false;
    }
  }

  setLastApplicationFinishTime() {
    try {
      process.env.lastApplicationFinishTime = new Date().toString();
    } catch (err) {
      logger.error(`failed set last application finish time, err: ${err}`);
    }
  }

  async processRepo(repoObj: any, repoImportanceCalcHelper: RepoImportanceCalcHelper, callObj: RulesManager, repo: Repo) {
    //Set some basic info for repoObj for even the case the importance will be 0
    await this.initBaseInfo(repoObj, repo);

    //Mark as mono repo
    if (!repo.noneRelevantRepo) {
      repo.monoRepoParent = await this.getIsMonoRepoFromRepoInfoJSON(repo);
      if (repo.monoRepoParent) {
        repo.monoRepoParentOrphanedFilesCount = await this.getOrphanedFilesCount(repo);
        repo.monoRepoChildrenSubfolders = await this.getMonoRepoChildrenSubfoldersFromRepoInfoJSON(repo);
      }
    }

    //Get commits as they required for determine if we need to ignore the repo
    const sortedCommits = await this.commits(repo);
    repoObj[CodeRepoTypes[CodeRepoTypes.commits]] = sortedCommits;
    this.setLastPushTime(sortedCommits, repo);

    const files = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.files]);

    //If relevant
    if (repoImportanceCalcHelper.isRepoImportanceAreZero(repo, files.length).length == 0) {
      if (!this.toolProgressBaseNotSet) {
        this.toolProgressBaseNotSet = true;
        callObj.toolProgressBase.updateLastProgressTime("default", "code_repo");
      }

      const startTime = new Date().getTime();
      await Promise.all([this.doConnectorApisCalls(repoObj, repo), this.handleSecurityTools(repoObj, repo)]);
      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
      logger.info(`finish run sec tools and apis for repo: ${repo.fullName}, elapsedTime: ${elapsedTime}`);

      await this.setRepoAdditionalInfo(repoObj, repo); //roman should we remove it for pipeline scan

      //Ignore the parent mono repo, use only the actual repos inside it
      if (repo.monoRepoParent && !repo.disable) {
        let reposExtractedFromMonoRepo = await this.splitMonoRepo(repo, repoObj);
        logger.info(`repos extracted from mono repo: ${reposExtractedFromMonoRepo}, length : ${reposExtractedFromMonoRepo.length}`);
        if (reposExtractedFromMonoRepo.length >= 1) {
          logger.info(`found ${reposExtractedFromMonoRepo.length} repos in monorepo ${repo.fullName}`);

          StatesHelper.Instance.addToAppsCount(reposExtractedFromMonoRepo.length);
          callObj.resultsHandler.setTotalApps(StatesHelper.Instance.numberOfApps);

          this.promisePoolHelper.addRange(reposExtractedFromMonoRepo);
        } else {
          logger.error(`0 repos Found in monorepo ${repo.fullName}`);
        }
      }
    } else {
      StatesHelper.Instance.clonedRepos[repo.fullName] = "not-important";
      await this.setRepoAdditionalInfo(repoObj, repo);
    }

    PipeLineHelper.Instance.setPullRequestIntroducingMergeCommit(await this.tryFindingPullRequestIntroducingMergeCommit(repoObj));
    PipeLineHelper.Instance.setJobTriggeredBy(await this.tryFindingJobTriggeredBy());

    await callObj.applicationsManager.updateAppManagerRepoItem(repoObj);

    this.cleanRepoLargeCollections(repoObj);

    //Save the repo object for later iteration
    this.reposObj.push(repoObj);

    return true;
  }

  checkIfNeedToRunSCAbaseOnFiles(repo: Repo, files: File[]) {
    try {
      if (files.length > 0) {
        for (const file of files) {
          for (const [devLang, devFiles] of Object.entries(dependencyFiles.languages)) {
            const exist = devFiles.find(i => file.name.toLowerCase().includes(i.toLowerCase()));
            //Found at least 1 dep file
            if (exist) {
              logger.info(
                `found for checkIfNeedToRunSCAbaseOnFiles for: ${repo.fullName}, dependency file: ${exist}, matched file: ${file.name}, total files count: ${files.length}`,
              );
              return true;
            }
          }
        }
        return false;
      }
    } catch (err) {
      logger.error(`failed to checkIfNeedToRunSCAbaseOnFiles for: ${repo.fullName}, err: ${err}`);
    }
    return true;
  }

  async handleSCExecution(repo: Repo, allAlerts: SecurityEvent[], sbomAlerts: SbomEvent[], repoObj) {
    try {
      const files = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.files]);

      const applicableFilesSCA = this.checkIfNeedToRunSCAbaseOnFiles(repo, files);
      if (!applicableFilesSCA) {
        logger.info(`no need to run handleSCExecution for repo: ${repo.fullName}, no sca files`);
        return;
      }

      logger.info(`try handleSCExecution for repo: ${repo.fullName}`);
      const startTime = new Date().getTime();

      const onlyScaTools = new codeToolsCreator(this.uuid, this.orgPolicyParser, this.orgName, this.securityToolsQueue, this.token);
      onlyScaTools.setToolsByCat(SecurityAlertType[SecurityAlertType.sca]);
      const securityToolsCollectorSCAonly = new CodeToolsManager(
        this.uuid,
        this.orgPolicyParser,
        this.orgName,
        repo,
        this.securityToolsQueue,
        onlyScaTools,
        this.callObj.toolProgressBase,
      );

      //Run first pipe2poetry
      const cliToolsImages: CliToolsImage[] = [];
      const pip2poetryHelper = new Pip2poetryHelper(this.callObj.pip2poetryQueue, this.uuid, this.orgName);
      await pip2poetryHelper.setRepoPip2poetryHelperInfo(repo, cliToolsImages);

      //Add external tools to run like snyk
      this.addExternalCLIimagesToExecute(repo, cliToolsImages, onlyScaTools);

      const dependencyGraphHelper: DependencyGraphHelper = new DependencyGraphHelper(
        this.callObj.dependencyGraphQueue,
        this.callObj.depJackingQueue,
        this.uuid,
        this.orgName,
      );

      let shouldRunDependencyGraphBeforeTools = true;
      let scaSecAlerts: SecurityEvent[] = [];
      let sbomInfo: SbomEvent[] = [];

      const specificDevLan = repo.languages.find(
        i =>
          i.language.toLowerCase() === "java" ||
          i.language.toLowerCase() === "scala" ||
          i.language.toLowerCase() === "kotlin" ||
          i.language.toLowerCase() === "maven pom" ||
          i.language.toLowerCase() === "sbt" ||
          i.language.toLowerCase() === "gradle",
      );
      if (specificDevLan) {
        logger.info(
          `handleSCExecution for repo: ${repo.fullName}, specificDevLan: ${specificDevLan.language}, languagePercentage: ${specificDevLan.languagePercentage} found`,
        );
      } else {
        shouldRunDependencyGraphBeforeTools = false;
        logger.info(`handleSCExecution for repo: ${repo.fullName}, not found`);
      }

      if (shouldRunDependencyGraphBeforeTools) {
        //First run dep graph then run tools
        await dependencyGraphHelper.setRepoDependencyGraphInfo(repo, repoObj, files);
        await securityToolsCollectorSCAonly.sendScanRequest();
        Array.from(securityToolsCollectorSCAonly.failedTools).forEach(i => repo.addFailedSecurityTools(i as string));
        scaSecAlerts = await securityToolsCollectorSCAonly.collectAlerts();
        sbomInfo = await securityToolsCollectorSCAonly.collectSbom();
      } else {
        //Run together dep graph and tools
        await securityToolsCollectorSCAonly.sendScanRequest();
        Array.from(securityToolsCollectorSCAonly.failedTools).forEach(i => repo.addFailedSecurityTools(i as string));
        const p = securityToolsCollectorSCAonly.collectAlerts();
        const p2 = dependencyGraphHelper.setRepoDependencyGraphInfo(repo, repoObj, files);
        const res = await Promise.all([p, p2]);
        scaSecAlerts = res[0] as any;
        sbomInfo = await securityToolsCollectorSCAonly.collectSbom();
      }

      sbomInfo.forEach(i => {
        sbomAlerts.push(i);
      });
      scaSecAlerts.forEach(i => {
        allAlerts.push(i);
      });

      //Ayman scaTrigger --> integration
      //take issues from trivy
      //send to scaTrigger
      //we get what direct and what not direct
      //try optimization send all the unique libs both from sbomInfo and secAlerts then do the connecton by
      //lib name and lib version and file name to avoid duplication
      //  blame: BlameResponse; --> to put data in

      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
      logger.info(
        `finish handleSCExecution for repo: ${repo.fullName}, secAlerts: ${scaSecAlerts.length}, sbomAlerts: ${sbomInfo.length} elapsedTime: ${elapsedTime}`,
      );
    } catch (err) {
      logger.error(`failed to handleSCExecution for: ${repo.fullName}, err: ${err}`);
    }
  }

  async handleAllExceptSCAexecution(
    repo: Repo,
    allAlerts: SecurityEvent[],
    apiSecurityItems: ApiSecurityItem[],
    applicationSecurityEvents: ApiSecurityItem[],
  ) {
    try {
      logger.info(`try handleAllExceptSCAexecution for repo: ${repo.fullName}`);
      const startTime = new Date().getTime();

      const toolsCreator = new codeToolsCreator(this.uuid, this.orgPolicyParser, this.orgName, this.securityToolsQueue, this.token);
      toolsCreator.setAllToolsExceptCat(SecurityAlertType[SecurityAlertType.sca]);
      const securityToolsCollector = new CodeToolsManager(
        this.uuid,
        this.orgPolicyParser,
        this.orgName,
        repo,
        this.securityToolsQueue,
        toolsCreator,
        this.callObj.toolProgressBase,
      );

      await securityToolsCollector.sendScanRequest();
      Array.from(securityToolsCollector.failedTools).forEach(i => repo.addFailedSecurityTools(i as string));
      const p = securityToolsCollector.collectAlerts();

      const dockerfileScanner = new DockerfileScannerHelper(this.callObj.callGraphQueue, this.uuid, this.orgName);
      const pDockerfileScanner = dockerfileScanner.setRepoDockerfileScannerInfo(repo);

      repo.callGraphHelper = new CallGraphHelper(this.callObj.callGraphQueue, this.uuid, this.orgName);
      const pCallGraphHelperRequestOnly = repo.callGraphHelper.sendRepoCallGraphInfo(repo);

      const res = await Promise.all([p, pDockerfileScanner, pCallGraphHelperRequestOnly]);

      const secEventsFromTools = res[0] as SecurityEvent[];
      const dockerSecEvents = res[1] as SecurityEvent[];

      secEventsFromTools.forEach(i => {
        allAlerts.push(i);
      });
      dockerSecEvents.forEach(i => {
        allAlerts.push(i);
      });

      //Run api security after semgrep
      if (StatesHelper.Instance.isApiSecEnable) {
        const apiDiscoveryHelper = new APIDiscoveryHelper(this.callObj.apiDiscoveryQueue, this.uuid, this.orgName);

        //From code api discovery
        await apiDiscoveryHelper.setRepoAPIDiscoveryInfo(repo, apiSecurityItems);

        //from openapi/swagger files
        try {
          const files = await this.getOpenApiFilesFromRepoInfoJSON(repo);
          await APIDiscoveryHelper.extractAPIsFromSwagger(files, repo, applicationSecurityEvents);
        } catch (err) {
          logger.error(`failed to extract APIs from openapi/swagger files for: ${repo.fullName}, err: ${err}`);
        }
      }

      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
      logger.info(
        `finish handleAllExceptSCAexecution for repo: ${repo.fullName}, secEventsFromTools: ${secEventsFromTools.length}, dockerSecEvents: ${dockerSecEvents.length}, appSecEvents: ${applicationSecurityEvents.length}, elapsedTime: ${elapsedTime}`,
      );
    } catch (err) {
      logger.error(`failed to handleAllExceptSCAexecution for: ${repo.fullName}, err: ${err}`);
    }
  }

  setIgnoreTools(repo: Repo, files: File[]) {
    let pythonExist = false;
    let iacExist = false;
    let dockerfileExist = false;
    let csExist = false;
    let psExist = false;
    let cExist = false;
    let vbExist = false;
    let rustExist = false;
    let kotlinExist = false;
    let jsExist = false;
    let tsExist = false;
    let goExist = false;
    let phpExist = false;
    let scalaExist = false;
    let javaExist = false;
    let shellExist = false;
    let rubyExist = false;
    let swiftExist = false;
    let ansibleExist = false;
    let chefExist = false;
    let puppetExist = false;
    let terraformExist = false;
    let cloudformationExist = false;
    let helmExist = false;
    let pulumiExist = false;
    let argocdExist = false;
    let karpenterExist = false;
    let arnExist = false;
    let saltstackExist = false;
    let vargentExist = false;
    try {
      repo.languages.forEach(i => {
        let lowerCaseLang = i.language.toLowerCase();
        if (lowerCaseLang === "python") {
          pythonExist = true;
        } else if (lowerCaseLang === "dockerfile") {
          dockerfileExist = true;
          iacExist = true;
        } else if (lowerCaseLang === "c#" || lowerCaseLang === "csharp") {
          csExist = true;
        } else if (lowerCaseLang === "java") {
          javaExist = true;
        } else if (lowerCaseLang === "kotlin") {
          kotlinExist = true;
        } else if (lowerCaseLang === "javascript") {
          jsExist = true;
        } else if (lowerCaseLang === "typescript") {
          tsExist = true;
        } else if (lowerCaseLang === "go") {
          goExist = true;
        } else if (lowerCaseLang === "php") {
          phpExist = true;
        } else if (lowerCaseLang === "scala") {
          scalaExist = true;
        } else if (lowerCaseLang === "powershell") {
          psExist = true;
        } else if (lowerCaseLang === "c" || lowerCaseLang === "c++") {
          cExist = true;
        } else if (lowerCaseLang === "vb" || lowerCaseLang === "visual basic") {
          vbExist = true;
        } else if (lowerCaseLang === "rust") {
          rustExist = true;
        } else if (lowerCaseLang === "shell") {
          shellExist = true;
        } else if (lowerCaseLang === "ruby") {
          rubyExist = true;
        } else if (lowerCaseLang === "swift") {
          swiftExist = true;
        } else if (lowerCaseLang === "vagrant") {
          vargentExist = true;
        } else if (lowerCaseLang === "terraform" || lowerCaseLang === "terraform-plan") {
          terraformExist = true;
          iacExist = true;
        } else if (lowerCaseLang === "cloud formation") {
          cloudformationExist = true;
          iacExist = true;
        } else if (lowerCaseLang === "helm") {
          helmExist = true;
          iacExist = true;
        } else if (lowerCaseLang === "pulumi") {
          pulumiExist = true;
          iacExist = true;
        } else if (lowerCaseLang === "argo cd") {
          argocdExist = true;
          iacExist = true;
        } else if (lowerCaseLang === "karpenter") {
          karpenterExist = true;
          iacExist = true;
        } else if (lowerCaseLang === "azure resource manager") {
          arnExist = true;
          iacExist = true;
        } else if (lowerCaseLang === "saltstack") {
          saltstackExist = true;
          iacExist = true;
        } else if (lowerCaseLang === "chef") {
          chefExist = true;
          iacExist = true;
        } else if (lowerCaseLang === "puppet") {
          puppetExist = true;
          iacExist = true;
        } else if (lowerCaseLang === "ansible") {
          ansibleExist = true;
          iacExist = true;
        } else if (
          lowerCaseLang === "swagger" ||
          lowerCaseLang === "openapi" ||
          lowerCaseLang === "kubernetes" ||
          lowerCaseLang === "docker compose" ||
          lowerCaseLang === "github actions" ||
          lowerCaseLang === "gitlab ci/cd" ||
          lowerCaseLang === "cloud build" ||
          lowerCaseLang === "buildkite" ||
          lowerCaseLang === "azure pipelines" ||
          lowerCaseLang === "drone ci"
        ) {
          iacExist = true;
        }
      });
      if (!pythonExist) {
        repo.ignoredTools.push("bandit");
      }
      if (!iacExist) {
        repo.ignoredTools.push("checkov");
      }
      if (!dockerfileExist) {
        repo.ignoredTools.push("docker-file-scanning");
      }
      if (!(cExist || csExist || psExist || vbExist || rustExist)) {
        repo.ignoredTools.push("devskim");
      }
      if (StatesHelper.Instance.isPipelineScan) {
        if (
          !(
            shellExist ||
            pythonExist ||
            javaExist ||
            kotlinExist ||
            jsExist ||
            tsExist ||
            goExist ||
            csExist ||
            phpExist ||
            cExist ||
            scalaExist ||
            rubyExist ||
            swiftExist
          )
        ) {
          repo.ignoredTools.push("semgrep");
        }
      } else {
        if (
          !(
            iacExist ||
            shellExist ||
            pythonExist ||
            javaExist ||
            kotlinExist ||
            jsExist ||
            tsExist ||
            goExist ||
            csExist ||
            phpExist ||
            cExist ||
            scalaExist ||
            rubyExist ||
            swiftExist
          )
        ) {
          repo.ignoredTools.push("semgrep");
        }
      }

      if (repo.ignoredTools.length > 0) {
        logger.info(
          `ignored tools for repo: ${repo.fullName}, ignoredTools: ${repo.ignoredTools.join(", ")}, dev lan: ${repo.languages
            .map(i => `${i.language} - ${i.languagePercentage}`)
            .join(", ")}`,
        );
      }
    } catch (err) {
      logger.error(`failed to setIgnoreTools for: ${repo.fullName}, err: ${err}`);
    }

    // extract tags from language
    try {
      if (!StatesHelper.Instance.isPipelineScan) {
        if (vargentExist) {
          repo.addRepoSeverityChangedReason(severityReasons.vagrant);
        }
        if (chefExist) {
          repo.addRepoSeverityChangedReason(severityReasons.chef);
        }
        if (puppetExist) {
          repo.addRepoSeverityChangedReason(severityReasons.puppet);
        }
        if (ansibleExist) {
          repo.addRepoSeverityChangedReason(severityReasons.ansible);
        }
        if (terraformExist) {
          repo.addRepoSeverityChangedReason(severityReasons.terraform);
        }
        if (cloudformationExist) {
          repo.addRepoSeverityChangedReason(severityReasons.cloudformation);
        }
        if (helmExist) {
          repo.addRepoSeverityChangedReason(severityReasons.helm);
        }
        if (pulumiExist) {
          repo.addRepoSeverityChangedReason(severityReasons.pulumi);
        }
        if (argocdExist) {
          repo.addRepoSeverityChangedReason(severityReasons.argocd);
        }
        if (karpenterExist) {
          repo.addRepoSeverityChangedReason(severityReasons.karpenter);
        }
        if (arnExist) {
          repo.addRepoSeverityChangedReason(severityReasons.arn);
        }
        if (saltstackExist) {
          repo.addRepoSeverityChangedReason(severityReasons.saltstack);
        }
      }
    } catch (err) {
      logger.error(`failed extract tags from language for: ${repo.fullName}, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async handleSecurityTools(repoObj: any, repo: Repo) {
    try {
      const startTime = new Date().getTime();

      let sbomAlerts: SbomEvent[] = [];
      let allSecEvents: SecurityEvent[] = repoObj[CodeRepoTypes[CodeRepoTypes.securityEvents]];
      repoObj[ArtifactoryTypes[ArtifactoryTypes.sbom]] = sbomAlerts;
      const files = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.files]);

      if (await this.setInterceptInfo(repo, allSecEvents)) {
        return;
      }

      const shouldRun = !repo.disable && (repo.isMonoRepoParentWithOrphanedFiles || !repo.monoRepoParent);

      if (shouldRun) {
        //Api security
        let applicationSecurityEvents: ApiSecurityItem[] = [];
        let apiSecurityItems: ApiSecurityItem[] = [];

        //Cash flow
        if (repo.isDelta) {
          await this.getDataFromCash(repo, applicationSecurityEvents, allSecEvents, sbomAlerts);
        } else {
          this.setIgnoreTools(repo, files);
          const pSCAonly = this.handleSCExecution(repo, allSecEvents, sbomAlerts, repoObj);
          const pAllToolsExceptSCA = this.handleAllExceptSCAexecution(repo, allSecEvents, apiSecurityItems, applicationSecurityEvents);
          await Promise.all([pSCAonly, pAllToolsExceptSCA]);
        }

        //For container matching
        if (StatesHelper.Instance.isContainerEnable && !StatesHelper.Instance.isPipelineScan) {
          const info = (await this.getRepoInfo(repo)) as any;
          await RepositoryMatcher.instance.addCodeRepositoryFilesToMap(repo, info.filesWithLanguages || [], files || []);
        }

        this.postProcessingSecEvents(repo, allSecEvents, sbomAlerts, apiSecurityItems, applicationSecurityEvents);
        this.setDepConfusionData(repo, repoObj);

        this.fileHelper.deleteAllFilesInRootDir(repo.securityResDir);
      } else {
        logger.info(
          `no need to run handleSecurityTools for: ${repo.fullName}, disable: ${repo.disable}, isMonoRepoParentWithOrphanedFiles: ${repo.isMonoRepoParentWithOrphanedFiles}, monoRepoParent: ${repo.monoRepoParent}`,
        );
      }

      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
      logger.info(`finish run handleSecurityTools for repo: ${repo.fullName}, elapsedTime: ${elapsedTime}`);
    } catch (err) {
      logger.error(`failed to handleSecurityTools for: ${repo.fullName}, err: ${err}`);
    }
  }

  async setInterceptInfo(repo: Repo, allAlerts: SecurityEvent[]) {
    try {
      const interceptSecEventsFromTools = await InterceptHelper.collectSecEvents(
        { type: "generic", name: repo.fullName, repo },
        this.orgName,
        this.uuid,
      );
      interceptSecEventsFromTools.forEach(i => {
        allAlerts.push(i);
      });

      if (interceptSecEventsFromTools.length > 0) {
        return true;
      }
    } catch (err) {
      logger.error(`failed to setInerceptInfo for: ${repo.fullName}, err: ${err}`);
    }
    return false;
  }

  @PerformanceTelemetry()
  async doConnectorApisCalls(repoObj: any, repo: Repo) {
    if (repo.disable) {
      return;
    }
    if (StatesHelper.Instance.isPipelineScan) {
      return;
    }

    logger.info(`start do connector api calls for repo: ${repo.fullName}`);
    const startTime = new Date().getTime();

    await this.collectRepoInfo(repoObj, repo);
    await this.enrichRepoObj(repoObj, repo, this.secondEnrichResourcesToCollect);
    await this.enrichRepoObj(repoObj, repo, this.thirdEnrichResourcesToCollect);
    await this.enrichRepoObj(repoObj, repo, this.forthEnrichResourcesToCollect);
    await this.updateRepoTopics(repo);

    let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
    logger.info(`finish do connector api calls for repo: ${repo.fullName}, elapsedTime: ${elapsedTime}`);
  }

  setLastPushTime(sortedCommits: Commit[], repo: Repo) {
    if (sortedCommits.length > 0) {
      if (!repo.lastPushTime) {
        const lastCodeChangeTime = sortedCommits[0].date;
        repo.lastPushTime = lastCodeChangeTime;
        logger.error(`roman2: ${repo.lastPushTime}`);
      }
    }
  }

  cleanRepoLargeCollections(repoObj: any) {
    repoObj[CodeRepoTypes[CodeRepoTypes.securityEvents]] = [];
    repoObj[CodeRepoTypes[CodeRepoTypes.pulls]] = [];
    repoObj[CodeRepoTypes[CodeRepoTypes.commits]] = [];
    repoObj[ArtifactoryTypes[ArtifactoryTypes.sbom]] = [];
  }

  setClientConfiguredProps(repo: Repo) {
    setConfiguredProps(repo);
  }

  isAppOverrideRelevance(id: string) {
    return appOverrideRelevance(id);
  }

  async processRepoOnMonoRepo(repoObj: any, repoImportanceCalcHelper: RepoImportanceCalcHelper, callObj: RulesManager, repo: Repo) {
    //Set some basic info for repoObj for even the case the importance will be 0
    await this.initBaseInfo(repoObj, repo);
    this.setClientConfiguredProps(repo);

    const files = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.files]);
    if (repoImportanceCalcHelper.isRepoImportanceAreZero(repo, files.length).length == 0) {
      if (StatesHelper.Instance.isContainerEnable) {
        const info = await this.getRepoInfo(repo);
        const files = await this.files(repo);
        if (info?.filesWithLanguages?.length) {
          RepositoryMatcher.instance.addCodeRepositoryFilesToMap(repo, info.filesWithLanguages, files);
        } else {
          logger.warn(`list of files absent in repo ${repo.fullName}`);
        }
      }

      if (!this.toolProgressBaseNotSet) {
        this.toolProgressBaseNotSet = true;
        callObj.toolProgressBase.updateLastProgressTime("default", "code_repo");
      }

      await this.handleSecurityTools(repoObj, repo);
    }

    await this.setRepoAdditionalInfo(repoObj, repo);

    await callObj.applicationsManager.updateAppManagerRepoItem(repoObj);

    this.cleanRepoLargeCollections(repoObj);

    //Save the repo object for later iteration
    this.reposObj.push(repoObj);
    return true;
  }

  addExternalCLIimagesToExecute(repo: Repo, cliToolsImages: CliToolsImage[], toolsCreator: codeToolsCreator): void {
    try {
      if (cliToolsImages.length > 0) {
        cliToolsImages.forEach(image => {
          const newTool = toolsCreator.setSpecificTool(Constant.snykCLItool);
          if (newTool) {
            if (StatesHelper.Instance.externalToolCount[image.queueKey]) {
              StatesHelper.Instance.externalToolCount[image.queueKey]++;
            } else {
              StatesHelper.Instance.externalToolCount[image.queueKey] = 1;
            }

            newTool.env_redis_url = image.queueKey;
            newTool.command = `'source /var/env-var.env && SNYK_TOKEN=09e1705e-9b8c-4fbc-95ae-f0651164a253 snyk test --all-projects --detection-depth=15 "CLONEDIR" --json-file-output="OUTPUTPATHsnykSCATest.json" > /dev/null'`;
            // DEBUG logs for Sofi
            if (
              [
                "lantern-consumer-service",
                "braze-toolkit",
                "sofiplus-entitlement",
                "money-service-autoconfigure",
                "reactive-comms-stats",
                "spring-component-test-utils",
                "promo-engine",
                "kafka-connect-s3-connector",
                "peregrine-kms-conversion",
              ].includes(repo.name)
            ) {
              newTool.command = `'source /var/env-var.env && DEBUG=snyk-test SNYK_TOKEN=09e1705e-9b8c-4fbc-95ae-f0651164a253 snyk test --all-projects --detection-depth=15 "CLONEDIR" --json-file-output="OUTPUTPATHsnykSCATest.json"'`;
            }
            logger.info(
              `addExternalCLIimagesToExecute for repo: ${repo.fullName}, image: ${JSON.stringify(image)} from total: ${
                cliToolsImages.length
              }`,
            );
            newTool.monoRepoCommand = newTool.command;
            newTool.fullCodeOverride =
              image.queueKey.startsWith("SNYKCLISBT") ||
              image.queueKey.startsWith("SNYKCLIGRADLE") ||
              image.queueKey.startsWith("SNYKCLIMAVEN");
          } else {
            logger.error(
              `failed single addExternalCLIimagesToExecute, repo: ${repo.fullName}, for image: ${JSON.stringify(image)} from total: ${
                cliToolsImages.length
              }`,
            );
          }
        });
      } else {
        if (StatesHelper.Instance.externalToolCount["none"]) {
          StatesHelper.Instance.externalToolCount["none"]++;
        } else {
          StatesHelper.Instance.externalToolCount["none"] = 1;
        }

        logger.info(`addExternalCLIimagesToExecute: no images to run for repo: ${repo.fullName}`);
      }
    } catch (err) {
      logger.error(`failed addExternalCLIimagesToExecute, repo: ${repo.fullName}, err: ${err}`, err);
    }
  }

  organizedFilesBasedOnCommits(commits: Commit[], allReposInMonoRepo: string[], repo: Repo) {
    const commitsMap = {};
    let caret = "/";

    for (const commit of commits) {
      try {
        if (commit.uniqueFiles.length == 0) {
          continue;
        }
        for (const uniqueFile of commit.uniqueFiles) {
          let uniqueFileDebug = `${repo.cloneDir}/${uniqueFile}`;

          if (process.env.DEBUG && process.env.WINDOWS) {
            const stringHelper: StringHelper = new StringHelper();
            uniqueFileDebug = stringHelper.replaceAllRegex(uniqueFileDebug, "/", "\\");
            caret = "\\";
          }

          const associatedRepos = allReposInMonoRepo.filter(i => uniqueFileDebug.includes(i + caret));

          if (associatedRepos.length >= 1) {
            const repoInfo = associatedRepos[0];
            if (commitsMap[repoInfo] == undefined) {
              commitsMap[repoInfo] = [commit];
            } else {
              commitsMap[repoInfo].push(commit);
            }
            break;
          }
        }
      } catch (err) {
        logger.error(`failed organized files based on commits, err: ${err}`);
      }
    }
    return commitsMap;
  }

  organizedciCandidatesFiles(commits: Commit[], repo: Repo) {
    try {
      commits.forEach(commitItem => {
        commitItem.filesModified.forEach(fileModified => repo.ciCandidates.add(`${repo.cloneDir}/${fileModified.path}`));
      });
    } catch (err) {
      logger.error(`failed organized ci candidate based on commits, err: ${err}`);
    }
  }

  organizedFilesBasedOPulls(pulls: PullRequest[], allReposInMonoRepo: string[], repo: Repo) {
    const pullsMap = {};
    let caret = "/";
    if (process.env.DEBUG != undefined) {
      caret = "\\";
    }

    if (pulls == undefined) {
      return [];
    }

    for (const pull of pulls) {
      try {
        if (pull.pullsCommitInfo.length == 0) {
          continue;
        }

        const singleFiles = pull.pullsCommitInfo.filter(i => !i.noFilesFound);
        if (singleFiles.length == 0) {
          continue;
        }

        for (const singleFile of singleFiles) {
          for (const uniqueFile of singleFile.uniqueFiles) {
            let uniqueFileDebug = `${repo.cloneDir}/${uniqueFile}`;

            if (process.env.DEBUG != undefined) {
              const stringHelper: StringHelper = new StringHelper();
              uniqueFileDebug = stringHelper.replaceAllRegex(uniqueFileDebug, "/", "\\");
            }

            const associatedRepos = allReposInMonoRepo.filter(i => uniqueFileDebug.includes(i + caret));
            if (associatedRepos.length == 1) {
              const repoInfo = associatedRepos[0];
              if (pullsMap[repoInfo] == undefined) {
                pullsMap[repoInfo] = [pull];
              } else {
                pullsMap[repoInfo].push(pull);
              }
              break;
            }
          }
        }
      } catch (err) {
        logger.error(`failed organized pulls based on pulls, err: ${err}`);
      }
    }
    return pullsMap;
  }

  async splitMonoRepo(repo: Repo, repoObj: any): Promise<any[]> {
    try {
      if (repo.monoRepoParent) {
        const startTime = new Date().getTime();

        const allReposInMonoRepo = await this.getMonoRepoChildrenFromRepoInfoJSON(repo);

        repo.monorepoChildrenCount = allReposInMonoRepo.length;

        const commits = this.organizedFilesBasedOnCommits(repoObj[CodeRepoTypes[CodeRepoTypes.commits]], allReposInMonoRepo, repo);
        const pulls = this.organizedFilesBasedOPulls(repoObj[CodeRepoTypes[CodeRepoTypes.pulls]], allReposInMonoRepo, repo);
        const pushedCommits = this.organizedFilesBasedOPulls(repoObj[CodeRepoTypes[CodeRepoTypes.pushedCommits]], allReposInMonoRepo, repo);

        const monoRepos = [];
        for (const repoPathFromDisk of allReposInMonoRepo) {
          try {
            const r = repoPathFromDisk.replace(repo.cloneDir, "");
            const repoNameForUI = r.replace("//", "/");

            if (r.startsWith(".")) {
              continue;
            }

            const monoRepoChildId = `${repo.id}_${r}`;
            const monoRepo = new Repo(
              this.uuid,
              this.orgName,
              repo.type,
              repoNameForUI,
              monoRepoChildId,
              `${repo.fullName}${repoNameForUI}`,
              repo.createdAt,
              repo.defaultBranch,
              repo.description,
              repo.disable,
              repo.cloneDir,
              repo.downloadCount,
              repo.hasIssues,
              repo.hasWiki,
              repo.hasIssues,
              repo.homepage,
              repo.privateVisability,
              [],
              0,
              repo.watchersCount,
              repo.ownerName,
              repo.link,
              repo.forksCount,
              repo.lastPushTime,
              repo.project,
              `${repo.fileLink}${repoNameForUI}/`,
              repo.linkFilePreffix,
              repo.tags,
              repo.settingLink,
              repo.commitLink,
              repo.pushesLink,
              repo.pullsLink,
              repo.organization,
              repo.id,
              repo.isOrgRepo,
              repo.name,
              repo.pipelineScanInfo,
              repo.vcsType,
            );

            repo.monorepoChildrenAppIds.add(monoRepoChildId);

            monoRepo.vcsType = repo.vcsType;
            monoRepo.repositoryHistorySize = repo.repositoryHistorySize;
            monoRepo.largeGitHistory = repo.largeGitHistory;
            monoRepo.organization = repo.organization;
            monoRepo.monoRepoChild = true;
            monoRepo.parentRepoOfMonoRepo = repo;
            monoRepo.cloneDir = repoPathFromDisk;
            monoRepo.insideFolder = r;
            monoRepo.headSha = repo.headSha;

            monoRepo.gitRoles = this.roleHelper.getGitRoles(repoType[monoRepo.type.toLowerCase()]);

            const filesList: File[] = await this.files(monoRepo);
            monoRepo.filesCount = filesList.length;

            monoRepo.deploymentFilesYmls = this.getDeploymentFilesYmls(filesList);

            await this.getAndSetRepoDevLanguagesKubernetesAndOrchestrator(monoRepo, filesList);

            //This we get from getRepoDevLanguagesFromFiles and should be taken from there
            if (monoRepo.orchestrator.length == 0) {
              monoRepo.orchestrator = repo.orchestrator;
            }
            if (monoRepo.kubernetes.length == 0) {
              monoRepo.kubernetes = repo.kubernetes;
            }

            let commitsPerRepo: Commit[] = commits[repoPathFromDisk];
            if (commitsPerRepo == undefined) {
              commitsPerRepo = [];
            }

            let pullsPerRepo: PullRequest[] = pulls[repoPathFromDisk];
            if (pullsPerRepo == undefined) {
              pullsPerRepo = [];
            }
            let pushedCommitsPerRepo: PullRequest[] = pushedCommits[repoPathFromDisk];
            if (pushedCommitsPerRepo == undefined) {
              pushedCommitsPerRepo = [];
            }

            const users: User[] = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.users]);

            const usersAfterFiler = users.filter(
              user =>
                commitsPerRepo.find(commit => commit.authorEmail.includes(user.name) || commit.authorEmail.includes(user.username)) !=
                undefined,
            );

            const sortedCommitsPerRepo = this.sortCommitsByDates(commitsPerRepo, repo);

            monoRepo.lastPushTime = repo.lastPushTime;
            monoRepo.isDelta = repo.isDelta;
            this.organizedciCandidatesFiles(sortedCommitsPerRepo, monoRepo);

            const newRepoObj = {};
            newRepoObj["uuid"] = this.uuid;
            newRepoObj["uniqueID"] = this.token.type + "_" + monoRepo.name + "_" + monoRepo.id;
            newRepoObj["resourceType"] = ResourceType[ResourceType.code_repo];
            newRepoObj[ResourceType[ResourceType.code_repo]] = monoRepo;
            newRepoObj[CodeRepoTypes[CodeRepoTypes.commits]] = sortedCommitsPerRepo;
            newRepoObj[CodeRepoTypes[CodeRepoTypes.files]] = filesList;
            newRepoObj[CodeRepoTypes[CodeRepoTypes.pulls]] = pullsPerRepo;
            newRepoObj[CodeRepoTypes[CodeRepoTypes.pushedCommits]] = pushedCommitsPerRepo;
            newRepoObj[CodeRepoTypes[CodeRepoTypes.users]] = usersAfterFiler.length > 0 ? usersAfterFiler : users;

            newRepoObj[CodeRepoTypes[CodeRepoTypes.webhooks]] = repoObj[CodeRepoTypes[CodeRepoTypes.webhooks]]
              ? repoObj[CodeRepoTypes[CodeRepoTypes.webhooks]]
              : [];
            newRepoObj[CodeRepoTypes[CodeRepoTypes.workflows]] = repoObj[CodeRepoTypes[CodeRepoTypes.workflows]]
              ? repoObj[CodeRepoTypes[CodeRepoTypes.workflows]]
              : [];

            const orgPolicyParser: OrgPolicyParser = new OrgPolicyParser(this.uuid);
            const cicdToolFromPolicy = orgPolicyParser.getCICDToolsBasededOnPolicy(null);

            let cicdHelper: CicdHelper = new CicdHelper(this.uuid, repo.name, repo.type, cicdToolFromPolicy, null);

            let cicdTools = await cicdHelper.getCicdTools(
              newRepoObj[CodeRepoTypes[CodeRepoTypes.webhooks]],
              newRepoObj[CodeRepoTypes[CodeRepoTypes.workflows]],
              newRepoObj[CodeRepoTypes[CodeRepoTypes.files]],
              monoRepo,
            );

            newRepoObj[ResourceType[ResourceType.code_repo]]["specialFiles"] = repo.specialFiles;

            if (cicdHelper.activeOrgCicdTools.length == 0) {
              cicdHelper.activeOrgCicdTools = repoObj.cicdHelper.activeOrgCicdTools;

              cicdTools.activeOrgCicdTools = repoObj.cicdHelper.activeOrgCicdTools;
            }
            if (cicdHelper.disableOrgCicdTools.length == 0) {
              cicdHelper.disableOrgCicdTools = repoObj.cicdHelper.disableOrgCicdTools;

              cicdTools.disableOrgCicdTools = repoObj.cicdHelper.disableOrgCicdTools;
            }
            if (cicdHelper.cloudDeployments.length == 0) {
              cicdHelper.cloudDeployments = repoObj.cicdHelper.cloudDeployments;
            }
            if (cicdHelper.deploymentFiles.length == 0) {
              cicdHelper.deploymentFiles = repoObj.cicdHelper.deploymentFiles;
            }

            if (cicdHelper.artifactory.length == 0) {
              cicdHelper.artifactory = repoObj.cicdHelper.artifactory;
              monoRepo.artifactory = repoObj.cicdHelper.artifactory;
            }
            if (cicdHelper.containerFiles.length == 0) {
              cicdHelper.containerFiles = repoObj.cicdHelper.containerFiles;
            }
            newRepoObj["cicdTools"] = cicdTools;
            newRepoObj["cicdHelper"] = cicdHelper;
            newRepoObj["cloudDeployments"] = cicdHelper.cloudDeployments;
            newRepoObj["artifactory"] = cicdHelper.artifactory;
            newRepoObj["monoRepo"] = true;

            monoRepos.push(newRepoObj);
          } catch (err) {
            logger.error(`failed extend single mono repo, for parent repo: ${repo.fullName}, err: ${err}`);
          }
        }

        let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);

        logger.info(`finish split monorepo for repo: ${repo.fullName} in ${elapsedTime} minutes, monorepo count: ${monoRepos.length}`);
        return monoRepos;
      }
    } catch (err) {
      logger.error(`failed extend all mono repos, for parent repo: ${repo.fullName}, err: ${err}`);
    }
    return [];
  }

  async getDataFromCash(repo: Repo, applicationSecurityEvents: ApiSecurityItem[], allAlerts: SecurityEvent[], sbomAlerts: SbomEvent[]) {
    try {
      logger.info(`try get from cash for repo: ${repo.fullName}`);
      const startTime = new Date().getTime();

      const secEventsFromCash = await this.cacheResovler.getFromCache<SecurityEvent>(
        { id: repo.id, idKey: "repoId", name: repo.fullName },
        Cache.SecurityEvents,
      );
      secEventsFromCash.forEach(i => {
        setSecEventFromDelta(repo, i);
      });

      if (StatesHelper.Instance.isApiSecEnable) {
        let apiSecurityItems = await this.cacheResovler.getFromCache<ApiSecurityItem>(
          { id: repo.id, idKey: "appId", name: repo.fullName },
          Cache.apiSecurityEvents,
        );
        if (apiSecurityItems && apiSecurityItems?.length > 0) {
          for (let secEvent of apiSecurityItems) {
            if (secEvent.scanId !== this.uuid) {
              secEvent.scanId = this.uuid;
            }
            if ("_id" in secEvent) {
              delete secEvent["_id"];
            }
            applicationSecurityEvents.push(secEvent);
          }
        }
      }

      secEventsFromCash.forEach(i => {
        allAlerts.push(i);
      });

      const res = await this.cacheResovler.getSbomCache({ id: repo.id, idKey: "repoId", name: repo.fullName });
      res.forEach(i => {
        sbomAlerts.push(i);
      });

      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
      logger.info(
        `finish get from cash for repo: ${repo.fullName}, secEventsFromCash: ${secEventsFromCash.length}, sbomAlerts: ${sbomAlerts.length}, elapsedTime: ${elapsedTime}`,
      );
    } catch (err) {
      logger.error(`failed getDataFromCash repo: ${repo.fullName}, err: ${err}`);
    }
  }

  async postProcessingSecEvents(
    repo: Repo,
    allSecEvents: SecurityEvent[],
    sbomAlerts: SbomEvent[],
    apiSecurityItems: ApiSecurityItem[],
    applicationSecurityEvents: ApiSecurityItem[],
  ) {
    //Start info
    const verificationAndStarsHelper = this.callObj.applicationsManager.verificationAndStarsHelper;
    for (const alert of allSecEvents) {
      if (alert?.ruleId === "cicd.github-actions.pin-actions-to-commit-sha") {
        await GlobalCodeRepoData.Instance.handleActions(alert, repo);
      }
    }
    await verificationAndStarsHelper.getDataFromCache(repo);

    for (const securityEvent of allSecEvents) {
      const devLan = await this.getDevLan(repo, securityEvent.fileName, true, false);
      securityEvent.language = devLan;

      if (this.isRepoInfoJsonFeatureEnabled) {
        const devLanFromRepoInfoJSON = await this.getDevLanFromRepoInfoJSON(repo, securityEvent.fileName);
        if (devLanFromRepoInfoJSON) {
          securityEvent.language = devLanFromRepoInfoJSON;
        }
      }
      securityEvent.language = getDevLanBasedOnFileName(securityEvent.language, securityEvent.fileName);
    }

    this.setRepoPkgManager(allSecEvents, sbomAlerts, repo);

    if (repo.unlistedActions?.size /* && only for github ?*/) {
      await this.setRepoVerification(repo);
    }

    await this.handleAPISecurityEvents(repo, apiSecurityItems, applicationSecurityEvents);
  }

  async handleAPISecurityEvents(repo: Repo, apiSecurityItems: ApiSecurityItem[], applicationSecurityEvents: ApiSecurityItem[]) {
    try {
      const shouldRun = StatesHelper.Instance.isApiSecEnable && !StatesHelper.Instance.isPipelineScan;

      if (!shouldRun) {
        return;
      }

      const apiCodeCount: number = apiSecurityItems.length;
      //const llmClientAPIHelper = new LlmClientAPIHelper(this.callObj.llmClientQueue, this.uuid, this.orgName);
      //await llmClientAPIHelper.callLlmClientForAPIEnrichment(repo, apiSecurityItems);

      //Save application security data
      if (applicationSecurityEvents.length > 0) {
        applicationSecurityEvents.forEach(i => {
          apiSecurityItems.push(i);
        });
      }

      if (apiSecurityItems.length > 0) {
        if (!repo.isDelta) {
          logger.info(`saving API security items: ${repo.fullName}, items before merge: ${apiSecurityItems.length}`);
          apiSecurityItems = APIDiscoveryHelper.mergeAPISecurityItems(apiSecurityItems, repo?.fullName);

          let apiSecurityItemsHistory: ApiSecurityItem[] = await this.callObj.resultsHandler.mongoDBreport.getAPiSecurityHistory(
            repo?.repoId,
          );
          const numOfHistoryItems: number = apiSecurityItemsHistory?.length;
          apiSecurityItemsHistory = APIDiscoveryHelper.updateFirstSeen(apiSecurityItems, apiSecurityItemsHistory, repo?.fullName);
          if (apiSecurityItemsHistory?.length > numOfHistoryItems) {
            await this.callObj.resultsHandler.mongoDBreport.addAPiSecurityHistory(apiSecurityItemsHistory, repo?.repoId);
          }

          await this.cacheResovler.setForCache<ApiSecurityItem>(
            { id: repo.id, idKey: "appId", name: repo.fullName },
            apiSecurityItems,
            Cache.apiSecurityEvents,
          );

          logger.info(`saving API security items: ${repo.fullName}, after merge: ${apiSecurityItems.length}`, {
            "ox-api-swagger-count": applicationSecurityEvents.length,
            "ox-api-code-count": apiCodeCount,
            "ox-api-merged-count": apiSecurityItems.length,
            "ox-api-repo": repo.fullName,
          });
        }

        await this.callObj.resultsHandler.mongoDBreport.addAPiSecurity(apiSecurityItems);
      }
    } catch (err) {
      logger.error(`handleAPISecurityEvents failed err: ${err}, repo: ${repo.fullName}`);
    }
  }

  async setRepoVerification(repo: Repo) {
    try {
      const verificationAndStarsHelper = this.callObj.applicationsManager.verificationAndStarsHelper;

      await verificationAndStarsHelper.setItems(repo);
      await verificationAndStarsHelper.getDataFromCache(repo);
    } catch (e) {
      logger.error(`setRepoVerification failed err: ${e}, repo: ${repo.fullName}`);
    }
  }

  setRepoPkgManager(allAlerts: SecurityEvent[], allSbom: SbomEvent[], repo: Repo) {
    try {
      if (repo.pkgManagers.length > 0) {
        return;
      }

      const uniquePkgManagers = new Set();
      const res = [];
      allAlerts.forEach(i => {
        if (i.pkgManager) {
          if (!uniquePkgManagers.has(i.pkgManager.toLowerCase())) {
            res.push(getPkgManagerPretty(i.pkgManager));
            uniquePkgManagers.add(i.pkgManager.toLowerCase());
          }
        }
      });
      repo.pkgManagers = res;

      allSbom.forEach(i => {
        i?.sbomHelper?.extendedSbom?.components?.forEach(j => {
          if (j.pkgManager) {
            if (!uniquePkgManagers.has(j.pkgManager.toLowerCase())) {
              res.push(getPkgManagerPretty(j.pkgManager));
              uniquePkgManagers.add(j.pkgManager.toLowerCase());
            }
          }
        });
      });
      repo.pkgManagers = res;
    } catch (err) {
      logger.error(`failed set repo pkg manager for: ${repo.fullName}, err: ${err}`);
    }
  }

  async commits(repo: Repo): Promise<any> {
    let commitsList: Commit[] = [];

    try {
      if (repo.noneRelevantRepo) {
        return [];
      }

      const extendedCommits =
        isLocalDevelopment() && !process.env.DOCKER_DEBUG
          ? await this.getCommitsFromDisk(repo)
          : await this.getCommitsFromGitInfoJSON(repo);

      this.organizedciCandidatesFiles(extendedCommits, repo);
      const repoCreatedOInHours = this.timeHelper.getTimeIntervalFronNowInHours(repo.createdAt);

      // for emails
      extendedCommits.reverse().map(extendedCommit => {
        const isOrgDomain = this.isOrgMail(extendedCommit.authorEmail);
        if (isOrgDomain) {
          this.globalCodeRepoData.userMailMap.set(extendedCommit.authorName, extendedCommit.authorEmail);
        }
      });

      for (const extendedCommit of extendedCommits) {
        try {
          const commitTimeInHours = this.timeHelper.getTimeIntervalFronNowInHours(extendedCommit.date);

          if (repoCreatedOInHours != -1 && commitTimeInHours != -1 /* && !repo.monoRepoParent */) {
            if (commitTimeInHours > repoCreatedOInHours) {
              continue;
            }
          }

          // new implementation

          let commit = new Commit(
            repo.commitLink + extendedCommit.hash,
            extendedCommit.date,
            extendedCommit.authorEmail,
            extendedCommit.authorName,
            extendedCommit.message,
            extendedCommit.hash,
            extendedCommit.filesAdded,
            extendedCommit.filesDeleted,
            extendedCommit.filesModified,
            extendedCommit.filesRenamed,
          );

          commitsList.push(commit);
        } catch (err) {
          logger.error(`get single commit failed repo: ${repo.name}, err: ${err}`);
          StatesHelper.Instance.addFailedTool(repoResourceType.commits, repo.id);
        }
      }
    } catch (err) {
      logger.error(`get all commit failed repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool(repoResourceType.commits, repo.id);
    }

    const sorted = this.sortCommitsByDates(commitsList, repo);
    this.globalCodeRepoData.addCommit(sorted, repo);
    return sorted;
  }

  async initBaseInfo(repoObj: any, repo: Repo) {
    repoObj["uuid"] = this.uuid;
    repoObj["uniqueID"] = this.token.type + "_" + repo.name + "_" + repo.id;
    repoObj["resourceType"] = ResourceType[ResourceType.code_repo];
    repoObj[ResourceType[ResourceType.code_repo]] = repo;
    repoObj[CodeRepoTypes[CodeRepoTypes.securityEvents]] = [];

    //Set unique files to be used for seartching connection to this repo
    const files: File[] = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.files]);
    const uniqueFiles = new Set();
    files.forEach(i => uniqueFiles.add(i.fileNameWithoutDisk));
    repoObj[CodeRepoTypes[CodeRepoTypes.uniqueFiles]] = uniqueFiles;

    if (repo.sizeInBytes <= 0 && !repo.noneRelevantRepo) {
      const repoSize = this.isRepoInfoJsonFeatureEnabled
        ? await this.getRepositorySizeInBytesFromRepoInfoJSON(repo)
        : await this.fileHelper.getFolderSizeWithTimeout(repo.cloneDir);
      repo.sizeInBytes = repoSize;

      const repoHistorySize = this.isRepoInfoJsonFeatureEnabled ? await this.getRepositoryHistorySizeInBytesFromRepoInfoJSON(repo) : -1;
      repo.setRepositoryHistorySize(repoHistorySize);
    }

    if (repo.repositoryHistorySize >= 2000000000) {
      logger.info(`set largeGitHistory ${repo.fullName} size: ${repo.repositoryHistorySize}`);
      repo.largeGitHistory = true;
    }

    const { tags, excludedTagsIds } = await TagsService.Instance.getAppTagsAndExclusions(this.orgName, repo.id);
    repo.excludedTagsIds = excludedTagsIds;
    repo.appTags = tags;

    StatesHelper.Instance.pipelineScanInfo.repoName = repo.fullName;
    StatesHelper.Instance.pipelineScanInfo.numberOfFilesScanned = repo.filesCount;
    StatesHelper.Instance.pipelineScanInfo.performance = PipeLineHelper.Instance.performance;
    StatesHelper.Instance.pipelineScanInfo.sourceType = repo.type;

    ToolsExecutionStats.addResourceDelta(repo.fullName, repo.id, "repo", repo.isDelta, repo.type);

    await this.setRepoInfoFromCashForUnchangedRepo(repo);
  }

  async setRepoInfoFromCashForUnchangedRepo(repo: Repo) {
    try {
      if (!repo.isDelta) {
        return;
      }
      const app = await this.mongoDBApplications.getApplicationById(repo.id);
      if (app == null || !app) {
        return;
      }
      const severityChangedReason = app.severityChangedReason;
      if (!severityChangedReason) {
        logger.info(
          `set severityChangedReason from cash for ${repo.fullName} count: ${severityChangedReason.length}, severityChangedReason is undefined`,
        );
        return;
      }
      if (!Array.isArray(severityChangedReason)) {
        logger.error(
          `failed set setRepoInfoFromCashForUnchangedRepo from cash for repo: ${repo.fullName} severityChangedReason are not array`,
        );
        return;
      }

      severityChangedReason.forEach(i => {
        repo.addRepoSeverityChangedReason(i, i.extraInfo);
      });

      logger.info(
        `set severityChangedReason from cash for ${repo.fullName} count: ${severityChangedReason.length}, repo severity factors: ${repo.severityChangedReason.length}`,
      );
    } catch (err) {
      logger.error(`failed set setRepoInfoFromCashForUnchangedRepo from cash for repo: ${repo.fullName}, err: ${err}`);
    }
  }

  async collectRepoInfo(repoObj: any, repo: Repo) {
    const startTime = new Date().getTime();

    //Add all resources to brnach or main repo object
    const firstLevelApisProms = this.resourcesToCollect.map(resource => this.addFirstLevelItemToRepo(repo, repoObj, resource));
    await Promise.all(firstLevelApisProms);

    let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
    logger.info(`finish collect repo info for repo: ${repo.fullName} in ${elapsedTime} minutes`);
  }

  async setDepConfusionData(repo: Repo, repoObj: any) {
    try {
      const allSecEvents: SecurityEvent[] = repoObj[CodeRepoTypes[CodeRepoTypes.securityEvents]];
      //Dep confusion scopes events
      const depConfusionScopesEvents = allSecEvents.filter(event => event.securityAlertType === SecurityAlertType.depConfusionScopes);
      logger.info(`depConfusionScopesEvents count: ${depConfusionScopesEvents.length}, for repo: ${repo.fullName}`);

      GlobalCodeRepoData.Instance.addSecEvent(depConfusionScopesEvents);
      for (const event of depConfusionScopesEvents) {
        GlobalCodeRepoData.Instance.addRepoToScope(event);
      }
    } catch (err) {
      logger.error(`failed set setDepConfusionData from cash for repo: ${repo.fullName}, err: ${err}`);
    }
  }

  async setRepoAdditionalInfo(repoObj: any, repo: Repo) {
    const orgPolicyParser: OrgPolicyParser = new OrgPolicyParser(this.uuid);

    const webhook = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.webhooks]);
    const workflows = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.workflows]);
    const files = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.files]);
    const securityEvents = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.securityEvents]);
    const pulls = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.pulls]);
    const pushes = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.pushedCommits]);
    const users = this.jsonHelper.lookupArrayVal(repoObj, CodeRepoTypes[CodeRepoTypes.users]) as User[];

    //CICD, set only in case not mono repo
    //for mono repo its done in the section of mono repo
    if (repo.parentRepoOfMonoRepo == null) {
      const cicdToolFromPolicy = orgPolicyParser.getCICDToolsBasededOnPolicy(null);
      const cicdHelper: CicdHelper = new CicdHelper(this.uuid, repo.name, repo.type, cicdToolFromPolicy, null);
      const cicdTools = await cicdHelper.getCicdTools(webhook, workflows, files, repo);
      repoObj["cicdTools"] = cicdTools;
      repoObj["cicdHelper"] = cicdHelper;
      repoObj["cloudDeployments"] = cicdHelper.cloudDeployments;
      repoObj["artifactory"] = cicdHelper.artifactory;
    }

    const securityToolFromPolicy = orgPolicyParser.getSecurityToolsBasededOnPolicy(null);
    const securityToolsHelper: SecurityToolsHelper = new SecurityToolsHelper(
      this.uuid,
      repo.name,
      securityToolFromPolicy,
      repoObj["cicdHelper"].deploymentFiles,
      this.callObj.collectorManager.collectors,
      repo,
      files,
    );
    const securityTools = securityToolsHelper.getSecurityTools(webhook, workflows, files, securityEvents);
    repoObj["securityTools"] = securityTools;

    try {
      securityToolsHelper.setSpecialFiles(files);
    } catch (e) {
      StatesHelper.Instance.addFailedTool(repoResourceType.specialFiles, repo.id);
      logger.error(`failed to set special files for ${repo.name}`);
    }

    const sortedCodeChangesByDate = this.sortPullsAndPushesByDates([...pushes, ...pulls], repo);
    //Set last code push time if empty
    if (!repo.lastPushTime) {
      if (sortedCodeChangesByDate.length > 0) {
        const lastCodeChangeTime = sortedCodeChangesByDate[0].createdAt;
        repo.lastPushTime = lastCodeChangeTime;
      }
    }

    const sortedCommits = this.sortCommitsByDates(repoObj.commits, repo);

    //Set first code push time if empty
    if (!repo.createdAt) {
      if (sortedCommits.length > 0) {
        const firstCodeChangeTime = sortedCommits[sortedCommits.length - 1].date;
        repo.createdAt = firstCodeChangeTime;
      } else if (sortedCodeChangesByDate.length > 0) {
        const firstCodeChangeTime = sortedCodeChangesByDate[sortedCodeChangesByDate.length - 1].createdAt;
        repo.createdAt = firstCodeChangeTime;
      }
    }

    const repoImportance = await this.getRepoImportance(repoObj, repo);

    const secInfra = securityToolsHelper.getUnprotectedLanguages(webhook, workflows, files, securityEvents, repo.languages);

    const mostVeretanUsers = this.getRepoVeteranReviewers([...pulls, ...pushes]);

    repo.setAdditionalInfo(
      securityTools.activeSast.map(i => i.name),
      securityTools.activeSca.map(i => i.name),
      securityTools.activeSecrets.map(i => i.name),
      securityTools.activeIac.map(i => i.name),
      securityTools.activeCspm.map(i => i.name),
      securityTools.disableSast.map(i => i.name),
      securityTools.disableSca.map(i => i.name),
      securityTools.oxSecurityTools,
      secInfra.unprotectedSastDevLanguages,
      secInfra.unprotectedScaDevLanguages,
      repoObj["cicdTools"].activeOrgCicdTools,
      webhook.length,
      securityToolsHelper.getContainerFiles(files),
      repoImportance,
      files.length,
      [],
      repoObj["cicdHelper"].cloudDeployments,
      secInfra.secInfra,
      users,
      mostVeretanUsers,
      securityToolsHelper.toolCoverage,
    );

    return repoObj;
  }

  async enrichRepoObj(repoObj: any, repo: Repo, resources: Resource[]) {
    try {
      logger.info(`enrichRepoObj for repo: ${repo.fullName}`);

      const startTime = new Date().getTime();

      const repoFromObj = this.jsonHelper.lookupArrayVal(repoObj, ResourceType[ResourceType.code_repo], false);

      if (repoFromObj == null) {
        logger.error(`failed enrich repo info because type: ${ResourceType[ResourceType.code_repo]} not found in repo: ${repo.fullName}`);
        return;
      }

      const apisProms = resources.map(resource => this.enrichItemToRepoObj(repoFromObj as Repo, repoObj, resource));

      await Promise.all(apisProms);

      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);

      logger.info(`finish enrich repo info for repo: ${repo.fullName} in ${elapsedTime} minutes`);
    } catch (err) {
      logger.error(`failed enrich resources repo: ${repo.fullName}, err: ${err}`);
    }
  }

  async files(repo: Repo) {
    let filesObj: File[] = [];

    try {
      const files = this.isRepoInfoJsonFeatureEnabled //&& repo.vcsType !== VCSType.tfvc
        ? await this.getFilesFromRepoInfoJSON(repo)
        : await this.getfilesFromClone(repo);

      for (const fileInfo of files) {
        const pathInfo = this.fileHelper.getFileNameAccordingToLinkPage(fileInfo.name, repo.cloneDir);
        filesObj.push(new File(fileInfo.name, repo.fileLink + pathInfo, repo.cloneDir));
      }
    } catch (err) {
      logger.error(`get files failed repo: ${repo.name}, err: ${err}`);
    }

    return filesObj;
  }

  async getRepoDevLanguages(repo: Repo, devLan: any): Promise<DevLanguages[]> {
    let lan: DevLanguages[] = [];

    try {
      logger.debug(`try get dev language for repo: ${repo.name}`);

      let total: number = 0;

      Object.entries(Constant.languageRenameMap).forEach(([oldName, newName]) => {
        if (devLan.hasOwnProperty(oldName)) {
          delete Object.assign(devLan, { [newName]: devLan[oldName] })[oldName];
        }
      });

      Object.entries(devLan).forEach(([key, value]) => {
        if (key.toLowerCase() != "dockerfile") {
          total += value as number;
        }
      });

      Object.entries(devLan).forEach(([key, value]) => {
        if (key.toLowerCase() != "dockerfile") {
          let precentageNum = Math.trunc(((value as number) / total) * 100);
          if (precentageNum > 0) {
            let devLanguages = new DevLanguages(key, precentageNum);
            lan.push(devLanguages);
          }
        }
      });

      logger.debug(`finish get dev language for repo: ${repo.name}, dev lan count: ${lan.length}`);
    } catch (err) {
      throw `get dev language for repo: ${repo.name}, err: ${err}`;
    }
    return lan;
  }

  getDeploymentFilesYmls(files: File[]): File[] {
    return files.filter(element => {
      return element.path.endsWith(".yml") || element.path.endsWith(".yaml") || element.path.endsWith("Jenkinsfile");
    });
  }

  // returns dev languages
  // pushes to repo.kubernetes and repo.orchestrator from this.getDevLan method
  getRepoDevLanguagesFromFiles(repo: Repo, listOfFiles: File[], acceptAll: Boolean = false, deepAnalysis: Boolean = false) {
    let devLan = {};
    let total = 0;
    listOfFiles.forEach(element => {
      let res = this.getDevLan(repo, element.path, acceptAll, deepAnalysis);
      res = getDevLanBasedOnFileName(res, element.name);
      if (res) {
        if (Constant.languageRenameMap.hasOwnProperty(res)) {
          res = Constant.languageRenameMap[res];
        }
        total++;
        if (devLan.hasOwnProperty(res)) {
          devLan[res] = devLan[res] + 1;
        } else {
          devLan[res] = 1;
        }
      }
    });

    let lan: DevLanguages[] = [];
    Object.entries(devLan).forEach(([key, value]) => {
      if (Constant.dockerRegex.exec(key) == null) {
        const val = value as number;
        let precentageNum = Math.trunc((val / total) * 100);
        if (precentageNum > 0) {
          let devLanguages = new DevLanguages(key, precentageNum);
          lan.push(devLanguages);
        }
      }
    });

    logger.debug(`finish split dev language repo: ${repo.name}`);
    return lan;
  }

  async getAndSetRepoDevLanguagesKubernetesAndOrchestrator(repo: Repo, filesList: File[]) {
    if (this.isRepoInfoJsonFeatureEnabled) {
      repo.languages = await this.getRepoDevLanguagesFromRepoInfoJSON(repo);
      repo.kubernetes = await this.getKubernetesFilesFromRepoInfoJSON(repo);
      repo.orchestrator = await this.getOrchestratorFilesFromRepoInfoJSON(repo);
    } else {
      repo.languages = await this.getRepoDevLanguagesFromFiles(repo, filesList, true, true);
    }
  }

  async getfilesFromClone(repo: Repo) {
    const fileHelper: FileHelper = new FileHelper(this.uuid);
    const res = await fileHelper.getFiles(repo.cloneDir);
    return res;
  }

  async getFileCount(path: string) {
    const fileHelper: FileHelper = new FileHelper(this.uuid);
    const files = await fileHelper.getFiles(path);
    return files.length;
  }

  private async getRepoImportance(codeRepoInfo, repo: Repo) {
    try {
      let ymls = [];
      let readme = [];
      let securityMD = [];
      let license = [];
      let gitignore = [];

      const files = this.jsonHelper.lookupArrayVal(codeRepoInfo, CodeRepoTypes[CodeRepoTypes.files]);

      for (const file of files) {
        const filePathToLower = file.path;

        if (filePathToLower.includes(".yml") || filePathToLower.includes(".yaml")) {
          ymls.push(file);
        }
        if (filePathToLower.includes("readme")) {
          readme.push(file);
        }
        if (filePathToLower.includes("security.md")) {
          securityMD.push(file);
        }
        if (filePathToLower.includes("license.md")) {
          license.push(file);
        }
        if (filePathToLower.includes(".gitignore")) {
          gitignore.push(file);
        }
      }

      let gitIgnoreContent = "";
      try {
        if (gitignore.length > 0) {
          gitIgnoreContent = fs.readFileSync(gitignore[0].path, "utf8");
        }
      } catch (err) {
        logger.error("");
      }

      let totalDevLanguagesPrecentag = 0;
      repo.languages.forEach(element => {
        totalDevLanguagesPrecentag += element.languagePercentage;
      });

      const commits: Commit[] = this.jsonHelper.lookupArrayVal(codeRepoInfo, CodeRepoTypes[CodeRepoTypes.commits]);
      const pulls = this.jsonHelper.lookupArrayVal(codeRepoInfo, CodeRepoTypes[CodeRepoTypes.pulls]);
      const pushes = this.jsonHelper.lookupArrayVal(codeRepoInfo, CodeRepoTypes[CodeRepoTypes.pushedCommits]);
      const users = this.jsonHelper.lookupArrayVal(codeRepoInfo, CodeRepoTypes[CodeRepoTypes.users]);

      const uniqueCodeChangesByDate = this.getUniqueCodeChangesByDate(repo, [...pulls, ...pushes]);

      const uniqueCommits: Commit[] = this.getUniqueUserCommits(repo, commits);

      let commitsCount = commits.length;
      let ownerName = this.getOwnerRepoBasedOnCommits(repo, commits);
      if (ownerName === null) {
        // no users from commits
        ownerName = this.getOwnerRepoBasedOnUsers(repo, users);
      }
      if (ownerName != null) {
        repo.ownerName = ownerName.owner;
        repo.ownerEmail = ownerName.email;
      }

      let totalCommits = commitsCount > commits.length ? commitsCount : commits.length + pulls.length;
      if (files.length == 0) {
        totalCommits = 0;
      }

      let uniqueCommitsInfo = uniqueCommits.length;
      //This 2 are specific for demo
      if (repo.users != -1) {
        uniqueCommitsInfo = repo.users;
      }

      let numOfBranches = this.jsonHelper.lookupArrayVal(codeRepoInfo, CodeRepoTypes[CodeRepoTypes.branches]).length;
      if (numOfBranches == 0) {
        numOfBranches = 1;
      }
      // create interface for info object
      const info: RepoImportanceInfo = {
        numberOfcommits: totalCommits,
        codeChanges: pushes.length + pulls.length,
        uniqueCommits: uniqueCommitsInfo,
        lastCodeChange: repo.lastPushTime,
        numberOfPushes: pushes.length,
        numberOfPullRequests: pulls.length,
        numberOfUniqueCodeChangesByDate: uniqueCodeChangesByDate.length,
        numberOfMerges: pulls.length + commits.filter(i => i.merged).length,
        numberOfLanguageFiles: totalDevLanguagesPrecentag,
        branches: numOfBranches,
        numberOfTags: 0,
        numberOfYMLs: ymls.length,
        numberOfFiles: files.length,
        mainBranch: repo.defaultBranch,
        size: repo.sizeInBytes,
        creator: ownerName !== null ? ownerName.owner : "",
        createdAt: repo.createdAt,
        gitIgnore: {
          exist: gitignore.length > 0,
          lines: gitIgnoreContent.split("\n").length,
        },
        readMe: readme.length > 0,
        securityMD: securityMD.length > 0,
        license: license.length > 0,
        isPrivate: repo.privateVisability,
        extendedInfo: {
          version: repo.type,
          forks_count: repo.forksCount,
          has_downloads: (repo.downloadCount as number) > 0,
          watchers_count: repo.watchersCount,
        },
      };

      const importanceCalcHelper: RepoImportanceCalcHelper = new RepoImportanceCalcHelper(this.uuid, this.orgName);

      const importanceCalc = await importanceCalcHelper.getRepoImportance(info, repo, null);
      return importanceCalc;
    } catch (err) {
      logger.error(`faild get repo importance repo: ${repo.name}, err: ${err}`);
    }
    return [];
  }

  private getUniqueUserCommits(repo: Repo, commits: Commit[]) {
    let uniqueCommitsInfo: Commit[] = [];

    try {
      let uniqueCommits = new Set();
      logger.debug(`try get unique commits repo ${repo.name}`);

      for (const commit of commits) {
        if (uniqueCommits.has(commit.authorName)) {
          continue;
        }
        uniqueCommits.add(commit.authorName);
        uniqueCommitsInfo.push(commit);
      }

      logger.debug(`finish get unique commits repo ${repo.name}`);
      return uniqueCommitsInfo;
    } catch (err) {
      logger.error(`repo: ${repo.name}, err: ${err}`);
    }
    return uniqueCommitsInfo;
  }

  private setAndExtendWithMandatoryResources(resources: Resource[]) {
    try {
      for (const codeRepoTypes of this.mandatoryResources) {
        if (resources.some(i => i.name === CodeRepoTypes[codeRepoTypes])) {
          continue;
        }

        let resource: Resource = new Resource();
        resource.name = CodeRepoTypes[codeRepoTypes].toLowerCase();
        resource.type = this.resourceType;
        resources.push(resource);
      }

      //Split resources
      for (const resource of resources) {
        if (resource.global) {
          this.globalEnrichResourcesToCollect.push(resource);
        } else if (this.secondEnrichResources.some(i => CodeRepoTypes[i] == resource.name)) {
          this.secondEnrichResourcesToCollect.push(resource);
        } else if (this.thirdEnrichResources.some(i => CodeRepoTypes[i] == resource.name)) {
          this.thirdEnrichResourcesToCollect.push(resource);
        } else if (this.forthEnrichResources.some(i => CodeRepoTypes[i] == resource.name)) {
          this.forthEnrichResourcesToCollect.push(resource);
        } else {
          this.resourcesToCollect.push(resource);
        }
      }
    } catch (err) {
      logger.error(`failed extend with mandatory resources, err: ${err}`);
    }
  }

  setLastCodeChange(apiRepo: any, lastCodeChange: string) {
    try {
      apiRepo.lastCodeChange = new Date(lastCodeChange);
    } catch (err) {
      logger.error(`failed set last code change, err: ${err}`);
    }
  }

  private async getGitInfoJSON(repo: Repo): Promise<GitInfoJSON> {
    const defaultResponse = {
      headSha: null,
      commitCount: 0,
      commits: [],
    };

    // TFS has no git info
    if (repo.vcsType === VCSType.tfvc) {
      return defaultResponse;
    }

    // no git info when it's not requested from cloner
    if (repo.useDotGit === false) {
      return defaultResponse;
    }

    // don't event attempt to read the file unless we know clone was attempted and was successful
    if (repo.failedClone || !repo.successfulClone) {
      return defaultResponse;
    }

    try {
      const contents = this.fileHelper.readFile(`${repo.codeZipDir}-git-info.json`);
      const parsed = JSON.parse(contents) as GitInfoJSON;
      logger.debug(
        `read and parsed git info from json for ${repo.fullName}. headSha: ${parsed.headSha}, ` +
          `total commit count: ${parsed.commitCount}, retrieved commit count: ${parsed.commits.length}`,
      );
      return parsed;
    } catch (e) {
      logger.error(`unable to read or parse git info for ${repo.fullName} from json, e: ${e}`);
      return defaultResponse;
    }
  }

  private async getRepoInfoJSONFromFile(repo: Repo): Promise<RepositoryInfoJSON> {
    const defaultResponse: RepositoryInfoJSON = {
      repoInfo: {
        size: 0,
        gitSize: 0,
        codeSize: 0,
        repoHistorySize: 0,
        devLanguages: [],
        filesWithLanguages: [],
        kubernetesFiles: [],
        orchestratorFiles: [],
      },
      isMonoRepo: false,
      repoInfoPerMonorepoChild: [],
      repoInfoForOrphanedFiles: null,
    };

    // don't event attempt to read the file unless we know clone was attempted and was successful
    if (repo.failedClone || !repo.successfulClone) {
      return defaultResponse;
    }

    try {
      const contents = this.fileHelper.readFile(`${repo.codeZipDir}-repo-info.json`);
      const parsed = JSON.parse(contents) as RepositoryInfoJSON;
      logger.info(
        `read and parsed repo info from json for ${repo.fullName}. ` +
          `file count: ${parsed.repoInfo.filesWithLanguages.length}, size: ${parsed.repoInfo.size}, gitSize: ${parsed.repoInfo.gitSize}, codeSize: ${parsed.repoInfo.codeSize}, ` +
          `dev languages count: ${parsed.repoInfo.devLanguages.length}, ` +
          `isMonoRepo: ${parsed.isMonoRepo}, mono repo children count: ${parsed.repoInfoPerMonorepoChild?.length}.`,
      );
      return parsed;
    } catch (e) {
      logger.error(`unable to read or parse repo info for ${repo.fullName} from json, e: ${e}`);
      return defaultResponse;
    }
  }

  private async getRepoInfoJSONFromCacheOrFile(repo: Repo): Promise<RepositoryInfoJSON> {
    const key = [repo.vcsType, repo.type, repo.fullName].join("-");
    const cached = this.repoInfoJSONCache.get(key);
    if (cached) return cached;
    const info = await this.getRepoInfoJSONFromFile(repo);
    this.repoInfoJSONCache.set(key, info);
    return info;
  }

  // accounts for mono repo child/parent
  private async getRepoInfo(repo: Repo): Promise<RepositoryInfo> {
    // regular repo
    if (!repo.monoRepoChild) {
      const infoJSON = await this.getRepoInfoJSONFromCacheOrFile(repo);
      return infoJSON.repoInfo;
    }

    const parentInfoJSON = await this.getRepoInfoJSONFromCacheOrFile(repo.parentRepoOfMonoRepo);
    const monoRepoChild = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;

    const childFileInfo = parentInfoJSON.repoInfoPerMonorepoChild.find(fileInfo => fileInfo.monoRepoChild === monoRepoChild);

    if (childFileInfo) return childFileInfo.repoInfo;

    return {
      size: 0,
      gitSize: 0,
      codeSize: 0,
      repoHistorySize: 0,
      devLanguages: [],
      filesWithLanguages: [],
      kubernetesFiles: [],
      orchestratorFiles: [],
    };
  }

  // accounts for mono repo child/parent
  private async getfilesWithLanguages(repo: Repo): Promise<FileWithLanguage[]> {
    // regular repo
    if (!repo.monoRepoChild) {
      const infoJSON = await this.getRepoInfoJSONFromCacheOrFile(repo);
      let files = infoJSON?.repoInfo?.filesWithLanguages;
      if (infoJSON?.isMonoRepo) {
        let fileLength = files?.length;
        for (const child of infoJSON?.repoInfoPerMonorepoChild) {
          files = files.filter(file => file?.filePath?.startsWith(child?.monoRepoChild) == false);
        }
        logger.info(`getfilesWithLanguages, repo: ${repo.fullName}  file length: ${fileLength}, after mono repo filter: ${files?.length}`);
      }
      return files;
    }

    const parentInfoJSON = await this.getRepoInfoJSONFromCacheOrFile(repo.parentRepoOfMonoRepo);
    const monoRepoChild = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;

    const childFileInfo = parentInfoJSON.repoInfoPerMonorepoChild.find(fileInfo => fileInfo.monoRepoChild === monoRepoChild);

    if (childFileInfo) {
      return childFileInfo.repoInfo?.filesWithLanguages ?? [];
    }

    return [];
  }

  async getFilesFromRepoInfoJSON(repo: Repo): Promise<{ name: string }[]> {
    const info = await this.getRepoInfo(repo);
    return info.filesWithLanguages.map(file => ({
      name: `${repo.cloneDir}/${file.filePath}`,
    }));
  }

  async getRepoDevLanguagesFromRepoInfoJSON(repo: Repo): Promise<DevLanguages[]> {
    const info = await this.getRepoInfo(repo);
    return info.devLanguages.map(dl => new DevLanguages(dl.language, dl.languagePercentage));
  }

  async getKubernetesFilesFromRepoInfoJSON(repo: Repo): Promise<KubernetesFile[]> {
    const info = await this.getRepoInfo(repo);
    return info.kubernetesFiles.map(f => ({
      ...f,
      link: repo.fileLink + f.fileName,
    }));
  }

  async getOrchestratorFilesFromRepoInfoJSON(repo: Repo): Promise<OrchestratorFile[]> {
    const info = await this.getRepoInfo(repo);
    return info.orchestratorFiles.map(f => ({
      ...f,
      link: repo.fileLink + f.fileName,
    }));
  }

  async getDevLanFromRepoInfoJSON(repo: Repo, pathInfo: string) {
    const info = await this.getRepoInfo(repo);
    const file = info.filesWithLanguages.find(file => file.filePath === pathInfo);
    return file ? file.language : null;
  }

  async getOpenApiFilesFromRepoInfoJSON(repo: Repo) {
    const filesWithLanguages = await this.getfilesWithLanguages(repo);
    if (!filesWithLanguages) {
      logger.error(`getOpenApiFilesFromRepoInfoJSON filesWithLanguages is null for repo: ${repo.fullName}`);
      return [];
    }

    let files = filesWithLanguages.filter(
      file => file?.language?.toLowerCase() === "swagger" || file?.language?.toLowerCase() === "openapi",
    );

    logger.info(`getOpenApiFilesFromRepoInfoJSON repo: ${repo?.fullName} clode dir: ${repo?.cloneDir}`);
    logger.info(`getOpenApiFilesFromRepoInfoJSON files after filter: ${files?.length} repo: ${repo?.fullName}`);

    return files;
  }

  async getIsMonoRepoFromRepoInfoJSON(repo: Repo): Promise<boolean> {
    if (repo.monoRepoChild) {
      return false;
    }
    const infoJSON = await this.getRepoInfoJSONFromCacheOrFile(repo);
    return infoJSON.isMonoRepo;
  }

  async getMonoRepoChildrenFromRepoInfoJSON(repo: Repo): Promise<string[]> {
    if (repo.monoRepoChild) {
      return [];
    }
    const infoJSON = await this.getRepoInfoJSONFromCacheOrFile(repo);
    return infoJSON.repoInfoPerMonorepoChild.map(f => `${repo.cloneDir}/${f.monoRepoChild}`);
  }

  async getMonoRepoChildrenSubfoldersFromRepoInfoJSON(repo: Repo): Promise<string[]> {
    if (repo.monoRepoChild) {
      return [];
    }
    const infoJSON = await this.getRepoInfoJSONFromCacheOrFile(repo);
    return infoJSON.repoInfoPerMonorepoChild.map(f => f.monoRepoChild);
  }

  async getOrphanedFilesCount(repo: Repo): Promise<number> {
    const infoJSON = await this.getRepoInfoJSONFromCacheOrFile(repo);
    const repoInfo = infoJSON?.repoInfoForOrphanedFiles;
    if (!repoInfo) return 0;

    logger.info(`[repoInfoForOrphanedFiles] file count: ${repoInfo?.filesWithLanguages?.length}, size: ${repoInfo?.size}`);
    return repoInfo?.filesWithLanguages?.length ?? 0;
  }

  async getRepositorySizeInBytesFromRepoInfoJSON(repo: Repo): Promise<number> {
    const info = await this.getRepoInfo(repo);
    return info.size;
  }

  async getRepositoryHistorySizeInBytesFromRepoInfoJSON(repo: Repo): Promise<number> {
    const info = await this.getRepoInfo(repo);
    return info.repoHistorySize;
  }

  setFormerUsers(usersMap: any) {
    try {
      const items = this.globalCodeRepoData.UserPullRequest;
      logger.info(`try set former users, pulls: ${Object.keys(items).length}`);
      for (const [key, perm] of Object.entries(items)) {
        try {
          const userName = key;
          if (usersMap[userName]) {
            continue;
          }

          const val: UserPullRequest = perm as any;
          const u: User = new User(
            val.lastPullRequest.author,
            val.lastPullRequest.authorUserName,
            Constant.formerUserId,
            "",
            "",
            val.lastPullRequest.createdAt,
          );
          logger.info(`adding former user from pulls: ${val.lastPullRequest.author}`);
          this.globalCodeRepoData.formerUsers.push(u);
        } catch (err) {
          logger.error(`failed to generate single former users, err: ${err}`);
          StatesHelper.Instance.globalApisFails.add(resourceType.allPublicRepos);
        }
      }

      const itemsReviewers = this.globalCodeRepoData.UserReviewers;
      logger.info(`try set former users, reviews: ${Object.keys(itemsReviewers).length}`);
      for (const [key, perm] of Object.entries(itemsReviewers)) {
        try {
          const userName = key;
          if (usersMap[userName]) {
            continue;
          }

          const val: UserReviewer = perm as any;
          const u: User = new User(
            val.lastReviewer.author,
            val.lastReviewer.userName,
            Constant.formerUserId,
            "",
            "",
            val.lastReviewerRequest.toString(),
          );
          logger.info(`adding former user from reviews: ${val.lastReviewer.author}`);
          this.globalCodeRepoData.formerUsers.push(u);
        } catch (err) {
          logger.error(`failed to generate single former users, err: ${err}`);
          StatesHelper.Instance.globalApisFails.add(resourceType.allPublicRepos);
        }
      }
    } catch (err) {
      logger.error(`failed set all former users err: ${err}`);
      StatesHelper.Instance.globalApisFails.add(resourceType.allPublicRepos);
    }
  }

  async getCommitsFromGitInfoJSON(repo: Repo): Promise<GitCommit[]> {
    if (repo.disable) {
      return [];
    }

    const commits = (await this.getGitInfoJSON(repo)).commits;
    const limit = repo.monoRepoParent ? 30000 : 2000;

    return commits.slice(0, limit);
  }

  async getHeadShaFromGitInfoJSON(repo: Repo): Promise<string | null> {
    return (await this.getGitInfoJSON(repo)).headSha;
  }

  async getHeadSha(repo: Repo, gitHelper: GitHelper) {
    return process.env.DEBUG && !process.env.DOCKER_DEBUG ? await gitHelper.getHeadSha(repo) : await this.getHeadShaFromGitInfoJSON(repo);
  }

  async getCommitsFromDisk(repo: Repo) {
    try {
      const res = await Timeout.wrap(this.getCommitsFromDiskTimeoutWrap(repo), 1000 * 60 * 7, "Commit rom disk");
      return res;
    } catch (err) {
      logger.error(`failed get commits for with timeout: ${repo.cloneDir}, err: ${err}`);
    }
    return [];
  }

  private async getCommitsFromDiskTimeoutWrap(repo: Repo) {
    try {
      if (repo.disable) {
        return [];
      }

      let commitsPromise = await gitToJs(repo.cloneDir);
      const limit = repo.monoRepoParent ? 30000 : 2000;
      if (commitsPromise.length > limit) {
        commitsPromise = commitsPromise.slice(0, limit);
      }

      const allCommits = [];
      commitsPromise.forEach(i => {
        if (i.date === "GITPARSEMESSAGE") {
          i.date = i.authorEmail;
          i.authorEmail = i.authorName;
        }
        allCommits.push(i);
      });

      return allCommits;
    } catch (err) {
      logger.error(`failed get commits for: ${repo.cloneDir}, err: ${err}`);
    }
    return [];
  }

  private async addFirstLevelItemToRepo(repo: Repo, repoObj: any, resource: Resource) {
    let data = [];

    try {
      //already added, no need to add again in case of duplication except sec events
      if (repoObj[resource.name] != undefined && resource.name !== Constant.securityEventsResource) {
        return;
      }
      if (this.funcNames.has(resource.name)) {
        data = await this[resource.name](repo);
      }

      //Due to the fact we wait from tools AND from api for sec events we need to add and not overwrite(means not to do =)
      if (resource.name === Constant.securityEventsResource) {
        if (Array.isArray(data)) {
          if (data.length > 0) {
            const allSecEvents: SecurityEvent[] = repoObj[CodeRepoTypes[CodeRepoTypes.securityEvents]];
            data.forEach(i => {
              allSecEvents.push(i);
            });
            logger.info(`adding sec alerts from api, repo ${repo.fullName} alerts count: ${data.length}`);
          }
        }
        return;
      }

      repoObj[resource.name] = data;
    } catch (err) {
      logger.error(`failed collect resources: ${resource.name}, repo: ${repo.name}, err: ${err}`);
    }
  }

  private async enrichItemToRepoObj(repo: Repo, repoObj: any, resource: Resource) {
    let data = [];

    try {
      if (repoObj[resource.name] != undefined) {
        return;
      }

      //Dont run pulls on pipeline scan
      if (resource.name === CodeRepoTypes[CodeRepoTypes.pulls]) {
        if (StatesHelper.Instance.isPipelineScan) {
          repoObj[resource.name] = [];
          return;
        }
      }

      if (this.funcNames.has(resource.name)) {
        logger.info(`start enrich repo: ${resource.name} for repo: ${repo.fullName} minutes`);
        data = await this[resource.name](repoObj);
        logger.info(`finish enrich repo: ${resource.name} for repo: ${repo.fullName} minutes`);
      }

      //Add existing
      if (repoObj[resource.name]) {
        const items = repoObj[resource.name];
        data.forEach(i => {
          items.push(i);
        });
      }
      //Create new
      else {
        repoObj[resource.name] = data;
      }
    } catch (err) {
      logger.error(`failed enrich resources: ${resource.name}, repo: ${repo.fullName}, err: ${err}`);
    }
  }
  private getUniqueCodeChangesByDate(repo: Repo, codeChanges: Commit[]) {
    const uniqueCodeChanges = new Set();
    const uniqueCodeChangesInfo = [];
    try {
      for (let codeChange of codeChanges) {
        const day = startOfDay(new Date(codeChange.date)).toString();
        if (uniqueCodeChanges.has(day)) {
          continue;
        }
        uniqueCodeChanges.add(day);
        uniqueCodeChangesInfo.push(codeChange);
      }
      logger.debug(`finish get unique code changes by date repo ${repo.name}`);
    } catch (err) {
      logger.error(`repo: ${repo.name}, err: ${err}`);
    }
    return uniqueCodeChangesInfo;
  }

  private sortPullsAndPushesByDates(pushAndPulls: PullRequest[], repo: Repo) {
    try {
      const sorted = pushAndPulls.sort(function (a, b) {
        return a.diffFromNowToCreatedAtInDays - b.diffFromNowToCreatedAtInDays;
      });
      return sorted;
    } catch (err) {
      logger.error(`failed sort pull and pushes repo: ${repo.name}, err: ${err}`);
    }

    return pushAndPulls;
  }

  sortCommitsByDates(commits: Commit[], repo: Repo) {
    try {
      const sorted = commits.sort(function (a, b) {
        return a.diffFromNowToCreatedAtInDays - b.diffFromNowToCreatedAtInDays;
      });
      return sorted;
    } catch (err) {
      logger.error(`repo: ${repo.name}, err: ${err}`);
    }

    return commits;
  }

  private getDevLan(repo: Repo, pathInfo: string, acceptAll: Boolean = false, deepAnalysis: Boolean = false) {
    let len = "";
    try {
      let extention = path.extname(pathInfo).toLowerCase();
      if (Constant.otherLanguages.hasOwnProperty(extention)) {
        return Constant.otherLanguages[extention];
      } else if (deepAnalysis && Constant.fileDeepClassfication.hasOwnProperty(extention)) {
        if (!fs.existsSync(pathInfo)) {
          return "";
        }
        const fileContent = fs.readFileSync(pathInfo, "utf8");
        const inspectionContent = fileContent.substring(0, 5000).replace(/#[^\n]+\n/g, "");
        for (const deepClassification of Constant.fileDeepClassfication[extention]) {
          if (deepClassification.hasOwnProperty("pathPattern") && deepClassification.pathPattern.exec(pathInfo)) {
            return deepClassification.name;
          } else if (deepClassification.hasOwnProperty("contentPattern") && deepClassification.contentPattern.exec(inspectionContent)) {
            logger.debug(`found ${deepClassification.name} at path ${pathInfo}`);
            const hash = crypto.createHash("sha256").update(fileContent).digest("hex");
            const fileName = pathInfo.replace(`${repo.cloneDir}/`, "");
            const link = repo.fileLink + fileName;
            if (deepClassification.name == "Kubernetes") {
              Constant.kubernetesKinds.forEach(k8s => {
                if (k8s.kindPattern.exec(fileContent)) {
                  const match = k8s.lookupPattern.exec(fileContent);
                  if (match) {
                    const startIndex = match.index + match[0].length;
                    const endIndex = startIndex + fileContent.slice(startIndex).indexOf("\n");
                    const name = fileContent.slice(startIndex, endIndex);
                    repo.kubernetes.push({
                      type: AppFlowType.Kubernetes,
                      subType: getKubernetesSubSystem(k8s.kind),
                      name: name,
                      size: "0",
                      hashType: HahsType.sha256,
                      hash: hash,
                      fileName: fileName,
                      link,
                    } as KubernetesFile);
                  }
                }
              });
            } else if (deepClassification.name == OrchestratorSystem.Ansible) {
              repo.orchestrator.push({
                type: OrchestratorSystem.Ansible,
                name: fileName,
                size: "0",
                hashType: HahsType.sha256,
                hash: hash,
                fileName: fileName,
                link: link,
              } as OrchestratorFile);
            }
            return deepClassification.name;
          }
        }
      }
      len = detect.filename(pathInfo);
      if (len === "Kotlin" && pathInfo.endsWith("build.gradle.kts")) {
        len = "Gradle";
      } else if (map.hasOwnProperty(len)) {
        const typeInfo = map[len];
        if (acceptAll || typeInfo.type === "programming") {
          return len;
        }
      }
    } catch (err) {
      logger.error(` failed get dev lan for file path: ${pathInfo}, err: ${err}`);
    }
    return len;
  }

  async initApplicationsFromDB(mongoConnect: MongoConnect) {
    try {
      const mongoDBapplicationsConfigurations = new MongoDBapplicationsConfigurations(this.uuid, this.orgName, mongoConnect);
      const res = await mongoDBapplicationsConfigurations.getApplicationsFromDB();
      //this.applicationsConfig = res;
      AppConfigHelper.Instance.applicationsConfig = res;
    } catch (e) {
      logger.error(`failed get applications from DB ${e}`);
    }
  }

  getGitRoles(git) {
    try {
      return this.roleHelper.getGitRoles(git);
    } catch (e) {
      logger.error(`getGitRoles err: ${e}`);
    }
    return {};
  }

  getRepoVeteranReviewers(pulls: PullRequest[]) {
    try {
      const map = new Map<string, number>();
      pulls.forEach(pr => {
        const reviewers = pr.reviewers;
        reviewers.forEach(re => {
          const isReviewer = map.has(re.author);
          if (!isReviewer) {
            map.set(re.author, 1);
          } else {
            map.set(re.author, map.get(re.author) + 1);
          }
        });
      });
      const sortedMap = new Map(
        [...map.entries()].sort((a, b) => {
          return a[1] < b[1] ? 1 : -1;
        }),
      );
      return Array.from(sortedMap.keys());
    } catch (e) {
      logger.error(`failed to get repo veteran reviewers`);
    }
    return [];
  }

  // for pipeline scans, a single monitored resource should always be provided within a single connector
  getPipelineScanRepo(): ConnectorResource | null {
    if (!StatesHelper.Instance.isPipelineScan) return null;

    if (!this.userSelectedRepos?.monitoredResources) {
      logger.info(`Unable to get pipeline scan repo, no monitoredResources`);
      return null;
    }

    const resources = Object.values(this.userSelectedRepos.monitoredResources);

    if (resources.length > 1 || resources.length === 0) {
      logger.info(`Unable to get pipeline scan repo, count of resources in monitoredResources is ${resources.length}`);
      return null;
    }

    return resources[0] ?? null;
  }

  getPipelineScanRepoId(): string | null {
    const repo = this.getPipelineScanRepo();
    if (!repo) return null;
    return repo.id;
  }

  getPipelineScanInfo(repoId: any, repoName: string): PipelineScanInfo {
    const defaultInfo = {
      sourceBranch: null,
      targetBranch: null,
      sha: null,
      baseSha: null,
    };

    if (!StatesHelper.Instance.isPipelineScan) return defaultInfo;

    if (!this.userSelectedRepos?.monitoredResources) {
      logger.info(`Unable to get branch info during pipeline scan for repo: ${repoName}, repoId: ${repoId}, no monitoredResources`);
      return defaultInfo;
    }

    const resource = this.userSelectedRepos?.monitoredResources?.[repoId];

    if (!resource) {
      logger.info(
        `Unable to get branch info during pipeline scan for repo: ${repoName}, repoId: ${repoId}, no corresponding resource found in monitoredResources`,
      );
      return defaultInfo;
    }

    logger.info(
      `Will return branch info during pipeline scan for repo: ${repoName}, repoId: ${repoId}, sourceBranch: ${resource.sourceBranch}, targetBranch: ${resource.targetBranch}`,
    );

    return {
      sourceBranch: resource.sourceBranch ?? null,
      targetBranch: resource.targetBranch ?? null,
      sha: resource.sha ?? null,
      baseSha: resource.baseSha ?? null,
    };
  }

  throwIfUnsuccessfulPipelineScanRepoEval() {
    if (StatesHelper.Instance.isPipelineScan) {
      if (StatesHelper.Instance.scanInfoStats.failedClones > 0) {
        throw new Error("unsuccessful pipeline scan repo eval: failed clone detected");
      }
    }
  }

  isUnsuccessfulPipelineScanRepoEvalError(err: unknown) {
    if (err instanceof Error) {
      return err.message.includes("unsuccessful pipeline scan repo eval");
    }
    return false;
  }

  // for pipeline scan cloner feature: fetching files via API
  abstract getAPICredentials(
    repo: Repo,
  ): Record<string, string | number | boolean> | Promise<Record<string, string | number | boolean>> | null;
  abstract getAPIRepoInfo(repo: Repo): Record<string, string | number> | null;

  abstract findPullRequestIntroducingMergeCommit(repoObj: any, branch: string, sha: string): Promise<PullRequest | null>;

  abstract findFilesModifiedInPullRequest(
    repo: Repo,
    sourceBranch: string,
    targetBranch: string,
    sha: string | null,
    pullRequestId: string | null,
  ): Promise<string[] | null>;

  async tryFindingPullRequestIntroducingMergeCommit(repoObj: any): Promise<PullRequest | null> {
    try {
      if (!StatesHelper.Instance.isPipelineScan) return null;
      const repo: Repo = repoObj.code_repo;
      if (
        !repo ||
        repo.pipelineScanInfo.targetBranch || // if target branch is defined no need to look for this info
        !repo.pipelineScanInfo.sourceBranch ||
        !repo.pipelineScanInfo.sha
      ) {
        return null;
      }
      const pullRequest = await this.findPullRequestIntroducingMergeCommit(
        repoObj,
        repo.pipelineScanInfo.sourceBranch,
        repo.pipelineScanInfo.sha,
      );
      return pullRequest ?? null;
    } catch (e) {
      return null;
    }
  }

  async tryFindingFilesModifiedInPullRequest(repo: Repo): Promise<string[] | null> {
    const startTime = Date.now();
    const getExecutionTime = () => (Date.now() - startTime) / 1000;
    const TIMEOUT_ERR_MSG = "timeout finding files modified in pull request";
    const TIMEOUT_VALUE = millis.from.minutes(1);

    if (!StatesHelper.Instance.isPipelineScan) return null;
    if (!repo) return null;

    try {
      const { pipelineScanInfo } = repo;
      const { sourceBranch, targetBranch, sha } = pipelineScanInfo;

      if (!sourceBranch || !targetBranch) {
        return null;
      }

      StatesHelper.Instance.pipelineScanInfo.filesModifiedInPullRequest.isPullRequest = true;

      let files = await Timeout.wrap(
        this.findFilesModifiedInPullRequest(
          repo,
          sourceBranch,
          targetBranch,
          sha ?? null,
          PipeLineHelper.Instance.pipelineScanJobInfo?.pullRequestId ?? null,
        ),
        TIMEOUT_VALUE,
        TIMEOUT_ERR_MSG,
      );

      if (files) {
        files = files
          .map((file: string) => StringHelper.ensureNoStartChar(file, "/"))
          .filter((file: string) => file !== "" && file !== "." && file !== "..");
        files = files.length > 0 ? files : null;
      }

      logger.info(
        `[tryFindingFilesModifiedInPullRequest][${repo.type}] for ${repo.name}, count: ${files?.length}, ` +
          `files: [${files?.slice(0, 100)?.join(", ")}${files?.length > 100 ? ", ..." : ""}].`,
      );

      StatesHelper.Instance.pipelineScanInfo.filesModifiedInPullRequest.execution = getExecutionTime();
      StatesHelper.Instance.pipelineScanInfo.filesModifiedInPullRequest.fetched = Array.isArray(files);
      StatesHelper.Instance.pipelineScanInfo.filesModifiedInPullRequest.fileCount = files?.length ?? -1;

      return files;
    } catch (e) {
      StatesHelper.Instance.pipelineScanInfo.filesModifiedInPullRequest.execution = getExecutionTime();
      if (e?.message === TIMEOUT_ERR_MSG) {
        StatesHelper.Instance.pipelineScanInfo.filesModifiedInPullRequest.timedOut = true;
      }
      logger.error(`[tryFindingFilesModifiedInPullRequest][${repo.type}] for ${repo.name}, e: ${e}`);
      return null;
    }
  }

  async tryFindingJobTriggeredBy(): Promise<string | null> {
    if (!StatesHelper.Instance.isPipelineScan) return null;
    return PipeLineHelper.Instance.pipelineScanJobInfo.jobTriggeredBy;
  }

  async updateRepoTopics(repo: Repo) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }
      if (repo.type.toLowerCase() !== repoType.github) {
        return;
      }

      if (!StatesHelper.Instance.importGithubTopics) {
        // if setting is off remove all tags from api

        const removedTopicsIds = repo.appTags
          .filter(appTag => appTag.isGithubTopicTag)
          .map(appTag => appTag.tagId)
          .flat();

        await TagsService.Instance.modifyAppsTags([repo.id], [], removedTopicsIds);

        const withoutTopics = repo.appTags.filter(appTag => !appTag.isGithubTopicTag);
        repo.appTags = _.uniqBy(withoutTopics, "tagId");

        return;
      }

      // new fetched topics names
      const topicsNames = repo.topics.map(t => t.name);

      // remove topics that dont exist in gh anymore
      const removedTopicsIds = repo.appTags
        .filter(appTag => appTag.isGithubTopicTag && !topicsNames.includes(appTag.name))
        .map(appTag => appTag.tagId)
        .flat();

      // reset Topics from appTags
      repo.appTags = repo.appTags.filter(appTag => !appTag.isGithubTopicTag);

      // add to tags
      // doesnt return added ids if already existed
      await TagsService.Instance.addTopicAsTags(repo.topics);

      // get the new tag ids
      const allTags = await TagsService.Instance.getAllTags();
      const newInsertedTags = allTags?.filter(tag => topicsNames.includes(tag.name));
      const newInsertedTagsIds = newInsertedTags.map(t => t.tagId);

      // update app with added tags
      await TagsService.Instance.modifyAppsTags([repo.id], newInsertedTagsIds.flat(), removedTopicsIds);

      // we combine the tags we already have with the topics from api
      // const tagsWithTopics = [...repo.appTags, ...(repo.topics as (IOxTag & { appliedBy: string })[])];
      repo.appTags = _.uniqBy([...repo.appTags, ...newInsertedTags], "tagId");
    } catch (e) {
      logger.error(`failed to updateRepoTopics for repo: ${repo.name}`, e);
    }
  }
}

export default CodeRepoBase;
