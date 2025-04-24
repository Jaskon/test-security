import { Octokit } from "@octokit/core";
import * as OXGitHubApp from "@oxappsec/ox-github-app";
import PipelineMgr from "../../appmgr/PipelineMgr";
import { getLatestActions, getWorkflowsByActions } from "../../appmgr/PipelineMgrLogic";
import { CICDConnectorsTypes, CICDJob, CICDRepo } from "../../entitis/cicidRepoTypes";
import { GitHubRequest } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { GitHub } from "../../entitis/connectorsSpecific/GitHubTypes";
import { GithubHelper } from "../../helper/connectorsSpecific/githubHelper";
import {
  GitHubCredentials,
  GitHubCredentialsType,
  GITHUB_APP_INSTALLATION_TOKEN_REFRESH_INTERVAL,
  resolveGitHubCredentials,
} from "../../helper/github/credentials";
import { extendedWriteFile } from "../../helper/IO/fileHlper";
import { RateLimitHelperFactory } from "../../helper/rateLimitHelper";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";
import CIToolBase from "../base/CIToolBase";

const logger = loggerImport.getDebugLogger();

const per_page_max_res = 100;
const max_jobs = 10;
const retry_count = 4;
const timeout_to_wait_after_rate_limit_happen = 1000 * 60 * 3;

class GitHubCITool extends CIToolBase {
  octokit: Octokit;
  api: any;
  host: string;
  username: string;
  private_token: string;
  credentials: GitHubCredentials;
  githubHelper: GithubHelper;
  timeHelper: TimeHelper = new TimeHelper(this.uuid);
  pipelineStats: ReturnType<typeof PipelineMgr>;
  workflowFilesMap = new Map<string, string>();

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.credentials = resolveGitHubCredentials(token);
    this.private_token = this.credentials.token;

    this.initCredentialsRefresh();
    this.initGitHubApp();

    this.githubHelper = new GithubHelper(per_page_max_res, this);

    this.host = token.host;

    this.rateLimitHelper = RateLimitHelperFactory.getRateLimitHelperPerToken(this.token.name, 200);

    this.pipelineStats = PipelineMgr({
      uuid: this.uuid,
      orgId: this.orgName,
    });
  }

  async initLib() {
    try {
      logger.info(`try init lib for: ${this.token.name}, url: ${this.token.host}`);

      this.initGitHubAPI();
    } catch (err) {
      logger.error(`failed init ${this.token.name} err: ${err}`);
    }
  }

  initGitHubAPI() {
    logger.info(`try init Octokit for: ${this.token.name}, url: ${this.token.host}`);

    this.octokit = new Octokit({
      auth: this.credentials.token,
      baseUrl: this.token.host ? this.token.host : null,
    });
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

      // re-init octokit since token changed
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

    const { GITHUB_APP_ID, GITHUB_APP_PRIVATE_KEY, GITHUB_APP_RO_ID, GITHUB_APP_RO_PRIVATE_KEY } = process.env;
    OXGitHubApp.init([
      {
        appId: GITHUB_APP_ID,
        privateKey: GITHUB_APP_PRIVATE_KEY,
      },
      {
        appId: GITHUB_APP_RO_ID,
        privateKey: GITHUB_APP_RO_PRIVATE_KEY,
      },
    ]);
  }

  async getAllcicsTools(callObj: RulesManager): Promise<CICDRepo[]> {
    logger.info(`GithubCI: getAllcicsTools called`);

    const cicdRepos: CICDRepo[] = [];
    try {
      const allRepos = await this.repositoriesInit();

      for (const element of allRepos) {
        const c = new CICDRepo(
          element.name,
          element.branch,
          element.repo,
          element.webhookTriggered,
          element.repoId,
          element.owner,
          CICDConnectorsTypes.Github,
        );

        cicdRepos.push(c);
      }
      return cicdRepos;
    } catch (err) {
      logger.error(`failed to get cicd list obj for: ${this.token.type}, err: ${err}`);
    }
    return [];
  }

  async repositoriesInit(): Promise<any> {
    logger.info(`${this.token.name} init`);

    const projectsResults = [];
    let repos =
      this.credentials.type === GitHubCredentialsType.App
        ? await this.githubHelper.getAllInstallationRepos()
        : await this.githubHelper.getAllReposOfOrg();

    logger.info(`${this.token.name} repo number: ${repos.length}`);

    if ("https://api.github.com" !== this.token.host) {
      if (repos.length > 0) {
        StatesHelper.Instance.allReposOfGitlabOnPrem = repos;
      } else {
        if (StatesHelper.Instance.allReposOfGitlabOnPrem.length > 0) {
          repos = StatesHelper.Instance.allReposOfGitlabOnPrem;
          logger.info(`using allReposOfGitlabOnPrem: ${this.token.name}, allRepos: ${repos.length}`);
        }
      }
    }

    for (const repo of repos) {
      try {
        if (!this.repoSelectedByUser(repo.id.toString(), repo.full_name, repo.created_at)) {
          continue;
        }

        await this.appMgr.CreateCITool(
          {
            reponame: repo.full_name,
            username: "multi",
            vcs_type: "github",
            default_branch: repo.default_branch,
            vcs_url: repo.html_url,
          },
          CICDConnectorsTypes.Github,
        );

        projectsResults.push({
          name: repo.full_name,
          branch: repo.default_branch,
          repo: repo.html_url,
          webhookTriggered: true,
          owner: repo.owner.login,
          repoId: repo.id,
        });
      } catch (err) {
        logger.error(`failed get workflows, err: ${err}`);
      }
    }

    return projectsResults;
  }

  async jobs(cicdRepo: CICDRepo): Promise<CICDJob[]> {
    let jobs: CICDJob[] = [];

    try {
      const query = {
        url: "GET /repos/{owner}/{repo}/actions/runs",
        parms: {
          owner: cicdRepo.repoOwner,
          repo: this.getName(cicdRepo.repoName),
          timeout: 90000,
          page: 1,
        },
        singleRequest: true,
      };

      let actions = await this.invokeRequest(query);

      if (actions.length > max_jobs) {
        actions = actions.slice(0, max_jobs);
      }

      const latestActions = getLatestActions(actions, 1);

      const proms = latestActions.map(i => this.getJobs(cicdRepo, i));
      const jobsRes = await Promise.all(proms);
      jobs = jobsRes.flat();
    } catch (err) {
      logger.error(`failed get workflows, cicd for repo: ${cicdRepo.repoName}, err: ${err}`);
    }

    return jobs;
  }

  async getJobs(cicdRepo: CICDRepo, job) {
    const jobs: CICDJob[] = [];
    try {
      try {
        const ciJob: CICDJob = new CICDJob(
          cicdRepo.repoName.trim(),
          job.status,
          job.name,
          job?.triggering_actor?.login ? job?.triggering_actor?.login : "",
          job.head_sha,
          job.ref,
          job.html_url,
          `${job.id}`,
          cicdRepo.repoName,
          "gitHub-actions",
        );

        ciJob.logs_url = job.logs_url;
        ciJob.startTime = job.created_at;
        ciJob.diffTime = this.timeHelper.getTimeIntervalFronNowInMili(job.created_at);
        ciJob.buildName = job.name;

        //Pipeline info
        ciJob.pipelineId = job.workflow_id;
        ciJob.pipelineLink = this.getWorkFlowUrl(job);
        ciJob.pipelineTime = job.updated_at ? job.updated_at : job.run_started_at;
        ciJob.pipelineStatus = job.status;
        ciJob.pipelineDiffInTime = this.timeHelper.getTimeIntervalFronNowInMili(ciJob.pipelineTime);

        this.appMgr.CreateCIJob(ciJob);
        jobs.push(ciJob);
      } catch (err) {
        logger.error(`failed get single job of run for repo: ${cicdRepo.repoName}, err: ${err}`);
      }
    } catch (err) {
      logger.error(`failed get all jobs of run for repo: ${cicdRepo.repoName}, err: ${err}`);
    }
    return jobs;
  }

  getWorkFlowUrl(job) {
    try {
      let u = job.html_url.replace(job.id.toString(), "").replace("runs/", "");
      u = u + job.path.replace(".github/", "");
      return u;
    } catch (err) {
      logger.error(`failed get workflow, err: ${err}`);
    }
    return job.html_url;
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
      if (err.response) {
        if (err.response.status == 429) {
          return true;
        }
      }
    } catch (e) {
      logger.error(`failed pare error output err: ${e}, original err: ${err}`);
    }
    return false;
  }

  async invokeRequest(query: any) {
    const r: GitHubRequest = new GitHubRequest();
    r.query = query;

    const res = await this.rateLimitHelper.sendApiRequest(
      r.query.url,
      r,
      this.isRateLimitErrFunction,
      this.handleRequest.bind(this),
      null,
      retry_count,
      this,
    );

    return res.flat();
  }

  async getTimeToWait() {
    return this.githubHelper.getTimeToWait(this.rateLimitHelper, timeout_to_wait_after_rate_limit_happen);
  }

  async handleRequest(gitHubRequest: GitHubRequest) {
    const res = await this.octokit.request(gitHubRequest.query.url, gitHubRequest.query.parms);

    return res.data;
  }

  getName(fullName: string) {
    try {
      const index = fullName.indexOf("/");
      if (index) fullName = fullName.substr(index + "/".length, fullName.length);
      return fullName;
    } catch (err) {
      logger.error(`failed to get name for: ${this.token.type}, err: ${err}`);
    }
    return fullName;
  }
}

export default GitHubCITool;
