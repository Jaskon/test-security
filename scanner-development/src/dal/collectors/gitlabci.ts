import { Gitlab } from "@gitbeaker/node";
import FeatureFlags from "@oxappsec/ox-feature-flag";
import axios from "axios";
import https from "https";
import PipelineMgr from "../../appmgr/PipelineMgr";
import { CICDConnectorsTypes, CICDJob, CICDRepo } from "../../entitis/cicidRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { isJson } from "../../entitis/commonTypes";
import { GitlabRepository, Pipeline } from "../../entitis/connectorsSpecific/gitLabTypes";
import { getGitlabRepoName } from "../../helper/commonUtils";
import { RateLimitHelperFactory } from "../../helper/rateLimitHelper";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";
import CIToolBase from "../base/CIToolBase";

const per_page_max_res = 1;
const max_pages = 1;
const max_jobs = 10;
const max_pipelines = 1;
const retry_count = 4;
const timeout_to_wait_after_rate_limit_happen = 1000 * 60 * 1.5;
const logger = loggerImport.getDebugLogger();

class GitlanCIRequest {
  query: any;
  page: number = 1;
}

class GitLabCITool extends CIToolBase {
  api: any;
  host: string;
  private_token: string;
  usingOathToken = false;
  timeHelper: TimeHelper = new TimeHelper(this.uuid);
  pipelineStats: ReturnType<typeof PipelineMgr>;
  shouldBypassCertChecks: boolean;
  Based64_token: string;

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
    this.rateLimitHelper = RateLimitHelperFactory.getRateLimitHelperPerToken(this.token.name, 200);

    if (isIdpToken) {
      const idpToken = JSON.parse(token.password);
      tempToken = idpToken.access_token;
    }

    this.host = token.host;
    this.private_token = tempToken;

    this.pipelineStats = PipelineMgr({
      uuid: this.uuid,
      orgId: this.orgName,
    });
  }

  async initLib() {
    const oauthTokenRegex = /[a-z0-9]{64}/g;
    const personalTokenRegex = /glpat-[0-9a-zA-Z\-]{20}/g;
    const oldPersonalTokenRegex = /[0-9a-zA-Z\-\_]{20}/g;

    this.shouldBypassCertChecks = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "ox-disable-gitlab-cert-validation", true);

    const shouldUseBasicAuthChecks = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "ox-use-basic-auth-check", true);
    if (shouldUseBasicAuthChecks) {
      logger.info(`shouldUseBaseAuthChecks for: ${this.token.name}, url: ${this.token.host} set to true`);
      this.Based64_token = Buffer.from(`${this.private_token}:`).toString("base64");

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
        });
        this.usingOathToken = true;
      } else if (this.private_token.match(personalTokenRegex) || this.private_token.match(oldPersonalTokenRegex)) {
        this.api = new Gitlab({
          host: this.token.host,
          token: this.token.password,
          requestTimeout: 5000,
          rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
        });
      } else {
        logger.error(`Got unfamiliar token type, trying to use personal token`);

        this.api = new Gitlab({
          host: this.token.host,
          token: this.token.password,
          requestTimeout: 5000,
          rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
        });
      }
    }
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

  async getAllcicsTools(callObj: RulesManager): Promise<CICDRepo[]> {
    const cicdRepos: CICDRepo[] = [];

    logger.info(`try set cicd list for: ${this.token.name}`);

    try {
      const allRepos = await this.repositoriesInit();

      for (const element of allRepos) {
        const c = new CICDRepo(
          element.name,
          element.branch,
          element.repo,
          element.webhookTriggered,
          element.repoId,
          "",
          CICDConnectorsTypes.Gitlab,
        );
        cicdRepos.push(c);
      }
      return cicdRepos;
    } catch (err) {
      logger.error(`failed to get all cicd list for: ${this.token.name}, err: ${err}`);
    }
    logger.info(`finish set cicd list for: ${this.token.name}`);
    return [];
  }

  async repositoriesInit(): Promise<any> {
    const projectsResults = [];

    logger.info(`try set repositories init for: ${this.token.name}`);

    try {
      const repos: GitlabRepository[] = await this.api.Projects.all({
        maxPages: 100000,
        perPage: 100,
        membership: true,
      });

      for (const repo of repos) {
        try {
          if (!this.repoSelectedByUser(repo.id.toString(), repo.name_with_namespace, repo.created_at)) {
            continue;
          }

          projectsResults.push({
            name: getGitlabRepoName(repo.name_with_namespace),
            branch: repo.default_branch,
            repo: repo.web_url,
            webhookTriggered: "",
            repoId: repo.id,
          });
        } catch (err) {
          logger.error(`failed set repositories init for: ${this.token.name}, err: ${err}`);
        }
      }
    } catch (error) {
      logger.error(`failed to get repositories init for: ${this.token.name}, err: ${error}`);
    }

    logger.info(`finish set repositories init for: ${this.token.name}`);
    return projectsResults;
  }

  async jobs(cicdRepo: CICDRepo): Promise<CICDJob[]> {
    let jobs: CICDJob[] = [];

    try {
      const pipeLines: Pipeline[] = await this.getPipelines(cicdRepo.repoId, cicdRepo.repoName);

      const reducedPipelines = pipeLines.length > max_pipelines ? pipeLines.slice(0, max_pipelines) : pipeLines;
      const proms = reducedPipelines.map(pipeline => this.pushToJobs(cicdRepo, jobs, pipeline));
      await Promise.all(proms);
    } catch (err) {
      logger.error(`failed get ${this.token.name} jobs err: ${err}`);
    }

    return jobs;
  }

  private async getPipelines(repoId, repoName) {
    try {
      const query = {
        url: `${this.host}/api/v4/projects/${repoId}/pipelines`,
        singleRequest: true,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
          httpsAgent: new https.Agent({
            rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
          }),
        },
      };

      const res = await this.invokeRequest(query);
      return res;
    } catch (err) {
      logger.error(`failed to get cicd pipeline, repo: ${repoName}, err: ${err}`);
    }
    return [];
  }

  private async pushToJobs(cicdRepo: CICDRepo, jobs: CICDJob[], pipeline) {
    try {
      const query = {
        url: `${this.host}/api/v4/projects/${cicdRepo.repoId}/pipelines/${pipeline.id}/jobs`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
        },
        httpsAgent: new https.Agent({
          rejectUnauthorized: this.shouldBypassCertChecks ? false : true,
        }),
      };

      let res = await this.invokeRequest(query);

      res = res.length > max_jobs ? res.slice(0, max_jobs) : res;

      for (const job of res) {
        try {
          const commitMessage = job.commit?.message?.replace(/\n/g, "") ?? "";
          const ciJob: CICDJob = new CICDJob(
            cicdRepo.repoName,
            job.status,
            `${commitMessage ? commitMessage + ":" + job.name : job.name}`,
            job?.user?.name,
            job?.commit?.id,
            job.ref,
            job.web_url,
            job.id.toString(),
            getGitlabRepoName(cicdRepo.repoName),
            "gitlab-ci/cd",
          );

          ciJob.startTime = job.created_at;
          ciJob.diffTime = this.timeHelper.getTimeIntervalFronNowInMili(job.created_at);
          ciJob.buildName = job.name;

          //Pipeline info
          ciJob.pipelineId = pipeline.id;
          ciJob.pipelineLink = pipeline.web_url;
          ciJob.pipelineTime = pipeline.updated_at ? pipeline.updated_at : pipeline.created_at;
          ciJob.pipelineStatus = pipeline.status;
          ciJob.pipelineDiffInTime = this.timeHelper.getTimeIntervalFronNowInMili(ciJob.pipelineTime);

          jobs.push(ciJob);
        } catch (err) {
          logger.error(`failed to get single cicd job: ${JSON.stringify(job)}, repo: ${cicdRepo.repoName}, err: ${err}`);
        }
      }
    } catch (err) {
      logger.error(`failed to all cicd jobs, repo: ${cicdRepo.repoName}, err: ${err}`);
    }
  }

  async getTimeToWait() {
    return timeout_to_wait_after_rate_limit_happen;
  }

  private getTokenHeader() {
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

  isRateLimitErrFunction(err: any) {
    try {
      if (err.toString().includes("rate limit")) {
        return true;
      }
      if (err.toString().includes("ECONNRESET".toLowerCase())) {
        return true;
      }
      if (err.response && err.response.status == 429) {
        return true;
      }
      if (err.toString().includes("timeout of")) {
        return true;
      }
    } catch (e) {
      logger.error(`failed pare error output, err: ${e}, original err: ${err}`);
    }
    return false;
  }

  getQueryNextPage(r: GitlanCIRequest, singleRes: any) {
    if (r.query.singleRequest) if (r.query.singleRequest) return false;
    if (r.page > max_pages) return false;
    if (singleRes.length < per_page_max_res) return false;

    r.page++;
    return true;
  }

  async invokeRequest(query: any) {
    const r: GitlanCIRequest = new GitlanCIRequest();
    r.query = query;

    const res = await this.rateLimitHelper.sendApiRequest(
      r.query.url,
      r,
      this.isRateLimitErrFunction,
      this.axiosCall,
      this.getQueryNextPage,
      retry_count,
      this,
    );

    return res.flat();
  }

  async axiosCall(r: GitlanCIRequest) {
    const instance = axios.get(r.query.url + `?per_page=${per_page_max_res}&page=${r.page}`, r.query.params);
    const res: any = await instance;
    return res.data;
  }
}

export default GitLabCITool;
