import axios from "axios";
import qs from "qs";
import { ApplicationManager } from "../../appmgr/AppManager";
import { CICDConnectorsTypes, CICDJob, CICDRepo } from "../../entitis/cicidRepoTypes";
import { getTFSRepo, getTFSRepoNameFromBranch } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { isJson } from "../../entitis/commonTypes";
import { AzureProject, AzureRepo } from "../../entitis/connectorsSpecific/azureTypes";
import { RateLimitHelperFactory } from "../../helper/rateLimitHelper";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";
import CIToolBase from "../base/CIToolBase";

const retry_count = 4;
const max_builds = 10;
const max_jobs = 5000;
const timeout_to_wait_after_rate_limit_happen = 1000 * 60 * 3;
const Timeout = require("await-timeout");

class AzureCIRequest {
  url: string;
  options?: any;
}

const client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
const logger = loggerImport.getDebugLogger();
class AzureCITool extends CIToolBase {
  api: any;
  host: string;
  private_token: string;
  refreshToken: string;
  appMgr: ApplicationManager;
  projects: any;
  sleepWasCalled = false;
  usingOathToken = false;
  repoToBuild = {};
  jobResults: CICDJob[] = [];
  parallelLogsDiscussion: Promise<void>[] = [];
  logLimiterMap: Map<string, string> = new Map();
  organizations: string[] = [];
  accountName: string;
  timeHelper: TimeHelper = new TimeHelper("");

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

    if (isIdpToken) {
      const idpToken = JSON.parse(token.password);
      tempToken = idpToken.access_token;
      this.refreshToken = idpToken.refresh_token;
      this.usingOathToken = true;
    }

    this.host = token.host;
    this.private_token = tempToken;

    this.rateLimitHelper = RateLimitHelperFactory.getRateLimitHelperPerToken(this.token.name, 200);

    this.appMgr = new ApplicationManager(this.uuid);
  }

  async initLib() {
    logger.info(`start init AzureCI`);

    if (this.usingOathToken) {
      this.private_token = await this.tryRefreshToken();
    }

    await this.setAzureDevOpsOrganizationNames(this.private_token);

    //
    // Set the organization/username of the account
    //
    const url = this.token.host;
    const splitted = url.split("/");
    this.accountName = splitted[splitted.length - 1];

    const projects = await this.getAllProject();
    const res = projects.map(project => this.parseProjectAllBuildsTimeout(project));
    await Promise.all(res);

    logger.info(`finish init AzureCI`);
  }

  async getAllcicsTools(callObj: RulesManager): Promise<CICDRepo[]> {
    try {
      let cicdRepos: CICDRepo[] = [];
      for (const org of this.organizations) {
        //Tfs
        let tfsRepos: any = await this.invokeRequest(`https://dev.azure.com/${org}/_apis/tfvc/items?api-version=6.0`, {
          auth: this.getAuth(),
          timeout: 30000,
        });

        if (tfsRepos) {
          tfsRepos = tfsRepos.filter(i => i.path != undefined && i.path !== "$/");

          const notHaveBuilds = tfsRepos.filter(i => !this.repoToBuild[getTFSRepo(i.path).toLowerCase()]);
          if (notHaveBuilds.length > 0) {
            logger.info(`AzureCI following repos not have builds: ${notHaveBuilds.map(i => i.path).join(", ")}`);
          }

          const haveBuilds = tfsRepos.filter(i => this.repoToBuild[getTFSRepo(i.path).toLowerCase()]);
          haveBuilds.forEach(i => {
            i.name = getTFSRepo(i.path);
            cicdRepos.push(new CICDRepo(i.name, "master", i.url, true, i.name, "", CICDConnectorsTypes.AzurePipeLine));
          });
        }

        //Git
        const repos: any = await this.invokeRequest(`https://dev.azure.com/${org}/_apis/git/repositories?api-version=6.0-preview.1`, {
          auth: this.getAuth(),
          timeout: 30000,
        });
        if (repos) {
          const notHaveBuilds = repos.filter(i => !this.repoToBuild[i.name]);
          if (notHaveBuilds.length > 0) {
            logger.info(`AzureCI following repos not have builds: ${notHaveBuilds.map(i => i.name).join(", ")}`);
          }

          const haveBuilds = repos.filter(i => this.repoToBuild[i.name]);
          haveBuilds.forEach(i => {
            cicdRepos.push(new CICDRepo(i.name, i.defaultBranch, i.webUrl, true, i.id, "", CICDConnectorsTypes.AzurePipeLine));
          });
        }
      }

      let monitored: CICDRepo[] = cicdRepos.filter(apiRepo =>
        this.repoSelectedByUser(apiRepo.repoId.toString(), apiRepo.repoName, undefined),
      );

      //monitored = monitored.slice(0, 1);
      return monitored;
    } catch (err) {
      logger.error(`failed to get AzureCI repos obj for: ${this.token.type}, err: ${err}`);
    }
    return [];
  }

  async jobs(repo: CICDRepo): Promise<CICDJob[]> {
    try {
      const repoSpecificJobs = this.jobResults.filter(job => job.repo_name === repo.repoName);

      logger.info(`Repo: ${repo.repoName} Found ${repoSpecificJobs.length} jobs`);

      return repoSpecificJobs;
    } catch (err) {
      logger.error(`failed to get AzureCI jobs obj for repo: ${repo.repoName}, err: ${err}`);
    }
    return [];
  }

  async parseBuildLogs(build: any, project: any) {
    try {
      const buildsLogs: any = await this.invokeRequest(
        `https://dev.azure.com/${project.organization}/${project.name}/_apis/build/builds/${build.id}/logs?api-version=6.0`,
        {
          auth: this.getAuth(),
          timeout: 90000,
        },
      );

      if (!buildsLogs) {
        return [];
      }

      const promissBuilds = buildsLogs.slice(0, max_jobs).map(log => this.parseBuildDetails(build, log.id));
      await Promise.all(promissBuilds);
    } catch (err) {
      logger.error(`failed get all AzureCI logs single build for project name: ${project.name}, err: ${err}`);
    }
    return [];
  }

  //
  // This API is for Build jobs
  //
  async parseBuildDetails(build: any, logId: string) {
    const idinfo = `${build.id}:${logId}`;
    const repoName = build.repository && build.repository.name ? build.repository.name : build.definition.name;

    try {
      const user = build?.requestedFor?.displayName ? build?.requestedFor?.displayName : build?.requestedBy?.displayName;

      const ciJob: CICDJob = new CICDJob(
        repoName,
        build.result,
        "",
        user,
        "",
        build.sourceBranch,
        build?._links?.web?.href ? build?._links?.web?.href : build.url,
        idinfo,
        repoName,
        "azure-pipelines",
      );

      ciJob.startTime = build.startTime;
      ciJob.diffTime = build.diffTime;
      ciJob.buildName = build.buildNumber;

      if (build.buildNumberRevision) {
        ciJob.buildName = ciJob.buildName + "_" + build.buildNumberRevision;
      }

      //Pipeline info
      ciJob.pipelineId = build.buildNumber;
      ciJob.pipelineLink = build?._links?.web?.href ? build?._links?.web?.href : build.url;
      ciJob.pipelineTime = build.finishTime ? build.finishTime : build.startTime;
      ciJob.pipelineStatus = build.status;
      ciJob.pipelineDiffInTime = this.timeHelper.getTimeIntervalFronNowInMili(ciJob.pipelineTime);

      this.jobResults.push(ciJob);
    } catch (err) {
      logger.error(`failed get single AzureCI build details for single build, err: ${err}`);
    }
  }

  async parseProjectAllBuildsTimeout(project: AzureRepo) {
    try {
      await Timeout.wrap(this.parseProjectAllBuilds(project), 1000 * 60 * 60, `timeout azureci single project`);
    } catch (err) {
      logger.error(`failed parse project all builds timeout project: ${project.name}, err: ${err}`);
    }
  }

  async parseProjectAllBuilds(project: AzureRepo) {
    try {
      const builds: any = await this.invokeRequest(
        `https://dev.azure.com/${project.organization}/${project.name}/_apis/build/builds?$top=${max_builds}&api-version=6.0`,
        {
          auth: this.getAuth(),
          timeout: 30000,
        },
      );

      //Builds
      const allBuilds = builds;
      if (allBuilds.length == 0) {
        return false;
      }

      const timeHelper: TimeHelper = new TimeHelper("");
      const repoToBuild = {};
      for (const build of allBuilds) {
        build.diffTime = timeHelper.getTimeIntervalFronNowInMili(build.startTime);

        let name = "";
        let nameForRepoToBuildKey = "";
        if (build.repository.type === "TfsVersionControl") {
          name = build.sourceBranch;
          nameForRepoToBuildKey = getTFSRepoNameFromBranch(build.sourceBranch);
        } else {
          name = build.repository.name;
          nameForRepoToBuildKey = name;
        }

        if (!name) {
          name = build.definition.name;
          nameForRepoToBuildKey = name;
        }

        if (repoToBuild[name]) {
          repoToBuild[name].push(build);
          this.repoToBuild[nameForRepoToBuildKey].push(build);
        } else {
          repoToBuild[name] = [build];
          this.repoToBuild[nameForRepoToBuildKey] = [build];
        }
      }

      const buildsToCheck = Object.values(repoToBuild).flat();

      const res = buildsToCheck.map(async (i: any) => {
        await this.parseBuildLogs(i, project);
      });

      await Promise.all(res);

      logger.info(`finish parse project builds for project: ${project.name}`);
    } catch (err) {
      logger.error(`failed in AzureCI to collect all builds for single project: ${project.name}, err: ${err}`);
    }
  }

  toArrayBuffer(buf) {
    const ab = new ArrayBuffer(buf.length);
    const view = new Uint8Array(ab);
    for (let i = 0; i < buf.length; ++i) {
      view[i] = buf[i];
    }
    return ab;
  }

  async setAzureDevOpsOrganizationNames(accessToken: string) {
    try {
      if (this.organizations.length > 0) {
        return this.organizations;
      }

      if (!this.usingOathToken) {
        this.organizations = this.token.userName ? [this.token.userName] : [];
        logger.info(`finish set AzureCI organizations for PAT: ${this.organizations.join(", ")}`);
        return;
      }

      logger.info("getting organizations");
      const url = "https://app.vssps.visualstudio.com/_apis/accounts";
      const orgList = await axios.get<any>(url, {
        headers: {
          Authorization: `Bearer ${accessToken}`,
        },
      });

      this.organizations = orgList.data.map(org => org.AccountName);

      logger.info(`finish set AzureCI organizations: ${this.organizations.join(", ")}`);
    } catch (e) {
      StatesHelper.Instance.globalApisFails.add("azure-pipelines");
      logger.error(`failed to get AzureCI organizations, e: ${e}`);
    }
  }

  async getAllProject() {
    logger.info(`try get all AzureCI projects`);

    const projectsInfo: AzureRepo[] = [];

    //
    // Getting builds from Azure Build Service
    //
    try {
      for (const organization of this.organizations) {
        const projects: AzureProject[] = await this.invokeRequest(`https://dev.azure.com/${organization}/_apis/projects?api-version=6.0`, {
          auth: this.getAuth(),
          timeout: 30000,
        });

        for (const project of projects) {
          try {
            const p: AzureRepo = {
              name: project.name,
              repoId: project.id,
              organization: organization,
            };
            projectsInfo.push(p);
          } catch (err) {
            logger.error(`failed get single project: ${JSON.stringify(project)} for AzureCI, err: ${err}`);
          }
        }
      }
    } catch (err) {
      logger.error(`failed get all project for AzureCI, err: ${err}`);
    }

    logger.info(`found ${projectsInfo.length} projects for AzureCI`);

    return projectsInfo;
  }

  async tryRefreshToken() {
    try {
      const url = `https://app.vssps.visualstudio.com/oauth2/token`;
      const response = await axios.post(
        url,
        qs.stringify({
          client_id: process.env.AZURE_IDP_CLIENT_ID,
          grant_type: "refresh_token",
          client_assertion: process.env.AZURE_IDP_CLIENT_SECRET,
          client_assertion_type: client_assertion_type,
          assertion: this.refreshToken,
          redirect_uri: process.env.IDP_REDIRECT_URI,
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
      return response.data.access_token;
    } catch (error) {
      logger.error("failed to create access token from refresh token", error);
      return null;
    }
  }

  getAuth() {
    return {
      username: "",
      password: this.private_token,
    };
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

  async invokeRequest(url: string, options?: any) {
    const r: AzureCIRequest = new AzureCIRequest();
    r.url = url;
    r.options = options;

    const res = await this.rateLimitHelper.sendApiRequest(url, r, this.isRateLimitErrFunction, this.axiosCall, null, retry_count, this);

    const finalRes = [];
    for (const item of res) {
      if (item.value) {
        finalRes.push(item.value);
      }
    }
    return finalRes.flat();
  }

  async getTimeToWait() {
    return timeout_to_wait_after_rate_limit_happen;
  }

  async axiosCall(r: AzureCIRequest) {
    const result = (await axios.get(r.url, r.options)) as any;
    return result.data;
  }
}

export default AzureCITool;
``;
