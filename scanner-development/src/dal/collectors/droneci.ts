import CIToolBase from "../base/CIToolBase";
import loggerImport from "../../logger";
import { Token } from "../../entitis/collectorEntitisTypes";
import { DroneBaseBuild, DroneExtendedBuild, DroneRepo } from "../../entitis/connectorsSpecific/droneCITypes";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import { CICDConnectorsTypes, CICDJob, CICDRepo } from "../../entitis/cicidRepoTypes";
import RulesManager from "../../policy/rules/ruleManager";
import { DroneCIApi } from "../../dal/collectors/api/DroneCIApi";
import { ApplicationManager } from "../../appmgr/AppManager";
import PromisePool from "@supercharge/promise-pool/dist";
import { parseArtifacts } from "../../appmgr/ParseArtifacts";
import { artifactSchema } from "../../entitis/ArtifactTypes";
import TimeHelper from "../../helper/timeHelper";

const logger = loggerImport.getDebugLogger();

class DroneCITool extends CIToolBase {
  token: Token;
  api: DroneCIApi;
  appMgr: ApplicationManager;
  timeHelper: TimeHelper = new TimeHelper(this.uuid);

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.token = token;
    this.appMgr = new ApplicationManager(this.uuid);

    logger.info("[DroneCI] initializing ci cd tool");
  }

  async initLib() {
    this.api = new DroneCIApi(this.token.host, this.token.password);
  }

  private mapDroneRepoToCICDRepo = (droneRepo: DroneRepo): CICDRepo => {
    return new CICDRepo(droneRepo.name, droneRepo.default_branch, "", true, droneRepo.id, droneRepo.namespace, CICDConnectorsTypes.DroneCI);
  };

  private mapDroneBuildToCICDJob = (build: DroneBaseBuild, repo: CICDRepo): CICDJob => {
    const buildUrl = this.api.getBuildUrl(repo.repoOwner, repo.repoName, build.number);

    const job = new CICDJob(
      repo.repoName,
      build.status,
      build.action,
      build.trigger,
      build.after,
      repo.defaultBranch,
      buildUrl,
      build.id.toString(),
      "",
      "droneci",
    );

    const startTime = new Date(build.started * 1000).toISOString();
    job.startTime = startTime;
    job.diffTime = this.timeHelper.getTimeIntervalFronNowInMili(startTime);

    job.buildName = `${build.id}. ${build.message}`;

    //Pipeline info
    job.pipelineId = build.id.toString();
    job.pipelineLink = buildUrl;

    const pipelineTime = new Date((build.finished ? build.finished : build.started) * 1000).toISOString();
    job.pipelineTime = pipelineTime;
    job.pipelineStatus = build.status;
    job.pipelineDiffInTime = this.timeHelper.getTimeIntervalFronNowInMili(pipelineTime);

    return job;
  };

  async getAllcicsTools(callObj: RulesManager): Promise<CICDRepo[]> {
    try {
      const repos = await this.api.getRepos();
      return repos.map(this.mapDroneRepoToCICDRepo);
    } catch (e) {
      logger.error(`[DroneCI] error getting cicd repos, e:`, e);
      return [];
    }
  }

  private async processBuild(cicdRepo: CICDRepo, build: DroneExtendedBuild): Promise<CICDJob> {
    const cicdJob = this.mapDroneBuildToCICDJob(build, cicdRepo);
    this.appMgr.CreateCIJob(cicdJob);

    const buildLog = await this.api.getBuildLog(cicdRepo.repoOwner, cicdRepo.repoName, build);

    const artifactsParsingResult = await parseArtifacts(
      "any", // family
      buildLog, // data
      build.id,
      this.uuid,
    );

    if (!artifactsParsingResult.success) {
      return cicdJob;
    }

    for (const artifact of artifactsParsingResult.output) {
      const artifactParsingResult = artifactSchema.safeParse(artifact);

      if (!artifactParsingResult.success) {
        logger.error(
          `[DroneCI] Failed to parse artifacts for repo:${cicdRepo.repoName} build.id:${build.id}, build.number:${build.number} ` +
            `artifact:${JSON.stringify(artifactParsingResult)}`,
        );
        return cicdJob;
      }

      logger.info(`[DroneCI] Found artifacts for repo:${cicdRepo.repoName} build.id:${build.id}, build.number:${build.number} `);
      const parsedArtifact = artifactParsingResult.data;
      await cicdJob.addArtifact(parsedArtifact);
      await this.appMgr.CreateNode("Artifact", parsedArtifact);
    }

    return cicdJob;
  }

  async jobs(cicdRepo: CICDRepo): Promise<CICDJob[]> {
    try {
      await this.appMgr.CreateCITool(cicdRepo, CICDConnectorsTypes.DroneCI);

      const builds = await this.api.getExtendedBuilds(cicdRepo.repoOwner, cicdRepo.repoName);

      const { results: cicdJobs } = await PromisePool.withConcurrency(5)
        .for(builds)
        .process(build => this.processBuild(cicdRepo, build));

      return cicdJobs;
    } catch (e) {
      logger.error(`[DroneCI] error getting cicd jobs, e:`, e);
      return [];
    }
  }
}

export default DroneCITool;
