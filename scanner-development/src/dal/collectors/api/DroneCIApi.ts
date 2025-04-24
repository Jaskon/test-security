import drone from "drone-node";
import loggerImport from "../../../logger";
import {
  DroneBaseBuild,
  DroneBuildStepLog,
  DroneCIClient,
  DroneExtendedBuild,
  DroneRepo,
} from "../../../entitis/connectorsSpecific/droneCITypes";
import PromisePool from "@supercharge/promise-pool/dist";
import { EOL } from "os";
import StatesHelper from "../../../helper/statesHelper";

const logger = loggerImport.getDebugLogger();

export class DroneCIApi {
  droneClient: DroneCIClient;

  constructor(private url: string, token: string) {
    logger.info("[DroneCIApi] initializing drone client");
    this.droneClient = new drone.Client({
      url,
      token,
    });
  }

  public async getRepos(): Promise<DroneRepo[]> {
    try {
      const repos = await this.droneClient.selfRepos();
      return repos;
    } catch (e) {
      StatesHelper.Instance.globalApisFails.add("droneci");
      logger.error(`[DroneCIApi] Failed to fetch repos, e:`, e);
      return [];
    }
  }

  private async getBuilds(owner: string, repo: string): Promise<DroneBaseBuild[]> {
    try {
      const builds = this.droneClient.getBuilds(owner, repo, 1, 50); // pagination?
      return builds;
    } catch (e) {
      logger.error(`[DroneCIApi] Failed to fetch build for owner:${owner} repo:${repo}, e:`, e);
      return [];
    }
  }

  private async getExtendedBuild(owner: string, repo: string, number: number): Promise<DroneExtendedBuild | null> {
    try {
      const extendedBuild = await this.droneClient.getBuild(owner, repo, number);

      return extendedBuild;
    } catch (e) {
      logger.error(`[DroneCIApi] Failed to fetch build for owner:${owner} repo:${repo} number:${number}, e:`, e);
      return null;
    }
  }

  public async getExtendedBuilds(owner: string, repo: string): Promise<DroneExtendedBuild[]> {
    const builds = await this.getBuilds(owner, repo);

    const { results } = await PromisePool.withConcurrency(5)
      .for(builds)
      .process(build => this.getExtendedBuild(owner, repo, build.number));

    const extendedBuilds = results.filter(build => build !== null).sort((a, b) => b.id - a.id); // sort since promise pool doesn't maintain order

    return extendedBuilds;
  }

  public getBuildUrl(owner: string, repo: string, number: number) {
    return `${this.url}/${owner}/${repo}/${number}`;
  }

  private async getBuildStepLogs(owner: string, repo: string, build: number, stage: number, step: number): Promise<DroneBuildStepLog[]> {
    try {
      const stepLogs = await this.droneClient.getLogs(owner, repo, build, stage, step);
      return stepLogs;
    } catch (e) {
      logger.error(
        `[DroneCIApi] Failed to fetch build step logs for owner:${owner} repo:${repo} build:${build} stage:${stage} step:${step}, e:`,
        e,
      );
      return [];
    }
  }

  // concated log: build => stages => steps => logs
  public async getBuildLog(owner: string, repo: string, build: DroneExtendedBuild): Promise<string> {
    const { results: stageLogs } = await PromisePool.withConcurrency(5)
      .for(build.stages)
      .process(async stage => {
        const { results: stepLogs } = await PromisePool.withConcurrency(2)
          .for(stage.steps)
          .process(async step => {
            if (step.status === "skipped") {
              return {
                step: step.number,
                log: "",
              };
            }

            const buildStepLogs = await this.getBuildStepLogs(owner, repo, build.number, stage.number, step.number);

            // for each step, return a single string of joined lines
            return {
              step: step.number,
              log: buildStepLogs.map(log => log.out).join(""),
            };
          });

        // for each stage, return a single string of joined steps
        return {
          stage: stage.number,
          log: stepLogs
            .sort((a, b) => a.step - b.step) // sort since promise pool doesn't maintain order
            .map(l => l.log)
            .join(""),
        };
      });

    // for each build, return a single string of joined stages
    return stageLogs
      .sort((a, b) => a.stage - b.stage) // sort since promise pool doesn't maintain order
      .map(s => s.log)
      .join("");
  }
}
