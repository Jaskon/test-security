import PromisePool from "@supercharge/promise-pool/dist";
import axios from "axios";
import { ApplicationManager } from "../../appmgr/AppManager";
import { parseArtifacts } from "../../appmgr/ParseArtifacts";
import CircleCIApi from "../../dal/collectors/api/CircleCIAPI";
import { artifactSchema } from "../../entitis/ArtifactTypes";
import { CICDConnectorsTypes, CICDJob, CICDRepo } from "../../entitis/cicidRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { extendedWriteFile } from "../../helper/IO/fileHlper";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";
import CIToolBase from "../base/CIToolBase";

const logger = loggerImport.getDebugLogger();

const CircleCIConcurrencyFactor = process.env.CIRCLECI_CONCURRENCY_FACTOR ? parseInt(process.env.CIRCLECI_CONCURRENCY_FACTOR) : 50;

class CircleCITool extends CIToolBase {
  host: string;
  private_token: string;
  appMgr: ApplicationManager;
  api: any;
  name: string;
  recentBuilds: any = [];
  timeHelper: TimeHelper = new TimeHelper("");

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.host = token.host;
    this.private_token = token.password;
    this.appMgr = new ApplicationManager(this.uuid);
  }

  async initLib() {
    try {
      this.api = new CircleCIApi(this.token.password);

      //
      // This name is the name of the token owner
      //
      this.name = await this.api.fetchName();
    } catch (err) {
      StatesHelper.Instance.globalApisFails.add("circleci");
      logger.error(`failed to get cicd list obj for: ${this.token.type}, err: ${err}`);
    }
  }

  async getAllcicsTools(callObj: RulesManager): Promise<CICDRepo[]> {
    const cicdRepoTools: CICDRepo[] = [];

    const allOps = await this.api.fetchCIData();

    if (allOps.length > 0) {
      logger.info("CircleCI: trying to get the circleci token");

      //
      // We need to get the owner of the circleci token
      //
      this.name = allOps[0].username;
      logger.info(`CircleCI: found the circleci token (${this.name})`);
    }

    for (const ciOp of allOps) {
      cicdRepoTools.push(new CICDRepo(ciOp.reponame, ciOp.default_branch, ciOp.vcs_url, true, -1, "", CICDConnectorsTypes.CircleCI));
    }

    return cicdRepoTools;
  }

  async jobs(cicdTool: CICDRepo): Promise<CICDJob[]> {
    const jobResults: CICDJob[] = [];

    try {
      const jobs = new CircleCIApi(this.token.password, this.name, cicdTool.repoName);
      const recentBuilds = await jobs.fetchBuilds();
      if (recentBuilds && recentBuilds.length) {
        const { results, errors } = await PromisePool.for(recentBuilds.splice(0, 3))
          .withConcurrency(CircleCIConcurrencyFactor)
          .process(async (build: any) => {
            const ciJob: CICDJob = new CICDJob(
              build.reponame,
              build.outcome,
              build.subject,
              build.username,
              build.vcs_revision,
              build.branch,
              build.build_url,
              "",
              "",
              "circleci",
            );

            ciJob.startTime = build.start_time;
            ciJob.diffTime = this.timeHelper.getTimeIntervalFronNowInMili(build.start_time);
            ciJob.buildName = build.subject;

            //Pipeline info
            ciJob.pipelineId = build?.workflows?.workflow_id;
            ciJob.pipelineLink = build.build_url;
            ciJob.pipelineTime = build.stop_time ? build.stop_time : build.start_time;
            ciJob.pipelineStatus = build.status;
            ciJob.pipelineDiffInTime = this.timeHelper.getTimeIntervalFronNowInMili(ciJob.pipelineTime);

            jobResults.push(ciJob);

            // Find artifacts
            const lastJobOutput = `https://circleci.com/api/v1.1/project/${build.vcs_type}/${build.username}/${build.reponame}/${build.build_num}`;

            try {
              const jobOutput = await this.api.fetchImpl(async () => {
                const instance = axios.get(lastJobOutput, {
                  timeout: 90000,
                  headers: {
                    "Circle-Token": this.private_token,
                  },
                });

                return (await instance).data;
              }, 1);

              if (jobOutput.steps && jobOutput.steps.length) {
                let fullLog = "";

                for (const jobStep of jobOutput.steps) {
                  if ("actions" in jobStep && jobStep.actions && jobStep.actions.length) {
                    for (const action of jobStep.actions) {
                      if (!action.output_url) continue;

                      fullLog += jobStep.name + "\n";

                      try {
                        const jobLog = await this.api.fetchImpl(async () => {
                          const outputData = axios.get(action.output_url, {
                            timeout: 90000,
                          });

                          return (await outputData).data;
                        }, 1);

                        for (const singleJobLog of jobLog) {
                          fullLog += `${singleJobLog.message ? singleJobLog.message : JSON.stringify(singleJobLog)}\n`;
                        }
                      } catch (err) {
                        logger.error(`Failed to parse the job step ${action.name} with error: ${err}`);
                      }
                    }
                  }
                }

                const saveDebugLog = async (uniqueFileName: string, jobsArtifacts: string) => {
                  //For debug
                  try {
                    if (process.env.SAVE_ARTIFACTS === "true") {
                      // Save the artifact to shared location
                      const artifactsPath = process.env.OX_SHARED_DATA + `/${this.orgName}/` + uniqueFileName;

                      await extendedWriteFile(artifactsPath, jobsArtifacts);
                    }
                  } catch (err) {
                    logger.error(`Failed to save artifacts for ${uniqueFileName} with error: ${err}`);
                  }
                };

                await saveDebugLog(`${build.build_num}`, fullLog);

                const artifacts = await parseArtifacts(
                  "any", // family
                  fullLog, // data
                  `${build.build_num}`,
                  this.uuid,
                );

                if (artifacts.success) {
                  for (const singleArtifact of artifacts.output) {
                    const safelyParsedArtifact = artifactSchema.safeParse(singleArtifact);
                    if (safelyParsedArtifact.success) {
                      logger.info(`Found artifacts for ${build.reponame}`);

                      await ciJob.addArtifact(singleArtifact);
                    } else {
                      logger.error(`Failed to parse artifacts (${JSON.stringify(safelyParsedArtifact)})`);
                    }
                  }
                }
              }
            } catch (e) {
              logger.error(`CircleCIParser: Failed to fetch job data for artifact parsing:`, e);
            }
          });
      }

      return jobResults;
    } catch (err) {
      logger.error(`CircleCI failed to get jobs for ${cicdTool.repoName}`, err);
      StatesHelper.Instance.globalApisFails.add("circleci");
    }
    return [];
  }
}

export default CircleCITool;
