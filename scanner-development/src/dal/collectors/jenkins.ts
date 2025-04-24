import { Token } from "../../entitis/collectorEntitisTypes";
import loggerImport from "../../logger";
import CIToolBase from "../base/CIToolBase";
import Jenkins, { JenkinsApiResultWithStatus } from "./api/JenkinsAPI";

import { ApplicationManager } from "../../appmgr/AppManager";

import axios from "axios";
import { parseArtifacts } from "../../appmgr/ParseArtifacts";
import { artifactSchema } from "../../entitis/ArtifactTypes";
import { CICDConnectorsTypes, CICDJob, CICDRepo } from "../../entitis/cicidRepoTypes";
import {
  freeStyleJob,
  freeStyleProject,
  jobSchema,
  jobsListSchema,
  newBuildJob,
  newBuildJobSchema,
  newJenkinsJob,
  newJobSchema,
  updateServerUrl,
} from "../../entitis/connectorsSpecific/JenkinsTypes";
import { getRandomString } from "../../helper/hash";
import StatesHelper from "../../helper/statesHelper";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";

const { XMLParser, XMLBuilder, XMLValidator } = require("fast-xml-parser");

const logger = loggerImport.getDebugLogger();

class JenkinsCITool extends CIToolBase {
  host: string;
  username: string;
  private_token: string;
  appMgr: ApplicationManager;
  repos: string[];
  api: Jenkins;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.host = token.host;
    this.username = token.userName;
    this.private_token = token.password;
    this.appMgr = new ApplicationManager(this.uuid);
  }

  async initLib() {
    logger.info(`Initializing Jenkins with user: ${this.username} @ ${this.host}`);

    this.api = new Jenkins(this.username, this.private_token, this.host);
    await this.api.connect();
  }

  async getAllcicsTools(callObj: RulesManager): Promise<CICDRepo[]> {
    try {
      const cicdRepos: CICDRepo[] = [];
      const allRepos = await this.repositoriesInit();

      allRepos.forEach(element =>
        cicdRepos.push(
          new CICDRepo(element.name, element.branch, element.repo, element.webhookTriggered, -1, "", CICDConnectorsTypes.Jenkins),
        ),
      );
      return cicdRepos;
    } catch (err) {
      logger.error(`failed to get cicd list obj for: ${this.token.type}, err: ${err}`);
    }
    return [];
  }

  private async repositoriesInit(): Promise<any> {
    logger.info("Getting Jenkins repositories");

    let projects = [];
    const jobList = await this.api.getJobs();

    if (jobList) {
      const jobParsingResult = jobsListSchema.safeParse(jobList);

      if (jobParsingResult.success) {
        for (const job of jobList) {
          const jobConfigResult: JenkinsApiResultWithStatus = await this.api.getJobInfo(job.name);

          if (jobConfigResult.status === 403) {
            logger.error(`Failed to get job info for job: ${job.name} with error 403, skipping Jenkins...`);
            return [];
          }

          const jobConfig = jobConfigResult.data;
          try {
            if (jobConfig) {
              const parser = new XMLParser();

              let jObj = parser.parse(jobConfig, {
                parseAttributeValue: false,
                ignoreAttributes: true,
              });

              const jobParsingResult = jobSchema.safeParse(jObj);

              if (jobParsingResult.success) {
                const repo = jObj["flow-definition"].definition.scm.userRemoteConfigs["hudson.plugins.git.UserRemoteConfig"].url;
                const branch = jObj["flow-definition"].definition.scm.branches["hudson.plugins.git.BranchSpec"].name;

                projects.push({
                  name: job.name,
                  branch: branch,
                  repo: repo,
                  webhookTriggered: true,
                });

                //
                // We were able to contact the Jenkins server, so we can start making connections
                //
                const promise = await this.appMgr.CreateCITool(
                  {
                    reponame: job.name,
                    username: "",
                    vcs_type: "github",
                    vcs_url: repo.substr(0, repo.lastIndexOf(".")) || repo,
                    default_branch: branch.replace(/[*]\//g, ""),
                  },
                  CICDConnectorsTypes.Jenkins,
                );
              } else {
                const newJobParsingResult = newJobSchema.safeParse(jObj);

                if (newJobParsingResult.success) {
                  const newjObj: newJenkinsJob = jObj;

                  logger.info(`Found repository: ${newjObj.name} with branch: master`);

                  projects.push({
                    name: newjObj.name,
                    branch: "master",
                    repo: newjObj.fullName,
                    webhookTriggered: true,
                  });

                  const promise = await this.appMgr.CreateCITool(
                    {
                      reponame: job.name,
                      username: "",
                      vcs_type: "github",
                      vcs_url: job.name, // This is missing
                      default_branch: "master",
                    },
                    CICDConnectorsTypes.Jenkins,
                  );
                } else {
                  const freeStyleProjectResult = freeStyleProject.safeParse(jObj);

                  if (freeStyleProjectResult.success) {
                    const newjObj: freeStyleJob = jObj;
                    projects.push({
                      name: newjObj.project.displayName,
                      branch: newjObj.project.scm.branches["hudson.plugins.git.BranchSpec"].name,
                      repo: newjObj.project.displayName,
                      webhookTriggered: false,
                    });
                  } else {
                    logger.info(`Failed to parse a job: ${JSON.stringify(jobParsingResult)}`);

                    logger.info(`Failed to parse a new job: ${JSON.stringify(newJobParsingResult)}`);

                    logger.info(`Failed to parse a free style job: ${JSON.stringify(freeStyleProjectResult)}`);
                  }
                }
              }
            }
          } catch (err) {
            logger.error(`Failed to parse the jenkins job config with error: ${err}`);
          }
        }
      } else {
        logger.error(`Failed to parse Jenkins jobs, see: ${JSON.stringify(jobParsingResult)}`);
        StatesHelper.Instance.globalApisFails.add("jenkins");
      }
    }

    return projects;
  }

  async jobs(cicdRepo: CICDRepo): Promise<CICDJob[]> {
    let foundJobs: CICDJob[] = [];

    try {
      const jobInfo: newBuildJob = await this.api.getJob(cicdRepo.repoName);

      const jobParsingResult = newBuildJobSchema.safeParse(jobInfo);

      if (jobParsingResult.success) {
        const buildsToScan = jobInfo.builds.slice(0, Math.min(jobInfo.builds.length, 3));

        let jobCounter = 0;
        const randomJobId = getRandomString();

        await Promise.all(
          buildsToScan.map(async job => {
            const ciJob: CICDJob = new CICDJob(cicdRepo.repoName, "success", "Jenkins Job", "", "", "", job.url, "", "", "jenkins");

            foundJobs.push(ciJob);
            this.appMgr.CreateCIJob(ciJob);

            // Find artifacts
            const lastJobOutput = updateServerUrl(this.host, `${jobInfo.lastSuccessfulBuild.url}consoleText`);
            {
              try {
                const instance = axios.get(lastJobOutput, {
                  timeout: 30000,
                  headers: {
                    Authorization: `Basic ${Buffer.from(this.username + ":" + this.private_token).toString("base64")}`,
                  },
                });

                const jobOutput: any = (await instance).data;

                const artifacts = await parseArtifacts(
                  "any", // family
                  `${jobOutput}`, // data
                  `${randomJobId}:${jobCounter++}`,
                  this.uuid,
                );

                if (artifacts.success) {
                  for (const singleArtifact of artifacts.output) {
                    const safelyParsedArtifact = artifactSchema.safeParse(singleArtifact);
                    if (safelyParsedArtifact.success) {
                      logger.info(`Found artifacts for ${cicdRepo.repoName}`);
                      await ciJob.addArtifact(singleArtifact);
                    } else {
                      logger.error(`Failed to parse artifacts (${JSON.stringify(safelyParsedArtifact)})`);
                    }
                  }
                }
              } catch (e) {
                logger.error(`Failed to fetch job data for artifact parsing`);
              }
            }
          }),
        );
      } else {
        logger.error(`Failed to parse a job: ${JSON.stringify(jobParsingResult)}`);
      }
    } catch (err) {
      logger.error(`Failed to create job for cicd repo: ${cicdRepo.repoName}`);
    }

    return foundJobs;
  }
}

export default JenkinsCITool;
