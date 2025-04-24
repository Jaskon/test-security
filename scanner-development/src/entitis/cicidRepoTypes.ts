import loggerImport from "../logger";
import { Tool } from "../policy/rules/code/policyRulesBase";
import { AppFlowCICD, FoundByItem } from "./applicationsFlowTypes";
import { artifactType, K8Description } from "./ArtifactTypes";
import { CodeRepoTypes } from "./codeRepoTypes";
const logger = loggerImport.getDebugLogger();

export class CICDRepo {
  repoName: string;
  defaultBranch: string;
  buildUrl: string;
  webhookTriggered: boolean;
  repoId: number | string;
  repoOwner: string;
  toolName: string;
  organization: string;

  constructor(
    repoName: string,
    defaultBranch: string,
    buildUrl: string,
    webhookTriggered: boolean,
    repoId: number,
    repoOwner: string,
    toolName: string,
  ) {
    this.repoName = repoName == undefined || repoName == null ? "" : repoName;
    this.defaultBranch = defaultBranch == undefined || defaultBranch == null ? "" : defaultBranch;
    this.buildUrl = buildUrl == undefined || buildUrl == null ? "" : buildUrl;
    this.webhookTriggered = webhookTriggered;
    this.repoId = repoId;
    this.repoOwner = repoOwner;
    this.toolName = toolName;

    if (this.repoName === "") {
      const msg = "err: constructor, cicd repo repoName is empty";
      logger.error(msg);
      throw msg;
    }
  }
}

export class CICDJob {
  repo_name: string;
  result: string;
  subject: string;
  username: string;
  commit: string;
  defaultBranch: string;
  buildUrl: string;
  idinfo: string;
  repoName: string;
  diffTime: number;
  startTime: string;
  buildName: string;

  //Build pipeline
  pipelineId: string;
  pipelineLink: string;
  pipelineTime: string;
  pipelineStatus: string;
  pipelineDiffInTime: number;

  artifacts: string[] = [];
  parsedArtifacts: artifactType[] = [];
  K8Configuration?: K8Description;

  //Specific to github
  logs_url: string;
  tool: Tool = "UNKNOWN";

  constructor(
    repo_Name: string,
    result: string,
    subject: string,
    username: string,
    commit: string,
    defaultBranch: string,
    buildUrl: string,
    idinfo: string = "",
    repoName: string = "",
    tool: Tool,
  ) {
    this.repo_name = repo_Name == undefined || repo_Name == null ? "" : repo_Name;
    this.result = result == undefined || result == null ? "" : result;
    this.subject = subject == undefined || subject == null ? "" : subject;
    this.username = username == undefined || username == null ? "" : username;
    this.commit = commit == undefined || commit == null ? "" : commit;
    this.defaultBranch = defaultBranch == undefined || defaultBranch == null ? "" : defaultBranch;
    this.buildUrl = buildUrl == undefined || buildUrl == null ? "" : buildUrl;
    this.tool = tool;
    this.idinfo = idinfo;
    this.repoName = repoName;
    if (repoName === "") {
      this.repoName = this.repo_name;
    }

    if (this.repo_name === "") {
      const msg = "err: constructor, cicd job repoName is empty";
      logger.error(msg);
      throw msg;
    }
  }

  async addArtifact(artifact: artifactType) {
    this.parsedArtifacts.push(artifact);
  }

  addK8Configuration(k8Configuration: K8Description) {
    this.K8Configuration = k8Configuration;
  }
}

export class CICD {
  resourceType: string = "citool";

  //Build CICD(like githubci or gitlabci)
  jobs: CICDJob[] = [];
  repositories: CICDRepo;

  //All CICD tools include build cicd
  cicdAppFlow: AppFlowCICD[] = [];

  citool: CICDRepo;
}

export function getCICDType(type: string) {
  const lower = type.toLowerCase();
  if (lower === "pipeline") {
    return FoundByItem.Pipeline;
  }
  if (lower === CodeRepoTypes[CodeRepoTypes.files]) {
    return FoundByItem.File;
  }
  if (lower === CodeRepoTypes[CodeRepoTypes.workflows]) {
    return FoundByItem.File;
  }
  if (lower === CodeRepoTypes[CodeRepoTypes.webhooks]) {
    return FoundByItem.Webhook;
  }

  logger.error(`cannot find type: ${type} for get CICD type`);
  return "";
}

export function getCICDProvider(type: string) {
  const lower = type.toLowerCase();

  const keys = Object.values(CICDConnectorsTypes);
  const i = keys.find(k => lower === k.toLowerCase());
  if (i) {
    return i;
  }

  logger.error(`cannot find type: ${type} for get CICD provider `);
  return "";
}

export enum CICDConnectorsTypes {
  AzurePipeLine = "Azure Pipelines",
  TeamCity = "TeamCity",
  Github = "GitHub Actions",
  Gitlab = "GitLab CI/CD",
  Jenkins = "Jenkins",
  CircleCI = "Circle CI",
  DroneCI = "Drone CI",
  Buildkite = "Buildkite",
  BitbucketPipelines = "Bitbucket Pipelines",
  TravisCI = "Travis CI",
  CloudBuild = "Cloud Build",
  Generic = "Generic",
}
