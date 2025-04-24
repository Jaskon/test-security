import { SourceToolType } from "@oxappsec/ox-consolidated-categories/lib/src/ox-categories/config/categories-config";
import { Event } from "aws-sdk/clients/cloudtrail";
import { Token } from "../entitis/collectorEntitisTypes";
import Constant from "../entitis/constant";
import FileHelper from "../helper/IO/fileHlper";
import StringHelper from "../helper/stringHelper";
import TimeHelper from "../helper/timeHelper";
import loggerImport from "../logger";
import { Tool } from "../policy/rules/code/policyRulesBase";
import { AppFlowCloud } from "./applicationsFlowTypes";
import { ArtifactoryTypes } from "./artifactoryTypes";
import { ArtifactorySecEvent } from "./ArtifactTypes";
import { addParentTool, AlertSeverity, SecurityAlertType, SecurityEvent } from "./codeRepoTypes";
import { ExtraInfo } from "./issuesTypes";
import { ChangeReason } from "./service/blameTypes";
import StatesHelper from "../helper/statesHelper";
const uuidGenerator = require("uuid");

const logger = loggerImport.getDebugLogger();

export class Cloud {
  cloudAppFlow: AppFlowCloud[] = [];
  cloudSecurityEvents: CloudSecurityEvent[] = [];
  containerImage: ImageContainerDetail[] = [];
  //Prowler
  // dor to refactor
  vulnerabilities: SecurityEvent[] = [];
  cloud: CloudResource[] = [];
}

export enum CloudTypes {
  Unknown,
  cloudSecurityEvents,
  containerImage,
  lambda,
  EC2,
}

export enum CloudProviderType {
  AWS = "AWS",
  GCP = "GCP",
  Azure = "Azure",
  Kubernetes = "Kubernetes",
}

export function getCloudProviderType(typeStr: string) {
  const typeStrToLowerCase = typeStr.toLowerCase();
  if (typeStrToLowerCase === CloudProviderType.AWS.toLowerCase()) {
    return CloudProviderType.AWS;
  }
  if (typeStrToLowerCase === CloudProviderType.GCP.toLowerCase()) {
    return CloudProviderType.GCP;
  }
  if (typeStrToLowerCase === CloudProviderType.Azure.toLowerCase()) {
    return CloudProviderType.Azure;
  }
  if (typeStrToLowerCase === CloudProviderType.Kubernetes.toLowerCase()) {
    return CloudProviderType.Kubernetes;
  }
  return typeStr;
}

export function getCloudProviderSubType(type: string) {
  if (type == CloudTypes[CloudTypes.containerImage]) return AWSserviceTypes.ecr;
  if (type == CloudTypes[CloudTypes.EC2]) return AWSserviceTypes.ec2;
  if (type == CloudTypes[CloudTypes.lambda]) return AWSserviceTypes.lambda;

  const lower = type.toLowerCase();
  const keys = Object.values(AWSserviceTypes);
  const i = keys.find(k => lower === k.toLowerCase());
  if (i) {
    return i;
  }
  return type;
}

export enum AWSserviceTypes {
  unknown = "",
  iam = "iam",
  support = "support",
  ec2 = "ec2",
  cloudtrail = "cloudtrail",
  configservice = "configservice",
  s3 = "s3",
  kms = "kms",
  vpc = "vpc",
  ecr = "ecr",
  rds = "rds",
  elb = "elb",
  redshift = "redshift",
  macie = "macie",
  guardduty = "guardduty",
  cloudfront = "cloudfront",
  es = "es",
  route53 = "route53",
  lambda = "lambda",
  fargate = "fargate",
  apigateway = "apigateway",
  acm = "acm",
  trustedadvisor = "trustedadvisor",
  sqs = "sqs",
  sns = "sns",
  cloudformation = "cloudformation",
  ecs = "ecs",
  accessanalyzer = "accessanalyzer",
  autoscaling = "autoscaling",
  eks = "eks",
  securityhub = "securityhub",
  sagemaker = "sagemaker",
  glue = "glue",
  ssm = "ssm",
  dynamodb = "dynamodb",
  efs = "efs",
  cloudwatch = "cloudwatch",
  glacier = "glacier",
  account = "account",
  appstream = "appstream",
  backup = "backup",
  codeartifact = "codeartifact",
  codebuild = "codebuild",
  config = "config",
  directoryservice = "directoryservice",
  drs = "drs",
  elbv2 = "elbv2",
  emr = "emr",
  inspector2 = "inspector2",
  opensearch = "opensearch",
  organizations = "organizations",
  resourceexplorer2 = "resourceexplorer2",
  secretsmanager = "secretsmanager",
  shield = "shield",
  workspaces = "workspaces",
}

export enum CloudSecurityTestsTypes {
  unknown,
  group1,
  group2,
  group3,
  group4,
  cislevel1,
  cislevel2,
  extras,
  forensicsready,
  gdpr,
  hipaa,
  secrets,
  apigateway,
  rds,
  elasticsearch,
  pci,
  trustboundaries,
  internetexposed,
  iso27001,
  ekscis,
  ffiec,
  soc2,
  sagemaker,
  ens,
  glue,
  ftr,
}

export class CloudResourcesToRun {
  id: string;
  idForTools: string;
  name: string;
  service: AWSserviceTypes;
  serviceStr: string;
  cloudSecuirtyTestsTypes: CloudSecurityTestsTypes[] = [];
  cloudSecurityTestsTypeStr: string[] = [];
  severity: AlertSeverity;
  severityStr: string;
  toolType: string;
  fileForResults: string;
  folderRes: string;
  excludeChecks: string[] = [];

  constructor(
    id: string,
    name: string,
    service: string,
    severityStr: string,
    toolType: string,
    dirForResults: string,
    cloudSecurityTestsTypeStr?: string,
    excludeChecks?: string[],
  ) {
    this.name = name == null ? "" : name;
    this.serviceStr = service == null ? "" : service;
    this.toolType = toolType;

    this.name = name == null ? "" : name;

    const guid = uuidGenerator.v4().replaceAll("-", "_");
    this.folderRes = `${dirForResults}${guid}/`;

    this.id = id == null ? "" : id;
    this.idForTools = `${id}_${guid}`;

    //Make sure to create folder
    const fileHelper: FileHelper = new FileHelper(this.id);
    fileHelper.createDir(this.folderRes);

    //Set output file
    this.fileForResults = `${this.folderRes}${id}.json`;

    this.severityStr = "";
    this.setSeverity(severityStr);

    if (this.id === "") {
      const msg = `err: constructor cloud policy to execute, id empty`;
      logger.error(msg);
      throw msg;
    }

    if (AWSserviceTypes[this.serviceStr] == undefined && !StatesHelper.Instance.useProwlerWithServices) {
      const msg = `err: constructor cloud policy ${name} service ${this.serviceStr} not found in enum`;
      logger.error(msg);
      throw msg;
    }
    this.service = AWSserviceTypes[this.serviceStr];
    if (cloudSecurityTestsTypeStr) {
      this.addCloudSecurityTestsTypes(cloudSecurityTestsTypeStr);
    }

    if (this.name === "" && !StatesHelper.Instance.useProwlerWithServices) {
      const msg = `err: constructor cloud policy to execute, name empty`;
      logger.error(msg);
      throw msg;
    }

    if (this.severityStr === "" && !StatesHelper.Instance.useProwlerWithServices) {
      const msg = `err: constructor cloud policy to execute, severityStr empty`;
      logger.error(msg);
      throw msg;
    }

    if (excludeChecks && excludeChecks.length) {
      this.excludeChecks = excludeChecks;
    }
  }

  addCloudSecurityTestsTypes(cloudSecurityTestsTypeStr: string) {
    cloudSecurityTestsTypeStr = cloudSecurityTestsTypeStr.replace("-", "").toLowerCase();
    this.cloudSecurityTestsTypeStr.push(cloudSecurityTestsTypeStr);

    if (CloudSecurityTestsTypes[cloudSecurityTestsTypeStr] == undefined) {
      const msg = `err: constructor cloud Cloud security tests types ${this.cloudSecurityTestsTypeStr} not found in enum`;
      logger.error(msg);
      throw msg;
    }
    const type: CloudSecurityTestsTypes = CloudSecurityTestsTypes[cloudSecurityTestsTypeStr];

    this.cloudSecuirtyTestsTypes.push(type);
  }

  setSeverity(severity: string) {
    const severityToLower = severity.toLowerCase();
    if (severityToLower.includes("[high]")) {
      this.severityStr = AlertSeverity[AlertSeverity.High];
      this.severity = AlertSeverity.High;
    } else if (severityToLower.includes("[low]")) {
      this.severityStr = AlertSeverity[AlertSeverity.Low];
      this.severity = AlertSeverity.Low;
    } else if (severityToLower.includes("[critical]")) {
      this.severityStr = AlertSeverity[AlertSeverity.Critical];
      this.severity = AlertSeverity.Critical;
    } else if (severityToLower.includes("[medium]")) {
      this.severityStr = AlertSeverity[AlertSeverity.Medium];
      this.severity = AlertSeverity.Medium;
    } else if (severityToLower.includes("[informational]")) {
      this.severityStr = AlertSeverity[AlertSeverity.Info];
      this.severity = AlertSeverity.Info;
    }
  }
}

export class CloudResource {
  accountName: string;
  category: string;
  region: string;
  cloudService: string;
  resource: string;
  cloudEnv: string;
  account: string;

  constructor(
    accountName: string,
    category: string,
    region: string,
    cloudService: string,
    resource: string,
    cloudEnv: string,
    account: string,
  ) {
    this.accountName = accountName;
    this.category = category;
    this.region = region;
    this.cloudService = cloudService;
    this.resource = resource;
    this.cloudEnv = cloudEnv;
    this.account = account;

    if (this.cloudService === "") {
      const msg = `cloudService are empty, info ${this.accountName}`;
      throw msg;
    }

    if (this.resource === "") {
      const msg = `resource are empty, info ${this.resource}`;
      throw msg;
    }
  }
}

export class CloudSecurityEvent {
  securityProvider: string;
  securityProviders = new Set<string>();
  link: string;
  createdAt: string;
  createdAtInDays: Number;
  isSilent: boolean = false;
  violationInfo: string;
  title: string;
  severity: AlertSeverity;
  originalSeverity: AlertSeverity;
  confidence: AlertSeverity;
  severityStr: string;
  originalSeverityStr: string;
  confidenceStr: string;
  additionalInfo: string;
  securityAlertTypeStr: string = SecurityAlertType[SecurityAlertType.cspm];
  recommendation: string;
  description: string;
  eduVideoLink: string;
  openTimeInDays: number;
  securityAlertType: SecurityAlertType = SecurityAlertType.cspm;
  objType: CloudTypes = CloudTypes.cloudSecurityEvents;
  objTypeStr = CloudTypes[CloudTypes.cloudSecurityEvents];
  oxTool: boolean;
  moreInfoLink: string;
  id: string;
  secretType: string;
  secret: boolean;

  severityChangedReason: ChangeReason[] = [];
  severityChangeNumber: number;
  validSecret: boolean = false;
  secretChecked: boolean = false;
  extraInfo: ExtraInfo[] = [];

  accountName: string;
  organization: string;
  category: string;
  region: string;
  cloudService: string;
  cloudEnv: string;
  isViolation: boolean;

  //This is needed for exclusions dont delete this or change!!!
  realMatch: string = "";
  accountId: string;
  resource: string;
  ruleId: string;
  secretContent: string;

  artifacts: ArtifactorySecEvent;
  repoName: string;

  //additional data
  additionalToolData: string;
  cloudAccountGroups: string[] = [];
  cloudAccountOwners: string[] = [];

  linkToExternalProduct: string;

  isManualConfig: boolean = false;
  tools: Tool[] = [];
  cweList: string[] = [];

  constructor(
    cloudEnv: string,
    securityProvider: string,
    link: string,
    createdAt: string,
    violationInfo: string,
    title: string,
    severity: string,
    additionalInfo: string,
    confidence: string,
    recommendation: string,
    oxTool: boolean,
    ruleId: string,
    moreInfoLink: string,
    accountName: string,
    category: string,
    region: string,
    cloudService: string,
    resource: string,
    secretContent: string,
    secretType: string,
    secret: boolean,
    isViolation: boolean,
    tool: Tool,
  ) {
    this.secretContent = secretContent;
    this.secretType = secretType;
    this.secret = secret;
    this.tools.push(tool);
    if (tool.toLowerCase().includes("prowler")) {
      this.tools.push("aws");
    }
    addParentTool(this, tool);

    this.link = link == null ? "" : link;
    this.securityProvider = securityProvider == null ? "" : securityProvider;
    this.createdAt = createdAt == null ? "" : createdAt;
    this.violationInfo = violationInfo == null ? "" : violationInfo;
    this.additionalInfo = additionalInfo == null ? "" : additionalInfo;
    this.title = title == null ? "" : title;
    this.recommendation = recommendation;
    this.oxTool = oxTool;
    this.ruleId = ruleId == null ? "" : ruleId;
    this.moreInfoLink = moreInfoLink == null ? "" : moreInfoLink;
    this.accountName = accountName == null ? "" : accountName;
    this.category = category == null ? "" : category;
    this.region = region == null ? "" : region;
    this.cloudService = cloudService == null ? "" : cloudService;
    this.resource = resource == null ? "no-specific-resource" : resource.toLowerCase();
    this.cloudEnv = cloudEnv;
    this.id = uuidGenerator.v4();
    this.isViolation = isViolation;

    const securityProviderForUI = oxTool
      ? StringHelper.capitalizeFirstLetter(SourceToolType["Cloud Security"])
      : StringHelper.capitalizeFirstLetter(this.securityProvider);
    this.securityProviders.add(securityProviderForUI);

    if (this.ruleId === "") {
      const msg = `ruleId, info ${this.title}`;
      throw msg;
    }

    if (this.securityProvider === "") {
      const msg = `securityProvider are empty, info ${this.title}`;
      throw msg;
    }

    if (this.securityAlertType === SecurityAlertType.Unknown) {
      const msg = `securityAlertType are unknown, info ${this.title}`;
      throw msg;
    }

    if (this.violationInfo === "") {
      const msg = `violationInfo are empty, info ${this.title}`;
      throw msg;
    }

    if (this.resource === "") {
      const msg = `resource are empty, info ${this.title}`;
      throw msg;
    }

    const timeHelper: TimeHelper = new TimeHelper("security event");
    this.createdAtInDays = timeHelper.getTimeIntervalFronNowInDays(this.createdAt);

    this.setOepnTimeInfo();
    this.setSeverity(severity);
    this.setConfidence(confidence);

    this.originalSeverityStr = this.severityStr;
    this.originalSeverity = this.severity;

    if (securityProvider === "") {
      const msg = `securityProvider is empty, info ${this.title}`;
      throw msg;
    }

    if (this.severity == AlertSeverity.Unknown) {
      const msg = `failed to detect severity for: ${severity} info ${this.title}`;
      throw msg;
    }
  }

  async setManaulConfig(isConfig: boolean): Promise<void> {
    this.isManualConfig = isConfig;
  }

  setSeverity(severity: string) {
    this.severity = AlertSeverity.Unknown;
    this.severityStr = AlertSeverity[AlertSeverity.Unknown];

    if (severity == null || !severity) {
      return;
    }
    if (Constant.infoRegex.exec(severity) != null) {
      this.severity = AlertSeverity.Info;
    }
    if (Constant.lowRegex.exec(severity) != null) {
      this.severity = AlertSeverity.Low;
    }
    if (Constant.mediumRegex.exec(severity) != null) {
      this.severity = AlertSeverity.Medium;
    }
    if (Constant.highRegex.exec(severity) != null) {
      this.severity = AlertSeverity.High;
    }
    if (Constant.criticalRegex.exec(severity) != null) {
      this.severity = AlertSeverity.Critical;
    }
    if (Constant.applRegex.exec(severity) != null) {
      this.severity = AlertSeverity.Appoxalypse;
    }

    this.severityChangeNumber = this.severity;
    this.severityStr = AlertSeverity[this.severity];
  }

  setConfidence(confidence: string) {
    this.confidence = AlertSeverity.Unknown;
    this.confidenceStr = AlertSeverity[AlertSeverity.Unknown];

    if (confidence == null || !confidence) {
      return;
    }
    if (Constant.infoRegex.exec(confidence) != null) {
      this.confidence = AlertSeverity.Info;
    }
    if (Constant.lowRegex.exec(confidence) != null) {
      this.confidence = AlertSeverity.Low;
    }
    if (Constant.mediumRegex.exec(confidence) != null) {
      this.confidence = AlertSeverity.Medium;
    }
    if (Constant.highRegex.exec(confidence) != null) {
      this.confidence = AlertSeverity.High;
    }
    if (Constant.criticalRegex.exec(confidence) != null) {
      this.confidence = AlertSeverity.Critical;
    }
    if (Constant.applRegex.exec(confidence) != null) {
      this.confidence = AlertSeverity.Appoxalypse;
    }

    this.confidenceStr = AlertSeverity[this.confidence];
  }

  setOepnTimeInfo() {
    this.openTimeInDays = -1;
    if (this.createdAt != null) {
      let openTime = new Date(this.createdAt);
      const openTimeInfo = openTime.getTime();
      const seconds = (new Date().getTime() - openTimeInfo) / 1000;
      const openTimeInHours = seconds / 3600;

      this.openTimeInDays = Math.trunc(openTimeInHours / 24);
    }
  }
}

//
// AWS ECR Repository definition
//
export interface ECRRepository {
  repositoriesData: RepositoriesDatum[];
}

export interface RepositoriesDatum {
  repositories: Repository[];
}

export interface Repository {
  repositoryArn: string;
  registryId: string;
  repositoryName: string;
  repositoryUri: string;
  createdAt: string;
  imageTagMutability: ImageTagMutability;
  imageScanningConfiguration: ImageScanningConfiguration;
  encryptionConfiguration: EncryptionConfiguration;
}

export interface EncryptionConfiguration {
  encryptionType: EncryptionType;
}

export enum EncryptionType {
  Aes256 = "AES256",
  None = "NONE",
}

export interface ImageScanningConfiguration {
  scanOnPush: boolean;
}

export enum ImageTagMutability {
  Mutable = "MUTABLE",
  Immutable = "IMMUTABLE",
}

//
// AWS ECR Docker Image definition
//
export interface ECRImageDetails {
  imageDetails: ImageDetail[];
}

export class ImageDetail {
  baseImage: {
    layers: Set<string>;
    repo?: string;
    digest?: string;
    /**
     * @deprecated
     */
    tag?: string;
    tags: Array<{ name: string; current: boolean }>;
  };
  isHeavy: boolean;
  registryId: string;
  repositoryName: string;
  imageDigest: string;
  imageTags: string[] = [];
  name: string;
  location: string;
  imageSizeInBytes: number;
  region: string;
  imagePushedAt: string;
  imagePushedAtInDays: number;
  imagePullAtInDays: number;
  imageManifestMediaType: ImageManifestMediaType;
  artifactMediaType: ArtifactMediaType;
  lastRecordedPullTime?: string;
  imageDigestWithoutPrefix: string;
  cloudEnv: string;
  imageId: string;
  cicdFoundByHash: boolean = false;
  cicdFoundByName: boolean = false;
  cicdFoundInDockerHub: boolean = false;
  imageRunningInCloud: boolean = false;
  token: Token;
  link: string;
  objType: ArtifactoryTypes = ArtifactoryTypes.image;
  objTypeStr: string = ArtifactoryTypes[ArtifactoryTypes.image];
  accessToken?: string;
  workloadInfo: WorkloadInfo[] = [];

  dockerFilePath?: string;
  os?: string;
  osVersion?: string;

  runningContainerDescription?: string;
}

export class ImageContainerDetail {
  imageDetail: ImageDetail = null;
  lastImageAvailableInRegistry: ImageDetail = null;
  cloudEnv: string = "AWS";
  imageDigestWithoutPrefix: string;
  imageNameWithoutTag: string;
  cluster: string;
  region: string;
  containerImageInfo: any = null;
  taskDefinition: any = null;
  cicdFoundByHash: boolean = false;
  cicdFoundByName: boolean = false;
  cicdFoundInDockerHub: boolean = false;
  link: string;
  objType: CloudTypes = CloudTypes.containerImage;
  objTypeStr: string = CloudTypes[CloudTypes.containerImage];
  auditTrail: Event = null;
}
export class WorkloadInfo {
  cluster: string;
  region: string;
  type: string;
  k8sType: string;
  consoleLink: string;
}

export enum ArtifactMediaType {
  ApplicationVndDockerContainerImageV1JSON = "application/vnd.docker.container.image.v1+json",
}

export enum ImageManifestMediaType {
  ApplicationVndDockerDistributionManifestV2JSON = "application/vnd.docker.distribution.manifest.v2+json",
}

//
// Container definition
//

// Generated by https://quicktype.io

export interface ECSContainer {
  name: string;
  image: string;
  cpu: number;
  portMappings: PortMapping[];
  essential: boolean;
  environment: Environment[];
  mountPoints: MountPoint[];
  volumesFrom: any[];
  stopTimeout: number;
  logConfiguration: LogConfiguration;
}

export interface Environment {
  name: string;
  value: string;
}

export interface LogConfiguration {
  logDriver: string;
  options: Options;
}

export interface Options {
  "awslogs-group": string;
  "awslogs-region": string;
  "awslogs-stream-prefix": string;
}

export interface MountPoint {
  sourceVolume: string;
  containerPath: string;
  readOnly: boolean;
}

export interface PortMapping {
  containerPort: number;
  hostPort: number;
  protocol: string;
}

//
// AWS ECS Task Definition
//
export interface ECSTaskDefinition {
  taskDefinitionArn: string;
  containerDefinitions: ContainerDefinition[];
  family: string;
  taskRoleArn: string;
  executionRoleArn: string;
  networkMode: string;
  revision: number;
  volumes: Volume[];
  status: string;
  requiresAttributes: RequiresAttribute[];
  placementConstraints: any[];
  compatibilities: string[];
  requiresCompatibilities: string[];
  cpu: string;
  memory: string;
  registeredAt: string;
  registeredBy: string;
}

export interface ContainerDefinition {
  name: string;
  image: string;
  cpu: number;
  portMappings: PortMapping[];
  essential: boolean;
  environment: Environment[];
  mountPoints: MountPoint[];
  volumesFrom: any[];
  stopTimeout: number;
  logConfiguration: LogConfiguration;
}

export interface Environment {
  name: string;
  value: string;
}

export interface LogConfiguration {
  logDriver: string;
  options: Options;
}

export interface Options {
  "awslogs-group": string;
  "awslogs-region": string;
  "awslogs-stream-prefix": string;
}

export interface MountPoint {
  sourceVolume: string;
  containerPath: string;
  readOnly: boolean;
}

export interface PortMapping {
  containerPort: number;
  hostPort: number;
  protocol: string;
}

export interface RequiresAttribute {
  name: string;
}

export interface Volume {
  name: string;
  efsVolumeConfiguration: EFSVolumeConfiguration;
}

export interface EFSVolumeConfiguration {
  fileSystemId: string;
  rootDirectory: string;
  transitEncryption: string;
  authorizationConfig: AuthorizationConfig;
}

export interface AuthorizationConfig {
  iam: string;
}

//
// Container definition
//
export interface AWSContainerDefinition {
  container: ECSContainer;
  taskDefinition: ECSTaskDefinition;
  image: string;
  region: string;
}

//
// AWS ECS Task Definition
//
export interface AWSECSTaskDefinition {
  taskDefinition: ECSTaskDefinition;
  region: string;
}

//
// ECS Cluster type
//
export interface AWSClusterArn {
  clusterArns: string[];
}

//
// ECS Cluster tasks
//
export interface AWSClusterTasks {
  runningTasks: RunningTasks;
  region: string;
}

export interface RunningTasks {
  taskArns: string[];
}

//
// ECS Cluster Task Definition
//

export interface AWSEcsTaskDefinition {
  taskDefinition: TaskDefinition[];
  region: string;
  cluster: string;
}

export interface TaskDefinition {
  attachments: Attachment[];
  attributes: Attribute[];
  availabilityZone: string;
  capacityProviderName: string;
  clusterArn: string;
  connectivity: string;
  connectivityAt: string;
  containers: Container[];
  cpu: string;
  createdAt: string;
  desiredStatus: string;
  enableExecuteCommand: boolean;
  group: string;
  healthStatus: string;
  lastStatus: string;
  launchType: string;
  memory: string;
  overrides: Overrides;
  platformVersion: string;
  platformFamily: string;
  pullStartedAt: string;
  pullStoppedAt: string;
  startedAt: string;
  startedBy: string;
  tags: any[];
  taskArn: string;
  taskDefinitionArn: string;
  version: number;
  ephemeralStorage: EphemeralStorage;
}

export interface Attachment {
  id: string;
  type: string;
  status: string;
  details: Attribute[];
}

export interface Attribute {
  name: string;
  value: string;
}

export interface Container {
  containerArn: string;
  taskArn: string;
  name: string;
  image: string;
  imageDigest: string;
  runtimeId: string;
  lastStatus: string;
  networkBindings: any[];
  networkInterfaces: NetworkInterface[];
  healthStatus: string;
  managedAgents: ManagedAgent[];
  cpu: string;
}

export interface ManagedAgent {
  lastStartedAt: string;
  name: string;
  lastStatus: string;
}

export interface NetworkInterface {
  attachmentId: string;
  privateIpv4Address: string;
}

export interface EphemeralStorage {
  sizeInGiB: number;
}

export interface Overrides {
  containerOverrides: ContainerOverride[];
  inferenceAcceleratorOverrides: any[];
}

export interface ContainerOverride {
  name: string;
}
