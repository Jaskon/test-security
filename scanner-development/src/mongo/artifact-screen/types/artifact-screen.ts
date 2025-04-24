import { ApplicationFlow } from "./app-flow-types";
import { AWS } from "./aws-cloud-attributes";

export interface Artifact {
  // Unique Identifier for an artifact (name+version or name+hash)
  id: string;

  // The date we collected the artifact
  collectedAt: Date;

  // The scan ID, which found the artifact
  scanId: string;

  // Basic Description
  artifactInfo: ArtifactInfo;

  // Application related identifiable information
  // e.g Application Name, Application Unique ID: xxxxx
  appDescription?: ApplicationDescription;

  // Categories of issues
  categories?: IssueSummary[];

  // The related code description of the artifact
  // like: commit, owner...
  codeDescription?: CodeArtifactDescription;

  cicdDescription?: CICDArtifactDescription;

  pipelineInfo?: PipelineInfo;

  registryDescription?: ArtifactRegistryDescription[];

  cloudData?: CloudArtifactData[];

  filterScreenData: FilterScreenData;

  secretIssues?: string[]; //SecretScanning
  confIssues?: string[]; //ContainerMisconfiguration
  vulnDepIssues?: string[]; //VulnerableDependencyUser
  vulnDepBaseIssues?: string[]; //VulnerableDependencyBase
  vulnDepInstructionIssues?: string[]; //VulnerableDependencyInstruction
}

export interface FilterScreenData {
  // When the artifact was run, (Optional, since the artifact can be deployed, but not executed)
  // Production execution date (best effort)
  lastExecutionTime?: Date;

  // Check if the artifact deployed to production
  inProduction: boolean;

  // Check if the artifact is deployed to cloud systems
  deployed: boolean;

  // Number of high severities for this artifact
  highSeverityIssues: number;

  // Shows if the artifact is part of latest version
  lastVersion: boolean;
}

// Artifact Info describes the artifacts itself
export interface ArtifactInfo {
  // Type of the artifact,
  type: "Container" | "Lambda" | "NPM" | "Yarn" | string;

  // Artifact display name
  name: string;

  // Artifact display version
  version?: string;

  // Artifact hash if applicable
  hash?: string;

  // Artifact size, human readable text (e.g 25MB or 1.5GB)
  size?: string;
}

export interface ApplicationDescription {
  // Application type
  appType?: string;

  // Application Name
  appName: string;

  // Application Id: a unique identifier
  appId: string;

  // Application Priority at the time of the artifact creation
  businessPriority?: number;

  // Application Flow
  appFlow?: ApplicationFlow;

  toolsInfo: ToolInfo[];
}

export interface ToolInfo {
  toolName: string;
  name: string[];
  total?: number;
  category: string;
  criticality: number;
}

export interface IssueSummary {
  catId: number;

  severities: {
    info: number;
    low: number;
    medium: number;
    high: number;
    critical: number;
    appox: number;
  };
}

export interface CodeArtifactDescription {
  // What is the SCM behind the artifact
  scm: "GitHub" | "Azure" | "AWS CodeBuild" | "GitLab" | "Bitbucket" | "Bitbucket stash" | string;

  // The commit which initiated the artifact creation
  commit: string;

  // The link to the commit on SCM
  commitLink: string;

  // The merge link if applicable
  mergeLink?: string;

  // Pull request date
  prDate: Date;

  // Pull request owner
  prOwner: string;

  // Approvers
  prApprovals?: string[];

  // Reviewers, empty if no reviewers
  prReviewers?: string[];

  //e.g 10 changes: utils.js
  fileChanged?: FileChanged[];

  // Code state: public/private
  isPublic?: boolean;

  // Source branch of the commit/Merge request/Pull request
  sourceBranch?: string;

  // Destination branch of the commit/Merge request/Pull request
  destinationBranch?: string;
}

export interface FileChanged {
  fileName: string;
  change: string;
}

export interface CICDArtifactDescription {
  // Pipeline name: should be unique (AppID:pipeline)
  id: string;

  // Detected CI/CD system
  type: "Jenkins" | "Github Actions" | string;

  // Pipeline latest data, taken else where
  // Fetch currently live available data
  pipeline?: PipelineStatistics;

  pipelineExecution: PipelineExecution;
}

export interface PipelineInfo {
  owner?: string;
  developer?: string;
}

export interface PipelineStatistics {
  // Pipeline name: should be unique (AppID:pipeline)
  id: string;

  // Link to the code
  link: string;

  // Owner (devops engineer) who created this pipeline
  owner: string;

  // Last developer pushed code?! Most of the commits?!
  developer: string;

  // When this pipeline was created, probably git log
  creationTime: Date;

  lastExecutionTime: Date;

  // Number of times this pipeline was running
  executed: number;
}

export interface PipelineExecution {
  // Link to the artifact pipeline
  link?: string;

  // Pipeline name (usually this is a merge request)
  pipelineName?: string;

  // Pipeline id
  pipelineId: string;

  // How was the code pushed or introduced
  pushType: "Code Push" | "Merge Request" | "Pull Request" | string;

  // Who initiated the operation
  executedBy: string;

  // When the pipeline was created
  createTime: Date;

  // When the pipeline was updated, in case manual operation was done
  updateTime: Date;

  // Last status
  status: string;

  // Link to any artifacts created
  intermediateRegistryLink?: string[];
}

export interface ArtifactScreenHistoryStats {
  // Artifact ID
  id: string;

  // Application ID generating this artifact
  appId: string;

  // scan id, in which we found the artifact
  scanId: string;

  // When this was collected
  collectedAt: Date;

  // Creation date of the artifact, (Optional, since we might not have this information)
  createTime?: Date;

  // When the artifact was run, (Optional, since the artifact can be deployed, but not executed)
  lastExecutionTime?: Date;

  // Check if the artifact deployed to production
  inProduction: boolean;

  // Check if the artifact is deployed to cloud systems
  deployed: boolean;

  // Number of high severities for this artifact
  highSeverityIssues: number;

  // Shows if the artifact is part of latest version
  lastVersion: boolean;
}

export interface ArtifactRegistryDescription {
  // Registry type: JFrog, ECR, GCP
  type: "JFrog" | "ECR" | "GCP" | string;

  // Name of the sub folder, holding the artifact
  name: string;

  // Name of the main folder, if applicable
  project?: string;

  // Link to the registry location
  link?: string;

  // Artifact hash
  hash?: string;

  // Multiple tags if applicable
  tags?: string[];

  // Username that pushed the artifact, could be CI/CD user or developer name
  username?: string;

  // Type of the user, CI/CD, Standard user
  userType?: string;

  // When the artifact was uploaded
  uploadTime?: Date;

  // If the artifact was updated
  lastUpdate?: Date;

  // When was the artifact built, if applicable
  buildTime?: Date;

  // Indicates whether the artifact is publicly available
  isPublic?: boolean;
}

export interface CloudArtifactData {
  // Cloud specific identifier
  cloudIdentifier: "Lambda" | "Cloud Function" | "ECS" | "EC2" | "Compute Engine" | "EKS" | string;

  // Free text to identify the artifact location: staging, beta, alpha, dev, app, production
  environment?: string;

  // link to the artifact on cloud
  link?: string;

  // Last execution time, taken from Audit trails of the Cloud component
  lastExecutionTime?: Date;

  // The last modification time of the artifact on cloud
  // mostly it's when the artifact was uploaded (deployed)
  lastModifiedTime: Date;

  // Account that has this artifact
  account: string;

  // In which zone this artifact is deployed
  // eu-west-1 for example
  zone: string;

  // Cloud artifact specific description
  // CPU/Memory/Size/Mount points/Network configuration
  cloudDescription?: CloudDescription;
}

export interface CloudDescription {
  type: "AWS" | "GCP" | "Azure" | string;
  subType: "Lambda" | "Cloud Function" | "ECS" | "EC2" | "Compute Engine" | "EKS" | string;

  cloudEntityAttributes?: AWS.Attributes.ECS | AWS.Attributes.Lambda;
}
