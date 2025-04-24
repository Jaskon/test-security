import { z } from "zod";
import { AppFlowArtifacts } from "./applicationsFlowTypes";
import { ImageInfo } from "./artifactoryTypes";
import { SecurityEvent } from "./codeRepoTypes";

export const artifactSchema = z.object({
  type: z.string(),
  subType: z.string(),
  name: z.string(),
  size: z.string(),
  hashType: z.string(),
  hash: z.string(),
  resolved: z.boolean(),
  inputHash: z.string().optional(),
  revision: z.string().optional(),
  image: z.string().optional(),
  version: z.string().optional(),
  link: z.string().optional(),
});

export type artifactType = z.infer<typeof artifactSchema>;

export enum ArtifactConnectorsTypes {
  JFROG_ARTIFACTS = "jfrogArtifacts",
  GitLabContainerRegistry = "GitLab Container Registry",
  Generic = "Generic",
  GCP_ARTIFACTS = "Google Artifact Registry",
  GCP_CONTAINER = "Google Container Registry",
  AZURE_CONTAINER_REGISTRY = "Azure Container Registry",
  DOCKER_HUB = "Docker Hub",
  GOHARBOR_CONTAINER_REGISTRY = "GoHarbor Container Registry",
  cloudAWS = "cloudAWS",
}

export class Artifactory {
  securityEvents: SecurityEvent[] = [];
  artifactsFromSecEvents: ArtifactorySecEvent[] = [];
  registryImage: ImageInfo[] = [];

  artifactsAppFlow: AppFlowArtifacts[] = [];
}

export enum ArtifactorySecEventType {
  Unknown = "",
  Docker = "Docker Container",
  Zip = "Zip Archive",
  Serverless = "Serverless",
}

export enum ArtifactorySecEventSystem {
  Generic = "Generic",
  ECR = "Amazon ECR",
  NPM = "NPM",
  LAMBDA = "Lambda",
  GCP_CONTAINER = "Google Container Registry",
  GCP_ARTIFACTS = "Google Artifact Registry",
  GITLAB_REGISTRY = "GitLab Container Registry",
  JFROG_REGISTRY = "JFrog Artifactory",
  DOCKER_HUB = "Docker Hub",
  Harbor = "Harbor",
  QUERY_IO = "Query IO",
  CA = "AWS CodeArtifact",
  GITHUB_REGISTRY = "GitHub Container Registry",
  AZURE_CONTAINER_REGISTRY = "Azure Container Registry",
  AA = "Azure Artifacts",
  NEXUS_CONTAINER_REGISTRY = "Nexus Container Registry",
  GOHARBOR_CONTAINER_REGISTRY = "GoHarbor Container Registry",
}

export function guessArtifactSystem(str: string) {
  try {
    if (!str) {
      return ArtifactorySecEventSystem.Generic;
    }

    const toLower = str.toLowerCase();
    if (toLower.includes(".ecr.") || toLower === "ecr") return ArtifactorySecEventSystem.ECR;
    if (toLower.includes("docker.pkg.dev")) return ArtifactorySecEventSystem.GCP_ARTIFACTS;
    if (toLower.includes("gcr.io")) return ArtifactorySecEventSystem.GCP_CONTAINER;
    if (toLower.includes("registry.gitlab")) return ArtifactorySecEventSystem.GITLAB_REGISTRY;
    if (toLower === "lambda") return ArtifactorySecEventSystem.LAMBDA;
    if (toLower.includes("npm")) return ArtifactorySecEventSystem.NPM;
    if (toLower.includes("jfrog")) return ArtifactorySecEventSystem.JFROG_REGISTRY;
    if (toLower.includes("hub.docker")) return ArtifactorySecEventSystem.DOCKER_HUB;
    if (toLower.includes("docker.io")) return ArtifactorySecEventSystem.DOCKER_HUB;
    if (toLower.includes("quay.io")) return ArtifactorySecEventSystem.QUERY_IO;
    if (toLower.includes("ghcr.io")) return ArtifactorySecEventSystem.GITHUB_REGISTRY;
    if (toLower.includes("azurecr.io")) return ArtifactorySecEventSystem.AZURE_CONTAINER_REGISTRY;
    if (toLower.includes("mcr.microsoft.com")) return ArtifactorySecEventSystem.AZURE_CONTAINER_REGISTRY;

    if (toLower.match(/[-a-zA-Z0-9@:%._\+~#=]{1,256}\.[a-zA-Z0-9()]{1,6}\b([-a-zA-Z0-9()@:%_\+.~#?&//=]*)?/gi))
      return ArtifactorySecEventSystem.Generic;
  } catch (e) {}

  return ArtifactorySecEventSystem.Generic;
}

export function guessArtifactType(str: string) {
  const toLower = str.toLowerCase();
  if (toLower.includes(".zip")) return ArtifactorySecEventType.Zip;
  if (toLower.includes("docker") || toLower.includes(".dkr.")) return ArtifactorySecEventType.Docker;
  if (toLower.includes("serverless")) return ArtifactorySecEventType.Serverless;
  return ArtifactorySecEventType.Unknown;
}

export interface ArtifactorySecEvent {
  system: ArtifactorySecEventSystem;
  subType: ArtifactorySecEventType;
  repoFullName: string;
  imageCreatedAt: string;
  dockerVer: string;
  pkgCount: number;
  binariesCount: number;
  hasPackageManager: boolean;
  os: string;
  osVersion?: string;
  sha: string;
  dockerFileInRunTime: string;
  registry: string;
  tag: string;
  linkToRegistry: string;
  linkToTask: string;
  scanTime?: string;
  additionalInfo?: string;
  baseImage?: string;
  baseImageSha?: string;
  baseImageRegistry?: string;
  baseImageOsVersion?: string;
  baseImageTags?: Array<{ name: string; current: boolean }>;
  registryName?: string;
  runningOnHost?: string;
  region?: string;
  accountId?: string;
  imageLink?: string;

  //from Artifact(like jfog as example)
  buildName?: string;
  buildNumber?: string;
  repositoryName?: string;
  versionName?: string;
  buildCommit?: string;
  buildRepository?: string;
}

export interface DockerSearchCriteria {
  //"Image Uri represents the image name in ECR"
  imageUri: string;
  //"Tag represents the tag of the image"
  tag: string;
  //"Digest represents the digest of the image"
  digest: string;
  //"Date represents the date of the image"
  date?: string;
}

export interface Session {
  //"Session Id"
  uuid: string;
  //"Organization Id"
  orgId: string;
}

export interface SCM {
  //"SCM type"
  type: string;
  //"SCM repository id"
  id: string;
  //"Site, website of the SCM system";
  site: string;
  //"Token, access token of the SCM system";
  token: string;
  //"Scan all the repositories flag";
  scanAll: string;
}

export interface Pagination {
  //"Page number"
  page: string;
  //"Page size"
  size: string;
  //"Max Page size"
  maxSize: string;
}

export interface DockerSearchResult {
  //"Docker Search Result"
  items: DockerSearchCriteria;
  //"Result job id"
  jobId: string;
}

export interface EnrichedDockerSearchResult {
  //"Docker search result"
  results: DockerSearchResult;
  //"Pagination"
  pagination: Pagination;
}

export interface SlidingWindow {
  from: number;
  to: number;
}

export type CloudEnvironmentType = "AWS" | "GCP" | "Azure" | string;
export type CloudPlatformType = "EKS" | "ECS" | "AKS" | string;
export interface K8Description {
  capabilities: K8Capabilities;
  cloudEnv: CloudEnvironmentType;
  images: deployedImage[]; // all running containers
}

export interface deployedImage {
  image: string;
  tag: string;
  file: string;
}
export interface K8Capabilities {
  // kind: Secret
  // name: v1/email-service-secrets
  // file: .yaml
  [kind: string]: {
    name: string;
    file: string;
  }[];
}

export interface K8Yaml {
  apiVersion?: string;
  kind?: string;
  metadata?: { name?: string };
}

export const getArtifactIdFromArtifactObject = (artifact: artifactType): string => {
  switch (artifact.subType) {
    case "Docker Container":
      return `${artifact.hash}`;
    case "NPM":
    case "YARN":
      return `${artifact.name}@sha256:${artifact.hash}`;
    case "Serverless":
      return artifact.name;
  }

  return artifact.name;
};

export const shouldFilterForArtifactScreen = (artifact: artifactType): boolean => {
  switch (artifact.subType) {
    case "Docker Container":
      return false;
    case "NPM":
    case "YARN":
      return false;
    case "Serverless":
      return false;
  }

  return true;
};
