import { CloudEnvironmentType, CloudPlatformType } from "./ArtifactTypes";

export interface CloudGraphRes {
  dot: string;
  aws_account: string;
}

export class CloudImageId {
  name: string;
  hash: string;
  tag: string;
}

export class CloudGraphInput {
  monitorAll: boolean = false;
  monitorNewDate: number = null;
  monitorResources: string[] = [];
  eksConnection: string = "";
}

export interface CloudGraphNode extends Record<string, string> {
  cluster: string;
  region: string;
  image_id: string;
  type: string;
  severity_factors: string;
  cloud_type: CloudEnvironmentType;
  platform: CloudPlatformType;
}

export enum k8SupportedTypes {
  //pod = "k8s_pod",
  service = "k8s_service",
  job = "k8s_job",
  deployment = "k8s_deployment",
  cronJob = "k8s_cronjob",
}
