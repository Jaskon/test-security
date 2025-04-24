export interface ApplicationFlow {
  cicdInfo: AppFlowCICD[];
  cloudDeployments: AppFlowCloud[];
  artifacts: AppFlowArtifacts[];
  orchestrators: AppFlowOrchestrator[];
  repository: AppFlowRepo[];
  kubernetes: AppFlowKubernetes[];
}

export enum AppFlowType {
  Repo = "repository",
  CICD = "cicd",
  Registry = "file",
  Orchestrator = "orchestrator",
  Kubernetes = "Kubernetes",
  Cloud = "Cloud",
}

export class AppFlowItemBase {
  type: string;
  system: string;
  location: FoundLocation[] = [];

  constructor() {
    this.type = "";
    this.system = "";
  }
}

export class FoundLocation {
  runBy: string = "";
  foundBy: string = "";
  foundIn: string = "";
  link: string = "";
}

export enum FoundByItem {
  Registry = "Registry",
  File = "File",
  Pipeline = "Pipeline",
  Webhook = "Webhook",
  SecurityEvent = "Security Event",
  RunTime = "RunTime Environment",
}

//Repo
export class AppFlowRepo extends AppFlowItemBase {
  latestDate: string = "";
  constructor() {
    super();
    this.type = AppFlowType.Repo;
  }
}

//CICD
export class AppFlowCICD extends AppFlowItemBase {
  latestDate: string = "Not Executed";
  lastMonthJobCount: string = "0";
  constructor() {
    super();
    this.type = AppFlowType.CICD;
  }
}

//Artifacts
export class AppFlowArtifacts extends AppFlowItemBase {
  subType: string = "";
  hash: string = "";
  hashType: string = "";
  name: string = "";
  linkName: string = "";
  size: number = 0;
  date: string = "";

  constructor() {
    super();
    this.type = AppFlowType.Registry;
  }
}

export class AppFlowOrchestrator extends AppFlowItemBase {
  hash: string = "";
  hashType: string = "";
  name: string = "";
  size: number = 0;
  date: string = "";

  constructor() {
    super();
    this.type = AppFlowType.Orchestrator;
  }
}

export class AppFlowCloud extends AppFlowItemBase {
  subType: string = "";
  name: string = "";
  hash: string = "";
  hashType: string = "";
  link: string = "";

  constructor() {
    super();
    this.type = AppFlowType.Cloud;
  }
}

export class AppFlowKubernetes extends AppFlowItemBase {
  hash: string = "";
  hashType: string = "";
  name: string = "";
  subType: string = "";
  size: number = 0;
  date: string = "";

  constructor() {
    super();
    this.type = AppFlowType.Kubernetes;
  }
}

export enum HahsType {
  Unknown = "",
  sha256 = "SHA-256",
  SHA1 = "SHA-1",
  MD5 = "SHA-256",
}

export const appFlowCollection = "application";
