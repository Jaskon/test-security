import { SCAVulnerability } from "../helper/policy/scaVulHelper";
import { PolicyFix } from "../helper/service/policy-service/types";
import { Artifactory } from "./ArtifactTypes";
import { CICD } from "./cicidRepoTypes";
import { Cloud } from "./cloudTypes";
import { Repo, Repository } from "./codeRepoTypes";
import { AdditionalTab } from "./issuesTypes";
import { Kubernetes } from "./kubernetesTypes";
import { Orchestrator } from "./orchestratorTypes";

export enum SecInfra {
  SAST = "SAST",
  SCA = "SCA",
  IAC = "IaC",
  SECRET_SEARCH = "Secret Search",
  CSPM = "CSPM",
  CONTAINER_SECURITY = "Container Security",
  API_SECURITY = "API Security",
  VULNERABILITY_SCAN = "Vulnerability Scan",
}

export enum SystemEnum {
  CICD = "cicd",
  SECURITY = "security",
  CLOUD = "cloud",
  REGISTRY = "registry",
  REPOSITORY = "repository",
}

export enum Severity {
  INFO = 0,
  LOW = 1,
  MEDIUM = 2,
  HIGH = 3,
  CRITICAL = 4,
  APPOXALYPSE = 5,
}

export enum SeverityStr {
  info = "info",
  low = "low",
  medium = "medium",
  high = "high",
  critical = "critical",
  appox = "appox",
}

export enum IrrelevantReason {
  archived = "Archived Repo",
  failedClone = "No Access for Cloning",
  noFiles = "No Relevant Files",
  lastCodeChange = "No Code Changes",
  SetByClient = "Repository has been set by client to be irrelevant",
}

export interface AggColumn {
  header: string;
  key: string;
  tooltip: string;
  type: string;
  href: string;
}

export enum MongoUpdateRes {
  SUCCESSED = "Successed",
  FAILED = "Failed",
  SKIPPED = "Skipped",
}

export interface PolicyResListItem {
  mainTitle: string;
  secondTitle: string;
  info: string;
  recommendation: string;
  resource: string;
  isRepo: boolean;
  severity: any;
  resource_type: string;
  fixLink: string;
  policy_id: any;
  name: string;
  description: string;
  violation: boolean;
  additionalInfo: any;
  show_remediation: boolean;
  aggregatedInfo: any;
  detailedDescription: string;
  moreInfoLink: string;
  exclusionCategory: any;
  issueOwners: any;
  ruleId: any;
  extraInfo: any;
  cwe: any;
  snippet: any;
  cweList: any;
  issueId: string;
  dependencyChain: any;
  publicExploitLink: string;
  originalToolSeverity: any;
  severityChangeReason: any;
  severityChange: any;
  severityChangedReason: any;
  scaVulnerabilitysTable: any;
  sources: any;
  newIssuesPipelineOptionId: any;
  oldIssuesPipelineOptionId: any;
  pipelineScanJobInfo: any;
  countRule: any;
  fixes: PolicyFix;
  overrightBP: any;
  directSCAVulnerability: SCAVulnerability[];
  noneDirectSCAVulnerability: SCAVulnerability[];
  allUniqueLibs: Array<string>;
  languageInfo: any;
  indirectSupported: boolean;
  scaTriggerPkg: string;
  libId: string;
  isFixApplied: any;
  fixAppliedBy: any;
  oscarData: any;
  eventFromExternalTool: boolean;
  compliance: any;
  tools: any;
  graphExists: boolean;
  blameExists: boolean;
  secEventsSev: any;
  additionalTabs: AdditionalTab[];
  correlatedIssueId: string;
  correlatedRegistry: string;
  uniqueArtifacts: any[];
  problematicPkg: string;
  dataRangeInDays: any;
  scaFixType: any;
  oxRecommendationExists: boolean;
  commitInfoExists: boolean;
  ignoreResolve: any;
  triggerPkgForResolveIssues: string;
  uid: any;
  isSilent: boolean;
  version: any;
}

export interface PolicyRes {
  policy_id: string;
  name: string;
  categoryId: number;
  violation: boolean;
  total: number;
  list: PolicyResListItem[];
  description: string;
  severity: number;
  exclusionCategory: any;
}

export interface EvalRepoPolicyRes {
  extra?: Extra;
  policyRes: PolicyRes;
  collectorData: Repo;
  cicd: CICD;
  artifacts: Artifactory;
  orchestrator: Orchestrator;
  kubernetes: Kubernetes;
  repository: Repository;
  cloud: Cloud;
  attachedToApp: any;
  skipUpdateDb: boolean;
}

interface Extra {
  hasArtifact: boolean;
  hasOrchestrator: boolean;
  hasCloudResource: boolean;
}
