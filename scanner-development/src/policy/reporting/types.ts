import { OxExclusionCategory } from "@oxappsec/ox-consolidated-exclusions";
import { IOxTag } from "@oxappsec/ox-consolidated-tags";
import {
  AppFlowArtifacts,
  AppFlowCICD,
  AppFlowCloud,
  AppFlowKubernetes,
  AppFlowOrchestrator,
  AppFlowRepo,
} from "../../entitis/applicationsFlowTypes";
import { Relevance } from "../../entitis/codeRepoTypes";
import { Dictionary } from "../../entitis/commonTypes";
import { Severity as Sev, SeverityStr } from "../../entitis/reportTypes";
import { ChangeReason } from "../../entitis/service/blameTypes";
import { ScanType } from "../../entitis/service/connector-message-types";
import { PipelineScanResult } from "../../helper/service/report-service/types";
import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();
// import { Tag } from "../../helper/service/tags-service/tags-service.types";
export interface Flow {
  artifacts: any;
  cicd: string;
  cloudDeployment: CloudDeployment[];
  orchestrator: any[];
  repo: string;
}

export interface ScanId {
  scanId: string;
}
export interface SeverityViolation {
  label: string;
  policyCount: number;
  policyTotal: number;
  severity: number;
  policyList: Policy[];
}

export interface Policy {
  alertCount: number;
  appCount: number;
  id: string;
  policyName: string;
  severity: number;
}

export interface Violations {
  policyCount: number;
  label: string;
  children: SeverityViolation[];
}

export interface PolicyBySeverity extends ScanId {
  noViolations: {
    policyCount: number;
    label: string;
  };
  violations: Violations;
}

export interface CategoryItem {
  categoryName: string;
  catId: number;
  id: number;
  order: number;
  severities: SeveritiesObject;
  score: number;
  total: number;
  isNa: boolean;
  reason: string[];
}

export interface SecInfrastructure {
  label: string;
  order: number;
  byClient: number;
  nc: number;
  na: number;
  byOx: number;
  id: number;
  categoryName: string;
}

export interface CloudDeployment {
  type: string;
  subType: string;
  name: string;
  link: string;
}

export interface Artifact {
  hash: string;
  hashType: string;
  name: string;
  size: string;
  subType: string;
  type: string;
}
export interface ApplicationFlow {
  cicdInfo: AppFlowCICD[];
  cloudDeployments: AppFlowCloud[];
  artifacts: AppFlowArtifacts[];
  orchestrators: AppFlowOrchestrator[];
  repository: AppFlowRepo[];
  kubernetes: AppFlowKubernetes[];
}

export interface Pipeline {
  jobId: string;
  jobTriggeredAt: Date;
  scanResult: PipelineScanResult;
  issuesCount: number;
  jobTriggeredBy?: string;
  jobUrl?: string;
}
export interface Application extends ScanId {
  businessPriority: number;
  originalBusinessPriority?: number;
  categories: CategoryItem[];
  codeChanges: number;
  commitCount: number;
  daysSinceLastCodeChange?: number;
  appName: string;
  repoName: string;
  dockerfiles: Array<{ path: string }>;
  appId: string;
  lastCodeChange: Date;
  pullCount: number;
  pushCount: number;
  risk: number;
  securityPosture: number;
  userCount: number;
  violationCount: number;
  scannedAt: Date;
  new: boolean;
  updated: boolean;
  deployedProd: boolean;
  publicVisibility: boolean;
  relevant: boolean;
  irrelevantReasons: string[];
  secInfra: SecInfrastructure[];
  policiesViolationsBySeverity: PoliciesViolationsBySeverity[];
  createdAt: Date;
  daysSinceRepoCreation?: number;
  commitsCount?: { type: number };
  languages: Language[];
  version: string;
  watchersCount: number;
  creator: string;
  hasDownloads: boolean;
  forksCount: number;
  type: string;
  size: number;
  branchesCount: number;
  tagsCount: number;
  branch: string;
  headSha: string;
  yamlsCount: number;
  filesCount: number;
  overrideRelevance: Relevance;
  overridePriority: number;
  appOwners: Owner[];
  fakeApp: boolean;
  appCategory: string;
  parentType: string;
  isOverridingPriority: boolean;
  cicd?: string[];
  cloudDeployments?: CloudDeployment[];
  artifacts?: Artifact[];
  applicationFlows: ApplicationFlow;
  link: string;
  isMonoRepoChild: boolean;
  totalIssues: number;
  toolsCoverage: AppToolCoverage[];
  repoId: string;
  isOrgRepo: boolean;
  organization: string;
  repoRealName: string;
  pipeline?: Pipeline;
  pkgManagers: string[];
  monoRepoParent: string;
  monorepoChildrenCount?: number;
  monorepoChildrenAppIds?: string[];
  tags: (IOxTag & { appliedBy: string })[];
  severityChangedReason: ChangeReason[];
  cloneDir: string;
  codeZipDir: string;
}

export class AppToolCoverage {
  toolName: string;
  oxDelivered: boolean;
  coverage: boolean;
  type: string;
  sources: AppToolCoverageSource[] = [];
  reason?: string;
  validateInfo() {
    return this.type && this.toolName ? true : false;
  }
}

export interface CoverageResponse {
  isCovered: boolean;
  reason: string;
}

export enum CoverageReasons {
  ConnectorsNotConfigured = " apps are connected",
  NoPolicies = "All policies are disabled",
  CloudConnectorNotConfigured = "Cloud connector is not configured",
  CICDAndRegistryNotConnected = "CICD and Registry not connected",
  OXCSPMNotEnabled = "OX CSPM not connected",
  ExpiredToken = "Expired or Invalid Token",
  DiscoveredNotConnected = "Tools not counfigured",
  LanguagesNotSupportedByTool = "Dominant language not supported by tool",
  NoLanguages = "No Languages in repo",
  NoReason = "",
}

export enum AppToolCoverageSourceType {
  Webhook = "Webhook",
  CICD = "Build Log",
  MissingCoverageButHaveCICD = "Missing Security Template",
  Alert = "Security Alert",
  MentionInFile = "Deployment File",
  OX = "OX Enabled",
}

export class AppToolCoverageSource {
  match: string;
  type: AppToolCoverageSourceType;
}

export interface SeveritiesObject {
  [SeverityStr.info]: number;
  [SeverityStr.low]: number;
  [SeverityStr.medium]: number;
  [SeverityStr.high]: number;
  [SeverityStr.critical]: number;
  [SeverityStr.appox]: number;
}

export const severityConst: Dictionary<SeverityStr> = {
  [Sev.INFO]: SeverityStr.info,
  [Sev.LOW]: SeverityStr.low,
  [Sev.MEDIUM]: SeverityStr.medium,
  [Sev.HIGH]: SeverityStr.high,
  [Sev.CRITICAL]: SeverityStr.critical,
  [Sev.APPOXALYPSE]: SeverityStr.appox,
};

export type CategoriesSeverities = { [x in string]: SeveritiesObject };

export interface PolicyAlertCount {
  id: string;
  alertCount: number;
}
export interface Severity {
  severity: number;
  severityAlertCount: number;
  policies: PolicyAlertCount[];
}

export interface ApplicationMetadata {
  name: string;
  appId: string;
  risk: number;
  violationsCount: number;
  severity: number;
  severities: Severity[];
  publicVisibility: boolean;
  createdAt: Date;
  deployedProd: boolean;
  lastCodeChange: Date;
  relevant: boolean;
  appOwners: Owner[];
  appCategory: string;
}

export interface ApplicationPriority {
  label: string;
  low: number;
  severity: number;
  high: number;
  appsRelevant: number;
  applications: ApplicationMetadata[];
}

export interface SeverityAlert {
  severity: number;
  alerts: number;
}
export interface ScanInfo extends ScanId {
  //Ui progresss
  appsNotRelevant: number;
  appsRelevant: number;
  appsTotal: number;
  scanProgressItems: ScanProgress[];
  policiesLine1: string;
  policiesLine2: string;
  policyCount: number;
  scanDate: Date;
  successfulScan: boolean;
  systemsLine1: string;
  systemsLine2: string;
  error: string;
  score: number;
  severitiesAlerts: SeverityAlert[];
  isScheduledScan: boolean;
  scannedApps: number;
  isDone: boolean;
  cancelScan: boolean;
  scanType: ScanType;
  scanStartDate: Date;
  scanFinishDate: Date;
  scanInfoStats: string;
  policyPerCatStats: string;
  progressType: string;
}

export class ScanProgress {
  phase: string;
  count: number;
  total: number;
  order: number = 1;
}

export interface AppHistoryScore extends ScanId {
  score: number;
  date: Date;
  appId: string;
  appName: string;
  new: boolean;
  updated: boolean;
  deployedProd: boolean;
  publicVisibility: boolean;
  relevant: boolean;
  isScheduledScan: boolean;
  createdAt: Date;
  lastCodeChange: Date;
  daysSinceLastCodeChange: number;
  daysSinceRepoCreation: number;
  businessPriority: number;
  fakeApp: boolean;
  appCategory: string;
  parentType: string;
}

export interface System {
  name: string;
  count: number;
  applications: string[];
}

export interface DiscoverySystem extends ScanId {
  type: string;
  systems: System[];
}

export interface PolicyMetaData {
  policyName: string;
  alertCount: number;
}

export interface PoliciesViolationsBySeverity {
  severity: number;
  policies: PolicyMetaData[];
}

export interface Language {
  language: string;
  languagePercentage: number;
}

export type FakeApplication = Omit<Application, "overrideRelevance" | "createdAt" | "lastCodeChange" | "scannedAt">;

export interface IssueAppData {
  policyId: string;
  pName: string;
  categoryId: number;
  severity: number;
  appName: string;
  appId: string;
  appType: string;
  connector: string;
  exclusionCategory: OxExclusionCategory;
  appBp: number;
  originBranchName: string;
  repoId: string;
  repoRealName: string;
  organization: string;
  sourceBranch?: string;
  targetBranch?: string;
}

export enum AppOwnerRole {
  Dev = "Dev",
  Business = "Business",
  Security = "Security",
  Watcher = "Watcher",
}

export interface Owner {
  name: string;
  email: string;
  roles: AppOwnerRole[];
  id: string;
}

export enum CategoryReason {
  NoPolicies = "There are no policies enabled in this category",
  NoSystems = "There are no systems connected to run polices in this category",
  NoSecTools = "There are no security tools enabled in this category",
  NoArtifactory = "There are no artifactories connected to run policies in this category",
  NoCloud = "There are no cloud providers connected to run policies in this category",
}

export interface IScanSummaryHistory {
  scanId: string;
  scanDate: Date;
  totalSeverities: SeverityCount[];
  appSeverities: {
    appId: string;
    totalIssues: number;
    severities: SeverityCount[];
  }[];
}

export class ScanSummaryHistory {
  private appSeverities: Map<string, { appId: string; totalIssues: number; severities: Map<number, SeverityCount> }> = new Map();
  private totalSeverities: Map<number, SeverityCount> = new Map();
  constructor(private readonly scanId: string, private readonly scanDate: Date) {}

  addToTotalSeverities(severity: number) {
    try {
      const severityObj = this.totalSeverities.get(severity);
      if (!severityObj) {
        this.totalSeverities.set(severity, { severity, count: 1 });
      } else {
        severityObj.count++;
      }
    } catch (e) {
      logger.error(`failed addToTotalSeverities. error: ${e}`);
    }
  }

  addToAppSeverities(appId: string, severity: number) {
    try {
      const appSeverityObj = this.appSeverities.get(appId);
      if (!appSeverityObj) {
        const severities = new Map<number, SeverityCount>();
        severities.set(severity, { severity, count: 1 });
        this.appSeverities.set(appId, { appId, totalIssues: 1, severities });
      } else {
        appSeverityObj.totalIssues++;
        const severityObj = appSeverityObj.severities.get(severity);
        if (!severityObj) {
          appSeverityObj.severities.set(severity, { severity, count: 1 });
        } else {
          severityObj.count++;
        }
      }
    } catch (e) {
      logger.error(`failed addToAppSeverities. error: ${e}`);
    }
  }

  get() {
    try {
      const res: IScanSummaryHistory = {
        scanId: this.scanId,
        scanDate: this.scanDate,
        totalSeverities: Array.from(this.totalSeverities.values()),
        appSeverities: Array.from(this.appSeverities.values()).map(i => {
          return { appId: i.appId, totalIssues: i.totalIssues, severities: Array.from(i.severities.values()) };
        }),
      };
      return res;
    } catch (e) {
      logger.error(`failed get scan summery, error: ${e}`);
    }
    return null;
  }

  reduceFromTotalIssues(severity: number) {
    try {
      this.totalSeverities.get(severity).count--;
    } catch (e) {
      logger.error("failed reduceFromTotalIssues", e);
    }
  }

  reduceFromAppSeverities(appId: string, severity: number) {
    try {
      this.appSeverities.get(appId).totalIssues--;
      this.appSeverities.get(appId).severities.get(severity).count--;
    } catch (e) {
      logger.error("failed reduceFromAppSeverities", e);
    }
  }
}

export interface SeverityCount {
  severity: number;
  count: number;
}
