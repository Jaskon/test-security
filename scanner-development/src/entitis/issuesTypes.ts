import { OxExclusionCategory, OxRuleExclusion } from "@oxappsec/ox-consolidated-exclusions";
import { IOxTag } from "@oxappsec/ox-consolidated-tags";
import { Document, Types } from "mongoose";
import { SCAVulnerability } from "../helper/policy/scaVulHelper";
import { OscarInfo } from "../helper/policyExtraDataHelper";
import { VulnerabilityCount } from "../helper/sbom/sbomHelper";
import { GPTResponse } from "../helper/service/gpt-service/types";
import { ComplianceControl, CountRule, PolicyFix } from "../helper/service/policy-service/types";
import { PullRequest } from "../helper/service/pr-service/types";
import { SlackNotification } from "../helper/service/slack/slack.types";
import { Ticket } from "../helper/service/ticket-service/types";
import { AggItem } from "../mongo/schemas";
import { Tool } from "../policy/rules/code/policyRulesBase";
import { CweObject, Dependency, IssueOwner } from "./codeRepoTypes";
import { AggColumn } from "./reportTypes";
import { ChangeReason, FixIssue, LanguageInfo, SeverityChange } from "./service/blameTypes";
import { date, string } from "zod";
import { ScaFixType } from "./service/alertrRcommendationTypes";
import { CategoryDisplayName } from "@oxappsec/ox-consolidated-categories";
import { Owner } from "../policy/reporting/types";
import { PerformanceType } from "../helper/statesHelper";
export type SecretStatus = "active" | "inactive";

export class AdditionalTab {
  type: string;
  aggItems: AggItem[] = [];
}

interface SeverityChangeHistory {
  date: Date;
  severity: number;
}

export interface Issue {
  mongoId?: Types.ObjectId;
  currentIssueMongoId?: Types.ObjectId;
  severity: number;
  reducedSeverity: boolean;
  originalToolSeverity: string;
  severityChangeReason: string[];
  severityChangedReason: ChangeReason[];
  severityChange: SeverityChange;
  appBp: number;
  appOwners: Owner[];
  categoryId: number;
  issueId: string;
  needToBeRemoved: boolean;
  overrightBP: boolean;
  indirectSupported: boolean;
  appConScore: number;
  appName: string;
  mainTitle: string;
  appId: string;
  pId: string;
  pName: string;
  sId: string;
  scanId: string;
  repoId: string;
  sDate: Date;
  iid: string;
  originBranchName: string;
  cat: string;
  categoryDisplayName: CategoryDisplayName;
  iName: string;
  iOwner: string[];
  appType?: string;
  info: string;
  recommendation: string;
  learnMore: string[];
  connector: string;
  resource: string;
  resourceType: string;
  extraInfo: ExtraInfo[];
  aggSummary: string;
  aggColumns: AggColumn[];
  aggColumnsComment: string;
  aggItems?: AggItem[];
  recommendedExclusions: OxRuleExclusion[];
  detailedDescription: string;
  vioaltionInfoTitle: string;
  aggsType: string;
  secondTitle: string;
  exclusionCategory: OxExclusionCategory;
  ruleId: string;
  cwe: string[];
  version: string;
  snippet: string;
  issueOwners: IssueOwner[];
  excludedByApp: boolean;
  excludedByPolicy: boolean;
  excludedByAlert: boolean;
  fixLink: string;
  appCreatedAt: Date;
  deployedProd: boolean;
  publicVisibility: boolean;
  isFixAvailable: boolean;
  isChatGPTFixable: boolean;
  isFixApplied: boolean;
  lastCodeChange: Date;
  appCategory: string;
  cweList: CweObject[];
  fixIssue?: FixIssue;
  prDeatils?: PullRequest;
  fakeApp: boolean;
  dependencyChain: Dependency[];
  publicExploitLink: string;
  createdAt: Date;
  aggregatedItemsId?: string;
  updated?: Date;
  tickets: Ticket[];
  scaVulnerabilities: SCAVulnerability[];
  noneDirectSCAVulnerability: SCAVulnerability[];
  directSCAVulnerability: SCAVulnerability[];
  sources: string[];
  organization: string;
  repoName: string;
  comment?: string;
  pr?: PullRequest;
  countRule: CountRule;
  fixes: PolicyFix;
  groupId: string;
  exclusionId?: string;
  totalAggItems?: number;
  isNewIssue?: boolean;
  allUniqueLibs: string[];
  issueActions: IssueActionsType[];
  languageInfo?: LanguageInfo;
  isMonoRepoChild: boolean;
  monoRepoParent: string;
  slackNotification: SlackNotification[];
  scaTriggerPkg: string;
  libId: string;
  fixAppliedBy: string;
  oscarData: OscarInfo[];
  gptInfo?: GPTInfo;
  eventFromExternalTool: boolean;
  overrideSeverity?: boolean;
  originalSeverity?: number;
  tags: IOxTag[];
  scanIssueStatus: ScanIssueStatus;
  isFalsePositive: boolean;
  compliance: ComplianceControl[];
  tools: Tool[];
  excludedByTool: boolean;
  allAggItemsIds: string[];
  graphExists?: boolean;
  oxRecommendationExists?: boolean;
  triggerPkgForResolveIssues?: string;
  commitInfoExists?: boolean;
  uniqueArtifacts?: string[];
  blameExists?: boolean;
  secEventsSev?: VulnerabilityCount[];
  secretStatus?: SecretStatus;
  additionalTabs: AdditionalTab[];
  isPRAvailable: boolean;
  correlatedIssueId?: string;
  correlatedRegistry?: string;
  dataRangeInDays?: number;
  scaFixType?: ScaFixType;
  problematicPkg?: string;
  ignoreResolve?: boolean;
  aggFileNames?: string[];
  lastIssueSeenDate?: Date;
  aggregationsCount?: number;
  newDate?: Date;
  increasedAt?: Date;
  decreasedAt?: Date;
  prevSeverity?: number;
  isSilent: boolean;
  severityChangeHistory?: SeverityChangeHistory[];
  exposedByApiIds?: string[];
  exposedByApiItems?: { apiId: string; codeLocations: { link: string; callBranch: string[] }[] }[];
}

type ScanIssueStatus = "Unchanged" | "Updated" | "New";
export interface CICDIssue extends Issue {
  isBlocking: boolean; // deprecated, use `enforcement`
  enforcement: CICDIssueEnforcement;
  originalIssueId: string;
  cicdIssueStatus: CICDIssueStatus;
  sourceBranch: string;
  targetBranch?: string; // in case of PR: the branch to merge INTO

  // conforming to established scanner entity CICDJob
  jobId?: string;
  jobTriggeredAt?: string; // ISO string
  jobTriggeredAtDate?: Date; // date
  jobTriggeredBy?: string; // for azure: identity variable, can be a user name or a system identity, i.e. 'Microsoft.VisualStudio.Services.TFS'
  jobTriggeredReason?: string; // 'PullRequest', 'Manual', 'Schedule' ...
  jobUrl?: string;
  pullRequestId?: string;
  pullRequestUrl?: string;
}

export interface PipelineSummaryApp {
  appId: string;
  appName: string;
  appType: string;
}

export class PipelineSummary {
  apps: PipelineSummaryApp[] = [];
  sourceBranch: string;
  sourceBranchUrl?: string;
  targetBranch?: string; // in case of PR: the branch to merge INTO
  targetBranchUrl?: string;
  result: string = "Passed";
  totalBlockingIssues: number = 0;
  totalIssues: number = 0;
  newIssuesCountAppoxalypse: number = 0;
  newIssuesCountCritical: number = 0;
  newIssuesCountHigh: number = 0;
  newIssuesCountMedium: number = 0;
  newIssuesCountLow: number = 0;
  existingIssuesCountAppoxalypse: number = 0;
  existingIssuesCountCritical: number = 0;
  existingIssuesCountHigh: number = 0;
  existingIssuesCountMedium: number = 0;
  existingIssuesCountLow: number = 0;
  jobId?: string;
  jobTriggeredAt?: string; // ISO string
  jobTriggeredBy?: string; // for azure: identity variable, can be a user name or a system identity, i.e. 'Microsoft.VisualStudio.Services.TFS'
  jobTriggeredReason?: string; // 'PullRequest', 'Manual', 'Schedule' ...
  jobUrl?: string;
  pullRequestId?: string;
  pullRequestUrl?: string;
  eventType: PipelineSummeryEventType;
  scanId: string;
  performance: string = PerformanceType.regular;
}

export enum PipelineSummeryEventType {
  Push = "Push",
  Merge = "Merge",
  PullRequest = "Pull Request",
}

export enum CICDIssueStatus {
  New = "New",
  Old = "Old",
}

export enum CICDIssueEnforcement {
  Pending = "Pending",
  Block = "Block",
  Monitor = "Monitor",
}

export interface Snippet {
  fileName: string;
  snippetLineNumber: number;
  language: string;
  text: string;
}
export interface ExtraInfo {
  key: string;
  value?: string;
  snippet?: Snippet;
  link?: string;
  callBranch?: string[];
}

// export interface ExtraInfoContainer{
//   layerSha: string;
//   layerNum: number;
//   artifactName: string;
//   sha: string;
//   registryName: string;
// }

export interface IssuesObject {
  [appId: string]: Issue[];
}

export type IssueDocument = Issue & Document;
export type CICDIssueDocument = CICDIssue & Document;
export type PipelineSummeryDocument = PipelineSummary & Document;

export enum IssueActionsType {
  TicketCreated = "Ticket Created",
  PrAvailable = "PR Available",
  PrCreated = "PR Created",
  Comment = "Comment Created",
  FixAvailable = "Fix Available",
  SlackNotification = "Slack Sent",
  FixApplied = "Fix Applied",
  GPTAvailable = "ChatGPT Available",
  GPTCreated = "ChatGPT Description Created",
  ChangedSeverity = "Changed Severity",
  SeverityIncreased = "Severity Increased",
  SeverityDecreased = "Severity Decreased",
  ReportedAsFalsePositive = "False Positive",
  UNKNOWN = "UNKNOWN",
  UNAVAILABLE = "UNAVAILABLE",
  MAJOR = "MAJOR",
  MINOR = "MINOR",
  PATCH = "PATCH",
}

export interface GPTInfo {
  gptResponse: string;
  user: string;
  createdAt: Date;
}

export interface SeverityHistoryItem {
  issueId: string;
  firstSeenStat: SeverityHistoryInfo;
  history: SeverityHistoryInfo[];
  issueName: string;
  issuePolicyName: string;
}

export interface SeverityHistorySevChange {
  shortName: string;
  changeNumber: number;
  shouldBeSeverityFactor: boolean;
}

export interface SeverityHistoryInfo {
  severityDateChange: Date;
  scanId: string;
  severity: number;
  severityChangeReason?: SeverityChangeReason;
  severityChangeIds: SeverityHistorySevChange[];
  originalToolSeverity: string;
  originalSeverity: number;
}

export enum SeverityChangeReason {
  UNKNOWN = "UNKNOWN",
  ActionSeverityChange = "Action Severity Change",
  NewIssue = "New Issue",
}

export interface IssueAttackPath {
  repoId: string;
  issueId: string;
  newSeverity: { changedReason: ChangeReason; extraInfo?: ExtraInfo[] };
  exposedByApiIds?: string[];
  exposedByApiItems?: { apiId: string; codeLocations: { link: string; callBranch: string[] }[] }[];
}
