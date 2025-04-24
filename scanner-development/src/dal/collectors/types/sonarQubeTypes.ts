export interface RulesDescriptionSections {
  key: string;
  content: string;
}

export interface Rules {
  key: string;
  repo?: string;
  name: string;

  createdAt: string;

  htmlDesc: string;
  mdDesc: string;

  severity: string;
  status: string;

  isTemplate: boolean;

  tags: string[];
  sysTags: string[];

  lang: string;
  langName: string;

  params?: string[];

  defaultDebtRemFnType?: string;
  debtRemFnType?: string;

  type: string;

  defaultRemFnType?: string;
  defaultRemFnBaseEffort?: string;
  remFnType?: string;
  remFnBaseEffort?: string;
  remFnOverloaded?: string;

  scope?: string;

  isExternal: string;

  descriptionSections: RulesDescriptionSections[];
  educationPrinciples?: string[];
}

export interface SonarQubeIssueImpact {
  softwareQuality: string;
  severity: SonarQubeIssueSeverity;
}

export interface SonarQubeIssueMessageFormatting {
  start: number;
  end: number;
  type: string;
}

export interface SonarQubeIssueComment {
  key: string;
  login: string;
  htmlText: string;
  markdown: string;
  updatable: boolean;
  createdAt: string;
}

export interface SonarQubeIssueMessageFormatting {
  start: number;
  end: number;
  type: string;
}

export interface SonarQubeIssueLocation {
  textRange: {
    startLine: number;
    endLine: number;
    startOffset: number;
    endOffset: number;
  };
  msg: string;
  msgFormattings: SonarQubeIssueMessageFormatting[];
}

export interface SonarQubeIssueFlow {
  locations: SonarQubeIssueLocation[];
}

export interface SonarQubeIssue {
  key: string;
  component: string;
  project: string;
  rule: string;
  status: SonarQubeIssueStatus;
  resolution: SonarQubeIssueResolution;
  severity: SonarQubeIssueSeverity;
  cleanCodeAttribute?: string;
  cleanCodeAttributeCategory?: string;
  impacts?: SonarQubeIssueImpact[];
  message: string;
  messageFormattings: SonarQubeIssueMessageFormatting[];
  line: number;
  hash: string;
  author: string;
  effort: string;
  creationDate: string;
  updateDate: string;
  tags: string[];
  type: string;
  comments: SonarQubeIssueComment[];
  attr?: any;
  transitions?: string[];
  actions: string[];
  textRange: {
    startLine: number;
    endLine: number;
    startOffset: number;
    endOffset: number;
  };
  flows: SonarQubeIssueFlow[];
  quickFixAvailable: boolean;
  ruleDescriptionContextKey: string;
  codeVariants: string[];
}

// SonarQubeHotspot export interface
export interface SonarQubeHotspot {
  key: string;
  component: string;
  project: string;
  securityCategory: string;
  vulnerabilityProbability: string;
  status: SonarQubeHotspotStatus;
  resolution?: SonarQubeHotspotResolution | string;
  line: number;
  message: string;
  messageFormattings: any[];
  assignee: string;
  author: string;
  creationDate: string;
  updateDate: string;
  textRange: {
    startLine: number;
    endLine: number;
    startOffset: number;
    endOffset: number;
  };
  flows: any[];
  ruleKey: string;
}

export interface SonarQubeComponent {
  key: string;
  qualifier: SonarQubeComponentFilterQualifiers;
  name: string;
  project: string;
  branches?: SonarQubeProjectBranch[];
}

export interface SonarQubeProjectBranchStatus {
  qualityGateStatus: string;
}

export interface SonarQubeProjectBranch {
  name: string;
  isMain: boolean;
  type: string;
  status: SonarQubeProjectBranchStatus;
  analysisDate: string;
  excludedFromPurge: string;

  issues?: SonarQubeIssue[];
  hostspots?: SonarQubeHotspot[];
}

export interface SonarCloudProject {
  organization: string;
  key: string;
  qualifier: SonarCloudComponentQualifier;
  name: string;
  project: string;

  branches: SonarCloudProjectBranch[];
}

export interface SonarCloudIssue extends SonarQubeIssue {}

export interface SonarCloudHotspot extends SonarQubeHotspot {}

export interface SonarCloudProjectBranchStatus {
  qualityGateStatus?: string;
  bugs: number;
  vulnerabilities: number;
  codeSmells: number;
}

export interface SonarCloudProjectBranch {
  name: string;
  isMain: boolean;
  type: string;
  mergeBranch: string;
  status: SonarCloudProjectBranchStatus;
  analysisDate: string;
  commit: {
    sha: string;
    author?: {
      name: string;
    };
    date?: string;
    message?: string;
  };

  issues?: SonarCloudIssue[];
  hostspots?: SonarCloudHotspot[];
}

export enum SonarQubeIssueStatus {
  Open = "OPEN",
  Confirmed = "CONFIRMED",
  Resolved = "RESOLVED",
  Reopened = "REOPENED",
  Closed = "CLOSED",
}

export enum SonarQubeIssueResolution {
  Fixed = "FIXED",
  Removed = "REMOVED",
  FalsePositive = "FALSE-POSITIVE",
  WontFix = "WONTFIX",
}

export enum SonarQubeIssueSeverity {
  Blocker = "BLOCKER",
  Critical = "CRITICAL",
  Major = "MAJOR",
  Minor = "MINOR",
  Info = "INFO",
  High = "HIGH",
  Medium = "MEDIUM",
  Low = "LOW",
}

export enum SonarQubeHotspotStatus {
  ToReview = "TO_REVIEW",
  Reviewed = "REVIEWED",
}

export enum SonarQubeHotspotResolution {
  Acknowledged = "ACKNOWLEDGED",
  Fixed = "FIXED",
  Safe = "SAFE",
}

export enum SonarQubeComponentFilterQualifiers {
  APP = "APP", // Applications
  VW = "VW", // Portfolios
  SVW = "SVW", // Portfolios
  TRK = "TRK", // Projects
}

export enum SonarCloudComponentQualifier {
  BRC = "BRC", // Sub-projects
  DIR = "DIR", // Directories
  FIL = "FIL", // Files
  TRK = "TRK", // Projects
  UTS = "UTS", // Test Files
}
