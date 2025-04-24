// Json Export type

export interface CXScaJSONReport {
  FullReportUrl: null;
  RiskReportSummary: RiskReportSummary;
  Packages: Package[];
  Vulnerabilities: Vulnerability[];
  Licenses: License[];
  Policies: Policy[];
}

export interface License {
  ReferenceType: ReferenceType;
  Reference: string;
  RoyaltyFree: string;
  CopyrightRiskScore: number;
  RiskLevel: string;
  Linking: string;
  CopyLeft: string;
  PatentRiskScore: number;
  Name: string;
  Url: string;
  PackageUsageCount: number;
  IsViolatingPolicy: boolean;
}

export enum ReferenceType {
  LicenseFileInJar = "LicenseFileInJar",
  Other = "Other",
  PomFile = "PomFile",
}

export interface Package {
  Id: string;
  Name: string;
  Version: string;
  Licenses: string[];
  MatchType: string; // Filename
  HighVulnerabilityCount: number;
  MediumVulnerabilityCount: number;
  LowVulnerabilityCount: number;
  NumberOfVersionsSinceLastUpdate: number;
  NewestVersionReleaseDate: null | string;
  NewestVersion: null | string;
  Outdated: boolean;
  ReleaseDate: string;
  RiskScore: number;
  Severity: SeverityEnum;
  Locations: string[];
  PackageRepository: string; // Maven
  IsMalicious: boolean;
  IsDirectDependency: boolean;
  IsDevelopmentDependency: boolean;
  IsTestDependency: boolean;
  IsNpmVerified: boolean;
  IsViolatingPolicy: boolean;
  UsageType: UsageType;
  VulnerabilityCount: number;
}

export enum SeverityEnum {
  High = "HIGH",
  Medium = "MEDIUM",
  Low = "LOW",
  None = "NONE",
}

export enum UsageType {
  UnScanned = "UnScanned",
}

export interface Policy {
  Rules: Rule[];
  Description: string;
  PolicyName: string;
  BreakBuild: boolean;
  IsViolating: boolean;
  IsGlobal: boolean;
  IsPredefined: boolean;
}

export interface Rule {
  Name: string;
  IsViolated: boolean;
  violatingConditionGroups: ViolatingConditionGroup[];
}

export interface ViolatingConditionGroup {
  conditions: Condition[];
  violatingPackages: ViolatingPackage[];
}

export interface Condition {
  Id: string;
  GroupId: string;
  Parameter: string;
  Category: string;
  Operator: string;
  ParameterValue: ParameterValue;
}

export interface ParameterValue {
  ValueKind: number;
}

export interface ViolatingPackage {
  Id: string;
  ViolatingEntities: ViolatingEntity[];
}

export interface ViolatingEntity {
  id: string;
  conditionCategory: string;
  reportId: string;
  conditionId: string;
}

export interface RiskReportSummary {
  RiskReportId: string;
  ProjectId: string;
  ProjectName: string;
  ProjectCreatedOn: string;
  HighVulnerabilityCount: number;
  MediumVulnerabilityCount: number;
  LowVulnerabilityCount: number;
  TotalPackages: number;
  DirectPackages: number;
  CreatedOn: string;
  RiskScore: number;
  TotalOutdatedPackages: number;
  VulnerablePackages: number;
  TotalPackagesWithLegalRisk: number;
  HighVulnerablePackages: number;
  MediumVulnerablePackages: number;
  LowVulnerablePackages: number;
  LicensesLegalRisk: LicensesLegalRisk;
  ScanOrigin: string;
  ExploitablePathEnabled: boolean;
  ExploitablePathsFound: number;
  HasRemediationRecommendation: boolean;
  BuildBreakerPolicies: number;
  ProjectPolicies: string[];
  ViolatingPoliciesCount: number;
}

export interface LicensesLegalRisk {
  High: number;
  Medium: number;
  Low: number;
  Unknown: number;
}

export interface Vulnerability {
  Id: string;
  CveName: string;
  Score: number;
  Severity: Severity;
  PublishDate: string;
  References: string[];
  Description: string;
  Cvss: Cvss;
  Recommendations: null;
  PackageId: string;
  FixResolutionText: string;
  IsIgnored: boolean;
  ExploitableMethods: any[];
  Cwe: string;
  IsViolatingPolicy: boolean;
  IsNewInRiskReport: boolean;
  Type: Type;
}

export interface Cvss {
  Score: number;
  Severity: Severity;
  AttackVector: AttackVector;
  AttackComplexity: AttackComplexityEnum;
  Confidentiality: AttackComplexityEnum;
  Availability: SeverityEnum;
  ExploitCodeMaturity: null | string;
  RemediationLevel: null | string;
  ReportConfidence: null | string;
  ConfidentialityRequirement: null | string;
  IntegrityRequirement: null | string;
  AvailabilityRequirement: null | string;
  Version: number;
}

export enum AttackComplexityEnum {
  High = "HIGH",
  Low = "LOW",
  None = "NONE",
}

export enum AttackVector {
  Local = "LOCAL",
  Network = "NETWORK",
}

export enum Severity {
  High = "High",
  Medium = "Medium",
}

export enum Type {
  Regular = "Regular",
}
