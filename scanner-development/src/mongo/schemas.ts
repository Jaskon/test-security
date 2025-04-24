import { OxRuleExclusion } from "@oxappsec/ox-consolidated-exclusions";
import { IOxTag } from "@oxappsec/ox-consolidated-tags";
import * as mongoose from "mongoose";
import { ApiSecurityItem, ApiSecurityItemDef, ApiSecurityItemFunction, ApiSecurityItemResponse, Parameter } from "../entitis/apiTypes";
import {
  AppFlowArtifacts,
  AppFlowCICD,
  AppFlowCloud,
  AppFlowKubernetes,
  AppFlowOrchestrator,
  AppFlowRepo,
  FoundLocation,
} from "../entitis/applicationsFlowTypes";
import {
  AppSbom,
  Sbom,
  SbomComponent,
  SbomComponentProperty,
  SbomDependency,
  SbomLicense,
  SbomMetadata,
  SbomTool,
  SbomVulnerability,
  SbomVulnerabilityAdvisory,
  SbomVulnerabilityAffect,
  SbomVulnerabilityAffectVersion,
  SbomVulnerabilityRating,
  SbomVulnerabilityRatingSource,
  SbomVulnerabilitySource,
} from "../entitis/artifactoryTypes";
import { AttackGraph, AttackGraphMongo, ParsedAttackGraph } from "../entitis/attackPathTypes";
import { ImageDetail } from "../entitis/cloudTypes";
import { CweObject, Dependency, IssueOwner, Relevance, Repo } from "../entitis/codeRepoTypes";
import {
  AdditionalTab,
  CICDIssue,
  CICDIssueEnforcement,
  CICDIssueStatus,
  ExtraInfo,
  GPTInfo,
  Issue,
  IssueAttackPath,
  PipelineSummary,
  PipelineSummaryApp,
  PipelineSummeryEventType,
  SeverityChangeReason,
  SeverityHistoryInfo,
  SeverityHistoryItem,
  SeverityHistorySevChange,
  Snippet,
} from "../entitis/issuesTypes";
import { AggColumn, SeverityStr } from "../entitis/reportTypes";
import { OrgSbom } from "../entitis/sbomTypes";
import { ScaFixType } from "../entitis/service/alertrRcommendationTypes";
import { ActiveFix, ChangeReason, FixFile, FixIssue, FixPR, LanguageInfo } from "../entitis/service/blameTypes";
import { Edge, IssueCount, Node, Position } from "../helper/graphHelper";
import { SCAVulnerability } from "../helper/policy/scaVulHelper";
import { OscarInfo } from "../helper/policyExtraDataHelper";
import { VulnerabilityCount } from "../helper/sbom/sbomHelper";
import { ComplianceControl, Input, InputOption, PolicyFix } from "../helper/service/policy-service/types";
import { PRDeatils, PullRequest } from "../helper/service/pr-service/types";
import { SlackNotification } from "../helper/service/slack/slack.types";
import { Ticket } from "../helper/service/ticket-service/types";
import {
  AppHistoryScore,
  Application,
  ApplicationFlow,
  ApplicationMetadata,
  ApplicationPriority,
  AppToolCoverage,
  AppToolCoverageSource,
  CategoryItem,
  DiscoverySystem,
  IScanSummaryHistory,
  Language,
  Owner,
  Pipeline,
  PoliciesViolationsBySeverity,
  Policy,
  PolicyAlertCount,
  PolicyBySeverity,
  PolicyMetaData,
  ScanInfo,
  ScanProgress,
  SecInfrastructure,
  SeveritiesObject,
  Severity,
  SeverityAlert,
  SeverityCount,
  SeverityViolation,
  System,
  Violations,
} from "../policy/reporting/types";
import { PolicyCloudSecurityScanAggItem } from "../policy/rules/code/policyCloudSecurityScanNew";
import { PolicyCloudSecuritySecretScanAggItem } from "../policy/rules/code/policyCloudSecuritySecretScanNew";
import { policyCommitReviewCountAggItem } from "../policy/rules/code/policyCommitReviewCount";
import { AdminsAggItem } from "../policy/rules/code/policyDspmMaxAdmins";
import { ExposedAggItem } from "../policy/rules/code/policyMemberCreatePublicRepos";
import { PolicyNoMatchHashBetweenCICDandRegistryAggItem } from "../policy/rules/code/policyNoMatchHashBetweenCICDandRegistry";
import { PolicyOrgDomainRepoAggItem } from "../policy/rules/code/policyOrgDomainRepo";
import { PolicyRarePusherVeteranReviewsAggItem } from "../policy/rules/code/policyRarePusherVeteranReviews";
import { RemoveWriteAccessRepoAggItem } from "../policy/rules/code/policyRemoveWriteAccessRepo";
import { PolicySbomCodeLicensesAggItem } from "../policy/rules/code/policySbomCodeLicenses";
import { NotUsedLibsAggItem } from "../policy/rules/code/policySbomCodeNoImportedLibs";
import { PolicySecurityScanAggItem } from "../policy/rules/code/policySecurityScan";
import { RepoOfOrgAggItem } from "../policy/rules/code/policyUntouchedReposShouldBeArchived";
import { PolicyWebhookConfigurationAggItem } from "../policy/rules/code/policyWebhookConfiguration";
import { WebhooksReputationAggItem } from "../policy/rules/code/webhooksReputation";

export const PolicyScheme = new mongoose.Schema<Policy>({
  alertCount: { type: Number },
  appCount: { type: Number },
  id: { type: String },
  policyName: { type: String },
  severity: { type: Number },
});

export const PolicyBySeveritySchema = new mongoose.Schema<PolicyBySeverity>({
  scanId: { type: String },
  noViolations: {
    type: new mongoose.Schema({
      policyCount: { type: Number },
      label: { type: String },
    }),
  },
  violations: {
    type: new mongoose.Schema<Violations>({
      policyCount: { type: Number },
      label: { type: String },
      children: [
        {
          type: new mongoose.Schema<SeverityViolation>({
            label: { type: String },
            policyCount: { type: Number },
            policyTotal: { type: Number },
            severity: { type: Number },
            policyList: [{ type: PolicyScheme }],
          }),
        },
      ],
    }),
  },
});

export const SecInfrastructureSchema = new mongoose.Schema<SecInfrastructure>({
  label: { type: String },
  byClient: { type: Number },
  order: { type: Number },
  nc: { type: Number },
  na: { type: Number },
  byOx: { type: Number },
  id: { type: Number },
  categoryName: { type: String },
});

export const TagSchema = new mongoose.Schema<IOxTag & { appliedBy: string }>({
  tagId: { type: String },
  tagType: { type: String },
  isOxTag: { type: Boolean },
  name: { type: String },
  displayName: { type: String },
  createdBy: { type: String },
  appliedBy: { type: String },
  isGithubTopicTag: { type: Boolean },
  tagCategory: { type: String },
  deploymentModel: { type: String },
  purpose: { type: String },
});

export const OwnerSchema = new mongoose.Schema<Owner>({
  name: { type: String },
  email: { type: String },
  id: { type: String },
  roles: [{ type: String }],
});

export const ToolsCoverageSourceSchema = new mongoose.Schema<AppToolCoverageSource>({
  match: { type: String },
  type: { type: String },
});

export const ToolsCoverageSchema = new mongoose.Schema<AppToolCoverage>({
  toolName: { type: String },
  oxDelivered: { type: Boolean },
  coverage: { type: Boolean },
  type: { type: String },
  sources: [{ type: ToolsCoverageSourceSchema }],
  reason: { type: String },
});

const IssuesBySeveritiesSchema = new mongoose.Schema<SeveritiesObject>({
  [SeverityStr.info]: { type: Number },
  [SeverityStr.low]: { type: Number },
  [SeverityStr.medium]: { type: Number },
  [SeverityStr.high]: { type: Number },
  [SeverityStr.critical]: { type: Number },
  [SeverityStr.appox]: { type: Number },
});

export const ApplicationSchema = new mongoose.Schema<Application>({
  businessPriority: { type: Number },
  originalBusinessPriority: { type: Number },
  codeChanges: { type: Number },
  commitCount: { type: Number },
  cloneDir: { type: String },
  codeZipDir: { type: String },
  daysSinceLastCodeChange: { type: Number },
  appName: { type: String },
  dockerfiles: [{ path: { type: String } }],
  repoId: { type: String },
  appId: { type: String },
  isMonoRepoChild: { type: Boolean, default: false },
  lastCodeChange: { type: Date },
  pullCount: { type: Number },
  pushCount: { type: Number },
  monoRepoParent: { type: String },
  risk: { type: Number },
  securityPosture: { type: Number },
  userCount: { type: Number },
  violationCount: { type: Number },
  scannedAt: { type: Date },
  new: { type: Boolean },
  updated: { type: Boolean },
  deployedProd: { type: Boolean },
  publicVisibility: { type: Boolean },
  relevant: { type: Boolean },
  irrelevantReasons: { type: [String] },
  fakeApp: { type: Boolean },
  appCategory: { type: String },
  parentType: { type: String },
  repoName: { type: String },
  scanId: { type: String },
  secInfra: [{ type: SecInfrastructureSchema }],
  appOwners: { type: [OwnerSchema] },
  isOverridingPriority: { type: Boolean, default: false },
  link: { type: String },
  totalIssues: { type: Number },
  organization: { type: String },
  isOrgRepo: { type: Boolean },
  repoRealName: { type: String },
  pkgManagers: [{ type: String }],
  pipeline: {
    type: new mongoose.Schema<Pipeline>({
      jobId: { type: String },
      jobUrl: { type: String },
      jobTriggeredAt: { type: Date },
      jobTriggeredBy: { type: String },
      issuesCount: { type: Number },
      scanResult: { type: String },
    }),
  },
  tags: [
    {
      type: TagSchema,
    },
  ],

  categories: [
    {
      type: new mongoose.Schema<CategoryItem>({
        categoryName: { type: String },
        order: { type: Number },
        id: { type: Number },
        severities: {
          type: IssuesBySeveritiesSchema,
        },
        catId: { type: Number },
        score: { type: Number },
        total: { type: Number },
        isNa: { type: Boolean, default: false },
        reason: [{ type: String }],
      }),
    },
  ],
  policiesViolationsBySeverity: [
    {
      type: new mongoose.Schema<PoliciesViolationsBySeverity>({
        severity: { type: Number },
        policies: [
          {
            type: new mongoose.Schema<PolicyMetaData>({
              policyName: { type: String },
              alertCount: { type: Number },
            }),
          },
        ],
      }),
    },
  ],
  createdAt: { type: Date },
  daysSinceRepoCreation: { type: Number },
  commitsCount: { type: Number },
  languages: [
    {
      type: new mongoose.Schema<Language>({
        language: { type: String },
        languagePercentage: { type: Number },
      }),
    },
  ],

  version: { type: String },
  watchersCount: { type: Number },
  creator: { type: String },
  hasDownloads: { type: Boolean },
  forksCount: { type: Number },
  type: { type: String },
  size: { type: Number },
  branchesCount: { type: Number },
  tagsCount: { type: Number },
  branch: { type: String },
  headSha: { type: String },
  yamlsCount: { type: Number },
  filesCount: { type: Number },
  overrideRelevance: { type: String, default: Relevance.DEFAULT },
  overridePriority: { type: Number, default: -1 },
  applicationFlows: {
    type: new mongoose.Schema<ApplicationFlow>({
      cicdInfo: [
        {
          type: new mongoose.Schema<AppFlowCICD>({
            type: { type: String },
            system: { type: String },
            latestDate: { type: String },
            lastMonthJobCount: { type: String },
            location: [
              {
                type: new mongoose.Schema<FoundLocation>({
                  runBy: { type: String },
                  foundBy: { type: String },
                  foundIn: { type: String },
                  link: { type: String },
                }),
              },
            ],
          }),
        },
      ],
      repository: [
        {
          type: new mongoose.Schema<AppFlowRepo>({
            type: { type: String },
            system: { type: String },
            location: [
              {
                type: new mongoose.Schema<FoundLocation>({
                  runBy: { type: String },
                  foundBy: { type: String },
                  foundIn: { type: String },
                  link: { type: String },
                }),
              },
            ],
          }),
        },
      ],
      cloudDeployments: [
        {
          type: new mongoose.Schema<AppFlowCloud>({
            type: { type: String },
            subType: { type: String },
            name: { type: String },
            hash: { type: String },
            hashType: { type: String },
            account: { type: String },
            link: { type: String },
            k8sType: { type: String },
            imageName: { type: String },
            date: { type: String },
            cluster: { type: String },
            region: { type: String },
            location: [
              {
                type: new mongoose.Schema<FoundLocation>({
                  runBy: { type: String },
                  foundBy: { type: String },
                  foundIn: { type: String },
                  link: { type: String },
                }),
              },
            ],
          }),
        },
      ],
      artifacts: [
        {
          type: new mongoose.Schema<AppFlowArtifacts>({
            type: { type: String },
            system: { type: String },
            subType: { type: String },
            hash: { type: String },
            size: { type: Number },
            linkName: { type: String },
            hashType: { type: String },
            name: { type: String },
            date: { type: String },
            location: [
              {
                type: new mongoose.Schema<FoundLocation>({
                  runBy: { type: String },
                  foundBy: { type: String },
                  foundIn: { type: String },
                  link: { type: String },
                }),
              },
            ],
          }),
        },
      ],
      orchestrators: [
        {
          type: new mongoose.Schema<AppFlowOrchestrator>({
            type: { type: String },
            system: { type: String },
            hash: { type: String },
            hashType: { type: String },
            name: { type: String },
            size: { type: Number },
            date: { type: String },
            location: [
              {
                type: new mongoose.Schema<FoundLocation>({
                  runBy: { type: String },
                  foundBy: { type: String },
                  foundIn: { type: String },
                  link: { type: String },
                }),
              },
            ],
          }),
        },
      ],
      kubernetes: [
        {
          type: new mongoose.Schema<AppFlowKubernetes>({
            type: { type: String },
            system: { type: String },
            hash: { type: String },
            hashType: { type: String },
            name: { type: String },
            subType: { type: String },
            size: { type: Number },
            date: { type: String },
            location: [
              {
                type: new mongoose.Schema<FoundLocation>({
                  runBy: { type: String },
                  foundBy: { type: String },
                  foundIn: { type: String },
                  link: { type: String },
                }),
              },
            ],
          }),
        },
      ],
    }),
  },

  toolsCoverage: [{ type: ToolsCoverageSchema }],
  monorepoChildrenCount: { type: Number },
  monorepoChildrenAppIds: [{ type: String }],

  severityChangedReason: [
    {
      type: new mongoose.Schema<ChangeReason>({
        tagId: { type: String },
        changeNumber: { type: Number },
        shouldBeSeverityFactor: { type: Boolean },
        requiredHits: { type: Number, default: 0 },
        reason: { type: String },
        shortName: { type: String },
        changeCategory: { type: String },
        changePlusReasonFacet: { type: String },
        extraInfo: [
          {
            required: false,
            type: new mongoose.Schema<ExtraInfo>({
              key: { type: String },
              value: { type: String, required: false },
              link: { type: String, required: false },
              snippet: {
                type: new mongoose.Schema<Snippet>({
                  fileName: { type: String },
                  snippetLineNumber: { type: Number },
                  language: { type: String },
                  text: { type: String },
                }),
                required: false,
              },
            }),
          },
        ],
      }),
    },
  ],
});
ApplicationSchema.index({ scanId: 1, relevant: 1, fakeApp: 1 });
ApplicationSchema.index({ appId: 1 });

export const ApplicationMetadataSchema = new mongoose.Schema<ApplicationMetadata>({
  name: { type: String },
  appId: { type: String },
  risk: { type: Number },
  violationsCount: { type: Number },
  severity: { type: Number },
  createdAt: { type: Date },
  deployedProd: { type: Boolean },
  publicVisibility: { type: Boolean },
  lastCodeChange: { type: Date },
  relevant: { type: Boolean },
  appOwners: { type: [OwnerSchema] },
  appCategory: { type: String },
  severities: [
    {
      type: new mongoose.Schema<Severity>({
        severity: { type: Number },
        severityAlertCount: { type: Number },
        policies: [
          {
            type: new mongoose.Schema<PolicyAlertCount>({
              id: { type: String },
              alertCount: { type: Number },
            }),
          },
        ],
      }),
    },
  ],
});

export const ApplicationConfigSchema = ApplicationSchema.clone();
ApplicationConfigSchema.clearIndexes();
ApplicationConfigSchema.index({ appId: 1 });

export const ApplicationPrioritySchema = new mongoose.Schema<ApplicationPriority>({
  label: { type: String },
  low: { type: Number },
  severity: { type: Number },
  high: { type: Number },
  appsRelevant: { type: Number },
  applications: [{ type: ApplicationMetadataSchema }],
});

export const ScanInfoSchema = new mongoose.Schema<ScanInfo>({
  appsNotRelevant: { type: Number },
  appsRelevant: { type: Number },
  appsTotal: { type: Number },
  scanProgressItems: [
    {
      type: new mongoose.Schema<ScanProgress>({
        phase: { type: String },
        count: { type: Number },
        total: { type: Number },
      }),
    },
  ],
  policiesLine1: { type: String },
  policiesLine2: { type: String },
  policyCount: { type: Number },
  scanDate: { type: Date },
  scanId: { type: String },
  systemsLine1: { type: String },
  systemsLine2: { type: String },
  error: { type: String },
  progressType: { type: String },
  score: { type: Number },
  isDone: { type: Boolean },
  successfulScan: { type: Boolean },
  scanType: { type: String },
  scanStartDate: { type: Date },
  policyPerCatStats: { type: String },
  scanFinishDate: { type: Date },
  scannedApps: { type: Number },
  cancelScan: { type: Boolean },
  scanInfoStats: { type: String },
  severitiesAlerts: [
    {
      type: new mongoose.Schema<SeverityAlert>({
        severity: { type: Number },
        alerts: { type: Number },
      }),
    },
  ],
  isScheduledScan: { type: Boolean },
});
ScanInfoSchema.index({ scanDate: -1 });
export const AppHistoricalScoreSchema = new mongoose.Schema<AppHistoryScore>({
  appId: { type: String },
  appName: { type: String },
  score: { type: Number },
  date: { type: Date, default: new Date(), expires: "60d" },
  new: { type: Boolean },
  updated: { type: Boolean },
  deployedProd: { type: Boolean },
  publicVisibility: { type: Boolean },
  relevant: { type: Boolean },
  scanId: { type: String },
  isScheduledScan: { type: Boolean },
  createdAt: { type: Date },
  lastCodeChange: { type: Date },
  daysSinceLastCodeChange: { type: Number },
  daysSinceRepoCreation: { type: Number },
  businessPriority: { type: Number },
  fakeApp: { type: Boolean },
  appCategory: { type: String },
  parentType: { type: String },
});

AppHistoricalScoreSchema.index({ appId: 1, date: 1 });
AppHistoricalScoreSchema.index({ scanId: 1, relevant: 1 });

export const DiscoverySystemSchema = new mongoose.Schema<DiscoverySystem>({
  type: { type: String },
  systems: [
    {
      type: new mongoose.Schema<System>({
        name: { type: String },
        count: { type: Number },
        applications: [{ type: String }],
      }),
    },
  ],
  scanId: { type: String },
});

export const AggItemSchema = new mongoose.Schema<AggItem & { excludedByAlert: boolean }>({
  exclusionId: { type: String },
  accessLevel: { type: String },
  accountName: { type: String },
  additionalToolData: { type: String },
  registryName: { type: String },
  imageLink: { type: String },
  allEvents: { type: String },
  numberOfReposDomainAppear: { type: Number },
  binariesCount: { type: Number },
  layer: { type: String },
  commitBy: { type: String },
  commitLink: { type: String },
  commiterEmail: { type: String },
  commiterName: { type: String },
  createdAt: { type: String },
  date: { type: String },
  diffFromNowToCreatedAtInDays: { type: Number },
  diffInDays: { type: Number },
  dockerVer: { type: String },
  eduVideoLink: { type: String },
  email: { type: String },
  endLine: { type: Number },
  realMatch: { type: String },
  linkToExternalProduct: { type: String },
  uid: { type: String },
  isSilent: { type: Boolean },
  events: { type: String },
  fileCount: { type: Number },
  filePath: { type: String },
  fileName: { type: String },
  lockfile: { type: String },
  fileUri: { type: String },
  fromCommitHistory: { type: Boolean },
  pushedAt: { type: String },
  image: { type: String },
  imageCreatedAt: { type: String },
  lastAccess: { type: String },
  link: { type: String },
  vtLink: { type: String },
  startLine: { type: Number },
  match: { type: String },
  mergedBy: { type: String },
  os: { type: String },
  accountId: { type: String },
  pkgCount: { type: Number },
  baseImage: { type: String },
  pullRequestsCount: { type: Number },
  pushType: { type: String },
  region: { type: String },
  cloudEnv: { type: String },
  reputation: { type: String },
  resource: { type: String },
  reviewers: { type: String },
  secret: { type: String },
  service: { type: String },
  sha: { type: String },
  size: { type: String },
  snippet: { type: String },
  tag: { type: String },
  title: { type: String },
  url: { type: String },
  user: { type: String },
  username: { type: String },
  excludedByAlert: { type: Boolean, default: false },
  source: { type: String },
  ruleId: { type: String },
  fixes: [{ type: mongoose.Schema.Types.Mixed }],
  aggId: { type: String },
  language: { type: String },
  libName: { type: String },
  libVersion: { type: String },
  snippetLineNumber: { type: Number },
  isFixAvailable: { type: Boolean },
  isChatGPTFixable: { type: Boolean },
  isFixApplied: { type: Boolean },
  dependencyType: { type: String },
  dependencyChain: [
    new mongoose.Schema<Dependency>({
      name: { type: String },
      version: { type: String },
      package_manager: { type: String },
      path: { type: String },
      licenses: [{ type: String }],
    }),
  ],
  installedVersion: { type: String },
  pkgName: { type: String },
  fixedVersion: { type: String },
  triggerPkgName: { type: String },
  triggerPkgVersion: { type: String },
  triggerPkgUpgradeVersion: { type: String },
  hashAggId: { type: String },
  branch: { type: String },
  userLink: { type: String },
  userAvatar: { type: String },
  adminLocation: { type: String },
  devOperation: { type: String },
  adminOperation: { type: String },
  adminOperationDate: { type: String },
  lastAdminOperation: { type: String },
  devOperationDate: { type: String },
  orgRole: { type: String },
  earliestActivityDate: { type: String },
  repoPermissions: { type: String },
  repo: { type: String },
  repoCreator: { type: String },
  lastCodeDate: { type: String },
  reviewOperation: { type: String },
  reviewOperationDate: { type: String },
  sourceRepoName: { type: String },
  sourceRepoLink: { type: String },
  sourceCreationDate: { type: String },
  sourceLastModifyDate: { type: String },
  destinationRepoName: { type: String },
  destinationRepoLink: { type: String },
  destinationCreationDate: { type: String },
  destinationLastModifyDate: { type: String },
  destinationRepoVisibility: { type: String },
  destinationOrgName: { type: String },
  reasons: { type: String },
  nameAndVer: { type: String },
  stars: { type: String },
  downloads: { type: String },
  forks: { type: String },
  vulBySeverity: { type: String },
  blameExists: { type: Boolean },
  graphExists: { type: Boolean },
});

export const DependencyGraphNodeSchema = new mongoose.Schema<Node>(
  {
    position: new mongoose.Schema<Position>(
      { x: { type: Number }, y: { type: Number } },
      {
        _id: false,
        excludeIndexes: true,
      },
    ),
    id: { type: String },
    fullName: { type: String }, // Temp until Eyal's fix
    name: { type: String },
    width: { type: Number },
    height: { type: Number },
    vulnerable: { type: Boolean },
    issues: new mongoose.Schema<IssueCount>(
      {
        appox: { type: Number },
        critical: { type: Number },
        high: { type: Number },
        medium: { type: Number },
        low: { type: Number },
        info: { type: Number },
      },
      { _id: false, excludeIndexes: true },
    ),
  },
  { _id: false, excludeIndexes: true },
);

export const DependencyGraphEdgeSchema = new mongoose.Schema<Edge>(
  {
    v: { type: String },
    w: { type: String },
  },
  { _id: false, excludeIndexes: true },
);

export const ScaVulnerabilitySchema = new mongoose.Schema<SCAVulnerability>({
  cwe: [
    {
      type: new mongoose.Schema<CweObject>({
        shortName: { type: String },
        name: { type: String },
        description: { type: String },
        url: { type: String },
      }),
    },
  ],
  libName: { type: String },
  libVersion: { type: String },
  chainDepth: { type: String },
  dependencyChain: { type: String },
  dependencyType: { type: String },
  cve: { type: String },
  cveLink: { type: String },
  cvsVer: { type: String },
  exploitInTheWild: { type: Boolean },
  exploitInTheWildLink: { type: String },
  linkToExternalProduct: { type: String },
  description: { type: String },
  dateDiscovered: { type: String },
  minorVerWithFix: { type: String },
  majorVerWithFix: { type: String },
  exploitRequirement: { type: String },
  exploitCode: { type: String },
  originalSeverity: { type: String },
});

const SeverityChangedExtraInfoSchema = new mongoose.Schema<ExtraInfo>({
  key: { type: String },
  value: { type: String, required: false },
  link: { type: String, required: false },
  callBranch: [{ type: String }],
  snippet: {
    type: new mongoose.Schema<Snippet>({
      fileName: { type: String },
      snippetLineNumber: { type: Number },
      language: { type: String },
      text: { type: String },
    }),
    required: false,
  },
});

const SeverityChangedReasonSchema = new mongoose.Schema<ChangeReason>({
  tagId: { type: String },
  changeNumber: { type: Number },
  shouldBeSeverityFactor: { type: Boolean },
  requiredHits: { type: Number, default: 0 },
  reason: { type: String },
  shortName: { type: String },
  changeCategory: { type: String },
  changePlusReasonFacet: { type: String },
  extraInfo: [
    {
      required: false,
      type: SeverityChangedExtraInfoSchema,
    },
  ],
});

const ExposedByApiItemSchema = new mongoose.Schema({
  apiId: { type: String },
  codeLocations: [
    {
      type: new mongoose.Schema({
        link: { type: String },
        callBranch: [{ type: String }],
      }),
    },
  ],
});

export const IssueSchema = new mongoose.Schema<Issue>({
  sId: { type: String },
  scanId: { type: String },
  sDate: { type: Date },
  pId: { type: String },
  repoId: { type: String },
  iid: { type: String },
  pName: { type: String },
  cat: { type: String },
  severity: { type: Number },
  iName: { type: String },
  iOwner: [{ type: String }],
  originBranchName: { type: String },
  appConScore: { type: Number },
  appName: { type: String },
  indirectSupported: { type: Boolean },
  isFixAvailable: { type: Boolean },
  isChatGPTFixable: { type: Boolean },
  isFixApplied: { type: Boolean },
  appId: { type: String },
  appBp: { type: Number },
  appType: { type: String },
  info: { type: String },
  learnMore: [{ type: String }],
  connector: { type: String },
  resource: { type: String },
  correlatedIssueId: { type: String },
  correlatedRegistry: { type: String },
  resourceType: { type: String },
  recommendation: { type: String },
  detailedDescription: { type: String },
  vioaltionInfoTitle: { type: String },
  dataRangeInDays: { type: Number },
  aggsType: { type: String },
  problematicPkg: { type: String },
  ignoreResolve: { type: Boolean },
  version: { type: String },
  additionalTabs: [
    {
      type: new mongoose.Schema<AdditionalTab>({
        type: { type: String },
        aggItems: [{ type: AggItemSchema }],
      }),
    },
  ],
  aggItems: [{ type: AggItemSchema }],
  isSilent: { type: Boolean },
  mainTitle: { type: String },
  secondTitle: { type: String },
  scanIssueStatus: { type: String },
  ruleId: { type: String },
  exclusionCategory: { type: String },
  cwe: [{ type: String }],
  snippet: { type: String },
  excludedByApp: { type: Boolean },
  excludedByPolicy: { type: Boolean },
  monoRepoParent: { type: String },
  isMonoRepoChild: { type: Boolean },
  excludedByAlert: { type: Boolean },
  fixLink: { type: String },
  appCreatedAt: { type: Date },
  deployedProd: { type: Boolean },
  publicVisibility: { type: Boolean },
  lastCodeChange: { type: Date },
  appCategory: { type: String },
  fakeApp: { type: Boolean },
  issueId: { type: String },
  organization: { type: String },
  repoName: { type: String },
  countRule: { type: String },
  tools: [{ type: String }],
  scaTriggerPkg: { type: String },
  libId: { type: String },
  exclusionId: { type: String },
  totalAggItems: { type: Number },
  isNewIssue: { type: Boolean },
  allUniqueLibs: [{ type: String }],
  fixAppliedBy: { type: String },
  isFalsePositive: { type: Boolean },
  isPRAvailable: { type: Boolean },
  excludedByTool: { type: Boolean },
  allAggItemsIds: [{ type: String }],
  blameExists: { type: Boolean },
  graphExists: { type: Boolean },
  oxRecommendationExists: { type: Boolean },
  triggerPkgForResolveIssues: { type: String },
  commitInfoExists: { type: Boolean },
  uniqueArtifacts: [{ type: String }],
  secretStatus: { type: String },
  scaFixType: { type: String, enum: [...Object.values(ScaFixType)] },
  prevSeverity: { type: Number },
  secEventsSev: [
    {
      type: new mongoose.Schema<VulnerabilityCount>({
        severity: { type: String },
        count: { type: Number },
      }),
    },
  ],
  fixes: new mongoose.Schema<PolicyFix>({
    settingType: { type: String },
    tooltip: { type: String },
    warning: { type: String },
    confirmation: { type: String },
    description: { type: String },
    inputs: [
      new mongoose.Schema<Input>({
        type: { type: String },
        name: { type: String },
        multiSelect: { type: Boolean },
        minSelect: { type: Number },
        displayName: { type: String },
        maxSelect: { type: Number },
        options: [
          new mongoose.Schema<InputOption>({
            name: { type: String },
            isDisabled: { type: Boolean },
            metadata: { type: String },
            displayName: { type: String },
            selected: { type: Boolean },
            info: { type: String },
          }),
        ],
      }),
    ],
  }),
  gptInfo: {
    type: new mongoose.Schema<GPTInfo>({
      gptResponse: { type: String },
      user: { type: String },
      createdAt: { type: Date },
    }),
  },
  dependencyChain: [
    new mongoose.Schema<Dependency>({
      name: { type: String },
      version: { type: String },
      package_manager: { type: String },
      path: { type: String },
      licenses: [{ type: String }],
    }),
  ],
  oscarData: [
    new mongoose.Schema<OscarInfo>({
      name: { type: String },
      description: { type: String },
      url: { type: String },
      id: { type: String },
    }),
  ],
  publicExploitLink: { type: String },
  createdAt: { type: Date },
  aggregatedItemsId: { type: String },
  updated: { type: Date },
  severityChangeReason: [{ type: String }],
  categoryId: { type: Number },
  categoryDisplayName: { type: String },
  sources: [{ type: String }],
  comment: { type: String },
  pr: {
    type: new mongoose.Schema<PullRequest>({
      issueId: { type: String },
      prId: { type: String },
      prURL: { type: String },
      createdBy: { type: String },
    }),
  },
  tags: [
    {
      type: TagSchema,
    },
  ],
  severityChangedReason: [
    {
      type: SeverityChangedReasonSchema,
    },
  ],
  scaVulnerabilities: [{ type: ScaVulnerabilitySchema }],
  noneDirectSCAVulnerability: [{ type: ScaVulnerabilitySchema }],
  directSCAVulnerability: [{ type: ScaVulnerabilitySchema }],
  compliance: [
    new mongoose.Schema<ComplianceControl>({
      control: { type: String },
      description: { type: String },
      category: { type: String },
      standard: { type: String },
      controlLink: { type: String },
    }),
  ],
  severityChange: { type: String },
  originalToolSeverity: { type: String },
  tickets: [
    new mongoose.Schema<Ticket>({
      id: { type: String },
      ticketId: { type: String },
      key: { type: String },
      link: { type: String },
      provider: { type: String },
      createdBy: { type: String },
    }),
  ],
  prDeatils: {
    type: new mongoose.Schema<PRDeatils>({
      sourceControlType: { type: String },
      issueId: { type: String },
      appId: { type: String },
      repo: { type: String },
      prId: { type: String },
      prURL: { type: String },
      prBranchName: { type: String },
      commitMessage: { type: String },
      commiter: { type: String },
      comment: { type: String },
      date: { type: Date },
      prTitle: { type: String },
      prBody: { type: String },
      prStatus: { type: String },
      prApprover: { type: String },
      prReviewer: { type: String },
      prMergeTime: { type: Date },
    }),
  },
  fixIssue: {
    type: new mongoose.Schema<FixIssue>({
      fixType: { type: String },
      // fixTitle: { type: String },
      // fixDescription: { type: String },
      // isFixApplied: { type: Boolean },
      // fixAppliedBy: { type: String },
      activeFix: {
        type: new mongoose.Schema<ActiveFix>({
          fixId: { type: String },
          fixURL: { type: String },
        }),
      },
      fixPR: {
        type: new mongoose.Schema<FixPR>({
          issueBranch: { type: String },
          commitMessage: { type: String },
          fixFiles: [
            {
              type: new mongoose.Schema<FixFile>({
                filePath: { type: String },
                newFileContent: { type: String },
              }),
            },
          ],
        }),
      },
    }),
  },
  cweList: [
    {
      type: new mongoose.Schema<CweObject>({
        name: { type: String },
        description: { type: String },
        url: { type: String },
      }),
    },
  ],
  issueOwners: [
    {
      type: new mongoose.Schema<IssueOwner>({
        name: { type: String },
        email: { type: String },
      }),
    },
  ],
  extraInfo: [
    {
      type: new mongoose.Schema<ExtraInfo>({
        key: { type: String },
        value: { type: String },
        link: { type: String, required: false },
      }),
    },
  ],
  aggSummary: { type: String },
  groupId: { type: String },
  aggColumns: [
    {
      type: new mongoose.Schema<AggColumn>({
        header: { type: String },
        key: { type: String },
        tooltip: { type: String },
        type: { type: String },
        href: { type: String },
      }),
    },
  ],
  aggColumnsComment: { type: String },
  recommendedExclusions: [
    {
      type: new mongoose.Schema<OxRuleExclusion>({
        label: { type: String },
        recommended: { type: Boolean },
        tooltip: { type: String },
        excludeBy: [{ type: String }],
        id: { type: String },
        uidOnly: { type: Boolean },
        isDefault: { type: Boolean },
        exclusionScope: { type: String },
        ffKey: { type: String },
      }),
    },
  ],
  issueActions: [{ type: String }],
  languageInfo: {
    type: new mongoose.Schema<LanguageInfo>({
      version: { type: String },
      name: { type: String },
    }),
  },
  slackNotification: [
    {
      type: new mongoose.Schema<SlackNotification>({
        timestamp: { type: String },
        channelName: { type: String },
        createdBy: { type: String },
        user: { type: String },
      }),
    },
  ],
  overrideSeverity: { type: Boolean, default: false },
  originalSeverity: { type: Number },
  aggFileNames: [{ type: String }],
  lastIssueSeenDate: { type: Date },
  appOwners: { type: [OwnerSchema] },
  newDate: { type: Date },
  aggregationsCount: { type: Number },
  increasedAt: { type: Date },
  decreasedAt: { type: Date },
  exposedByApiIds: [{ type: String }],
  exposedByApiItems: [ExposedByApiItemSchema],
  severityChangeHistory: [
    {
      type: new mongoose.Schema({
        severity: { type: Number },
        date: { type: Date },
        originalToolSeverity: { type: String },
        manualSeverityChangeReason: { type: String },
        severityChangeReasonsAdded: [
          {
            type: new mongoose.Schema({
              reason: { type: String },
              shortName: { type: String },
              changeNumber: { type: Number },
            }),
          },
        ],
        severityChangeReasonsRemoved: [
          {
            type: new mongoose.Schema({
              reason: { type: String },
              shortName: { type: String },
              changeNumber: { type: Number },
            }),
          },
        ],
      }),
    },
  ],
});
IssueSchema.index({
  categoryId: 1,
  repoId: 1,
  "scaVulnerabilities.pkgName": 1,
  "scaVulnerabilities.installedVersion": 1,
});
IssueSchema.index({ categoryId: 1, repoId: 1, "aggItems.libName": 1, "aggItems.libVersion": 1 });
IssueSchema.index({ categoryId: 1, repoId: 1, "aggItems.pkgNmae": 1 });
IssueSchema.index({ categoryId: 1, repoId: 1, "aggItems.libName": 1 });

export const UniqueIssueSchema = IssueSchema.clone();
UniqueIssueSchema.clearIndexes();
UniqueIssueSchema.index({ issueId: 1 }, { unique: true });
UniqueIssueSchema.index({ sDate: 1 }, { expires: "365d" });
UniqueIssueSchema.index({ appId: 1 });
UniqueIssueSchema.index({ scanId: 1 });

export const PrevIssueSchema = IssueSchema.clone();
PrevIssueSchema.clearIndexes();
PrevIssueSchema.index({ issueId: 1 });
PrevIssueSchema.index({
  scanId: 1,
  excludedByAlert: 1,
  excludedByApp: 1,
  excludedByPolicy: 1,
  excludedByTool: 1,
  appId: 1,
  categoryDisplayName: 1,
});

IssueSchema.index({
  scanId: 1,
  excludedByAlert: 1,
  excludedByApp: 1,
  excludedByPolicy: 1,
});
IssueSchema.index({ issueId: 1 });
IssueSchema.index({ sDate: 1 }, { expires: "60d" });
IssueSchema.index({ scanId: 1, appId: 1, categoryDisplayName: 1 });
IssueSchema.index({ appId: 1 });

export const SilentSigIssueSchema = IssueSchema.clone();
SilentSigIssueSchema.clearIndexes();
SilentSigIssueSchema.index({ issueId: 1 });
SilentSigIssueSchema.index({ scanId: 1 });

export const CICDIssueSchema = new mongoose.Schema<CICDIssue>({
  ...IssueSchema.obj,
  originalIssueId: { type: String },
  sourceBranch: { type: String },
  targetBranch: { type: String },
  cicdIssueStatus: { type: String, enum: [...Object.values(CICDIssueStatus)] },
  isBlocking: { type: Boolean }, // deprecated, use `enforcement`
  enforcement: { type: String, enum: [...Object.values(CICDIssueEnforcement)] }, //Block
  jobId: { type: String },
  jobTriggeredAt: { type: String },
  jobTriggeredAtDate: { type: Date },
  jobTriggeredBy: { type: String },
  jobTriggeredReason: { type: String }, //Action
  jobUrl: { type: String },
  pullRequestId: { type: String }, //PR ID
  pullRequestUrl: { type: String }, // PRURL
});

export const SeverityCountSchema = new mongoose.Schema<SeverityCount>({
  count: { type: Number },
  severity: { type: Number },
});
export const ScanSummaryHistorySchema = new mongoose.Schema<IScanSummaryHistory>(
  {
    scanId: { type: String },
    scanDate: { type: Date, expires: "60d" },
    totalSeverities: [SeverityCountSchema],
    appSeverities: [
      new mongoose.Schema({
        appId: { type: String },
        totalIssues: { type: Number },
        severities: [SeverityCountSchema],
      }),
    ],
  },
  { timestamps: true },
);
ScanSummaryHistorySchema.index({ scanDate: -1 });
export const PipelineSchema = new mongoose.Schema<PipelineSummary>(
  {
    apps: [
      {
        type: new mongoose.Schema<PipelineSummaryApp>({
          appId: { type: String },
          appName: { type: String },
          appType: { type: String },
        }),
      },
    ],
    sourceBranch: { type: String },
    sourceBranchUrl: { type: String },
    targetBranch: { type: String },
    targetBranchUrl: { type: String },
    performance: { type: String },
    result: { type: String },
    totalBlockingIssues: { type: Number },
    totalIssues: { type: Number },
    newIssuesCountAppoxalypse: { type: Number },
    newIssuesCountCritical: { type: Number },
    newIssuesCountHigh: { type: Number },
    newIssuesCountMedium: { type: Number },
    newIssuesCountLow: { type: Number },
    existingIssuesCountAppoxalypse: { type: Number },
    existingIssuesCountCritical: { type: Number },
    existingIssuesCountHigh: { type: Number },
    existingIssuesCountMedium: { type: Number },
    existingIssuesCountLow: { type: Number },
    jobId: { type: String },
    jobTriggeredAt: { type: String },
    jobTriggeredBy: { type: String },
    jobTriggeredReason: { type: String },
    jobUrl: { type: String },
    pullRequestId: { type: String },
    pullRequestUrl: { type: String },
    eventType: {
      type: String,
      enum: [...Object.values(PipelineSummeryEventType)],
    },
    scanId: { type: String },
  },
  { timestamps: true },
);

// TODO: define indices
CICDIssueSchema.index({ scanId: 1 });
CICDIssueSchema.index({ jobTriggeredAtDate: 1 });

const SbomComponentSchema = new mongoose.Schema<SbomComponent>({
  "bom-ref": { type: String },
  type: { type: String },
  name: { type: String },
  purl: { type: String },
  version: { type: String },
  properties: [
    {
      type: new mongoose.Schema<SbomComponentProperty>({
        name: { type: String },
        value: { type: String },
      }),
    },
  ],
  licenses: [
    {
      type: new mongoose.Schema<SbomLicense>({
        expression: { type: String },
      }),
    },
  ],
});

const SbomSchema = new mongoose.Schema<Sbom>({
  bomFormat: { type: String },
  specVersion: { type: String },
  serialNumber: { type: String },
  version: { type: Number },
  metadata: {
    type: new mongoose.Schema<SbomMetadata>({
      timestamp: { type: String },
      tools: [
        {
          type: new mongoose.Schema<SbomTool>({
            vendor: { type: String },
            name: { type: String },
            version: { type: String },
          }),
        },
      ],
      component: { type: SbomComponentSchema },
    }),
  },
  components: [{ type: SbomComponentSchema }],
  dependencies: [
    {
      type: new mongoose.Schema<SbomDependency>({
        ref: { type: String },
        dependsOn: [{ type: String }],
      }),
    },
  ],
  vulnerabilities: [
    {
      type: new mongoose.Schema<SbomVulnerability>({
        id: { type: String },
        source: {
          type: new mongoose.Schema<SbomVulnerabilitySource>({
            name: { type: String },
            url: { type: String },
          }),
        },
        ratings: [
          {
            type: new mongoose.Schema<SbomVulnerabilityRating>({
              source: {
                type: new mongoose.Schema<SbomVulnerabilityRatingSource>({
                  name: { type: String },
                }),
              },
              severity: { type: String }, // enum
              score: { type: Number },
              method: { type: String },
              vector: { type: String },
            }),
          },
        ],
        cwes: [{ type: Number }],
        description: { type: String },
        advisories: [
          {
            type: new mongoose.Schema<SbomVulnerabilityAdvisory>({
              url: { type: String },
            }),
          },
        ],
        published: { type: String },
        updated: { type: String },
        affects: [
          {
            type: new mongoose.Schema<SbomVulnerabilityAffect>({
              ref: { type: String },
              versions: [
                {
                  type: new mongoose.Schema<SbomVulnerabilityAffectVersion>({
                    version: { type: String },
                    status: { type: String },
                  }),
                },
              ],
            }),
          },
        ],
      }),
    },
  ],
});

export const ImageDetailSchema = new mongoose.Schema<ImageDetail>({
  registryId: { type: String },
  repositoryName: { type: String },
  imageDigest: { type: String },
  imageTags: [{ type: String }],
  name: { type: String },
  imageSizeInBytes: { type: Number },
  region: { type: String },
  imagePushedAt: { type: String },
  imagePushedAtInDays: { type: Number },
  imagePullAtInDays: { type: Number },
  imageManifestMediaType: { type: String },
  artifactMediaType: { type: String },
  lastRecordedPullTime: { type: String },
  cloudEnv: { type: String },
  link: { type: String },
});

export const RepoSchema = new mongoose.Schema<Repo>({
  id: { type: String },
  name: { type: String },
  fullName: { type: String },
  description: { type: String },
  homepage: { type: String },
  createdAt: { type: String },
});

export const GraphSchema = new mongoose.Schema<ParsedAttackGraph>({
  nodes: [{ type: mongoose.Schema.Types.Mixed }],
  edges: [
    {
      type: new mongoose.Schema({
        v: { type: String },
        w: { type: String },
      }),
    },
  ],
});

export const AttackGraphSchema = new mongoose.Schema<AttackGraphMongo>({
  scanId: { type: String },
  type: { type: String },
  graph: { type: GraphSchema },
  issues: [{ type: String }],
  createdAt: { type: Date },
  appId: { type: String },
});
AttackGraphSchema.index({ issues: 1 });
AttackGraphSchema.index({ scanId: 1, appId: 1 });

export const AppSbomSchema = new mongoose.Schema<AppSbom>({
  appId: { type: String },
  scanId: { type: String },
  scanDate: { type: Date },
  imageDetail: { type: ImageDetailSchema }, // either imageDetail
  repo: { type: RepoSchema }, // or repo
  type: { type: String }, // image or repo, see AppSbomType. if image, has `imageDetail`, if repo has `repo`
  sbom: { type: SbomSchema },
});
AppSbomSchema.index({ scanId: 1, appId: 1, type: 1 });

export const OrgSbomSchema = new mongoose.Schema<OrgSbom>({
  scanId: { type: String },
  scanDate: { type: Date },
  sbom: { type: String },
  sbomCsv: { type: String },
});
OrgSbomSchema.index({ scanId: 1 });

export const IssueAttackPathSchema = new mongoose.Schema<IssueAttackPath>({
  repoId: { type: String },
  issueId: { type: String },
  newSeverity: { changedReason: SeverityChangedReasonSchema, extraInfo: [SeverityChangedExtraInfoSchema] },
  exposedByApiIds: [{ type: String }],
  exposedByApiItems: [ExposedByApiItemSchema],
});

export const ApiSecurityItemSchema = new mongoose.Schema<ApiSecurityItem>({
  uuid: { type: String },
  scanId: { type: String },
  title: { type: String },
  description: { type: String },
  version: { type: String },
  openapi: { type: String },
  servers: [{ type: String }],
  epName: { type: String },
  methodName: { type: String },
  methodDescription: { type: String },
  methodOperationId: { type: String },
  methodResponses: [
    {
      type: new mongoose.Schema<ApiSecurityItemResponse>({
        description: { type: String },
        code: { type: String },
      }),
    },
  ],
  methodSummary: { type: String },
  methodTags: [{ type: String }],
  fileName: [{ type: String }],
  methodParameters: [
    {
      type: new mongoose.Schema<Parameter>({
        description: { type: String },
        in: { type: String },
        name: { type: String },
        required: { type: Boolean },
      }),
    },
  ],
  appId: { type: String, index: true },
  appType: { type: String },
  appName: { type: String },
  appLink: { type: String },
  firstSeen: { type: Date },
  framework: { type: String },
  definitions: [
    {
      type: new mongoose.Schema<ApiSecurityItemDef>({
        source: { type: String },
        fileName: { type: String },
        line: { type: String },
        snippet: { type: String },
        link: { type: String },
        llmTitle: { type: String },
        llmDescription: { type: String },
        functions: [
          {
            type: new mongoose.Schema<ApiSecurityItemFunction>({
              function: { type: String },
              line: { type: Number },
              snippet: { type: String },
              filepath: { type: String },
              link: { type: String },
            }),
          },
        ],
      }),
    },
  ],
  issuesBySeverity: { type: IssuesBySeveritiesSchema, _id: false },
});

export const ApiSecurityItemHistorySchema = new mongoose.Schema<ApiSecurityItem>({
  scanId: { type: String },
  title: { type: String },
  epName: { type: String },
  methodName: { type: String },
  appId: { type: String, index: true },
  appType: { type: String },
  appName: { type: String },
  firstSeen: { type: Date },
  framework: { type: String },
  definitions: [
    {
      type: new mongoose.Schema<ApiSecurityItemDef>({
        source: { type: String },
        fileName: { type: String },
        line: { type: String },
      }),
    },
  ],
});

export const SeverityHistorySevChangeItem = new mongoose.Schema<SeverityHistorySevChange>({
  shortName: { type: String },
  changeNumber: { type: Number },
  shouldBeSeverityFactor: { type: Boolean },
});

export const SeverityHistoryInfoSchema = new mongoose.Schema<SeverityHistoryInfo>({
  severityDateChange: { type: Date },
  scanId: { type: String },
  severity: { type: Number },
  severityChangeReason: {
    type: String,
    enum: [...Object.values(SeverityChangeReason)],
    default: SeverityChangeReason.UNKNOWN,
  },
  severityChangeIds: [{ type: SeverityHistorySevChangeItem }],
  originalToolSeverity: { type: String },
  originalSeverity: { type: Number },
});

export const SeverityHistorySchema = new mongoose.Schema<SeverityHistoryItem>({
  issueId: { type: String },
  issueName: { type: String },
  issuePolicyName: { type: String },
  firstSeenStat: {
    type: SeverityHistoryInfoSchema,
  },
  //stores the severity history across scans
  history: [{ type: SeverityHistoryInfoSchema }],
});

SeverityHistorySchema.index({ issueId: 1 }, { unique: true });
SeverityHistorySchema.index({ "history.scanId": 1 });

export type AggItem =
  | PolicyCloudSecurityScanAggItem
  | PolicyCloudSecuritySecretScanAggItem
  | policyCommitReviewCountAggItem
  | PolicyNoMatchHashBetweenCICDandRegistryAggItem
  | PolicyOrgDomainRepoAggItem
  | PolicyRarePusherVeteranReviewsAggItem
  | RemoveWriteAccessRepoAggItem
  | PolicyWebhookConfigurationAggItem
  | WebhooksReputationAggItem
  | PolicySbomCodeLicensesAggItem
  | AdminsAggItem
  | PolicySecurityScanAggItem
  | RepoOfOrgAggItem
  | NotUsedLibsAggItem
  | ExposedAggItem;
