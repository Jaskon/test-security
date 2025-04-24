import { IOxTag } from "@oxappsec/ox-consolidated-tags";
import scanDiskDB from "@oxappsec/ox-disk-db";
import { Queue } from "bull";
import { sortBy } from "lodash";
import { stringSimilarity } from "string-similarity-js";
import { AsyncTracker } from "../async-tracker.service";
import { AppSbomType, ArtifactoryTypes, ContainerSecurityType, ImageInfo, SbomEvent, SbomVulnerability } from "../entitis/artifactoryTypes";
import { Artifactory, guessArtifactSystem } from "../entitis/ArtifactTypes";
import { CICD } from "../entitis/cicidRepoTypes";
import { Cloud, CloudResource, CloudSecurityEvent, ImageDetail } from "../entitis/cloudTypes";
import {
  addSeverityChangedReason,
  CodeRepoTypes,
  Dependency,
  getUniqueInfoForAggregation,
  Repo,
  Repository,
  repoType,
  SecurityAlertType,
  SecurityEvent,
  setSecEventFromDelta,
  VCSType,
} from "../entitis/codeRepoTypes";
import { ResourceType } from "../entitis/collectorEntitisTypes";
import { Dictionary } from "../entitis/commonTypes";
import { Constant } from "../entitis/constant";
import { ExtraInfo } from "../entitis/issuesTypes";
import { Kubernetes } from "../entitis/kubernetesTypes";
import { Orchestrator } from "../entitis/orchestratorTypes";
import { EvalRepoPolicyRes, Severity } from "../entitis/reportTypes";
import { ChangeReason, getDependencyType, SeverityFactorType, severityReasons } from "../entitis/service/blameTypes";
import { CacheResolver } from "../helper/cache/cache.resolver";
import { Cache } from "../helper/cache/cache.types";
import { adaptLibName, checkObjectSize } from "../helper/commonUtils";
import { PerformanceTelemetry } from "../helper/decorators/PerformanceTelemetry";
import { DiskDB } from "../helper/diskDbHelper";
import { isDevelopment, isLocalDevelopment } from "../helper/envUtils";
import MemoryMonitorHelper from "../helper/IO/memoryMonitorHelper";
import JsonHelper from "../helper/jsonHelper";
import { TimeOp } from "../helper/performance";
import { getScaVul, getUniqueKeyBaseOnSCAlib, SCAVulnerability } from "../helper/policy/scaVulHelper";
import { getSeverityFromStr, getUniqueSeverityReasonsBetweenTwoCollections } from "../helper/policy/severityHelper";
import Iqueue from "../helper/queue/Iqueue";
import { GoogleOpenSourceInsightsHelper } from "../helper/sbom/googleOpenSourceInsightsHelper";
import { ExtendedSbomComponent, extractPkgManagerFromPurl, getPkgName, SbomPackageInfo } from "../helper/sbom/sbomHelper";
import AlertRecommendationHelper from "../helper/service/alertRecommendationHelper";
import AutoFixHelper from "../helper/service/autoFixHelper";
import BlameHelper from "../helper/service/blameHelper";
import IacVerificationHelper from "../helper/service/iacValidatorHelper";
import LightBlameHelper from "../helper/service/lightBlameHelper";
import { Policy, Resource } from "../helper/service/policy-service/types";
import ResolveIssueValidationHelper from "../helper/service/resolveIssueValidationHelper";
import ScaVerificationHelper from "../helper/service/scaValidatorHelper";
import SecretValidationHelper from "../helper/service/secretValidationHelper";
import StatesHelper from "../helper/statesHelper";
import StringHelper from "../helper/stringHelper";
import SecurityToolsHelper from "../helper/tools/securityToolsHelper";
import loggerImport from "../logger";
import {
  Artifact,
  ArtifactRegistryDescription,
  ArtifactScreenHistoryStats,
  CICDArtifactDescription,
  CloudArtifactData,
  CodeArtifactDescription,
  FilterScreenData,
  IssueSummary,
} from "../mongo/artifact-screen/types/artifact-screen";
import { CveToolsService } from "../mongo/cve-tools.service";
import { DependencyGraph } from "../mongo/DependencyGraph.schema";
import { ArtifactInSbomLib, SbomMongoDocument } from "../mongo/sbom/types";
import JsonApplicationDiscoveryOverview from "../policy/reporting/jsonApplicationDiscoveryOverview";
import ResultsHandler from "../policy/reporting/ResultsHandler";
import { AppToolCoverage } from "../policy/reporting/types";
import PolicyRulesBase from "../policy/rules/code/policyRulesBase";
import RuleExclusions from "../policy/rules/ruleExclusions";
import policySecuritySecretsContainerScan = require("../policy/rules/code/policySecuritySecretsContainerScan");
import policyCloudSecuritySecretScanNew = require("../policy/rules/code/policyCloudSecuritySecretScanNew");
import policyCloudSecurityScanNew = require("../policy/rules/code/policyCloudSecurityScanNew");
import policyCommitReviewCount = require("../policy/rules/code/policyCommitReviewCount");
import policyDisableSAST = require("../policy/rules/code/policyDisableSAST");
import policyDisableSCA = require("../policy/rules/code/policyDisableSCA");
import policyNoCicd = require("../policy/rules/code/policyNoCicd");
import policyNoSAST = require("../policy/rules/code/policyNoSAST");
import policyNoSCA = require("../policy/rules/code/policyNoSCA");
import policyNoMatchHashBetweenCICDandRuntimeCloud = require("../policy/rules/code/policyNoMatchHashBetweenCICDandRuntimeCloud");
import policyNoMatchHashBetweenCICDandRegistry = require("../policy/rules/code/policyNoMatchHashBetweenCICDandRegistry");
import policyRunTimeNotHaveLatestImageVersion = require("../policy/rules/code/policyRunTimeNotHaveLatestImageVersion");
import policyOrgDomainRepo = require("../policy/rules/code/policyOrgDomainRepo");
import policyPublicRepo = require("../policy/rules/code/policyPublicRepo");
import policyRarePusherVeteranReviews = require("../policy/rules/code/policyRarePusherVeteranReviews");
import policyRemoveWriteAccessRepo = require("../policy/rules/code/policyRemoveWriteAccessRepo");
import policySbomCodeLicenses = require("../policy/rules/code/policySbomCodeLicenses");
import policySbomCodeLibNotPopular = require("../policy/rules/code/policySbomCodeLibNotPopular");
import policySbomCodeLibDeprecated = require("../policy/rules/code/policySbomCodeLibDeprecated");
import policySbomCodeLibOutdated = require("../policy/rules/code/policySbomCodeLibOutdated");
import policyUnprotectedDevLan = require("../policy/rules/code/policyUnprotectedDevLan");
import policyWebhookCICD = require("../policy/rules/code/policyWebhookCICD");
import policyDspmMaxAdmins = require("../policy/rules/code/policyDspmMaxAdmins");
import policyDspmRepoMaxAdmins = require("../policy/rules/code/policyDspmRepoMaxAdmins");
import policyDspmMoreThanOneAdmin = require("../policy/rules/code/policyDspmMoreThanOneAdmin");
import policyAllowForkingPrivateRepos = require("../policy/rules/code/policyAllowForkingPrivateRepos");
import policyBotNoOrgAdmin = require("../policy/rules/code/policyBotNoOrgAdmin");
import policyBotNoRepoAdmin = require("../policy/rules/code/policyBotNoRepoAdmin");
import policyNoCICDBotReview = require("../policy/rules/code/policyNoCICDBotReview");
import PolicyLicenseFile = require("../policy/rules/code/policyLicenseFile");
import policyOutsideCollaboratorsnNoAdmin = require("../policy/rules/code/policyOutsideCollaboratorsnNoAdmin");
import policy2FAEnabled = require("../policy/rules/code/policy2FAEnabled");
import policyOutsideCollaborators2FAEnabled = require("../policy/rules/code/policyOutsideCollaborators2FAEnabled");
import policyWebhookConfiguration = require("../policy/rules/code/policyWebhookConfiguration");
import policyMainBranchDoesntRequireCodeReview = require("../policy/rules/code/policyMainBranchDoesntRequireCodeReview");
import policyLimitBranchDeletionsToAdmins = require("../policy/rules/code/policyLimitBranchDeletionsToAdmins");
import policyUntouchedReposShouldBeArchived = require("../policy/rules/code/policyUntouchedReposShouldBeArchived");
import policyOrgOwnersWithNoActivity = require("../policy/rules/code/policyOrgOwnersWithNoActivity");
import policyRepoAdminsWithNoActivity = require("../policy/rules/code/policyRepoAdminsWithNoActivity");
import policyRequireSignedCommits = require("../policy/rules/code/policyRequireSignedCommits");
import policyRuntimeApplicationVulnerability = require("../policy/rules/code/policyRuntimeApplicationVulnerability");
import policyProtectedBranchShouldNotBeBypassed = require("../policy/rules/code/policyProtectedBranchShouldNotBeBypassed");
import policyProtectedBranchShouldNotBeBypassedOutsideCollaborators = require("../policy/rules/code/policyProtectedBranchShouldNotBeBypasseOutsideCollaborators");
import policyRareCodeChange = require("../policy/rules/code/policyRareCodeChange");
import policyProtectedBranchPushEventsNotBypassed = require("../policy/rules/code/policyProtectedBranchPushEventsNotBypassed");
import policyProtectedBranchPushEventsNotBypassedOutsideCollaborators = require("../policy/rules/code/policyProtectedBranchPushEventsNotByPassedOutsideCollaborators");
import webhooksReputation = require("../policy/rules/code/webhooksReputation");
import policyMemberCreatePublicRepos = require("../policy/rules/code/policyMemberCreatePublicRepos");
import policyOpenWiki = require("../policy/rules/code/policyOpenWiki");
import policyExternalToolsUnapprovedLicense = require("../policy/rules/code/policyExternalToolsUnapprovedLicense");
import policySecurityScanSCA = require("../policy/rules/code/policySecurityScanSCA");
import policySecurityScanNew = require("../policy/rules/code/policySecurityScanNew");
import policyAnomalousWebhooks = require("../policy/rules/code/policyAnomalousWebhooks");
import policyOutsideCollaboratorsWithNoActivityRepo = require("../policy/rules/code/policyOutsideCollaboratorsWithNoActivityRepo");
import policyCICDContextValues = require("../policy/rules/code/policyCICDContextValues");
import policyCICDEchoSecrets = require("../policy/rules/code/policyCICDEchoSecrets");
import policyCICDSecretsRepoVars = require("../policy/rules/code/policyCICDSecretsRepoVars");
import policyWorkflowMinPerm = require("../policy/rules/code/policyWorkflowMinPerm");
import policyPinActionSha = require("../policy/rules/code/policyPinActionSha");
import policySbomCodeNoImportedLibs = require("../policy/rules/code/policySbomCodeNoImportedLibs");
import policySbomTyposquatting = require("../policy/rules/code/policySbomTyposquatting");
import policyDeprecatedCommand = require("../policy/rules/code/policyDeprecatedCommand");
import policyGeneralCICD = require("../policy/rules/code/policyGeneralCICD");
import policySecuritySecretsContainerScanNew = require("../policy/rules/code/policySecuritySecretsContainerScanNew");
import policyDepConfusion = require("../policy/rules/code/policyDepConfusion");
import policyDepConfusionPython = require("../policy/rules/code/policyDepConfusionPython");
import PolicySbomRegistryLicenses = require("../policy/rules/code/policySbomRegistryLicenses");
import PolicySecurityScan = require("../policy/rules/code/policySecurityScan");
import PolicyVulnerabilityRuntimeMonitor = require("../policy/rules/code/policyVulnerabilityRuntimeMonitor");
import policyNoSecrets = require("../policy/rules/code/policyNoSecrets");

const Timeout = require("await-timeout");
const uuid = require("uuid");
const uuidGenerator = require("uuid");
const pathApi = require("path");
const logger = loggerImport.getDebugLogger();

class AppInfo {
  repo = null;
  repository = new Repository();
  cicd: CICD = new CICD();
  cloud: Cloud = new Cloud();
  orchestrator: Orchestrator = new Orchestrator();
  artifactory: Artifactory = new Artifactory();
  kubernetes: Kubernetes = new Kubernetes();
  tags: IOxTag[];
}

export interface IFallbackStats {
  sent: number; //how many request we send
  succeeded: number; //how many request succeeded from the external service(like blame)
  failed: number; //how many request failed from the external service(like blame)
  recovered: number; //recovered
}

export class FallbackStats {
  sent: number;
  succeeded: number;
  failed: number;
  recovered: number;

  constructor() {
    this.sent = 0;
    this.recovered = 0;
    this.failed = 0;
    this.succeeded = 0;
  }
}

export class Application {
  appInfo: AppInfo = new AppInfo();

  uuid: string;
  orgName: string;
  jsonHelper: JsonHelper;
  policyRules: Policy[];
  jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview;
  numberOfAddedCloudItems: number = 0;
  numberOfAddedCloudItemsBasedOnRepoName: number = 0;
  numberOfAddedCloudItemsBasedOnJobsContent: number = 0;
  uniqueCloudResources = new Set();
  uniqueArtifactsResources = new Set();
  ruleExclusions: RuleExclusions;
  resultsHandler: ResultsHandler;

  //Services
  blameHelper: BlameHelper;
  lightBlameHelper: LightBlameHelper;
  autoFixHelper: AutoFixHelper;
  secretValidationHelper: SecretValidationHelper;
  alertRecommendationHelper: AlertRecommendationHelper;
  iacValidatorHelper: IacVerificationHelper;
  scaVerificationHelper: ScaVerificationHelper;
  resolveIssueValidationHelper: ResolveIssueValidationHelper;

  //Policy that where executed already once and should execute again
  executedPolicy = new Set();

  //Sbom
  keyToLocalDB: string;

  fakeApp;
  skipAllEnrichmentTools = false;

  constructor(
    uuid: string,
    orgName: string,
    policyRules: Policy[],
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
    ruleExclusions: RuleExclusions,
    resultsHandler: ResultsHandler,
    blameQueue: Iqueue,
    secretValidationQueue: Iqueue,
    autoFixQueue: Iqueue,
    alertRecommendationQueue: Iqueue,
    iacVerificationQueue: Iqueue,
    scaVerificationQueue: Iqueue,
    private readonly openSourceInfoQueue: Queue,
    private readonly cacheResolver: CacheResolver,
    resolveIssueValidationQueue: Iqueue,
  ) {
    this.uuid = uuid;
    this.orgName = orgName;
    this.policyRules = policyRules;
    this.blameHelper = new BlameHelper(blameQueue, this.uuid, this.orgName);
    this.lightBlameHelper = new LightBlameHelper(blameQueue, this.uuid, this.orgName);
    this.secretValidationHelper = new SecretValidationHelper(secretValidationQueue, this.uuid, this.orgName);
    this.autoFixHelper = new AutoFixHelper(autoFixQueue, this.uuid, this.orgName);
    this.alertRecommendationHelper = new AlertRecommendationHelper(alertRecommendationQueue, this.uuid, this.orgName);
    // this.iacValidatorHelper = new IacVerificationHelper(iacVerificationQueue, this.uuid, this.orgName);
    this.scaVerificationHelper = new ScaVerificationHelper(scaVerificationQueue, this.uuid, this.orgName);
    this.resolveIssueValidationHelper = new ResolveIssueValidationHelper(resolveIssueValidationQueue, this.uuid, this.orgName);

    this.jsonHelper = new JsonHelper(this.uuid);
    this.jsonApplicationDiscoveryOverview = jsonApplicationDiscoveryOverview;
    this.ruleExclusions = ruleExclusions;
    this.resultsHandler = resultsHandler;
  }

  async handelAutoFixInfo(securityAlerts: SecurityEvent[], app: Application) {
    if (StatesHelper.Instance.isPipelineScan) {
      return;
    }

    const repoTempCast: any = app.appInfo.repo == null ? null : (app.appInfo.repo as any);
    if (repoTempCast == null) {
      return;
    }
    const repo = repoTempCast.code_repo as Repo;

    if (repo.vcsType === VCSType.tfvc) return;
    try {
      await this.autoFixHelper.sendAutoFix(securityAlerts, repo);
    } catch (err) {
      logger.error(`failed handel autoFix for single app: ${this.appInfo.repo.code_repo.fullName}, err: ${err} `);
    }
  }

  @PerformanceTelemetry("policy")
  async runAllPolicyForSingleApplication(execType: string = Constant.execType.duringScan) {
    await AsyncTracker.runWithAsyncTracker(async () => {
      AsyncTracker.setValue("ox-app-id", (this.appInfo?.repo?.code_repo as Repo)?.id);
      AsyncTracker.setValue("ox-app-name", (this.appInfo?.repo?.code_repo as Repo)?.name);
      const appName = this.getAppName();

      let policyResPerRepo: EvalRepoPolicyRes[];
      try {
        //at this point we cannot use connector if repo is not defined as our results in UI are based on repo
        if (this.appInfo.repo == null) {
          return;
        }

        const appCommonInfo = this.getCommonAppInfo(this.appInfo, true);

        const shouldRun = !this.skipAllEnrichmentTools;
        if (shouldRun) {
          //Set this items for cash it for next scan
          const itemsForCash = {
            onlyOxEventsForCash: [],
            sbomInfo: undefined,
          };
          itemsForCash.onlyOxEventsForCash = [];

          this.fixPackageManager();

          await Promise.all([this.setSecurityEvents(itemsForCash, execType), this.handleSbomForRepoCode(itemsForCash)]);

          await this.mergeSbomAndDependencyGraphInfo();

          //Happen only during scan
          if (execType === Constant.execType.duringScan) {
            await this.saveCodeSecInCashForDeltaScan(itemsForCash.onlyOxEventsForCash);
            await this.saveSbomInCacheForDeltaScan(itemsForCash.sbomInfo);
          }
        }

        const allEvents: SecurityEvent[] = this.appInfo.repo.securityEvents;
        for (const event of allEvents) {
          CveToolsService.instance.addToCveTools(appName, event);
        }

        const rulesToRun = this.getPolicyToExecute(execType);
        const collectorPolicyProms = rulesToRun.map(policyRule =>
          this.executePolicy(policyRule, this.appInfo, appCommonInfo, execType === Constant.execType.endScan),
        );
        const proms = await Promise.all(collectorPolicyProms);

        if (shouldRun && execType === Constant.execType.duringScan) {
          await this.saveSbomInfo();
        }

        policyResPerRepo = proms.filter(i => i != null);
        this.resultsHandler.setTotalApps(StatesHelper.Instance.numberOfApps);

        if (execType === Constant.execType.endScan) {
          const artifacts = this.createArtifactListForArtifactScreen(policyResPerRepo);
          await this.resultsHandler.saveArtifactScreen(artifacts);
        }

        let updateResFromOverview = false;
        if (this.resultsHandler.isPipelineScan) {
          updateResFromOverview = await this.resultsHandler.handleEvalRepoResForPipelineScan(policyResPerRepo);
        } else {
          updateResFromOverview = await this.resultsHandler.handleNewEvalRepoRes(policyResPerRepo);
        }

        if (updateResFromOverview) {
          await this.jsonApplicationDiscoveryOverview.setDone();
        }
      } catch (err) {
        logger.error(`failed execute all policy, for single app: ${appName}, err: ${err}`);
      } finally {
        this.cleanMemory();
      }
    });
  }

  createArtifactListForArtifactScreen(policyResPerRepo: EvalRepoPolicyRes[]): Artifact[] {
    try {
      const repo: Repo = this.appInfo.repo.code_repo;
      const singleApp = this.appInfo;
      const result: Artifact[] = [];
      const registryImageMapBySha: { [key: string]: ImageInfo[] } = {};

      for (const registryImage of this.appInfo.artifactory.registryImage) {
        const sha = registryImage.image.imageDigestWithoutPrefix;
        if (!registryImageMapBySha[sha]) {
          registryImageMapBySha[sha] = [];
        }
        registryImageMapBySha[sha].push(registryImage);
      }
      for (const [sha, registryImages] of Object.entries(registryImageMapBySha)) {
        const { confIssues, secretIssues, vulnDepBaseIssues, vulnDepInstructionIssues, vulnDepIssues } = this.createIssueIdListForArtifact(
          policyResPerRepo,
          registryImages[0].image.name,
        );
        const artifact: Artifact = {
          id: sha,
          collectedAt: new Date(),
          scanId: this.uuid,
          artifactInfo: {
            hash: sha,
            name: registryImages[0].image.name,
            type: "Container",
            version: registryImages[0].image.imageTags.join(", "),
          },
          appDescription: {
            appId: repo.id,
            appName: repo.fullName,
            appType: repo.type,
            appFlow: {
              artifacts: singleApp.artifactory.artifactsAppFlow,
              cloudDeployments: singleApp.cloud.cloudAppFlow,
              kubernetes: singleApp.kubernetes.kubernetesAppFlow,
              orchestrators: singleApp.orchestrator.orchestratorsAppFlow,
              cicdInfo: singleApp.cicd.cicdAppFlow,
              repository: singleApp.repository.repoAppFlow,
            },
            toolsInfo: [],
            businessPriority: repo.repoImportance.total, //tomer will need to update at end of the scan
          },
          categories: this.createArtifactCategories(policyResPerRepo),
          cicdDescription: this.createArtifactCICDDescription(registryImages[0].image),
          registryDescription: this.createArtifactRegistryDescription(registryImages),
          cloudData: this.createArtifactCloudData(sha, singleApp.cloud),
          filterScreenData: {
            deployed: false,
            highSeverityIssues: 0,
            inProduction: false,
            lastVersion: false,
          },
          codeDescription: this.createArtifactCodeDescription(repo),
          secretIssues,
          confIssues,
          vulnDepIssues,
          vulnDepBaseIssues,
          vulnDepInstructionIssues,
        };
        artifact.filterScreenData = this.createArtifactFilterScreenData(artifact, repo);
        result.push(artifact);
      }
      return result;
    } catch (error) {
      logger.error("createArtifactObjectForArtifactScreen - error:", error);
    }
  }

  createArtifactFilterScreenData(artifact: Artifact, repo: Repo): FilterScreenData {
    const artifactStats = this.createArtifactStats(artifact, repo);
    const filterScreenData: FilterScreenData = {
      deployed: false,
      highSeverityIssues: 0,
      inProduction: false,
      lastVersion: false,
    };
    filterScreenData.deployed = artifactStats.deployed;
    filterScreenData.highSeverityIssues = artifactStats.highSeverityIssues;
    filterScreenData.inProduction = artifactStats.inProduction;
    filterScreenData.lastVersion = artifactStats.lastVersion;

    if (artifactStats.lastExecutionTime) {
      filterScreenData.lastExecutionTime = artifactStats.lastExecutionTime;
    }
    return filterScreenData;
  }

  createArtifactStats(artifact: Artifact, repo: Repo): ArtifactScreenHistoryStats {
    const artifactStats: ArtifactScreenHistoryStats = {
      id: artifact.id,
      collectedAt: artifact.collectedAt,
      createTime: artifact.cicdDescription.pipelineExecution.createTime,
      deployed: false,
      appId: repo.id,
      scanId: this.uuid,
      highSeverityIssues: 0,
      inProduction: false,
      lastVersion: false,
    };
    for (const singleCloudItem of artifact.cloudData) {
      if (singleCloudItem.lastExecutionTime) {
        artifactStats.inProduction = true;
        artifactStats.deployed = true;
        artifactStats.lastExecutionTime = singleCloudItem.lastExecutionTime;
      } else {
        artifactStats.deployed = true;
      }
    }
    for (const singleCategory of artifact.categories) {
      artifactStats.highSeverityIssues +=
        singleCategory.severities.high + singleCategory.severities.critical + singleCategory.severities.appox;
    }
    return artifactStats;
  }

  createArtifactRegistryDescription(registryImages: ImageInfo[]): ArtifactRegistryDescription[] {
    const result: ArtifactRegistryDescription[] = [];
    for (const image of registryImages) {
      const type = guessArtifactSystem(image.image.name);
      const registryDescription: ArtifactRegistryDescription = {
        type,
        name: image.image.name,
        link: image.image.link,
        hash: image.image.imageDigestWithoutPrefix,
        username: `${type} User`,
        uploadTime: new Date(image.image.imagePushedAt),
        lastUpdate: new Date(image.image.imagePushedAt),
        buildTime: new Date(image.image.imagePushedAt),
      };
      result.push(registryDescription);
    }
    return result;
  }

  createArtifactCodeDescription(repo: Repo): CodeArtifactDescription {
    const result: CodeArtifactDescription = {
      scm: repo.type,
      isPublic: !repo.privateVisability,
      sourceBranch: repo.defaultBranch,
      commit: "", // roman
      prOwner: "", // roman
      commitLink: "", // roman
      prDate: new Date(), // roman
    };
    return result;
  }

  createArtifactCloudData(sha: string, cloud: Cloud): CloudArtifactData[] {
    const cloudData: CloudArtifactData = {
      zone: "",
      cloudIdentifier: "",
      lastModifiedTime: new Date(), // roman
      lastExecutionTime: new Date(), // roman
      account: "", //roman
      link: "", //roman
    };
    const result: CloudArtifactData[] = [cloudData];
    // for (const imageDetails of cloud.containerImage) {
    //   if (imageDetails.imageDigestWithoutPrefix !== sha) {
    //     continue;
    //   }
    //   const cloudData: CloudArtifactData = {
    //     zone: imageDetails.region,
    //     cloudIdentifier: imageDetails.cloudEnv,
    //     lastModifiedTime: new Date(), // roman
    //     lastExecutionTime: new Date(), // roman
    //     account: '', //roman
    //     link: imageDetails.link, //roman
    //     cloudDescription: {
    //       type: "", // roman
    //       subType: "", // roman
    //     },
    //   };
    //   result.push(cloudData);
    // }
    return result;
  }

  createArtifactCICDDescription(image: ImageDetail): CICDArtifactDescription {
    const date = image.imagePushedAt ? new Date(image.imagePushedAt) : new Date();
    const cicdDescription: CICDArtifactDescription = {
      id: image.imageDigestWithoutPrefix,
      type: "GitHub",
      pipelineExecution: {
        createTime: date,
        pipelineName: "",
        executedBy: "",
        pipelineId: "",
        pushType: "push",
        status: "",
        updateTime: date,
        link: "",
      },
    };
    return cicdDescription;
  }

  createArtifactCategories(policyResPerRepo: EvalRepoPolicyRes[]): IssueSummary[] {
    const severityMap = {
      [Severity.INFO]: "info",
      [Severity.LOW]: "low",
      [Severity.MEDIUM]: "medium",
      [Severity.HIGH]: "high",
      [Severity.CRITICAL]: "critical",
      [Severity.APPOXALYPSE]: "appox",
    };
    const categoriesMap: { [key: number]: IssueSummary } = {};
    for (const policyRes of policyResPerRepo) {
      if (!categoriesMap[policyRes.policyRes.categoryId]) {
        categoriesMap[policyRes.policyRes.categoryId] = {
          catId: policyRes.policyRes.categoryId,
          severities: {
            info: 0,
            low: 0,
            medium: 0,
            high: 0,
            critical: 0,
            appox: 0,
          },
        };
      }
      const category: IssueSummary = categoriesMap[policyRes.policyRes.categoryId];
      for (const policyResItem of policyRes.policyRes.list) {
        const severitySTR = severityMap[policyResItem.severity];
        category.severities[severitySTR]++;
      }
    }
    const categories: IssueSummary[] = Object.values(categoriesMap);
    return categories;
  }

  createIssueIdListForArtifact(policyResPerRepo: EvalRepoPolicyRes[], imageId: string) {
    const secretIssues = [];
    const confIssues = [];
    const vulnDepIssues = [];
    const vulnDepBaseIssues = [];
    const vulnDepInstructionIssues = [];

    for (const policyRes of policyResPerRepo) {
      let isArtifactScaBaseImage = policyRes.policyRes.policy_id === "oxPolicy_securityScan_222";
      let isArtifactScaApplication = policyRes.policyRes.policy_id === "oxPolicy_securityScan_221";
      let isArtifactScaPossibleBaseImage = policyRes.policyRes.policy_id === "oxPolicy_securityScan_220";
      let isArtifactScaUserInstructions = policyRes.policyRes.policy_id === "oxPolicy_securityScan__421";
      let isArtifactSecrets = policyRes.policyRes.policy_id === "oxPolicy_artifacts_securityScanSecret_1";
      let isPiiPolicy = policyRes.policyRes.policy_id === "oxPolicy_policyPiiContainer_1";
      let isIac = policyRes.policyRes.policy_id === "oxPolicy_artifacts_securityScanIAC_11";

      for (const policyResItem of policyRes.policyRes.list) {
        if (!policyResItem.uniqueArtifacts.includes(imageId)) {
          continue;
        }

        const { issueId } = policyResItem;
        if (isArtifactSecrets || isPiiPolicy) {
          secretIssues.push(issueId);
        } else if (isArtifactScaBaseImage || isArtifactScaPossibleBaseImage) {
          vulnDepBaseIssues.push(issueId);
        } else if (isArtifactScaUserInstructions) {
          vulnDepInstructionIssues.push(issueId);
        } else if (isIac) {
          confIssues.push(issueId);
        } else if (isArtifactScaApplication) {
          vulnDepIssues.push(issueId);
        }
      }
    }
    return { secretIssues, confIssues, vulnDepIssues, vulnDepBaseIssues, vulnDepInstructionIssues };
  }

  getPolicyToExecute(type: string) {
    if (StatesHelper.Instance.isCharterBank) {
      const res = this.policyRules.filter(i => i.policyId === "oxPolicy_runtimeMonitor_1");
      return res;
    }

    if (Constant.execType.codeSecurityExecutionAgain === type) {
      //SCA, SAST, IAC - run this policy always
      const res = this.policyRules.filter(i => i.catId === 4 || i.catId === 6 || i.catId === 8 || i.catId === 5);
      return res;
    }

    const res = this.policyRules.filter(i => !this.executedPolicy.has(i.policyId) && i.execType === type);
    return res;
  }

  updateExternalSecurityItem(securityEvent: SecurityEvent) {
    try {
      let resourceType = CodeRepoTypes[CodeRepoTypes.securityEvents];

      securityEvent.cloneForBlameService = this.appInfo.repo.code_repo.cloneDir;

      if (this.appInfo.repo.code_repo.type === repoType.awsCodeCommit) {
        if (securityEvent.startLineNumber >= 0) {
          securityEvent.link =
            this.appInfo.repo.code_repo.fileLink +
            securityEvent.fileName +
            this.appInfo.repo.code_repo.linkFilePreffix +
            securityEvent.startLineNumber +
            "-" +
            securityEvent.startLineNumber;
        } else {
          securityEvent.link = this.appInfo.repo.code_repo.fileLink + securityEvent.fileName;
        }
      } else if (this.appInfo.repo.code_repo.type === repoType.azureTFS) {
        if (securityEvent.startLineNumber >= 0) {
          securityEvent.link =
            this.appInfo.repo.code_repo.fileLink +
            securityEvent.fileName +
            "&version=T" +
            this.appInfo.repo.code_repo.linkFilePreffix +
            securityEvent.startLineNumber;
        } else {
          securityEvent.link = this.appInfo.repo.code_repo.fileLink + securityEvent.fileName + "&version=T";
        }
      } else {
        if (securityEvent.startLineNumber >= 0) {
          securityEvent.link =
            this.appInfo.repo.code_repo.fileLink +
            securityEvent.fileName +
            this.appInfo.repo.code_repo.linkFilePreffix +
            securityEvent.startLineNumber;
        } else {
          securityEvent.link = this.appInfo.repo.code_repo.fileLink + securityEvent.fileName;
        }
      }

      //Update resources
      if (this.appInfo.repo.hasOwnProperty(resourceType)) {
        this.appInfo.repo[resourceType].push(securityEvent);
      } else {
        this.appInfo.repo[resourceType] = [securityEvent];
      }

      const repo: Repo = this.appInfo.repo.code_repo;
      const possibleNewItem: AppToolCoverage = SecurityToolsHelper.getAppToolCoverageFromAlertsForApp(repo, securityEvent);
      if (possibleNewItem) {
        SecurityToolsHelper.addToToolCoverage(repo.toolsCoverage, possibleNewItem);
      }
      if (!repo.noneRelevantRepo || repo.markedAsRelevant) {
        CveToolsService.instance.addToCveTools(repo.fullName, securityEvent);
      }
    } catch (err) {
      logger.error(`failed update external security event item, err: ${err}, obj: ${JSON.stringify(securityEvent)}`);
    }
  }

  updateArtifactItem(artifactSecEvents: SecurityEvent[]) {
    try {
      this.appInfo.artifactory.securityEvents.push(...artifactSecEvents);
      this.appInfo.artifactory.artifactsFromSecEvents.push(...artifactSecEvents.map(event => event.artifacts).flat());
    } catch (err) {
      logger.error(`uuid: ${this.uuid}, failed update artifact item, err: ${err}, artifact obj: ${JSON.stringify(artifactSecEvents)}`);
    }
  }

  updateCloudItem(cloudObjItem: CloudSecurityEvent, type: string) {
    try {
      //Update cloud security alerts array only in case of violation happen
      if (cloudObjItem.isViolation) {
        this.appInfo.cloud.cloudSecurityEvents.push(cloudObjItem);

        if (type.toLowerCase() === "reponame") {
          this.numberOfAddedCloudItemsBasedOnRepoName++;
        } else if (type.toLowerCase() === "jobcontent") {
          this.numberOfAddedCloudItemsBasedOnJobsContent++;
        }
      }

      //Update cloud security resources in all cases because we are using this data
      //to set cloud resources
      const unique = `${cloudObjItem.resource}_${cloudObjItem.cloudService}_${cloudObjItem.region}`;
      if (!this.uniqueCloudResources.has(unique)) {
        this.uniqueCloudResources.add(unique);

        const cloudResource: CloudResource = new CloudResource(
          cloudObjItem.accountName,
          cloudObjItem.category,
          cloudObjItem.region,
          cloudObjItem.cloudService,
          cloudObjItem.resource,
          cloudObjItem.cloudEnv,
          cloudObjItem.accountName,
        );

        this.appInfo.cloud.cloud.push(cloudResource);
      }

      this.numberOfAddedCloudItems++;
    } catch (err) {
      logger.error(`uuid: ${this.uuid}, failed update cloud item, err: ${err}, cloud obj: ${JSON.stringify(cloudObjItem, null, 4)}`);
    }
  }

  private getCommonAppInfo(appInfo: AppInfo, attachedToApp) {
    const resourceRepo = appInfo.repo[ResourceType[ResourceType.code_repo]];
    if (resourceRepo == null) {
      throw `failed get main resource`;
    }

    return {
      resourceRepo: resourceRepo,
      resourceRepository: appInfo.repository,
      resourceCicd: appInfo.cicd,
      resourceCloud: appInfo.cloud,
      resourceArtifactory: appInfo.artifactory,
      resourceOrchestrator: appInfo.orchestrator,
      resourceKubernetes: appInfo.kubernetes,
      attachedToApp: attachedToApp,
      flowId: uuid.v4(),
    };
  }

  async getCashedSecEvents() {
    let repoFullName;
    try {
      if (this.appInfo.repo == null) {
        return [];
      }
      const run = StatesHelper.Instance.isContainerEnable;
      if (!run) {
        return [];
      }
      if (this.appInfo.artifactory.securityEvents.length == 0) {
        return [];
      }

      const repo: Repo = this.appInfo.repo.code_repo;
      repoFullName = repo.fullName;

      const codeRepoEvents: SecurityEvent[] = await this.getCodeRepoEvents(repo);
      return codeRepoEvents;
    } catch (err) {
      logger.error(`failed getCodeCashedEvents for repo: ${repoFullName}, err: ${err}`);
    }
    return [];
  }

  setArtifactSecurityFactorsToAppSecEvents() {
    if (this.appInfo.repo == null) {
      return;
    }

    const repo: Repo = this.appInfo.repo.code_repo;
    try {
      const uniqueSeverityChangedReasonsFromContainers = {};
      for (const registryImage of this.appInfo?.artifactory?.registryImage) {
        if (registryImage?.severityChangeReasons) {
          //Set all cloud unique severity factors from container alerts
          registryImage?.severityChangeReasons.forEach(i => {
            if (i?.severityFactorType === SeverityFactorType.Cloud && !uniqueSeverityChangedReasonsFromContainers[i.shortName]) {
              uniqueSeverityChangedReasonsFromContainers[i.shortName] = [i];
            }
          });
        }
      }

      this.updateWithCloudSeverityFactors(repo, uniqueSeverityChangedReasonsFromContainers);
    } catch (err) {
      logger.error(`failed setArtifactSecurityFactorsToAppSecEvents in single application: ${repo?.fullName}, err: ${err}`);
    }
  }

  async setCspmToRepo(
    codeRepoEvents: SecurityEvent[],
    containersFromCspmName: Map<string, CloudSecurityEvent>,
    containersFromCspmSha: Map<string, CloudSecurityEvent>,
  ) {
    try {
      //Dor handle it
      if (!StatesHelper.Instance.dorCspm) {
        return;
      }

      const repo: Repo = this.appInfo?.repo?.code_repo;

      this.appInfo.artifactory.registryImage.forEach(image => {
        try {
          const name = image.image.name;
          const sha = image.image.imageDigestWithoutPrefix;

          if (sha && containersFromCspmSha.has(sha)) {
            const events = containersFromCspmSha.get(sha);
            Object.values(events).forEach(event => {
              if (!event.correlatedCloudEvent) {
                this.appInfo.cloud.cloudSecurityEvents.push(event);
                event.correlatedRegistry = "";
                event.correlatedCloudEvent = true;
              }
            });
            logger.info(`found by sha: ${sha}, image: ${image.image.name}, repo: ${repo.fullName}`);
          }
          if (containersFromCspmName.has(name)) {
            const events = containersFromCspmName.get(name);
            Object.values(events).forEach(event => {
              if (!event.correlatedCloudEvent) {
                this.appInfo.cloud.cloudSecurityEvents.push(event);
                event.correlatedRegistry = "";
                event.correlatedCloudEvent = true;
              }
            });
            logger.info(`found by name: ${name}, image: ${image.image.name}, repo: ${repo.fullName}`);
          }
        } catch (e) {
          logger.error(`failed single setArtifactToCloudToRepo, image: ${image.image.name}`, e);
        }
      });
    } catch (e) {
      logger.error(e);
    }
  }

  //WE DONT CONNECT RUNTIME TO REGISTRY,
  //THE ONLY CONNECTION WE HAVE IS
  //CLOUD --> REPO, EXAMPLE: wiz runtime alert to repo scanner and vice verse
  //KEEP in minde if we manage to find connection we will overwrite the link of repo to registry
  async setArtifactToCloudToRepo(
    codeRepoEvents: SecurityEvent[],
    containersFromRuntimeName: Map<string, SecurityEvent>,
    containersFromRuntimeSha: Map<string, SecurityEvent>,
  ) {
    const repo: Repo = this.appInfo?.repo?.code_repo;

    try {
      if (!StatesHelper.Instance.isMatchingArtifactToCloud) {
        return;
      }
      if (!this?.appInfo?.artifactory?.registryImage.length) {
        return;
      }

      //Connect third party to repo by container registry
      //match sha or name of third party alert to a repo using ox container alert(registryImage)
      this.appInfo.artifactory.registryImage.forEach(image => {
        try {
          const name = image.image.name;
          const sha = image.image.imageDigestWithoutPrefix;

          if (sha && containersFromRuntimeSha.has(sha)) {
            const events = containersFromRuntimeSha.get(sha);
            Object.values(events).forEach(event => {
              if (!event.correlatedCloudEvent) {
                this.appInfo.artifactory.securityEvents.push(event);
                event.correlatedRegistry = "";
                event.correlatedCloudEvent = true;
              }
            });
            logger.info(`found by sha: ${sha}, image: ${image.image.name}, repo: ${repo.fullName}`);
          } else if (containersFromRuntimeName.has(name)) {
            const events = containersFromRuntimeName.get(name);
            Object.values(events).forEach(event => {
              if (!event.correlatedCloudEvent) {
                this.appInfo.artifactory.securityEvents.push(event);
                event.correlatedRegistry = "";
                event.correlatedCloudEvent = true;
              }
            });
            logger.info(`found by name: ${name}, image: ${image.image.name}, repo: ${repo.fullName}`);
          }
        } catch (e) {
          logger.error(`failed single setArtifactToCloudToRepo, image: ${image.image.name}`, e);
        }
      });

      //Repo SCA alerts
      const scaRepoMap: Map<string, SecurityEvent> = new Map<string, SecurityEvent>();
      for (const codeSecEvent of codeRepoEvents) {
        //Only SCA alerts
        const shouldRun =
          codeSecEvent.securityAlertType === SecurityAlertType.sca && codeSecEvent.securitySubTypeAlertType === SecurityAlertType.Unknown;
        if (!shouldRun) {
          continue;
        }

        const u = getUniqueKeyBaseOnSCAlib(codeSecEvent.pkgName, codeSecEvent.installedVersion);
        let key = `${u}_${codeSecEvent.blame.cve}`;
        scaRepoMap.set(key, codeSecEvent);
      }

      //Repo to Runtime
      const appId = repo.repoId;
      for (const artifactAlert of this.appInfo.artifactory.securityEvents) {
        if (artifactAlert.securitySubTypeAlertType !== SecurityAlertType.cloudRunTime) {
          continue;
        }

        const u = getUniqueKeyBaseOnSCAlib(artifactAlert.pkgName, artifactAlert.installedVersion);
        const key = `${u}_${artifactAlert.blame.cve}`;

        const repoSecEvent: SecurityEvent = scaRepoMap.get(key);
        if (repoSecEvent) {
          const scaUnique = getUniqueInfoForAggregation(repoSecEvent);
          const codeRepoIssueId = this.getCustomIssueId(scaUnique, appId, "oxPolicy_securityScan_120");
          const correlatedRegistry = "";

          const artifactUniqueUi = getUniqueInfoForAggregation(artifactAlert);
          const artifactRepoIssueIdForUI = `${appId}-oxPolicy_securityScan_420-${artifactUniqueUi}`;
          repoSecEvent.corelateIssue = artifactRepoIssueIdForUI;

          this.setExtraCodeAndContainerInfo(
            repoSecEvent,
            artifactAlert,
            this.appInfo.repo.code_repo,
            codeRepoIssueId,
            artifactRepoIssueIdForUI,
            correlatedRegistry,
          );
        }
      }
    } catch (e) {
      logger.error(`failed all setArtifactToCloudToRepo, repo: ${repo.fullName}`, e);
    }
  }

  async setArtifactSecurityEventsOnRepoApp(codeRepoEvents: SecurityEvent[]) {
    let repoFullName = "";

    let connectedCountViaSecEv = 0;
    let connectedCountViaSbom = 0;
    let notConnectedSCA = new Set();
    let secEventsCount = 0;

    const codeRepoMap = new Map<string, SecurityEvent[]>();
    const dockerRepoMap = new Map<string, SecurityEvent[]>();
    const secretRepoMap = new Map<string, SecurityEvent[]>();

    try {
      if (this.appInfo.repo == null) {
        return;
      }
      const run = StatesHelper.Instance.isContainerEnable;
      if (!run) {
        return;
      }
      if (this.appInfo.artifactory.securityEvents.length == 0) {
        return;
      }

      const repo: Repo = this.appInfo.repo.code_repo;
      repoFullName = repo.fullName;

      logger.info(
        `try set artifact sec event: ${this.appInfo.artifactory.securityEvents.length}, registry count: ${this.appInfo.artifactory.registryImage.length} repo: ${repo.fullName}`,
      );

      //Build code alerts data structure for optimization of matching
      for (const event of codeRepoEvents) {
        try {
          //Only sca
          if (event.securityAlertType === SecurityAlertType.sca && event.securitySubTypeAlertType === SecurityAlertType.Unknown) {
            const u = getUniqueKeyBaseOnSCAlib(event.pkgName, event.installedVersion);
            const key = `${u}_${event.blame.cve}`.toLowerCase();
            if (!codeRepoMap.has(key)) {
              codeRepoMap.set(key, [event]);
            } else {
              codeRepoMap.set(key, codeRepoMap.get(key).concat(event));
            }
          }
          //Docker file scanning
          else if (
            event.securityAlertType === SecurityAlertType.sca &&
            event.securitySubTypeAlertType === SecurityAlertType.dockerFileVul
          ) {
            //event.blame.triggerPackage holds the base image and the file path is the docker file
            // const key = `${event.filePath}`;
            const key = `${event.filePath}_${event.pkgName}_${event.installedVersion}`.toLowerCase();
            if (dockerRepoMap.has(key)) {
              dockerRepoMap.get(key).push(event);
            } else {
              dockerRepoMap.set(key, [event]);
            }
          }
          //Secrets
          else if (event.securityAlertType === SecurityAlertType.secrets || event.isPII) {
            if (!event.fromCommitHistory) {
              const extension = pathApi.extname(event.fileName);
              const fName = pathApi.basename(event.fileName, extension);
              const key = `${event.realMatch}_${fName}`.toLowerCase();
              if (secretRepoMap.has(key)) {
                secretRepoMap.get(key).push(event);
              } else {
                secretRepoMap.set(key, [event]);
              }
            }
          }
        } catch (err) {
          logger.error(`Failed set artifact security temp cash for sec events, repo: ${repoFullName} err ${err}`);
        }
      }
      secEventsCount = codeRepoEvents.length;

      let count = 0;
      //Only ox data(Trivy)
      for (const registryImage of this.appInfo?.artifactory?.registryImage) {
        const containerSecurityAlerts = registryImage.securityEvents;
        count += containerSecurityAlerts.length;

        let codeContainerDrift;
        if (repo.lastPushTime && registryImage?.image?.imagePushedAt) {
          const codeLastPush = Date.parse(repo.lastPushTime);
          const containerCreationDate = Date.parse(registryImage?.image?.imagePushedAt);

          if (codeLastPush && containerCreationDate) {
            codeContainerDrift = Math.round((codeLastPush - containerCreationDate) / (1000 * 3600 * 24));
            logger.info(`found container drift, image: ${registryImage?.image?.name}, codeContainerDrift:${codeContainerDrift}`);
          }
        }

        let containerExtraEvents: SecurityEvent[] = [];
        for (const containerSecurityAlert of containerSecurityAlerts) {
          if (codeContainerDrift !== undefined) {
            this.createCodeContainerDriftSeverityFactors(
              codeContainerDrift,
              containerSecurityAlert,
              repo,
              registryImage?.image?.imagePushedAt,
              repo.lastPushTime,
            );
          }

          let shouldRun = false;
          if (
            containerSecurityAlert.securityAlertType === SecurityAlertType.container &&
            containerSecurityAlert.securitySubTypeAlertType === SecurityAlertType.sca
          ) {
            if (
              containerSecurityAlert.containerScanType === ContainerSecurityType.appOnly ||
              containerSecurityAlert.containerScanType === ContainerSecurityType.baseOnly
            ) {
              shouldRun = true;
            }
          }
          if (
            containerSecurityAlert.securityAlertType === SecurityAlertType.container &&
            containerSecurityAlert.securitySubTypeAlertType === SecurityAlertType.secrets
          ) {
            shouldRun = true;
          }

          if (!shouldRun) {
            continue;
          }
          let [ableToConnect, extraSecEvents] = this.connectSecAlertsToCodeSecAlerts(
            containerSecurityAlert,
            codeRepoMap,
            dockerRepoMap,
            secretRepoMap,
            registryImage?.image?.dockerFilePath,
          );
          if (extraSecEvents?.length) {
            containerExtraEvents.push(...extraSecEvents);
          }
          if (ableToConnect) {
            connectedCountViaSecEv++;
          }

          if (ableToConnect) {
            connectedCountViaSbom++;
          } else {
            notConnectedSCA.add(`${containerSecurityAlert.pkgName}_${containerSecurityAlert.installedVersion}`);
          }
        }
        if (containerSecurityAlerts?.length) {
          logger.info(
            `Adding ${containerExtraEvents.length} duplicated container alerts due to multiple triggerPkg for image: ${registryImage?.image?.name}`,
          );
          containerSecurityAlerts.push(...containerExtraEvents);
          this.appInfo.artifactory.securityEvents.push(...containerExtraEvents);
        }
      }

      //Uncomment when supported - romanzit
      //await this.handleSbomCorrelation(repo);

      //First do blame
      //this.appInfo.artifactory.securityEvents hold info from trivy && from all external tools
      let allContainerAlerts: SecurityEvent[] = this.appInfo.artifactory.securityEvents;
      const notConnectedAlertsForBlame = allContainerAlerts.filter(i => !i.correlatedSCAEvent);

      const atLeastOneAlertNotFromOx = allContainerAlerts.find(i => !i.oxTool);
      if (atLeastOneAlertNotFromOx) {
        logger.info(`try remove duplication for container alerts in repo: ${repoFullName} count: ${allContainerAlerts.length}`);
        allContainerAlerts = SecurityToolsHelper.removeDuplication(this.uuid, repoFullName, allContainerAlerts);
      }

      await this.saveSbomFromRegistryForAppScreen();

      await MemoryMonitorHelper.Instance.printSnapshot(
        this.orgName,
        this.uuid,
        `after single setArtifactSecurityEventsOnRepoApp, repo: ${repo.fullName}`,
      );

      logger.info(
        `finish set artifact for repo: ${repoFullName} sec event: ${allContainerAlerts.length}, repo-cash secEventsCount: ${secEventsCount}, process: ${count}, repo: ${repo.fullName}, connectedCountViaSecEv: ${connectedCountViaSecEv}, connectedCountViaSbom: ${connectedCountViaSbom}, notConnected: ${notConnectedAlertsForBlame.length}`,
      );
    } catch (err) {
      logger.error(`failed set artifact security events in single application: ${repoFullName}, err: ${err}`);
    }
  }

  async handleSbomCorrelation(repo: Repo) {
    try {
      const sbomAlertsMap = new Map<string, ExtendedSbomComponent>();
      let sbomEventCount = 0;
      let sbomToSbomConnected = 0;
      let sbomToSbomNotConnected = 0;

      //Build sbom alerts data structure for optimization of matching
      const sbomAlerts: SbomEvent[] = await this.cacheResolver.getSbomCache({ id: repo.id, idKey: "repoId", name: repo.fullName });
      for (const event of sbomAlerts) {
        for (const component of event.sbomHelper.extendedSbom.components) {
          try {
            sbomEventCount++;
            const adaptedPkgName = adaptLibName(component.name);
            const key = `${adaptedPkgName}@${component.version}`;
            sbomAlertsMap[key.toLowerCase()] = component;
          } catch (err) {
            logger.error(`Failed set artifact security temp cash for sbom, repo: ${repo.fullName}, err ${err}`);
          }
        }
      }
      //Try connected sbom
      this.appInfo.artifactory.registryImage.forEach(image => {
        try {
          const i = image.sbomEvents;
          if (i.length == 0) {
            return;
          }
          const sbomEvent: SbomEvent = image.sbomEvents[0];
          sbomEvent.sbomHelper.extendedSbom.components.forEach(com => {
            const res = this.ConnectSbomDataToSbomEvent(com, sbomAlertsMap);
            if (res) {
              sbomToSbomConnected++;
            } else {
              sbomToSbomNotConnected++;
            }
          });
        } catch (err) {
          logger.error(`Failed set handleSbomCorrelation for single image: ${image.image.name}, repo: ${repo.fullName} err ${err}`);
        }
      });
    } catch (err) {
      logger.error(`Failed set handleSbomCorrelation for all images, repo: ${repo.fullName} err ${err}`);
    }
  }

  updateWithCloudSeverityFactors(repo: Repo, uniqueSeverityChangedReasonsFromContainers: any) {
    try {
      const cloudSeverityFactors = Object.values(uniqueSeverityChangedReasonsFromContainers).flat() as ChangeReason[];
      if (cloudSeverityFactors.length == 0) {
        return;
      }

      //Add to app tags based on cloud severity factors
      // const sf = this.chooseCorrectSeverityFactorForTags(repo, cloudSeverityFactors);
      this.resultsHandler.setRepoTags(cloudSeverityFactors, repo);

      //Add to repo cloud severity factors
      const appId = repo.id;
      const issues = this.resultsHandler.appToIssuesMap.get(appId);
      if (!issues) {
        return;
      }

      issues.forEach(issue => {
        //dev-process - 3
        //security-tool-coverage - 10
        //cicd - 25
        if (issue.categoryId === 3 || issue.categoryId === 10 || issue.categoryId === 25) {
          return;
        }
        cloudSeverityFactors.forEach(cloudSeverityFactor => {
          //Exist already
          if (issue.severityChangedReason.find(i => i.shortName === cloudSeverityFactor.shortName)) {
            return;
          }
          //Add
          issue.severityChangedReason.push(JSON.parse(JSON.stringify(cloudSeverityFactor)));
        });
      });
    } catch (err) {
      logger.error(`failed updateWithCloudSeverityFactors all in single application: ${repo.fullName}, err: ${err}`);
    }
  }

  createCodeContainerDriftSeverityFactors(
    codeContainerDrift: number,
    containerSecurityAlert: SecurityEvent,
    repo: Repo,
    containerCreationDate,
    lastCodeChange,
  ) {
    try {
      const extraInfo: ExtraInfo[] = [];
      extraInfo.push({
        key: "Container Creation",
        value: new Date(containerCreationDate).toDateString(),
      });
      extraInfo.push({
        key: "Last Code Change",
        value: new Date(lastCodeChange).toDateString(),
      });
      extraInfo.push({
        key: "Drift",
        value: `${codeContainerDrift} days`,
      });

      if (codeContainerDrift < 14) {
        addSeverityChangedReason(severityReasons.containerDriftLessTwoWeeks, containerSecurityAlert, repo, extraInfo);
        return;
      }
      if (codeContainerDrift <= 30) {
        addSeverityChangedReason(severityReasons.containerDriftLessOneMonth, containerSecurityAlert, repo, extraInfo);
        return;
      }
      if (codeContainerDrift > 30) {
        addSeverityChangedReason(severityReasons.containerDriftMoreOneMonth, containerSecurityAlert, repo, extraInfo);
        return;
      }
      if (codeContainerDrift > 180) {
        addSeverityChangedReason(severityReasons.containerDriftMoreSixMonth, containerSecurityAlert, repo, extraInfo);
        return;
      }

      //Debug
      //logger.info(`container drift didn't creay severity factors, container drift: ${codeContainerDrift}`);
    } catch (err) {
      logger.error(`failed creating code-container drift severity factors for container alert, err: ${err}`);
    }
  }

  connectSecAlertsToCodeSecAlerts(
    artifactAlert: SecurityEvent,
    codeRepoEvents: Map<string, SecurityEvent[]>,
    dockerRepoMap: Map<string, SecurityEvent[]>,
    secretRepoMap: Map<string, SecurityEvent[]>,
    dockerFilePath: string,
  ): [boolean, SecurityEvent[]] {
    try {
      const repo: Repo = this.appInfo.repo.code_repo;

      //Secrets
      if (artifactAlert.securitySubTypeAlertType === SecurityAlertType.secrets || artifactAlert.isPII) {
        const extension = pathApi.extname(artifactAlert.fileName);
        const fName = pathApi.basename(artifactAlert.fileName, extension);
        let key = `${artifactAlert.realMatch}_${fName}`.toLowerCase();

        let repoSecEvents: SecurityEvent[] = secretRepoMap.get(key);
        if (!repoSecEvents) {
          for (const [secretKey, events] of secretRepoMap.entries()) {
            const relevantEvents = events.filter(
              i => i.ruleId === artifactAlert.ruleId && stringSimilarity(artifactAlert.lineContent, i.lineContent) > 0.7,
            );
            if (relevantEvents.length > 0) {
              key = secretKey;
              break;
            }
          }
        }

        repoSecEvents = secretRepoMap.get(key);
        if (repoSecEvents) {
          for (const repoSecEvent of repoSecEvents) {
            artifactAlert.blame = repoSecEvent.blame;

            if (repoSecEvent.isPII) {
              //update artifact issue with PII
              const scaUnique = getUniqueInfoForAggregation(repoSecEvent);
              const codeRepoIssueId = this.getCustomIssueId(scaUnique, repo.id, "oxPolicy_policyPiiHardcoded_1"); //code policy for PII
              artifactAlert.title = repoSecEvent.title;

              //link to ui
              const artifactUniqueUi = getUniqueInfoForAggregation(artifactAlert);
              const artifactRepoIssueIdForUI = `${artifactAlert.imageId}_oxPolicy_policyPiiContainer_1_${artifactUniqueUi}`; //contianer policy for pii

              repoSecEvent.corelateIssue = artifactRepoIssueIdForUI;

              const correlatedRegistry = artifactAlert?.artifacts?.registryName;

              this.setExtraCodeAndContainerInfo(
                repoSecEvent,
                artifactAlert,
                repo,
                codeRepoIssueId,
                artifactRepoIssueIdForUI,
                correlatedRegistry,
              );
            } else {
              //update artifact issue with secret
              const scaUnique = getUniqueInfoForAggregation(repoSecEvent);
              const codeRepoIssueId = this.getCustomIssueId(scaUnique, repo.id, "oxPolicy_securityScan_secrets_1");
              artifactAlert.title = repoSecEvent.title;

              //link to ui
              const artifactUniqueUi = getUniqueInfoForAggregation(artifactAlert);
              const artifactRepoIssueIdForUI = `${artifactAlert.imageId}_oxPolicy_artifacts_securityScanSecret_1_${artifactUniqueUi}`;
              repoSecEvent.corelateIssue = artifactRepoIssueIdForUI;

              const correlatedRegistry = artifactAlert?.artifacts?.registryName;

              this.setExtraCodeAndContainerInfo(
                repoSecEvent,
                artifactAlert,
                repo,
                codeRepoIssueId,
                artifactRepoIssueIdForUI,
                correlatedRegistry,
              );
            }

            return [true, []];
          }
        }
      }
      //App container alert
      else if (artifactAlert.containerScanType === ContainerSecurityType.appOnly) {
        const u = getUniqueKeyBaseOnSCAlib(artifactAlert.pkgName, artifactAlert.installedVersion);
        const key = `${u}_${artifactAlert.blame.cve}`.toLowerCase();
        const repoSecEvents = codeRepoEvents.get(key) || [];

        let returnFlag = false;
        let extraAlerts = [];
        for (const repoSecEvent of repoSecEvents) {
          let consideredArtifactAlert = artifactAlert;
          if (!returnFlag) {
            returnFlag = true;
          } else {
            consideredArtifactAlert = structuredClone(artifactAlert);
            extraAlerts.push(consideredArtifactAlert);
          }

          consideredArtifactAlert.blame = repoSecEvent.blame;

          //update artifact issue with sca
          const scaUnique = getUniqueInfoForAggregation(repoSecEvent);
          const codeRepoIssueId = this.getCustomIssueId(scaUnique, repo.id, "oxPolicy_securityScan_120");

          const artifactUnique = getUniqueInfoForAggregation(consideredArtifactAlert);
          const artifactRepoIssueId = `${consideredArtifactAlert.imageId}_oxPolicy_securityScan_221_${artifactUnique}`;
          repoSecEvent.corelateIssue = artifactRepoIssueId;
          const correlatedRegistry = consideredArtifactAlert?.artifacts?.registryName;

          this.setExtraCodeAndContainerInfo(
            repoSecEvent,
            consideredArtifactAlert,
            repo,
            codeRepoIssueId,
            artifactRepoIssueId,
            correlatedRegistry,
          );
        }
        return [returnFlag, extraAlerts];
      }
      //Base container alerts
      else if (artifactAlert.containerScanType === ContainerSecurityType.baseOnly) {
        if (dockerFilePath) {
          const key = `${dockerFilePath}_${artifactAlert.pkgName}_${artifactAlert.installedVersion}`.toLowerCase();

          let dockerScaRepoSecEvents: SecurityEvent[] = dockerRepoMap.get(key);
          if (dockerScaRepoSecEvents) {
            for (const dockerScaRepoSecEvent of dockerScaRepoSecEvents) {
              //update artifact issue with sca
              const dockerScaUnique = getUniqueInfoForAggregation(dockerScaRepoSecEvent);
              const codeRepoIssueId = this.getCustomIssueId(dockerScaUnique, repo.id, "oxPolicy_deployment_221");
              const correlatedRegistry = artifactAlert?.artifacts?.registryName;

              //Use same base image for both of the alerts, the alert the comes from the docker file are the
              //correct one due to the fact dockerhub retrun several tags
              if (dockerScaRepoSecEvent?.blame?.triggerPackage?.name) {
                if (!artifactAlert.blame.triggerPackage) {
                  artifactAlert.blame.triggerPackage = new Dependency();
                }
                artifactAlert.blame.triggerPackage.name = dockerScaRepoSecEvent.blame.triggerPackage.name;
                artifactAlert.blame.triggerPackage.version = dockerScaRepoSecEvent?.blame?.triggerPackage?.version;
              } else {
                logger.error(`failed to get data for base image for repo: ${repo.fullName}`);
              }

              const artifactUnique = getUniqueInfoForAggregation(artifactAlert);
              const artifactRepoIssueId = `${artifactAlert.imageId}_oxPolicy_securityScan_222_${artifactUnique}`;
              dockerScaRepoSecEvent.corelateIssue = artifactRepoIssueId;

              this.setExtraCodeAndContainerInfo(
                dockerScaRepoSecEvent,
                artifactAlert,
                repo,
                codeRepoIssueId,
                artifactRepoIssueId,
                correlatedRegistry,
              );
              return [true, []];
            }
          }
        }
      }
    } catch (err) {
      logger.error(`Failed running ConnectSecAlertsToCodeSecAlerts err ${err}`);
    }
    return [false, []];
  }

  setExtraCodeAndContainerInfo(
    repoSecEvent: SecurityEvent,
    artifactAlert: SecurityEvent,
    repo: Repo,
    codeRepoIssueId: string,
    artifactRepoIssueId: string,
    correlatedRegistry: string,
  ) {
    artifactAlert.autoFixResponse = repoSecEvent.autoFixResponse;
    artifactAlert.scaValidatorTypesResponse = repoSecEvent.scaValidatorTypesResponse;
    //Ignore base image rec as the number may not be correlated
    const shouldIgnoreRec =
      artifactAlert.containerScanType === ContainerSecurityType.baseOnly && artifactAlert.securityAlertType === SecurityAlertType.container;
    if (!shouldIgnoreRec) {
      artifactAlert.alertRecommendationResponse = repoSecEvent.alertRecommendationResponse;
    }
    artifactAlert.validSecret = repoSecEvent.validSecret;
    artifactAlert.secretChecked = repoSecEvent.secretChecked;
    artifactAlert.iacValidatorTypesResponse = repoSecEvent.iacValidatorTypesResponse;
    artifactAlert.fixes = repoSecEvent.fixes;
    //Sometime the pkg name
    artifactAlert.pkgName = repoSecEvent.pkgName;
    artifactAlert.severity = repoSecEvent.severity;
    artifactAlert.severityStr = repoSecEvent.severityStr;
    artifactAlert.language = repoSecEvent.language;

    artifactAlert.relatedPR = repoSecEvent.relatedPR;
    artifactAlert.blame = repoSecEvent.blame;
    artifactAlert.startLineNumber = repoSecEvent.startLineNumber;
    artifactAlert.endLineNumber = repoSecEvent.endLineNumber;
    artifactAlert.lineContent = repoSecEvent.lineContent;
    artifactAlert.snippetContent = repoSecEvent.snippetContent;
    artifactAlert.fileName = repoSecEvent.fileName;
    artifactAlert.link = repoSecEvent.link;
    artifactAlert.pkgName = repoSecEvent.pkgName;
    artifactAlert.pkgManager = repoSecEvent.pkgManager;
    artifactAlert.filePath = repoSecEvent.filePath;
    artifactAlert.lockfile = repoSecEvent.lockfile;
    artifactAlert.correlatedSCAEvent = true;
    artifactAlert.severity = repoSecEvent.severity;
    artifactAlert.severityStr = repoSecEvent.severityStr;
    artifactAlert.originalSeverity = repoSecEvent.originalSeverity;
    artifactAlert.originalSeverityStr = repoSecEvent.originalSeverityStr;

    const newSRcollection = getUniqueSeverityReasonsBetweenTwoCollections(
      repoSecEvent.severityChangedReason,
      artifactAlert.severityChangedReason,
    );
    if (newSRcollection.length > 0) {
      artifactAlert.severityChangedReason = newSRcollection;
    }

    if (artifactRepoIssueId && correlatedRegistry) {
      //Update only if this issue was not updated
      const appId = repo.id;
      const issues = this.resultsHandler.appToIssuesMap.get(appId);
      if (issues) {
        const codeIssueForResHandle = issues.find(i => i.issueId === codeRepoIssueId);
        if (codeIssueForResHandle) {
          //Issue may have more sf then the code
          artifactAlert.corelateIssue = codeRepoIssueId;
          artifactAlert.correlatedRegistry = correlatedRegistry;
          let newSRcollection = getUniqueSeverityReasonsBetweenTwoCollections(
            codeIssueForResHandle.severityChangedReason,
            artifactAlert.severityChangedReason.filter(i => i.severityFactorType !== SeverityFactorType.Repo),
          );
          if (newSRcollection.length > 0) {
            codeIssueForResHandle.severityChangedReason = newSRcollection;
          }

          codeIssueForResHandle.correlatedIssueId = artifactRepoIssueId;
          codeIssueForResHandle.correlatedRegistry = correlatedRegistry;
        }
      }
    }
  }

  getCustomIssueId(unique: string, appId: string, pId: string) {
    return StringHelper.combineStrings(appId, pId, unique);
  }

  ConnectSbomDataToSbomEvent(secAlert: ExtendedSbomComponent, sbomAlerts: Map<string, ExtendedSbomComponent>) {
    try {
      const key = `${secAlert.name}@${secAlert.version}`;
      const item: ExtendedSbomComponent = sbomAlerts[key.toLowerCase()];
      if (item) {
        secAlert.blame = item.blame;
        secAlert.additionalInsight = item.additionalInsight;
        secAlert.pkgManager = item.pkgManager;
        secAlert.fileName = item.fileName;
        secAlert.scaValidator = item.scaValidator;
        secAlert.extraInfo = item.extraInfo;
        secAlert.dependencyGraphNodes = item.dependencyGraphNodes;
        secAlert.dependencyGraphEdges = item.dependencyGraphEdges;
        secAlert.triggerPackage = item.triggerPackage;
        secAlert.vulnerabilityCounts = item.vulnerabilityCounts;
        secAlert.vulnerabilityCountsArr = item.vulnerabilityCountsArr;
        return true;
      }
      return false;
    } catch (err) {
      logger.error(`Failed to run ConnectSbomDataToSbomEvent ${err}`);
    }
    return false;
  }

  private async reduceBlameRequestsForSBOMforPipelineScan(sbomEvents: SbomEvent[], repo: Repo) {
    try {
      if (sbomEvents.length === 0) {
        return;
      }
      if (!StatesHelper.Instance.isPipelineScan) {
        return;
      }

      let sbomEventCount = 0;
      const sbomEventsFromCache: SbomEvent[] = await this.cacheResolver.getSbomCache({ id: repo.id, idKey: "repoId", name: repo.fullName });

      const sbomAlertsMap = new Map();
      for (const event of sbomEventsFromCache) {
        for (const component of event.sbomHelper.extendedSbom.components) {
          const pkgName = adaptLibName(component.name);
          const key = `${pkgName}@${component.version}`;
          sbomAlertsMap.set(key, component);
        }
      }

      const found = [];
      const notFound = [];

      for (const event of sbomEvents) {
        for (const component of event.sbomHelper.extendedSbom.components) {
          try {
            sbomEventCount++;
            const pkgName = adaptLibName(component.name);
            const key = `${pkgName}@${component.version}`;
            const possibleSbomAlert = sbomAlertsMap.get(key);

            if (possibleSbomAlert) {
              const newComponent: ExtendedSbomComponent = JSON.parse(JSON.stringify(possibleSbomAlert));
              newComponent.askedOnce = true;
              newComponent.isOldEvent = true;
              found.push(newComponent);
              continue;
            } else {
              notFound.push(component);
            }
          } catch (err) {
            notFound.push(component);
            logger.error(`Failed add single sbom, repo: ${repo.fullName}, ${err}`);
          }
        }

        const finalArr = [...notFound, ...found];
        if (finalArr.length != event.sbomHelper.extendedSbom.components.length) {
          logger.error(
            `reduceBlameRequestsForSBOMforPipelineScan: number of events after process is different than the original alerts number. required number: ${event.sbomHelper.extendedSbom.components.length}, found matches length: ${found.length}, not found matches: ${notFound.length}, repo: ${repo.fullName}`,
          );
        }
        event.sbomHelper.extendedSbom.components = finalArr;
      }

      logger.info(
        `reduceBlameRequestsForSBOMforPipelineScan: reduced blame request for sbom alerts, original count: ${sbomEventCount}, reduced count: ${notFound.length}, sbomAlerts map length: ${sbomAlertsMap.size}, repo: ${repo.fullName}`,
      );
    } catch (err) {
      logger.error(`reduceBlameRequestsForSBOMforPipelineScan failed, err: ${err} `);
    }
  }

  private async reduceBlameRequestsForSCAforPipelineScan(securityEvents: SecurityEvent[], repo: Repo) {
    try {
      if (securityEvents.length === 0) {
        return [];
      }
      if (!StatesHelper.Instance.isPipelineScan) {
        return [];
      }

      const scaAlertsMap = new Map();
      const relevantAlerts = securityEvents.filter(
        i =>
          i.securityAlertType === SecurityAlertType.sca &&
          (i.securitySubTypeAlertType === SecurityAlertType.dockerFileVul || i.securitySubTypeAlertType === SecurityAlertType.Unknown),
      );

      const eventsFromCache = await this.getCodeRepoEvents(repo);
      for (const event of eventsFromCache) {
        //Only for ox trivy or container scanning
        const shouldProcess =
          (event.oxTool &&
            event.securityAlertType === SecurityAlertType.sca &&
            event.securitySubTypeAlertType === SecurityAlertType.Unknown) ||
          (event.oxTool &&
            event.securityAlertType === SecurityAlertType.sca &&
            event.securitySubTypeAlertType === SecurityAlertType.dockerFileVul);
        if (!shouldProcess) {
          continue;
        }
        if (!event.pkgName) {
          continue;
        }
        const pkgName = adaptLibName(event.pkgName);
        let key = `${pkgName}@${event.installedVersion}@${event.ruleId}@${event.originalFilName}`;

        const isSca = event.securityAlertType === SecurityAlertType.sca && event.securitySubTypeAlertType === SecurityAlertType.Unknown;
        if (StatesHelper.Instance.isMoovit && isSca) {
          key = pkgName;
        }

        scaAlertsMap.set(key, event);
      }

      logger.info(
        `reduceBlameRequestsForSCAforPipelineScan: found total ${securityEvents.length} alerts, and ${relevantAlerts?.length} relevant sca alerts, found from cache ${eventsFromCache.length} alerts and ${scaAlertsMap.size} relevant sca alerts. repo: ${repo.fullName}`,
      );

      const attached = new Set();
      const unattachedEvents = new Set();
      const found = [];
      for (const event of relevantAlerts) {
        if (!event.pkgName) {
          continue;
        }
        const pkgName = adaptLibName(event.pkgName);
        let scaKey = `${pkgName}@${event.installedVersion}@${event.ruleId}@${event.originalFilName}`;

        const isSca = event.securityAlertType === SecurityAlertType.sca && event.securitySubTypeAlertType === SecurityAlertType.Unknown;
        if (StatesHelper.Instance.isMoovit && isSca) {
          scaKey = pkgName;
        }

        const possibleScaAlert = scaAlertsMap.get(scaKey) as SecurityEvent;
        if (possibleScaAlert) {
          attached.add(event.uid);
          const copy = JSON.parse(JSON.stringify(event)) as SecurityEvent;
          copy.isOldEvent = true;
          if (copy?.blame?.askedOnce) {
            copy.blame.askedOnce = true;
          }
          logger.info(`reduceBlameRequestsForSCAforPipelineScan: found a match from cache, old issue: ${scaKey}, repo: ${repo.fullName}`);
          setSecEventFromDelta(repo, copy);
          found.push(copy);
          continue;
        }
        logger.info(
          `reduceBlameRequestsForSCAforPipelineScan: didn't find a match from cache, new issue: ${scaKey}, repo: ${repo.fullName}`,
        );
        unattachedEvents.add(scaKey);
      }

      const notFound = securityEvents.filter(i => !attached.has(i.uid));
      const finalList = [...found, ...notFound];

      if (finalList.length != securityEvents.length) {
        logger.error(
          `reduceBlameRequestsForSCAforPipelineScan: number of events after process is different than the original alerts number. required number: ${securityEvents.length}, found matches length: ${found.length}, not found matches: ${notFound.length}. repo: ${repo.fullName}`,
        );
      }

      logger.info(
        `reduceBlameRequestsForSCAforPipelineScan: reduced blame request for sca alerts, repo: ${repo.fullName}, original count: ${
          securityEvents.length
        }, reduced count: ${notFound.length}, found total ${attached.size} matches from cache, returned final list length: ${
          finalList.length
        }. scaAlertsMap keys: ${Array.from(scaAlertsMap.keys()).join(",")}`,
      );

      return finalList;
    } catch (err) {
      logger.error(`reduceBlameRequestsForSCAforPipelineScan failed, repo: ${repo.fullName}, err: ${err} `);
    }
    return [];
  }

  //Dont change the order of execution in this function
  private async setSecurityEvents(itemsForCash, execType: string) {
    let repoFullName = "";

    const repo: Repo = this?.appInfo?.repo?.code_repo;

    try {
      repoFullName = repo.fullName;

      if (this.appInfo.repo.code_repo.noneRelevantRepo) {
        logger.info(`skipping set security event to none relevant repo: ${repoFullName}`);
        return;
      }

      let allEvents: SecurityEvent[] = this.jsonHelper.lookupArrayVal(this.appInfo.repo, CodeRepoTypes[CodeRepoTypes.securityEvents]);
      if (allEvents.length == 0) {
        return;
      }

      const fromCash: SecurityEvent[] = [];
      let notFromCash: SecurityEvent[] = [];
      const uniqueExternalTools = new Set();
      allEvents.forEach(i => {
        if (!i.oxTool) {
          uniqueExternalTools.add(i.securityProvider);
        }

        if (i.fromCash) {
          fromCash.push(i);
        } else {
          notFromCash.push(i);
        }
      });

      if (notFromCash.length == 0) {
        logger.info(
          `no need to set sec event external service, sec events not from cash: ${notFromCash.length}, from cash: ${fromCash.length}, total: ${allEvents.length} for repo: ${repo.fullName}`,
        );
        return;
      }

      logger.info(
        `try set sec event: ${allEvents.length}, from cash: ${fromCash.length}, not from cash: ${notFromCash.length} repo: ${repo.fullName}, id: ${repo.repoId}`,
      );
      let securityAlerts = SecurityToolsHelper.removeDuplication(this.uuid, repoFullName, notFromCash);
      logger.info(
        `after remove duplication sec event: ${securityAlerts.length}, fromCash: ${fromCash.length}, notFromCash: ${notFromCash.length}, repo: ${repo.fullName}`,
      );

      //For pipeline only
      const pipeLineAlerts: SecurityEvent[] = await this.reduceBlameRequestsForSCAforPipelineScan(securityAlerts, repo);
      if (pipeLineAlerts) {
        if (pipeLineAlerts.length > 0) {
          securityAlerts = pipeLineAlerts;
        }
      }

      // security alerts are sortted twice since line number is modified by blame-service
      securityAlerts = sortBy(securityAlerts, ["fileName", "category", "ruleId", "startLineNumber"]);

      let shouldRunExtendedServices = true;
      if (isLocalDevelopment()) {
        shouldRunExtendedServices = process.env.RUN_BLAME ? true : false;
      }

      const codeRepoEventsFromCache: SecurityEvent[] = [];

      if (shouldRunExtendedServices) {
        if (StatesHelper.Instance.useLightBlame) {
          await this.lightBlameHelper.extendBlameSecurityEventsForSingleApp(securityAlerts, repo, "code security events", repo.fullName);
        } else {
          await this.blameHelper.extendBlameSecurityEventsForSingleApp(securityAlerts, repo, "code security events", repo.fullName);
        }

        securityAlerts = SecurityToolsHelper.removeDuplication(this.uuid, repoFullName, securityAlerts);
        securityAlerts = securityAlerts.filter(alert => !alert?.blame?.verifiedFp || !alert.oxTool);
        securityAlerts = sortBy(securityAlerts, ["fileName", "category", "ruleId", "startLineNumber"]);

        //Do this request in async to boost performance
        const proms = [];
        const p1 = this.secretValidationHelper.validateSecrets(securityAlerts, repo, "repo");
        const p3 = this.scaVerificationHelper.setScaValidator(securityAlerts, this);
        const p4 = this.handelAutoFixInfo(securityAlerts, this);

        proms.push(p1);
        proms.push(p3);
        proms.push(p4);
        await Promise.all(proms);

        await this.alertRecommendationHelper.setAlertRecommendation(securityAlerts, repo);
      }

      //Add the alerts from cash
      fromCash.forEach(i => {
        securityAlerts.push(i);
      });

      // // fill non success tools security events from cache
      this.ChangeFileNamesInfo(securityAlerts, repo);

      if (uniqueExternalTools.size > 0 && execType !== Constant.execType.duringScan) {
        const t = await this.connectBetweenSecExternalSecAlertsToOx(securityAlerts, codeRepoEventsFromCache, repo);
        if (t) {
          securityAlerts = t;
        }
      }

      const temp = await this.fillFailedSecurityTools(securityAlerts, repo, codeRepoEventsFromCache);
      if (temp) {
        if (temp.length > 0) {
          securityAlerts = temp;
        }
      }

      this.appInfo.repo[CodeRepoTypes[CodeRepoTypes.securityEvents]] = securityAlerts;

      itemsForCash.onlyOxEventsForCash = securityAlerts.filter(
        i =>
          i.oxTool ||
          i.collectedAsPartOfRepos ||
          i.securityProvider === Constant.Dependabot ||
          i.securityProvider === Constant.SnykCli ||
          i.securityProvider.includes(Constant.gitlabSecurityCenter),
      );

      StatesHelper.Instance.totalCodeSecurityAlertsAfterBlame += securityAlerts.length;
    } catch (err) {
      logger.error(`failed set security events in single application: ${repoFullName},  err: ${err}`);
    }
  }

  increaseFallbackStats(repo: Repo, fallbackStats: Dictionary<IFallbackStats>, toolName: string, field: keyof IFallbackStats) {
    try {
      if (!fallbackStats[toolName]) {
        fallbackStats[toolName] = new FallbackStats();
      }

      // logger.info(`increaseFallbackStats increase field: ${field}. tool: ${toolName},  before: ${fallbackStats[toolName][field]}`);
      fallbackStats[toolName][field]++;
      // logger.info(`increaseFallbackStats increase field: ${field}. tool: ${toolName},  after: ${fallbackStats[toolName][field]}`);
    } catch (error) {
      logger.error(`could not increase fallback stats for repo: ${repo.fullName}, org: ${this.orgName}, error: ${error}`);
    }
  }

  async fillFailedSecurityTools(currentSecEvents: SecurityEvent[], repo: Repo, codeRepoEventsFromCache: SecurityEvent[]) {
    //No need to run this flow for delta or pipeline as there are nothing to fix for tools
    if (StatesHelper.Instance.isPipelineScan) {
      return;
    }
    if (repo.isDelta) {
      return;
    }
    if (!StatesHelper.Instance.enableFallback) {
      return;
    }

    const fallbackStats: Dictionary<IFallbackStats> = {};

    //Add failed security events from disk DB by tool name (adding all events that failed)
    if (!codeRepoEventsFromCache.length) {
      codeRepoEventsFromCache = await this.getCodeRepoEvents(repo);
    }
    //Dont adjust the events if we didnt get the data from cash
    if (!codeRepoEventsFromCache) {
      logger.info(`enabled failedSecurityTools for repo: ${repo.fullName}, but no cash data so ignoring`);
      return;
    }
    if (codeRepoEventsFromCache.length === 0) {
      return;
    }

    logger.info(`codeRepoEventsFromCache length: ${codeRepoEventsFromCache.length} for repo: ${repo.fullName}`);

    if (repo.failedSecurityTools.size == 0) {
      logger.info(`failedSecurityTools has 0 length for repo: ${repo.fullName}`);
      return [];
    }

    logger.info(`failedSecurityTools repo: ${repo.fullName}, has failed security tools: ${[...repo.failedSecurityTools].join(", ")} `);

    const newSecEvent: SecurityEvent[] = [];

    //Remove all failed security events by tool name (adding all events that didn't failed)
    currentSecEvents.forEach(s => {
      try {
        const toolName = repo.fixSecurityToolsName(s.tool);
        this.increaseFallbackStats(repo, fallbackStats, toolName, "sent");
        const isFailed = repo.failedSecurityTools.has(toolName) || repo.failedSecurityTools.has(s.tool);
        if (!isFailed) {
          newSecEvent.push(s);
          this.increaseFallbackStats(repo, fallbackStats, toolName, "succeeded");
        } else {
          this.increaseFallbackStats(repo, fallbackStats, toolName, "failed");
        }
      } catch (err) {
        logger.error(`failedSecurityTools error while removing failed secEvents: ${repo.fullName}, org: ${this.orgName}, error: ${err}`);
        newSecEvent.push(s);
        this.increaseFallbackStats(repo, fallbackStats, s.tool, "succeeded");
      }
    });

    codeRepoEventsFromCache.forEach(s => {
      try {
        const toolName = repo.fixSecurityToolsName(s.tool);
        const isFailed = repo.failedSecurityTools.has(toolName) || repo.failedSecurityTools.has(s.tool);
        if (isFailed) {
          newSecEvent.push(s);
          this.increaseFallbackStats(repo, fallbackStats, toolName, "recovered");
        }
      } catch (err) {
        logger.error(`failedSecurityTools error while adding failed secEvents: ${repo.fullName}, org: ${this.orgName}, error: ${err}`);
        newSecEvent.push(s);
        this.increaseFallbackStats(repo, fallbackStats, s.tool, "recovered");
      }
    });

    Object.keys(fallbackStats).forEach(tool => {
      if (fallbackStats[tool].failed === 0) {
        delete fallbackStats[tool];
      }
    });

    logger.info(
      `Fallback stats for repo ${repo.fullName}: ${JSON.stringify(fallbackStats)}, failed security tools: ${Array.from(
        repo.failedSecurityTools,
      )}`,
    );

    Object.entries(fallbackStats).forEach(([tool, stats]) => {
      logger.info(
        `results failedSecurityTools for repo: ${repo.fullName}, org: ${this.orgName}, isDelta: ${
          repo.isDelta
        }, tool: ${tool}, stats ${JSON.stringify(stats)}`,
        {
          "ox-tool-name": tool,
          "retrieve-from-cache": stats.recovered > 0,
          "ox-tool-items-sent": stats.sent,
          "ox-tool-items-retrieve": stats.recovered,
        },
      );
    });
    return newSecEvent;
  }

  private ChangeFileNamesInfo(securityAlerts: SecurityEvent[], repo: Repo) {
    try {
      //Adjust in case balme cannot adjust it
      securityAlerts.forEach(i => {
        if (i.securityAlertType === SecurityAlertType.sca) {
          if (i.fileName.includes("package-lock.json")) {
            i.fileName = i.fileName.replace("package-lock.json", "package.json");
            i.filePath = i.filePath.replace("package-lock.json", "package.json");
          }
        }
      });
    } catch (err) {
      logger.error(`failed set ChangeFileNamesInfo for application: ${repo.fullName}, err: ${err}`);
    }
  }

  private async getCodeRepoEvents(repo: Repo): Promise<SecurityEvent[]> {
    const keyToLocalDB = "securityEvents";
    const totalTimer = TimeOp();
    totalTimer.start();
    let source = "none";
    let codeRepoEvents: SecurityEvent[] = [];

    try {
      const timer = TimeOp();
      timer.start();

      if (repo.hasSecurityEventsInDiskDB && StatesHelper.Instance.enableDiskDbFallback) {
        logger.info(`initializing diskDB for repo - ${repo.name}, repoId: ${repo.id}, orgId: ${this.orgName}`);
        const diskDb = new DiskDB();
        await diskDb.initialize({ uuid: this.uuid, orgId: this.orgName, repoId: String(repo.id) });
        logger.info(
          `repo diskDB has been initialized successfully repo - ${repo.name}, repoId: ${repo.id}, orgId: ${this.orgName}, path: ${diskDb.fullPath}`,
        );

        source = "diskDB";
        codeRepoEvents = await diskDb.get(keyToLocalDB);
        await diskDb.close();
        if (!codeRepoEvents) {
          codeRepoEvents = [];
        } else {
          logger.info(
            `got ${codeRepoEvents.length} codeRepoEvents from diskDB repo cache for repo: ${repo.fullName}, repoId: ${repo.id}, orgId: ${
              this.orgName
            },  keyToLocalDB: ${keyToLocalDB}, time took: ${timer.end()}`,
          );
        }
      } else {
        source = "mongoCache";
        codeRepoEvents = await this.cacheResolver.getFromCache<SecurityEvent>(
          { id: repo.id, idKey: "repoId", name: repo.fullName },
          Cache.SecurityEvents,
        );
        logger.info(
          `got ${codeRepoEvents.length} codeRepoEvents from mongo db repo cache for repo: ${repo.fullName}, repoId: ${repo.id}, orgId: ${
            this.orgName
          } keyToLocalDB: ${keyToLocalDB}, time took: ${timer.end()}`,
        );
        if (StatesHelper.Instance.enableDiskDbFallback) {
          logger.info(`initializing diskDB for repo - ${repo.name}, repoId: ${repo.id}, orgId: ${this.orgName}`);
          const diskDb = new DiskDB();
          await diskDb.initialize({ uuid: this.uuid, orgId: this.orgName, repoId: String(repo.id) });
          logger.info(
            `repo diskDB has been initialized successfully repo - ${repo.name}, repoId: ${repo.id}, orgId: ${this.orgName}, path: ${diskDb.fullPath}`,
          );

          timer.start();
          await diskDb.set(keyToLocalDB, codeRepoEvents);
          await diskDb.close();
          logger.info(
            `saved ${codeRepoEvents.length} codeRepoEvents in disk db for repo: ${repo.fullName}, repoId: ${repo.id}, orgId: ${
              this.orgName
            }, time took: ${timer.end()}`,
          );
          repo.hasSecurityEventsInDiskDB = true;
        }
      }

      codeRepoEvents.forEach(i => {
        setSecEventFromDelta(repo, i);
      });
      return codeRepoEvents;
    } catch (error) {
      logger.error(
        `Could not get codeRepoEvents from cache for the repo - ${repo.fullName}, source: ${source}, repoId: ${repo.id}, orgId: ${this.orgName}, keyToLocalDB: ${keyToLocalDB}, error: ${error}`,
      );
    } finally {
      logger.info(
        `getCodeRepoEvents total execution time - ${totalTimer.end()} for the repo - ${
          repo.fullName
        }, source: ${source}, codeRepoEvents length: ${codeRepoEvents.length}, repoId: ${repo.id}, orgId: ${
          this.orgName
        }, keyToLocalDB: ${keyToLocalDB}`,
      );
    }
    return [];
  }

  private async connectBetweenSecExternalSecAlertsToOx(
    securityAlertsFromExternalTools: SecurityEvent[],
    codeRepoEventsFromCache: SecurityEvent[],
    repo: Repo,
  ) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      const numberOfConnectsPerTool = {};

      const shouldRun =
        StatesHelper.Instance.enableDiskDbFallback ||
        StatesHelper.Instance.useAlertAggregation ||
        StatesHelper.Instance.orgName === "org_GJJM1J0PcJ8kwLSa" ||
        StatesHelper.Instance.orgName === "org_9NF1n5UBlc0auIHO" ||
        StatesHelper.Instance.orgName === "org_US3qDZlQqt1VzoxB";

      if (!shouldRun) {
        return securityAlertsFromExternalTools;
      }

      let codeRepoEvents: SecurityEvent[] = codeRepoEventsFromCache;
      if (!codeRepoEventsFromCache.length) {
        codeRepoEvents = await this.getCodeRepoEvents(repo);
      }

      const allAlerts = [...securityAlertsFromExternalTools, ...codeRepoEvents];

      const aggSecurityAlerts = SecurityToolsHelper.removeDuplication(this.uuid, repo.fullName, allAlerts);
      const finalRes: SecurityEvent[] = [];

      aggSecurityAlerts.forEach(secAlert => {
        try {
          //If ox tool and was not aggergated by remove duplication then ignore
          //as it was already updated
          if (secAlert.oxTool && secAlert.securityProvidersArr.length < 2) {
            return;
          }

          const appId = repo.id;
          const scaUnique = getUniqueInfoForAggregation(secAlert);
          let codeRepoIssueId = "";
          if (secAlert.securityAlertType === SecurityAlertType.secrets) {
            codeRepoIssueId = this.getCustomIssueId(scaUnique, repo.id, "oxPolicy_securityScan_secrets_1");
          } else if (secAlert.securityAlertType === SecurityAlertType.sast) {
            codeRepoIssueId = this.getCustomIssueId(scaUnique, repo.id, "oxPolicy_securityScan_205");
          } else if (
            secAlert.securityAlertType === SecurityAlertType.sca &&
            secAlert.securitySubTypeAlertType === SecurityAlertType.Unknown
          ) {
            codeRepoIssueId = this.getCustomIssueId(scaUnique, repo.id, "oxPolicy_securityScan_120");
          } else if (secAlert.securityAlertType === SecurityAlertType.iac) {
            codeRepoIssueId = this.getCustomIssueId(scaUnique, repo.id, "oxPolicy_securityScan_55");
          } else if (secAlert.securitySubTypeAlertType === SecurityAlertType.dockerFileVul) {
            codeRepoIssueId = this.getCustomIssueId(scaUnique, repo.id, "oxPolicy_deployment_221");
          } else {
            finalRes.push(secAlert);
            return;
          }

          const issues = this.resultsHandler.appToIssuesMap.get(appId);
          let connected = false;
          if (issues) {
            const codeIssueForResHandle = issues.find(i => i.issueId === codeRepoIssueId);
            if (codeIssueForResHandle) {
              //Calc unique sources
              const uniqueSource = new Set();
              if (codeIssueForResHandle.sources) {
                codeIssueForResHandle.sources.forEach(s => uniqueSource.add(s));
              }
              secAlert.securityProvidersArr.forEach(s => {
                if (numberOfConnectsPerTool[s]) {
                  numberOfConnectsPerTool[s] = numberOfConnectsPerTool[s] + 1;
                } else {
                  numberOfConnectsPerTool[s] = 1;
                }
                uniqueSource.add(s);
              });

              //Update, the > 1 is just for sanity
              if (uniqueSource.size > 1) {
                connected = true;
                codeIssueForResHandle.sources = Array.from(uniqueSource) as string[];
              }
            }
          }

          if (!connected) {
            finalRes.push(secAlert);
          }
        } catch (err) {
          logger.error(`failed connectBetweenSecExternalSecAlertsToOx in single alert for application: ${repo.fullName}, err: ${err}`);
        }
      });

      if (Object.keys(numberOfConnectsPerTool).length > 0) {
        logger.info(
          `finish connectBetweenSecExternalSecAlertsToOx for repo: ${repo.fullName}, finalSecEvents: ${
            finalRes.length
          }, before consolidation: ${securityAlertsFromExternalTools.length}, numberOfConnectsPerTool: ${JSON.stringify(
            numberOfConnectsPerTool,
          )}`,
        );
        return finalRes;
      } else {
        return securityAlertsFromExternalTools;
      }
    } catch (err) {
      logger.error(`failed connectBetweenSecExternalSecAlertsToOx application: ${repo.fullName}, err: ${err}`);
    }
    return securityAlertsFromExternalTools;
  }

  private fixPackageManager(): void {
    const repoName = this?.appInfo?.repo?.code_repo?.fullName;
    try {
      const securityEvents: SecurityEvent[] = this.jsonHelper.lookupArrayVal(
        this.appInfo.repo,
        CodeRepoTypes[CodeRepoTypes.securityEvents],
      );
      const securityEventsMap = securityEvents.reduce<Map<string, SecurityEvent>>((map, event) => map.set(event.ruleId, event), new Map());
      const sbomVulnerabilities: SbomVulnerability[] =
        this.appInfo.repo[ArtifactoryTypes[ArtifactoryTypes.sbom]]?.map((sbomEvent: SbomEvent) => sbomEvent.sbom.vulnerabilities).flat() ||
        [];

      for (const sbomVulnerability of sbomVulnerabilities) {
        try {
          if (!sbomVulnerability?.affects?.length) {
            continue;
          }
          const event = securityEventsMap.get(sbomVulnerability.id);
          if (!event) {
            continue;
          }
          const pkgManager = extractPkgManagerFromPurl(sbomVulnerability?.affects[0].ref);
          event.pkgManager = pkgManager;
        } catch (err) {
          logger.error(`Failed to fix package manager for ${sbomVulnerability.id} in ${repoName}: ${err}`);
        }
      }
    } catch (err) {
      logger.error(`Failed to fix package manager for ${repoName}: ${err}`);
    }
  }

  cleanMemory() {
    try {
      this.appInfo.repo[ArtifactoryTypes[ArtifactoryTypes.sbom]] = [];
      this.appInfo.repo[CodeRepoTypes[CodeRepoTypes.securityEvents]] = [];
    } catch (err) {
      logger.info(`failed clean memory, err: ${err}`);
    }
  }

  async handleSbomForRepoCode(itemsForCash) {
    try {
      if (this.appInfo.repository.sbomHandled) {
        return;
      }
      this.appInfo.repository.sbomHandled = true;

      const repo: Repo = this?.appInfo.repo?.code_repo;
      if (!repo) {
        return;
      }
      if (repo.isDelta) {
        return;
      }

      const sbomInfoEvents: SbomEvent[] = this.appInfo.repo[ArtifactoryTypes[ArtifactoryTypes.sbom]];
      if (sbomInfoEvents == undefined) {
        return;
      }
      if (sbomInfoEvents.length == 0) {
        return;
      }

      await this.reduceBlameRequestsForSBOMforPipelineScan(sbomInfoEvents, repo);

      const sbomInfo: SbomEvent = sbomInfoEvents[0];
      const p = this.handleGoogleOpenSourceInsights(sbomInfoEvents, repo);
      let p2;
      if (StatesHelper.Instance.useLightBlame) {
        p2 = this.lightBlameHelper.extendBlameSBOMForSingleApp(sbomInfo.sbomHelper.extendedSbom.components, sbomInfo, this, repo.fullName);
      } else {
        p2 = this.blameHelper.extendBlameSBOMForSingleApp(sbomInfo.sbomHelper.extendedSbom.components, sbomInfo, this, repo.fullName);
      }

      await Promise.all([p, p2]);

      await this.scaVerificationHelper.setScaValidatorSBOM(sbomInfo?.sbomHelper?.extendedSbom?.components, this);

      itemsForCash.sbomInfo = sbomInfo;
    } catch (err) {
      logger.error(`failed handle sbom blame info for repo: ${this?.appInfo?.repo?.code_repo?.fullName}, err: ${err}`);
    }
  }

  @PerformanceTelemetry("Cache")
  async saveCodeSecInCashForDeltaScan(onlyOxEvents: SecurityEvent[]) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }
      if (this.appInfo.repo == null) {
        return;
      }
      const repo: Repo = this?.appInfo?.repo.code_repo;
      if (!repo) {
        return;
      }
      await this.cacheResolver.setForCache<SecurityEvent>(
        { id: repo.id, idKey: "repoId", name: repo.fullName },
        onlyOxEvents,
        Cache.SecurityEvents,
      );
    } catch (err) {
      logger.error(`failed save sbom cash repo: ${this?.appInfo?.repo?.code_repo?.fullName}, err: ${err}`);
    }
  }

  @PerformanceTelemetry("Cache")
  async saveSbomInCacheForDeltaScan(sbomInfo: SbomEvent) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }
      if (this.appInfo.repo == null) {
        return;
      }
      const repo: Repo = this?.appInfo?.repo.code_repo;
      if (!repo) {
        return;
      }
      if (!sbomInfo) {
        return;
      }

      const safetyCheckForRam = sbomInfo.sbomHelper.extendedSbom.components.filter(
        i => i.dependencyGraphEdges?.length > 0 || i.dependencyGraphNodes?.length > 0,
      );
      if (safetyCheckForRam.length > 0) {
        logger.error(`something went wrong, saving sbom with graph data to sbom cash repo: ${this?.appInfo?.repo?.code_repo?.fullName}`);
      }

      await this.cacheResolver.setSbomCache({ id: repo.id, idKey: "repoId", name: repo.fullName }, sbomInfo);
    } catch (err) {
      logger.error(`failed save sbom cash repo: ${this?.appInfo?.repo?.code_repo?.fullName}, err: ${err}`);
    }
  }

  async handleGoogleOpenSourceInsights(sbomData: SbomEvent[], repo: Repo) {
    try {
      const googleOpenSourceInsightsHelper = new GoogleOpenSourceInsightsHelper(this.openSourceInfoQueue, this.orgName, this.uuid);
      await googleOpenSourceInsightsHelper.setApplicationSbomData(repo, sbomData);
    } catch (err) {
      logger.error(`failed handle google open source insights repo: ${this?.appInfo?.repo?.code_repo?.fullName}, err: ${err}`);
    }
  }

  async saveSbomInfo() {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }
      await this.saveSbomFromCodeForDownload();
      await this.saveSbomFromCodeForAppScreen();
      await this.saveSbomToLocalDB();
    } catch (err) {
      logger.error(`failed save all sbom in mongo, err: ${err}`);
    }
  }

  private async mergeSbomAndDependencyGraphInfo() {
    let sboms: ExtendedSbomComponent[] = [];
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      sboms = (this.appInfo.repo[ArtifactoryTypes[ArtifactoryTypes.sbom]] as SbomEvent[])
        ?.map(i => i.sbomHelper.extendedSbom.components)
        ?.flat();

      if (!sboms?.length) {
        return;
      }

      const dependencyGraphsMap = sboms.reduce<Map<string, DependencyGraph>>((acc, sbom) => {
        if (sbom.dependencyGraphEdges?.length || sbom.dependencyGraphNodes?.length) {
          acc.set(sbom.triggerPackage, this.extractDependencyGraphObj(sbom));
        }
        return acc;
      }, new Map<string, DependencyGraph>());

      const securityEvents: SecurityEvent[] = this.appInfo.repo?.securityEvents || [];

      for (const sbom of sboms) {
        //Set vulnerability counts for sbom
        try {
          const relatedSecurityEvents = securityEvents.filter(
            event => `${event.pkgName}@${event.installedVersion}` === `${sbom.name}@${sbom.version}`,
          );
          if (relatedSecurityEvents.length) {
            sbom.vulnerabilityCounts = {};
            for (const securityEvent of relatedSecurityEvents) {
              const severity = securityEvent.originalSeverityStr?.toLowerCase();
              if (!severity) {
                logger.error(`cannot find severity for: ${securityEvent.pkgName}_${securityEvent.installedVersion}`);
                continue;
              }
              sbom.vulnerabilityCounts[severity] = (sbom.vulnerabilityCounts[severity] || 0) + 1;
            }
            const vulnerabilityCountsArr = Object.entries(sbom.vulnerabilityCounts).map(([severity, count]) => ({
              severity: getSeverityFromStr(severity).toString(),
              count,
            }));
            sbom.vulnerabilityCountsArr = vulnerabilityCountsArr;
          }
        } catch (err) {
          logger.error(
            `failed set vulnerability counts for single lib: ${sbom.name}@${sbom.version}, repo: ${this.appInfo.repo.code_repo.fullName}, err: ${err}`,
          );
        }
        //Add some stats
        if (!dependencyGraphsMap.has(sbom.triggerPackage)) {
          StatesHelper.Instance.scanInfoStats.noGraph++;
        }
      }

      const repoName = this.appInfo.repo.code_repo.fullName;
      const onlySca = securityEvents.filter(i => i.securityAlertType === SecurityAlertType.sca);

      if (!dependencyGraphsMap.size) {
        logger.info(`no dep G for repo: ${repoName}`);
        return;
      }
      if (onlySca.length) {
        this.markGraphVulnerableNodes(dependencyGraphsMap, onlySca, repoName);
      }
      await this.resultsHandler.saveDependencyGraphs(repoName, [...dependencyGraphsMap.values()]);
    } catch (err) {
      logger.error(`failed merge sbom and dependency graph info repo ${this.appInfo.repo.code_repo.fullName}, err: ${err}`);
    } finally {
      this.clearSbomDependencyGraphMem(sboms);
    }
  }

  clearSbomDependencyGraphMem(sboms) {
    try {
      if (!sboms) {
        return;
      }
      sboms.forEach(item => {
        item.dependencyGraphNodes = [];
        item.dependencyGraphEdges = [];
      });
    } catch (err) {
      logger.error(`failed clear sbom dependency graphMem repo ${this.appInfo.repo.code_repo.fullName}, err: ${err}`);
    }
  }

  private markGraphVulnerableNodes(
    dependencyGraphsMap: Map<string, DependencyGraph>,
    securityEvents: SecurityEvent[],
    repoName: string,
  ): void {
    for (const event of securityEvents) {
      try {
        const vulnerableNodeName = `${event.pkgName}@${event.installedVersion}`;

        // logger.info(
        //   `vulnerableNodeName: ${vulnerableNodeName}, triggerPackage: ${event?.blame?.triggerPackage}, json: ${JSON.stringify(
        //     event,
        //   )}`,
        // );

        if (!event?.blame?.triggerPackage) {
          //logger.info(`no trigger pkg vulnerableNodeName: ${vulnerableNodeName}`);
          continue;
        }

        const triggerPackage = `${event.blame.triggerPackage.name}@${event.blame.triggerPackage.version}`;

        let graph = dependencyGraphsMap.get(triggerPackage);
        if (!graph) {
          //logger.info(`no graph for trigger pkg:${triggerPackage} vulnerableNodeName: ${vulnerableNodeName}`);
          continue;
        }

        event.graphNodesCount = graph.nodes.length;
        let node = graph.nodes.find(node => node.fullName === vulnerableNodeName);
        if (!node) {
          continue;
        }

        node.vulnerable = true;
        node.issues[event.severityStr?.toLowerCase()]++;
      } catch (err) {
        logger.error(`failed mark all graph vulnerable nodes ${repoName}, err: ${err}`);
      }
    }
  }

  async saveSbomToLocalDB() {
    try {
      const app = this;
      const sbomInfo: SbomEvent[] = app.appInfo.repo[ArtifactoryTypes[ArtifactoryTypes.sbom]] as SbomEvent[];

      if (!sbomInfo) {
        return;
      }
      if (sbomInfo.length == 0) {
        return;
      }

      const sbomComponent: ExtendedSbomComponent[] = sbomInfo.map(i => i.sbomHelper.extendedSbom.components).flat();

      const repo: Repo = this.appInfo.repo.code_repo;

      const session = {
        uuid: this.uuid,
        orgId: this.orgName,
      };
      const db = scanDiskDB();
      await db.initialize(session);

      this.keyToLocalDB = `${repo.name}/${uuidGenerator.v4()}`;

      await db.set().execute(this.keyToLocalDB, sbomComponent);
    } catch (err) {
      logger.error(`failed save all sbom data on disk repo: ${this.appInfo.repo.code_repo.fullName}, err: ${err}`);
    }
  }

  async getSbomDataFromLocalDB() {
    try {
      if (!this.keyToLocalDB) {
        return [];
      }

      const session = {
        uuid: this.uuid,
        orgId: this.orgName,
      };
      const db = scanDiskDB();
      await db.initialize(session);

      const res = (await db.get().execute(this.keyToLocalDB)) as any;
      if (!res) {
        return [];
      }
      return res;
    } catch (err) {
      logger.error(`failed save all sbom data on disk repo: ${this.appInfo.repo.code_repo.fullName}, err: ${err}`);
    }
    return [];
  }

  async saveSbomFromCodeForAppScreen() {
    try {
      const sbomMongoDocuments: SbomMongoDocument[] = [];
      const repo: Repo = this.appInfo.repo.code_repo;
      const app = this;

      try {
        const sbomInfo: SbomEvent[] = app.appInfo.repo[ArtifactoryTypes[ArtifactoryTypes.sbom]] as SbomEvent[];

        if (!sbomInfo) {
          return;
        }
        if (sbomInfo.length == 0) {
          return;
        }

        let sbomComponent: ExtendedSbomComponent[] = sbomInfo.map(i => i.sbomHelper.extendedSbom.components).flat();
        const securityEvents: SecurityEvent[] = app?.appInfo?.repo?.securityEvents || [];

        if (isDevelopment() || isLocalDevelopment()) {
          sbomComponent = sbomComponent.filter(comp => comp.purl);
        }

        sbomComponent.forEach(i => {
          try {
            const sbomMongoDocument: SbomMongoDocument = new SbomMongoDocument();
            sbomMongoDocument.source = "Repository";
            sbomMongoDocument.scanId = this.uuid;
            sbomMongoDocument.libraryVersion = i.version;
            sbomMongoDocument.appType = repo.type;
            sbomMongoDocument.libraryName = i.name;
            sbomMongoDocument.requestId = `${i.pkgManager}_${i.name}`;
            sbomMongoDocument.libForSearch = `${i.name}@${i.version}`;
            sbomMongoDocument.pkgManager = i.pkgManager || "N/A";
            sbomMongoDocument.libId = `${i.pkgManager}|${i.name}|${i.version}`;
            sbomMongoDocument.pkgName = getPkgName(i) || sbomMongoDocument.libraryName;
            sbomMongoDocument.appLink = repo.link;

            //Set file name
            let fileName = i.fileName;
            sbomMongoDocument.location = i.fileName;
            if (i.blame) {
              if (i.blame.fileName) {
                sbomMongoDocument.location = i.blame.fileName;
                fileName = i.blame?.fileName;
              }
              if (i.blame.startLineNumber) {
                if (i.blame.startLineNumber != -1) {
                  sbomMongoDocument.location = `${fileName} line: ${i.blame.startLineNumber}`;
                  sbomMongoDocument.locationLink = repo.fileLink + fileName + repo.linkFilePreffix + i.blame.startLineNumber;
                }
              }
              if (i.blame.dependencyChain) {
                sbomMongoDocument.dependencyLevel = Math.max(i.blame.dependencyChain.length - 1, 0);
              }
            }
            sbomMongoDocument.language = i.blame?.language || "N/A";

            //Save only the lic names
            let isNA = false;
            const licenses = i.licenses.map(i => i.expression);
            licenses.forEach(i => {
              if (i) {
                if (i !== "non-standard") {
                  sbomMongoDocument.licenses.push(i);
                }
              }
            });
            if (sbomMongoDocument.licenses.length == 0) {
              sbomMongoDocument.licenses.push("N/A");
              isNA = true;
            }

            sbomMongoDocument.appName = app.appInfo.repo.code_repo.fullName;
            sbomMongoDocument.appId = app.appInfo.repo.code_repo.id;
            // sbomMongoDocument.tags = app.appInfo.repo.code_repo.appTags;
            sbomMongoDocument.dependencyType = i.blame?.dependencyType
              ? StringHelper.capitalizeFirstLetter(getDependencyType(i.blame.dependencyType))
              : "Unknown";
            if (i.blame) {
              sbomMongoDocument.commit = {
                commitedAt: i.blame.commitDate,
                committerName: i.blame.commiterName,
                committerEmail: i.blame.commiterEmail,
              };
            }
            if (i.additionalInsight) {
              sbomMongoDocument.pkgManagerLink = i.additionalInsight?.linkToActualSite;
              sbomMongoDocument.latestVersion = {
                version: i.additionalInsight?.latestVer?.version,
                publishedAt: i.additionalInsight?.latestVer?.timeStr,
              };
              if (i.additionalInsight.projectInfo) {
                sbomMongoDocument.projectContributorsCount = i.additionalInsight?.projectInfo?.contributors;
                sbomMongoDocument.libLink = i.additionalInsight.projectInfo.Homepage ? i.additionalInsight.projectInfo.Homepage : "";
                sbomMongoDocument.stars = i.additionalInsight.projectInfo?.StarsCount ? i.additionalInsight.projectInfo?.StarsCount : -1;
                sbomMongoDocument.forks = i.additionalInsight.projectInfo.ForksCount ? i.additionalInsight.projectInfo?.ForksCount : -1;

                sbomMongoDocument.isDeprecated = i.isDeprecated;
                sbomMongoDocument.notPopular = i.notPopular;
                sbomMongoDocument.notImported = i.notImported;
                sbomMongoDocument.notUpdated = i.notUpdated != undefined ? i.notUpdated : false;
                sbomMongoDocument.licenseIssue = i.licenseIssue != undefined ? i.licenseIssue : false;
                if (isNA) {
                  sbomMongoDocument.licenseIssue = false;
                }

                if (i.additionalInsight?.currentVer?.timeStr) {
                  sbomMongoDocument.usedVersionReleaseDate = new Date(i.additionalInsight.currentVer.timeStr);
                }
              }
              sbomMongoDocument.downloads = i.additionalInsight.downloads ? i.additionalInsight.downloads : -1;
              sbomMongoDocument.copyWriteInfo = i.copyRight ? i.copyRight : ["N/A"];
              sbomMongoDocument.copyWriteInfoLink = i.additionalInsight.copyWriteInfoLink ? i.additionalInsight.copyWriteInfoLink : "";
            }
            if (i.extraInfo) {
              sbomMongoDocument.extraInfo = i.extraInfo;
            }
            sbomMongoDocument.triggerPackage = i.triggerPackage;
            sbomMongoDocument.languageInfo = i.blame?.runtime?.languageInfo;
            sbomMongoDocument.codeReference = "used in code";

            this.setSbomDocSevEvents(securityEvents, i.name, sbomMongoDocument, i, repo);

            //for sbom PackageInfo filter
            let packageInfo: SbomPackageInfo[] = [];
            if (sbomMongoDocument.isDeprecated) packageInfo.push(SbomPackageInfo.Deprecated);
            if (sbomMongoDocument.notPopular) packageInfo.push(SbomPackageInfo.NotPopular);
            if (sbomMongoDocument.notImported) packageInfo.push(SbomPackageInfo.NotUsed);
            if (sbomMongoDocument.notUpdated) packageInfo.push(SbomPackageInfo.NotUpdated);
            if (sbomMongoDocument.licenseIssue) packageInfo.push(SbomPackageInfo.UnapprovedLicense);
            if (sbomMongoDocument.hasVulnerabilities) packageInfo.push(SbomPackageInfo.HasVulnerabilities);
            sbomMongoDocument.packageInfo = packageInfo;

            StatesHelper.Instance.savedSbomsFromCode++;

            if (isDevelopment()) {
              const objSize = checkObjectSize(sbomMongoDocument);
              //Bigger then in mb
              if (objSize > 5) {
                logger.warn(`huge sbom repository object size: ${objSize}, repo: ${repo.fullName}`);
              }
            }

            sbomMongoDocuments.push(sbomMongoDocument);
          } catch (err) {
            logger.error(`failed save single sbom lib, repo: ${app.appInfo.repo.fullName}, err: ${err}`, err);
          }
        });
      } catch (err) {
        logger.error(`failed save all sboms libs for repo: ${app.appInfo.repo.fullName}, err: ${err}`);
      }

      if (sbomMongoDocuments.length > 0) {
        const startTime = Date.now();
        await this.resultsHandler.addSboms(sbomMongoDocuments);
        logger.info(`Saved code sbom for repo ${repo.name} into mongo (${Date.now() - startTime}ms)`);
      }
    } catch (err) {
      logger.error(`failed save sbom application for app screen, err: ${err}`);
    }
  }

  private extractDependencyGraphObj(sbomComponent: ExtendedSbomComponent): DependencyGraph {
    return {
      appId: this.appInfo.repo.code_repo.id,
      scanId: this.uuid,
      libName: sbomComponent.name,
      libVersion: sbomComponent.version,
      libForSearch: sbomComponent.triggerPackage,
      nodes: sbomComponent.dependencyGraphNodes,
      edges: sbomComponent.dependencyGraphEdges,
    };
  }

  @PerformanceTelemetry()
  async saveSbomFromRegistryForAppScreen() {
    try {
      const app = this;
      let sbomMongoDocuments: SbomMongoDocument[] = [];
      const uniqueLibsVerMap: Record<string, SbomMongoDocument> = {};

      try {
        const registryImage: ImageInfo[] = app?.appInfo?.artifactory?.registryImage;
        if (!registryImage) {
          return;
        }

        for (const imageObj of app.appInfo.artifactory.registryImage) {
          await AsyncTracker.runWithAsyncTracker(async () => {
            AsyncTracker.setValue("ox-image-name", imageObj.image.name);
            AsyncTracker.setValue("ox-image-id", imageObj.image.imageDigest);

            const sbomComponents = imageObj.sbomEvents.map(i => i.sbomHelper.extendedSbom.components).flat();
            const repo: Repo = this.appInfo.repo.code_repo;
            const containerSecurityAlerts = this?.appInfo?.artifactory?.securityEvents ? this?.appInfo?.artifactory?.securityEvents : [];

            logger.info(
              `try save sbom for all images from registry for app: ${this.appInfo.repo.code_repo.fullName}, image: ${imageObj.image.name}, sbomComponents: ${sbomComponents.length}`,
            );

            sbomComponents.forEach(i => {
              try {
                //Set artifact info
                const artifactInSbomLib = new ArtifactInSbomLib();
                artifactInSbomLib.os = imageObj?.image?.os;
                artifactInSbomLib.osVersion = imageObj?.image?.osVersion;
                artifactInSbomLib.baseImage = imageObj?.image?.baseImage?.repo || "";
                artifactInSbomLib.baseImageVersion = imageObj?.image?.baseImage?.tag || "";
                artifactInSbomLib.image = imageObj?.image?.name || "";
                artifactInSbomLib.imageLink = imageObj?.image?.link || "";
                artifactInSbomLib.imageCreatedAt = imageObj?.image?.imagePushedAt || "";
                artifactInSbomLib.registryName = imageObj?.image?.cloudEnv || "";
                artifactInSbomLib.sha = imageObj?.image?.imageDigestWithoutPrefix || "";
                artifactInSbomLib.layer = i.layerId;

                const key = `${i.name}_${i.version}`;
                if (uniqueLibsVerMap[key]) {
                  const item = uniqueLibsVerMap[key];
                  item.artifactInSbomLibs.push(artifactInSbomLib);
                  return;
                }

                const sbomMongoDocument = new SbomMongoDocument();

                sbomMongoDocument.source = "Registry";
                sbomMongoDocument.scanId = this.uuid;
                sbomMongoDocument.libraryName = i.name;
                sbomMongoDocument.libraryVersion = i.version;
                sbomMongoDocument.appType = repo.type;
                sbomMongoDocument.requestId = `${i.pkgManager}_${i.name}`;
                sbomMongoDocument.libForSearch = `${i.name}@${i.version}`;
                sbomMongoDocument.appId = this.appInfo.repo.code_repo.id;
                sbomMongoDocument.pkgManager = i.pkgManager || "N/A";
                sbomMongoDocument.pkgName = getPkgName(i) || sbomMongoDocument.libraryName;
                sbomMongoDocument.libId = `${sbomMongoDocument.pkgManager}|${sbomMongoDocument.libraryName}|${sbomMongoDocument.libraryVersion}`;
                sbomMongoDocument.appLink = repo.link;

                sbomMongoDocument.appName = app.appInfo.repo.code_repo.fullName;
                sbomMongoDocument.appId = app.appInfo.repo.code_repo.id;
                // sbomMongoDocument.tags = app.appInfo.repo.code_repo.appTags;
                sbomMongoDocument.dependencyType = i.blame?.dependencyType
                  ? StringHelper.capitalizeFirstLetter(getDependencyType(i.blame.dependencyType))
                  : "Unknown";
                if (i.blame) {
                  sbomMongoDocument.commit = {
                    commitedAt: i.blame.commitDate,
                    committerName: i.blame.commiterName,
                    committerEmail: i.blame.commiterEmail,
                  };
                }

                //Save only the lic names
                let isNA = false;
                const licenses = i.licenses.map(i => i.expression);
                licenses.forEach(i => {
                  if (i) {
                    if (i !== "non-standard") {
                      sbomMongoDocument.licenses.push(i);
                    }
                  }
                });
                if (sbomMongoDocument.licenses.length == 0) {
                  sbomMongoDocument.licenses.push("N/A");
                  isNA = true;
                }

                if (i.additionalInsight) {
                  sbomMongoDocument.pkgManagerLink = i.additionalInsight?.linkToActualSite;
                  sbomMongoDocument.latestVersion = {
                    version: i.additionalInsight?.latestVer?.version,
                    publishedAt: i.additionalInsight?.latestVer?.timeStr,
                  };
                  if (i.additionalInsight.projectInfo) {
                    sbomMongoDocument.projectContributorsCount = i.additionalInsight?.projectInfo?.contributors;
                    sbomMongoDocument.libLink = i.additionalInsight.projectInfo.Homepage ? i.additionalInsight.projectInfo.Homepage : "";
                    sbomMongoDocument.stars = i.additionalInsight.projectInfo?.StarsCount
                      ? i.additionalInsight.projectInfo?.StarsCount
                      : -1;
                    sbomMongoDocument.forks = i.additionalInsight.projectInfo.ForksCount ? i.additionalInsight.projectInfo?.ForksCount : -1;

                    sbomMongoDocument.isDeprecated = i.isDeprecated;
                    sbomMongoDocument.notPopular = i.notPopular;
                    sbomMongoDocument.notImported = i.notImported;
                    sbomMongoDocument.notUpdated = i.notUpdated != undefined ? i.notUpdated : false;
                    sbomMongoDocument.licenseIssue = i.licenseIssue != undefined ? i.licenseIssue : false;
                    if (isNA) {
                      sbomMongoDocument.licenseIssue = false;
                    }

                    if (i.additionalInsight?.currentVer?.timeStr) {
                      sbomMongoDocument.usedVersionReleaseDate = new Date(i.additionalInsight.currentVer.timeStr);
                    }
                  }
                  sbomMongoDocument.downloads = i.additionalInsight.downloads ? i.additionalInsight.downloads : -1;
                  sbomMongoDocument.copyWriteInfo = i.copyRight ? i.copyRight : ["N/A"];
                  sbomMongoDocument.copyWriteInfoLink = i.additionalInsight.copyWriteInfoLink ? i.additionalInsight.copyWriteInfoLink : "";
                }

                let fileName = i.fileName;
                sbomMongoDocument.location = i.fileName;
                if (i.blame) {
                  if (i.blame.fileName) {
                    sbomMongoDocument.location = i.blame.fileName;
                    fileName = i.blame?.fileName;
                  }
                  if (i.blame.startLineNumber) {
                    if (i.blame.startLineNumber != -1) {
                      sbomMongoDocument.location = `${fileName} line: ${i.blame.startLineNumber}`;
                      sbomMongoDocument.locationLink = repo.fileLink + fileName + repo.linkFilePreffix + i.blame.startLineNumber;
                    }
                  }
                  if (i.blame.dependencyChain) {
                    sbomMongoDocument.dependencyLevel = Math.max(i.blame.dependencyChain.length - 1, 0);
                  }
                }
                sbomMongoDocument.language = i.blame?.language || "N/A";

                if (i.extraInfo) {
                  sbomMongoDocument.extraInfo = i.extraInfo;
                }

                sbomMongoDocument.triggerPackage = i.triggerPackage;
                sbomMongoDocument.languageInfo = i.blame?.runtime?.languageInfo;

                //Vul info
                this.setSbomDocSevEvents(containerSecurityAlerts, i.name, sbomMongoDocument, i, repo);

                //Debug
                // logger.info(
                //   `finish attach vul to image registry for app: ${this.appInfo.repo.code_repo.fullName}, image: ${imageObj.image.name}, containerSecurityAlerts: ${containerSecurityAlerts.length}, vulnerabilities: ${sbomMongoDocument.vulnerabilities.length}, hasVulnerabilities: ${sbomMongoDocument.hasVulnerabilities}, setNotConnectedSbom: ${setNotConnectedSbom}, vulnerabilityCountsArr: ${i?.vulnerabilityCountsArr?.length}, lib: ${i.name}, ver: ${i.version}`,
                // );

                //for sbom PackageInfo filter
                let packageInfo: SbomPackageInfo[] = [];
                if (sbomMongoDocument.isDeprecated) packageInfo.push(SbomPackageInfo.Deprecated);
                if (sbomMongoDocument.notPopular) packageInfo.push(SbomPackageInfo.NotPopular);
                if (sbomMongoDocument.notImported) packageInfo.push(SbomPackageInfo.NotUsed);
                if (sbomMongoDocument.notUpdated) packageInfo.push(SbomPackageInfo.NotUpdated);
                if (sbomMongoDocument.licenseIssue) packageInfo.push(SbomPackageInfo.UnapprovedLicense);
                if (sbomMongoDocument.hasVulnerabilities) packageInfo.push(SbomPackageInfo.HasVulnerabilities);
                sbomMongoDocument.packageInfo = packageInfo;

                if (isDevelopment()) {
                  const objSize = checkObjectSize(sbomMongoDocument);
                  //Bigger then in mb
                  if (objSize > 15) {
                    logger.warn(`huge sbom registry object size: ${objSize}, repo: ${repo.fullName}`);
                  }
                }

                StatesHelper.Instance.savedSbomsFromRegistry++;

                sbomMongoDocument.artifactInSbomLibs.push(artifactInSbomLib);

                uniqueLibsVerMap[key] = sbomMongoDocument;
              } catch (err) {
                logger.error(`fail save single sbom registry lib :${JSON.stringify(i)} repo: ${app.appInfo.repo.fullName}`, err);
              }
            });

            sbomMongoDocuments = Object.values(uniqueLibsVerMap);

            if (isDevelopment()) {
              sbomMongoDocuments.forEach(sbomMongoDocument => {
                const objSize = checkObjectSize(sbomMongoDocument);
                //Bigger then in mb
                if (objSize > 15) {
                  logger.error(`huge sbom registry object size: ${objSize}, image: ${imageObj.image.name}`);
                }
              });
            }
          });
        }
      } catch (err) {
        logger.error(`failed saving all sboms registry libs for repo: ${app.appInfo.repo.fullName}`, err);
      }

      if (sbomMongoDocuments.length > 0) {
        const startTime = Date.now();
        await this.resultsHandler.addSboms(sbomMongoDocuments);
        logger.info(`Saved registry sbom for repo ${this.appInfo.repo.code_repo.fullName} into mongo (${Date.now() - startTime}ms)`);
      }
    } catch (err) {
      logger.error(`failed save sbom registry application for app screen`, err);
    }
  }

  setSbomDocSevEvents(
    secEvents: SecurityEvent[],
    pkgName: string,
    sbomMongoDocument: SbomMongoDocument,
    sbomObj: ExtendedSbomComponent,
    repo: Repo,
  ) {
    const relatedSecurityEvents = secEvents.filter(
      event => `${event.pkgName}@${event.installedVersion}` === `${pkgName}@${sbomObj.version}`,
    );
    const { directSCAVulnerability, noneDirectSCAVulnerability } = getScaVul(relatedSecurityEvents, repo.fullName);
    const vulnerabilities: SCAVulnerability[] = [].concat(directSCAVulnerability || [], noneDirectSCAVulnerability || []);
    if (vulnerabilities?.length) {
      sbomMongoDocument.vulnerabilities = vulnerabilities;
      sbomMongoDocument.hasVulnerabilities = sbomMongoDocument.vulnerabilities.length > 0;
    }
    const filterSecEvents = vulnerabilities.map(i => i.alert);
    //Vulnerability info
    sbomObj.vulnerabilityCounts = {};
    try {
      for (const securityEvent of filterSecEvents) {
        const severity = securityEvent.originalSeverityStr?.toLowerCase();
        if (!severity) {
          logger.error(`cannot find severity for: ${securityEvent.pkgName}_${securityEvent.installedVersion}`);
          continue;
        }
        sbomObj.vulnerabilityCounts[severity] = (sbomObj.vulnerabilityCounts[severity] || 0) + 1;
      }
      sbomMongoDocument.vulnerabilityCounts = sbomObj.vulnerabilityCounts;

      const vulnerabilityCountsArr = Object.entries(sbomObj.vulnerabilityCounts).map(([severity, count]) => ({
        severity: getSeverityFromStr(severity).toString(),
        count,
      }));
      sbomMongoDocument.vulnerabilityCountsArr = vulnerabilityCountsArr as any;
    } catch (err) {
      logger.error(
        `failed set vulnerability counts for single lib: ${sbomObj.name}@${sbomObj.version}, repo: ${repo.fullName}, err: ${err}`,
      );
    }
  }

  async saveSbomFromCodeForDownload() {
    let appId = "";
    let appName = "";
    try {
      appId = this.appInfo.repo.code_repo.id;
      appName = this.appInfo.repo.code_repo.fullName;

      const code_repo = this.appInfo.repo.code_repo;
      const sbomEvents: SbomEvent[] = this.appInfo.repo[ArtifactoryTypes[ArtifactoryTypes.sbom]] ?? [];
      if (sbomEvents.length == 0) {
        return;
      }

      logger.info(`try set repo info in DB for app: ${appId}, name: ${appName}`);

      for (const sbomEvent of sbomEvents) {
        await this.resultsHandler.setSbom(appId, sbomEvent.sbom, AppSbomType.repo, code_repo);
      }

      logger.info(`finish set repo info in DB for app: ${appId}, name: ${appName}`);
      return true;
    } catch (err) {
      logger.error(`failed to set sboms for repo: ${appId}, name: ${appName} err: ${err}`);
    }
    return false;
  }

  async handleFakeAppFlowForContainers() {
    try {
      const repo = this.appInfo.repo.code_repo;
      const events = this.appInfo.artifactory.securityEvents;

      //Ox tools already handle recommendation on artifact base class
      await this.alertRecommendationHelper.setAlertRecommendation(
        events.filter(i => !i.oxTool),
        repo,
      );
    } catch (err) {
      logger.error(`failed handleFakeAppFlowForContainers for unattached events, err: ${err}`);
    }
  }

  async handleFakeAppFlowForCode() {
    try {
      const repo = this.appInfo.repo.code_repo;
      const events = this.appInfo.repo[CodeRepoTypes[CodeRepoTypes.securityEvents]];
      await this.blameHelper.extendBlameSecurityEventsForSingleApp(events, repo, "code security fake apps", repo.fullName);
      await this.alertRecommendationHelper.setAlertRecommendation(events, repo);
    } catch (err) {
      logger.error(`failed handleFakeAppFlowForCode for unattached events, err: ${err}`);
    }
  }

  @PerformanceTelemetry("policy")
  async runAllPolicyForUnattachedEvents() {
    try {
      const appCommonInfo = this.getCommonAppInfo(this.appInfo, false);
      const execType = Constant.execType.duringScan;

      //Execute policy on all of the data
      const appName = this.getAppName();
      logger.info(`try execute all policy for unattached app: ${appName}, app uid: ${appCommonInfo.flowId}, execType:${execType}`);

      const collectorPolicyProms = this.policyRules.map(policyRule => this.executePolicy(policyRule, this.appInfo, appCommonInfo, false));

      const proms = await Promise.all(collectorPolicyProms);
      logger.info(`finish execute all policy for unattached app: ${appName}, app uid: ${appCommonInfo.flowId}, execType: ${execType}`);

      let res = proms.filter(i => i != null);

      if (this.fakeApp) {
        const appHasIssues = res.find(pol => pol.policyRes.total > 0);
        if (appHasIssues === undefined && !this.appInfo?.repo?.code_repo?.noneRelevantRepo) {
          return;
        }
      }

      this.resultsHandler.setTotalApps(StatesHelper.Instance.numberOfApps);
      await this.resultsHandler.handleUnattachedEvents(res);
    } catch (err) {
      logger.error(`failed execute all policy for unattached events, err: ${err}`);
    }
  }

  private getType(collectorData: any, resource: Resource) {
    if (resource.type.toLowerCase() === ResourceType[ResourceType.code_repo]) return collectorData.repo;
    if (resource.type.toLowerCase() === ResourceType[ResourceType.citool]) return collectorData.cicd;
    if (resource.type.toLowerCase() === ResourceType[ResourceType.cloud]) return collectorData.cloud;
    if (resource.type.toLowerCase() === ResourceType[ResourceType.artifactory]) return collectorData.artifactory;
    return null;
  }

  private async executePolicy(policyRule: Policy, collectorData: any, commonAppInfo: any, skipUpdateDb: boolean) {
    try {
      let resourcesData = {};
      resourcesData[ResourceType[ResourceType.code_repo]] = commonAppInfo.resourceRepo;
      resourcesData[ResourceType[ResourceType.citool]] = commonAppInfo.resourceCicd;
      resourcesData[ResourceType[ResourceType.cloud]] = commonAppInfo.resourceCloud;
      resourcesData[ResourceType[ResourceType.artifactory]] = commonAppInfo.resourceArtifactory;

      for (const resource of policyRule.resources) {
        const item = this.jsonHelper.lookupArrayVal(this.getType(collectorData, resource), resource.name);

        if (resourcesData[resource.name] != undefined) {
          resourcesData[resource.name] = [...resourcesData[resource.name], ...item];
        } else {
          resourcesData[resource.name] = item;
        }
      }

      //Policy runner object
      const policyRulesRunner: PolicyRulesBase = this.rulesFactory(policyRule);

      //Execute policy runner with data
      const policyTest = {
        uuid: this.uuid,
        orgName: this.orgName,
        flowUid: commonAppInfo.flowId,
        policyRuleMetadata: policyRule,
        resourcesData: resourcesData,
      };

      const policyRes = await policyRulesRunner.runEval(policyTest, this.resultsHandler);

      this.executedPolicy.add(policyRulesRunner.policyRuleMetadata.policyId);

      return {
        policyRes: policyRes,
        collectorData: commonAppInfo.resourceRepo,
        repository: commonAppInfo.resourceRepository,
        cicd: commonAppInfo.resourceCicd,
        cloud: commonAppInfo.resourceCloud,
        artifacts: commonAppInfo.resourceArtifactory,
        orchestrator: commonAppInfo.resourceOrchestrator,
        kubernetes: commonAppInfo.resourceKubernetes,
        attachedToApp: commonAppInfo.attachedToApp,
        skipUpdateDb: skipUpdateDb,
      };
    } catch (err) {
      logger.error(`failed execute policy: ${policyRule.name}`, err);
    }
    return null;
  }

  private rulesFactory(policyRule: Policy) {
    try {
      if (policyRule.functionName === "policyNoMatchHashBetweenCICDandRuntimeCloud")
        return new policyNoMatchHashBetweenCICDandRuntimeCloud.default();
      if (policyRule.functionName === "policyRunTimeNotHaveLatestImageVersion") return new policyRunTimeNotHaveLatestImageVersion.default();
      if (policyRule.functionName === "policyNoMatchHashBetweenCICDandRegistry")
        return new policyNoMatchHashBetweenCICDandRegistry.default();
      if (policyRule.functionName === "policySecuritySecretsContainerScan") return new policySecuritySecretsContainerScan.default();
      if (policyRule.functionName === "policySecuritySecretsContainerScanNew") return new policySecuritySecretsContainerScanNew.default();
      if (policyRule.functionName === "policyCloudSecuritySecretScanNew") return new policyCloudSecuritySecretScanNew.default();
      if (policyRule.functionName === "policyCloudSecurityScanNew") return new policyCloudSecurityScanNew.default();
      if (policyRule.functionName === "policyCommitReviewCount") return new policyCommitReviewCount.default();
      if (policyRule.functionName === "policyDisableSCA") return new policyDisableSCA.default();
      if (policyRule.functionName === "policyDisableSAST") return new policyDisableSAST.default();
      if (policyRule.functionName === "policyNoCicd") return new policyNoCicd.default();
      if (policyRule.functionName === "policyNoSAST") return new policyNoSAST.default();
      if (policyRule.functionName === "policyNoSCA") return new policyNoSCA.default();
      if (policyRule.functionName === "policySbomCodeNoImportedLibs") return new policySbomCodeNoImportedLibs.default();
      if (policyRule.functionName === "policySbomTyposquatting") return new policySbomTyposquatting.default();
      if (policyRule.functionName === "policyMemberCreatePublicRepos") return new policyMemberCreatePublicRepos.default();
      if (policyRule.functionName === "policyOrgDomainRepo") return new policyOrgDomainRepo.default();
      if (policyRule.functionName === "policyPublicRepo") return new policyPublicRepo.default();
      if (policyRule.functionName === "policyRemoveWriteAccessRepo") return new policyRemoveWriteAccessRepo.default();
      if (policyRule.functionName === "policySbomCodeLicenses") return new policySbomCodeLicenses.default();
      if (policyRule.functionName === "policySbomCodeLibNotPopular") return new policySbomCodeLibNotPopular.default();
      if (policyRule.functionName === "policySbomCodeLibDeprecated") return new policySbomCodeLibDeprecated.default();
      if (policyRule.functionName === "policySbomCodeLibOutdated") return new policySbomCodeLibOutdated.default();
      if (policyRule.functionName === "policySecurityScan") return new PolicySecurityScan.default();
      if (policyRule.functionName === "policyUnprotectedDevLan") return new policyUnprotectedDevLan.default();
      if (policyRule.functionName === "policyWebhookCICD") return new policyWebhookCICD.default();
      if (policyRule.functionName === "policyWebhookConfiguration") return new policyWebhookConfiguration.default();
      if (policyRule.functionName === "webhooksReputation") return new webhooksReputation.default();
      if (policyRule.functionName === "policyMainBranchDoesntRequireCodeReview")
        return new policyMainBranchDoesntRequireCodeReview.default();
      if (policyRule.functionName === "policyDspmMaxAdmins") return new policyDspmMaxAdmins.default();
      if (policyRule.functionName === "policyRuntimeApplicationVulnerability") return new policyRuntimeApplicationVulnerability.default();
      if (policyRule.functionName === "policyLimitBranchDeletionsToAdmins") return new policyLimitBranchDeletionsToAdmins.default();
      if (policyRule.functionName === "policyUntouchedReposShouldBeArchived") return new policyUntouchedReposShouldBeArchived.default();
      if (policyRule.functionName === "policyDspmMoreThanOneAdmin") return new policyDspmMoreThanOneAdmin.default();
      if (policyRule.functionName === "policyAllowForkingPrivateRepos") return new policyAllowForkingPrivateRepos.default();
      if (policyRule.functionName === "policyOutsideCollaborators2FAEnabled") return new policyOutsideCollaborators2FAEnabled.default();
      if (policyRule.functionName === "policy2FAEnabled") return new policy2FAEnabled.default();
      if (policyRule.functionName === "policyOutsideCollaboratorsnNoAdmin") return new policyOutsideCollaboratorsnNoAdmin.default();
      if (policyRule.functionName === "policyOutsideCollaborators2FAEnabled") return new policyOutsideCollaborators2FAEnabled.default();
      if (policyRule.functionName === "policyOpenWiki") return new policyOpenWiki.default();
      if (policyRule.functionName === "policyExternalToolsLicenseViolations") return new policyExternalToolsUnapprovedLicense.default();
      if (policyRule.functionName === "policyDspmRepoMaxAdmins") return new policyDspmRepoMaxAdmins.default();
      if (policyRule.functionName === "policyOrgOwnersWithNoActivity") return new policyOrgOwnersWithNoActivity.default();
      if (policyRule.functionName === "policyBotNoOrgAdmin") return new policyBotNoOrgAdmin.default();
      if (policyRule.functionName === "policyBotNoRepoAdmin") return new policyBotNoRepoAdmin.default();
      if (policyRule.functionName === "policyRepoAdminsWithNoActivity") return new policyRepoAdminsWithNoActivity.default();
      if (policyRule.functionName === "policyLicenseFile") return new PolicyLicenseFile.default();
      if (policyRule.functionName === "policyRareCodeChange") return new policyRareCodeChange.default();
      if (policyRule.functionName === "policyRequireSignedCommits") return new policyRequireSignedCommits.default();
      if (policyRule.functionName === "policyProtectedBranchPushEventsNotBypassed")
        return new policyProtectedBranchPushEventsNotBypassed.default();
      if (policyRule.functionName === "policyProtectedBranchPushEventsNotBypassedOutsideCollaborators")
        return new policyProtectedBranchPushEventsNotBypassedOutsideCollaborators.default();
      if (policyRule.functionName === "policyProtectedBranchShouldNotBeBypassed")
        return new policyProtectedBranchShouldNotBeBypassed.default();
      if (policyRule.functionName === "policyNoCICDBotReview") return new policyNoCICDBotReview.default();
      if (policyRule.functionName === "policyProtectedBranchShouldNotBeBypassedOutsideCollaborators")
        return new policyProtectedBranchShouldNotBeBypassedOutsideCollaborators.default();
      if (policyRule.functionName === "policySecurityScanSCA") return new policySecurityScanSCA.default();
      if (policyRule.functionName === "policySecurityScanNew") return new policySecurityScanNew.default();
      if (policyRule.functionName === "policyAnomalousWebhooks") return new policyAnomalousWebhooks.default();
      if (policyRule.functionName === "policyOutsideCollaboratorsWithNoActivityRepo")
        return new policyOutsideCollaboratorsWithNoActivityRepo.default();
      if (policyRule.functionName === "policyCICDContextValues") return new policyCICDContextValues.default();
      if (policyRule.functionName === "policyCICDEchoSecrets") return new policyCICDEchoSecrets.default();
      if (policyRule.functionName === "policyCICDSecretsRepoVars") return new policyCICDSecretsRepoVars.default();

      if (policyRule.functionName === "policyWorkflowMinPerm") return new policyWorkflowMinPerm.default();
      if (policyRule.functionName === "policyPinActionSha") return new policyPinActionSha.default();
      if (policyRule.functionName === "policyDeprecatedCommand") return new policyDeprecatedCommand.default();

      if (policyRule.functionName === "policyGeneralCICD") return new policyGeneralCICD.default();
      if (policyRule.functionName === "policyDepConfusion") return new policyDepConfusion.default();
      if (policyRule.functionName === "policyDepConfusionPython") return new policyDepConfusionPython.default();
      if (policyRule.functionName === "PolicySbomRegistryLicenses") return new PolicySbomRegistryLicenses.default();
      if (policyRule.functionName === "policyVulnerabilityRuntimeMonitor") return new PolicyVulnerabilityRuntimeMonitor.default();
      if (policyRule.functionName === "policyNoSecrets") return new policyNoSecrets.default();
    } catch (err) {
      logger.error(`failed load policy code file: ${policyRule.name}, err: ${err}`);
    }

    logger.error(`cannot find policy code file: ${policyRule.name}, policy function name: ${policyRule.functionName}`);
    return null;
  }

  private getAppName() {
    try {
      if (this.appInfo.repo != null) {
        const repo: Repo = this.appInfo.repo.code_repo;
        return repo.fullName;
      }
    } catch (err) {
      logger.error(`failed get app name error , err: ${err}, appInfo: ${JSON.stringify(this.appInfo)}`);
    }

    return "uncorrelated events";
  }
}
