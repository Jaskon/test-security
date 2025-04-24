import { ImageDetail as EcrImageDetail } from "@aws-sdk/client-ecr";
import { Container } from "@aws-sdk/client-ecs";
import { OxCategoriesIds } from "@oxappsec/ox-consolidated-categories";
import FeatureFlags from "@oxappsec/ox-feature-flag";
import { PromisePool } from "@supercharge/promise-pool/dist/promise-pool";
import { Queue } from "bull";
import fs from "fs";
import { groupBy } from "lodash";
import path from "path";
import { AsyncTracker } from "../async-tracker.service";
import { isFunctionOrImageTooOld } from "../codeOpenSourceTools/cloudTools/specifcTools/AWSBussinessLogic";
import AWSCloudTrail from "../codeOpenSourceTools/cloudTools/specifcTools/AWSCloudTrail";
import ArtifactoryBase from "../dal/base/artifactoryBase";
import CollectorManager from "../dal/collectorManager";
import GlobalCodeRepoData from "../dal/GolobalCollectorData/globalCodeRepoData";
import { AppFlowRepo, FoundLocation } from "../entitis/applicationsFlowTypes";
import { AppSbomType, ArtifactoryTypes, ImageInfo, SbomComponentType, SbomEvent } from "../entitis/artifactoryTypes";
import { DockerSearchCriteria, EnrichedDockerSearchResult, Pagination, SCM, Session, SlidingWindow } from "../entitis/ArtifactTypes";
import { AttackPathInputSecurityEvents, AttackPathJSON } from "../entitis/attackPathTypes";
import { CICD, CICDJob, CICDRepo } from "../entitis/cicidRepoTypes";
import { CloudGraphRes } from "../entitis/CloudGraphTypes";
import { CloudSecurityEvent, CloudTypes, getCloudProviderType, ImageContainerDetail, ImageDetail } from "../entitis/cloudTypes";
import {
  addSeverityChangedReason,
  addSeverityCloudChangedReason,
  CodeRepoTypes,
  File,
  Relevance,
  replaceAll,
  Repo,
  repoType,
  RepoTypeName,
  SecurityAlertType,
  SecurityEvent,
  User,
} from "../entitis/codeRepoTypes";
import { AWSEcrRepositoryName, AWSLambdaTrailData, FunctionArn, Instances } from "../entitis/connectorsSpecific/AWSRelatedTypes";
import { Constant } from "../entitis/constant";
import { DockerHubInfo, DockerhubRequest } from "../entitis/DockerhubTypes";
import { ExtraInfo, Issue } from "../entitis/issuesTypes";
import { IrrelevantReason } from "../entitis/reportTypes";
import { severityReasons } from "../entitis/service/blameTypes";
import { setConfiguredProps } from "../helper/appConfigHelper";
import {
  mergeArtifactsForAppFlow,
  mergeCICDForAppFlow,
  mergeCloudAppFlow,
  mergeKubernetesAppFlow,
  mergeOrchestratorAppFlow,
} from "../helper/appFlow/appFlowHelper";
import RepoImportanceCalcHelper from "../helper/appPriority/repoImportanceCalcHelper";
import { CacheResolver } from "../helper/cache/cache.resolver";
import retainApplicationsForArtifactScreen from "../helper/decorators/artifactScreenApplicationDecorators";
import { PerformanceTelemetry } from "../helper/decorators/PerformanceTelemetry";
import DeltaScansHelper from "../helper/deltaScan/deltaScansHelper";
import { isDevelopment, isLocalDevelopment } from "../helper/envUtils";
import { hash } from "../helper/hash";
import { isExcludedAlert } from "../helper/IO/fileFilter";
import FileHelper from "../helper/IO/fileHlper";
import MemoryMonitorHelper from "../helper/IO/memoryMonitorHelper";
import JsonHelper from "../helper/jsonHelper";
import { perfOpExp } from "../helper/performance";
import { PipeLineHelper } from "../helper/pipelineHelper";
import Iqueue from "../helper/queue/Iqueue";
import { MatchResult, MatchResultString, RepositoryMatcher } from "../helper/repository-matching/RepositoryMatcher";
import RoleHelper from "../helper/roleHelper";
import { ExtendedSbomComponent } from "../helper/sbom/sbomHelper";
import ACMHelper from "../helper/service/artifactCloudMatcherHelper";
import AttackPathHelper from "../helper/service/attackPathHelper";
import CloudGraphHelper from "../helper/service/cloudGraphHelper";
import DockerhubHelper from "../helper/service/dockerhubHelper";
import OpenWikiHelper from "../helper/service/openWikiHelper";
import { PolicyService } from "../helper/service/policy-service/api";
import { Policy } from "../helper/service/policy-service/types";
import { TagsService } from "../helper/service/tags-service/tags-service.service";
import VerificationAndStarsHelper from "../helper/service/verificationAndStarsHelper";
import StatesHelper from "../helper/statesHelper";
import StringHelper from "../helper/stringHelper";
import { millisToMinutesAndSeconds, ScanPhaseTime, sendScannerPhaseTimeTelemetry } from "../helper/telemetry-utils";
import TimeHelper from "../helper/timeHelper";
import loggerImport from "../logger";
import { CveToolsService } from "../mongo/cve-tools.service";
import MongoDBapplications from "../mongo/mongoDBapplications";
import { AggItem } from "../mongo/schemas";
import { InterceptHelper } from "../orgSpecificTools/StandardChartered/InterceptHelper";
import JsonApplicationDiscoveryOverview from "../policy/reporting/jsonApplicationDiscoveryOverview";
import ResultsHandler from "../policy/reporting/ResultsHandler";
import RuleExclusions from "../policy/rules/ruleExclusions";
import RulesParser from "../policy/rules/rulesParser";
import Artifactory from "./../policy/reporting/fakeCollectorsData/Artifactory.json";
import CloudCollectorData from "./../policy/reporting/fakeCollectorsData/AWS.json";
import CodeRepo from "./../policy/reporting/fakeCollectorsData/code-repo.json";
import { Application } from "./application";
import ArtifactStats from "./ArtifactsStats";
import integrityStats from "./integrityStats";
import IntegrityVerifier from "./IntegrityVerifier";
import { enrichArtifacts } from "./ParseArtifacts";
import { Artifact, IssueSummary } from "../mongo/artifact-screen/types/artifact-screen";

const uuid = require("uuid");

const logger = loggerImport.getDebugLogger();
type ImageDigestWithoutPrefixType = string;

class ApplicationsManager {
  uuid: string;
  orgName: string;
  rulesParser: RulesParser;
  policyRules: Policy[] = [];
  jsonHelper: JsonHelper;
  timeHelper: TimeHelper;
  fileHelper: FileHelper;
  roleHelper: RoleHelper;

  artifactoryForSbom: ArtifactoryBase;
  cloudGraphs: CloudGraphRes[] = [];
  //UI reporting
  jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview;

  applications: Application[] = [];
  fakeApplications: Application[] = [];

  //Cloud
  allCloudSecurityEvents: CloudSecurityEvent[] = [];

  allUnattachedAWSRuntimeResources: Map<ImageDigestWithoutPrefixType, ImageContainerDetail> = new Map();
  allUnattachedAWSRuntimeResourcesSha = new Set();
  runTimeContainersNotConnected: ImageContainerDetail[] = [];

  //External sast\sca
  allUnattachedExternalCodeSecurityEvents = {};
  //Artifacts
  allArtifactsSecurityEventsForExternalTools: SecurityEvent[] = [];
  //Runtime
  runtimeArtifactsSecurityEvents: SecurityEvent[] = [];

  dockerhubHelper: DockerhubHelper;

  //CICD General Data
  uniqueImagesSet: Set<string> = new Set();
  regExImage: Map<string, CICD> = new Map();
  allCICDjobs = {};
  allCICDjobsByImageName = {};
  allCICD: CICD[] = [];
  artifactsStatsMgr;

  //Artifact image storage
  allImagesFromRegistry: ImageInfo[] = [];
  notConnectedImagesToApps: ImageInfo[] = [];

  //Statistics
  totalCloudEvents = 0;
  totalCICDevents = 0;
  totalCICDeventsWithJobs = 0;
  totalCICDJobsNumber = 0;
  totalRepoEvents = 0;
  resultsHandler: ResultsHandler;
  cloudEnvToCloudEvents = {};

  //Exclusions
  ruleExclusions: RuleExclusions;
  collectorManager: CollectorManager;

  //Fake apps
  allFakeApps = new Set();

  //Blame
  blameQueue: Iqueue;

  //Auto fix
  autoFixQueue: Iqueue;

  //Secret validation
  secretValidationQueue: Iqueue;

  //Iac VerificationQueue
  iacVerificationQueue: Iqueue;

  //ResolveIssueValidationQueue
  resolveIssueValidationQueue: Iqueue;

  //Dockerhub queue
  dockerhubQueue: Iqueue;

  //Sca VerificationQueue
  scaVerificationQueue: Iqueue;

  //Alert recommendation
  alertRecommendationQueue: Iqueue;

  //Delta scan
  deltaScansHelper: DeltaScansHelper;

  //Open wiki
  openWikiHelper: OpenWikiHelper;

  //Verification (org) and stars
  verificationAndStarsHelper: VerificationAndStarsHelper;

  // Artifact to cloud matcher
  artifactCloudMatcherHelper: ACMHelper;
  artifactCloudMatcherQueue: Iqueue;

  // Attack Path
  attackPathQueue: Iqueue;
  maxAggItemsFoAttackPath = 5;

  integrityStats: ReturnType<typeof integrityStats>;

  constructor(
    uuid: string,
    orgName: string,
    rulesParser: RulesParser,
    policyRules: Policy[],
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
    ruleExclusions: RuleExclusions,
    updateCollections: ResultsHandler,
    collectorManager: CollectorManager,
    blameQueue: Iqueue,
    secretValidationQueue: Iqueue,
    autoFixQueue: Iqueue,
    deltaScansHelper: DeltaScansHelper,
    alertRecommendationQueue: Iqueue,
    iacVerificationQueue: Iqueue,
    dockerhubQueue: Iqueue,
    openWikiQueue: Iqueue,
    private readonly isPipelineScan: boolean,
    scaVerificationQueue: Iqueue,
    readonly openSourceInfoQueue: Queue,
    readonly cachResovler: CacheResolver,
    verificationAndStarsQueue: Iqueue,
    private readonly mongoDBapplications: MongoDBapplications,
    resolveIssueValidationQueue: Iqueue,
    attackPathQueue: Iqueue,
  ) {
    this.uuid = uuid;
    this.orgName = orgName;
    this.rulesParser = rulesParser;
    this.policyRules = policyRules;
    this.jsonApplicationDiscoveryOverview = jsonApplicationDiscoveryOverview;
    this.jsonHelper = new JsonHelper(this.uuid);
    this.ruleExclusions = ruleExclusions;
    this.resultsHandler = updateCollections;
    this.timeHelper = new TimeHelper(this.uuid);
    this.collectorManager = collectorManager;
    this.blameQueue = blameQueue;
    this.scaVerificationQueue = scaVerificationQueue;
    this.autoFixQueue = autoFixQueue;
    this.secretValidationQueue = secretValidationQueue;
    this.alertRecommendationQueue = alertRecommendationQueue;
    this.iacVerificationQueue = iacVerificationQueue;
    this.dockerhubQueue = dockerhubQueue;
    this.fileHelper = new FileHelper("");
    this.roleHelper = new RoleHelper("github");
    this.deltaScansHelper = deltaScansHelper;
    this.cachResovler = cachResovler;
    this.resolveIssueValidationQueue = resolveIssueValidationQueue;
    this.dockerhubHelper = new DockerhubHelper(dockerhubQueue, this.uuid, this.orgName);
    this.openWikiHelper = new OpenWikiHelper(openWikiQueue, this.uuid, this.orgName);
    this.verificationAndStarsHelper = new VerificationAndStarsHelper(verificationAndStarsQueue, this.uuid, this.orgName);
    this.artifactsStatsMgr = ArtifactStats({ uuid: this.uuid, orgId: this.orgName });

    this.integrityStats = integrityStats();
    this.artifactCloudMatcherHelper = new ACMHelper();
    this.attackPathQueue = attackPathQueue;
  }

  @PerformanceTelemetry()
  async finalizeScan() {
    try {
      logger.info(`start finalize scan`);
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `start finalize scan`);

      const startTime = new Date().getTime();

      StatesHelper.Instance.isAttachResources = true;
      await this.resultsHandler.updateScanInfoStateWithDBupdate();
      await this.updateApplicationInfo();

      //Set time monitor
      const elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));
      StatesHelper.Instance.scanInfoStats.totalFinalizingTime = `${elapsedTime} minutes`;
      logger.info(`finish finalize scan in: ${elapsedTime} minutes`);

      //Set to true for end of scan
      StatesHelper.Instance.isFinalizing = true;
      StatesHelper.Instance.isAttachResources = false;
      await this.resultsHandler.updateScanInfoStateWithDBupdate();
    } catch (err) {
      logger.error(`failed finalize scan, err: ${err}`);
    }
  }

  async updateApplicationInfo() {
    try {
      //Try to attach all events to app before taken the unattached onces
      //For CICD, Artifacts, Cloud and clear collection after this
      let allApps = this.applications;

      if (StatesHelper.Instance.isCharterBank) {
        await this.handleSpecificOrgLogic();
        return;
      }

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `before attachCloudGraphInfo`);
      await CloudGraphHelper.attachCloudGraphInfo(this.allImagesFromRegistry, this.cloudGraphs);

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `before AttachAppSources`);
      await this.AttachAppSources(allApps);
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `after AttachAppSources`);

      //Generate - App Flow in app
      this.applications.forEach(i => mergeCICDForAppFlow(i));
      this.applications.forEach(i => mergeArtifactsForAppFlow(i));
      this.applications.forEach(i => mergeOrchestratorAppFlow(i));
      this.applications.forEach(i => mergeKubernetesAppFlow(i));
      this.applications.forEach(i => mergeCloudAppFlow(i));

      //Recalc all BP after we set all app flow
      await this.recalcImportanceWithResources();
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `after AppFlowInApp`);

      //Update all collection of apps in ram with new data we discover at the end of
      this.resultsHandler.updateAllAppsCollectionInRam(this.applications);
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `after updateAllAppsCollectionInRam`);

      //Cleanup
      this.allCICD = [];

      const fakeApps: Application[] = [];

      //Create Fake apps for clo events
      await this.createFakeAppsForCloudEvents(fakeApps);
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `after createFakeAppsForCloudEvents`);
      //Create Fake apps for artifacts
      await this.createFakeAppsForArtifactoryEvents(fakeApps);
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `after createFakeAppsForArtifactoryEvents`);
      //Create Fake apps for code security events
      await this.createFakeAppsForSecurityAlerts(fakeApps);
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `after createFakeAppsForSecurityAlerts`);
      //Create Fake apps for code repo settings
      await this.createFakeAppsForRepoSetting();
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `after createFakeAppsForRepoSetting`);
      await this.createFakeAppsForRepoUsers();
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `after createFakeAppsForRepoUsers`);
    } catch (err) {
      logger.error(`failed update unattached events, err: ${err}`);
    }
  }

  async handleSpecificOrgLogic(): Promise<void> {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }
      if (StatesHelper.Instance.kongHostUrl && StatesHelper.Instance.kongToken) {
        const url = StatesHelper.Instance.kongHostUrl || "https://kong.loca.lt";
        const token = StatesHelper.Instance.kongToken || "";
        const appRepo = await this.createFakeApp("Kong-api-gateway");
        appRepo.skipAllEnrichmentTools = true;
        const secEvents = await InterceptHelper.collectSecEvents({ type: "kong", name: url, url, token }, this.orgName, this.uuid);
        appRepo.appInfo.repo[CodeRepoTypes[CodeRepoTypes.securityEvents]] = secEvents;
        this.applications.push(appRepo);
      }
      if (StatesHelper.Instance.solaceUsername && StatesHelper.Instance.solacePassword) {
        const username = StatesHelper.Instance.solaceUsername || "admin";
        const password = StatesHelper.Instance.solacePassword || "password";
        const appRepo = await this.createFakeApp("Solace");
        appRepo.skipAllEnrichmentTools = true;
        const secEvents = await InterceptHelper.collectSecEvents(
          { type: "solace", name: username, username, password },
          this.orgName,
          this.uuid,
        );
        appRepo.appInfo.repo[CodeRepoTypes[CodeRepoTypes.securityEvents]] = secEvents;
        this.applications.push(appRepo);
      }
    } catch (err) {
      logger.error(`failed handleSpecificOrg, err: ${err}`);
    }
  }

  async createFakeApp(name: string): Promise<Application> {
    const appRepo = new Application(
      this.uuid,
      this.orgName,
      this.policyRules,
      this.jsonApplicationDiscoveryOverview,
      this.ruleExclusions,
      this.resultsHandler,
      this.blameQueue,
      this.secretValidationQueue,
      this.autoFixQueue,
      this.alertRecommendationQueue,
      this.iacVerificationQueue,
      this.scaVerificationQueue,
      this.openSourceInfoQueue,
      this.cachResovler,
      this.resolveIssueValidationQueue,
    );

    await this.setFakeAppInfo(name, appRepo, CodeRepo);
    this.setFakeRepoInfo(appRepo);
    return appRepo;
  }

  @PerformanceTelemetry()
  async collectCllGraphRes() {
    try {
      if (!StatesHelper.Instance.isCallGraphEnable) {
        logger.info(`collectCllGraphRes call graph is disabled`);
        return;
      }

      logger.info(`start wait collectCllGraphRes`);

      const proms = this.applications.map(app => {
        let appName;
        try {
          const repo: Repo = app.appInfo.repo.code_repo;
          appName = repo.fullName;
          if (!repo.callGraphHelper) {
            return;
          }
          return repo.callGraphHelper.waitForRes(repo);
        } catch (err) {
          logger.error(`failed collectCllGraphRes for single app: ${appName}, err: ${err}`);
        }
      });
      await Promise.all(proms);

      logger.info(`finish wait collectCllGraphRes`);
    } catch (err) {
      logger.error(`failed collectCllGraphRes for all apps, err: ${err}`);
    }
  }

  async setAttackPath(issues: Issue[], images: ImageInfo[], application: Application) {
    const appName: string = (application.appInfo?.repo?.code_repo as Repo)?.fullName;
    try {
      if (!StatesHelper.Instance.isAttackPathEnable) {
        return;
      }

      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      const repo: Repo = application.appInfo.repo.code_repo;
      if (repo.isDelta) {
        await AttackPathHelper.setAttackPathToIssuesFromCache(repo, issues, this.cachResovler);
        return;
      }

      //Handle attack path
      logger.info(`[setAttackPath] start wait attack path for app: ${appName}`);

      const attackPathInput: AttackPathJSON = new AttackPathJSON();
      attackPathInput.repoPath = repo.getRepoForToolsBasedOnEnv();

      if (repo?.callGraphHelper && repo.callGraphHelper?.filePathResForCallGraph && repo.callGraphHelper?.resExist) {
        attackPathInput.callGraphInfo = JSON.parse(fs.readFileSync(repo.callGraphHelper?.filePathResForCallGraph, "utf8"));
      } else {
        logger.info(`[setAttackPath] no result callGraphHelper for single app: ${appName}`);
      }

      if (repo?.apiDiscoveryInfoPath && fs.existsSync(repo?.apiDiscoveryInfoPath)) {
        attackPathInput.api = JSON.parse(fs.readFileSync(repo?.apiDiscoveryInfoPath, "utf8"));
      } else {
        logger.info(`[setAttackPath] no result apiDiscovery for single app: ${appName}`);
      }

      if (this?.cloudGraphs && this?.cloudGraphs.length > 0) {
        attackPathInput.cloudGraphInfo = this?.cloudGraphs;
      } else {
        logger.info(`[setAttackPath] no result cloudGraph for single app: ${appName}`);
      }

      logger.info(`[setAttackPath] attack path images length: ${images.length}, for ${appName}`);
      const filteredImages = images
        .map(obj => obj.image)
        .map(({ name, location, imageId, cloudEnv, region, imageTags, imageDigestWithoutPrefix, repositoryName }) => ({
          name,
          location,
          imageId,
          cloudEnv,
          region,
          imageTags,
          imageDigestWithoutPrefix,
          repositoryName,
        }))
        .flat();
      attackPathInput.images = filteredImages;

      logger.info(`[setAttackPath] attack path codeSecEvents length : ${issues.length}, for ${appName}`);
      const filteredIssues: Issue[] = issues.filter(
        item =>
          item?.categoryId === OxCategoriesIds.OpenSourceSecurity ||
          //item?.categoryId === OxCategoriesIds.IaC ||
          //item?.categoryId === OxCategoriesIds.ContainerSecurity ||
          item?.categoryId === OxCategoriesIds.CodeSecurity, //||
        //item?.categoryId === OxCategoriesIds.SecretScan, ||
        //item?.categoryId === OxCategoriesIds.SBOM, need to add uid to aggitem for sbom
      );

      let minimizedIssues = [];
      let issueIdToIssue = new Map<string, Issue>();
      for (const issue of filteredIssues) {
        if (issue?.categoryId === OxCategoriesIds.CodeSecurity) {
          const aggItems: AggItem[] = await this.resultsHandler.mongoDBreport.getAggItems(issue?.currentIssueMongoId);
          const attackPathInputItem: AttackPathInputSecurityEvents = AttackPathHelper.prepareCodeSecurityIssue(aggItems, issue);
          if (attackPathInputItem) {
            minimizedIssues.push(attackPathInputItem);
            issueIdToIssue.set(issue.issueId, issue);
          }
        }

        if (issue?.categoryId === OxCategoriesIds.OpenSourceSecurity) {
          const attackPathInputItem: AttackPathInputSecurityEvents = AttackPathHelper.prepareSCAIssue(issue);
          if (attackPathInputItem) {
            minimizedIssues.push(attackPathInputItem);
            issueIdToIssue.set(issue.issueId, issue);
          }
        }
      }

      logger.info(`[setAttackPath] filtered codeSecEvents: ${filteredIssues.length} agg Issues: ${minimizedIssues.length}, for ${appName}`);
      if (minimizedIssues.length === 0) {
        return;
      }

      attackPathInput.vulnerabilities = minimizedIssues;

      const attackPathHelper = new AttackPathHelper(this.attackPathQueue, this.uuid, this.orgName);
      const attackPathRes = await attackPathHelper.generateAttackPath(repo, attackPathInput);

      if (attackPathRes) {
        await attackPathHelper.saveAttackGraphs(attackPathRes, issueIdToIssue, this.resultsHandler, this.cachResovler);
      }

      logger.info(`[setAttackPath] finish setAttackPath for single app: ${appName}`);
    } catch (err) {
      logger.error(`[setAttackPath] failed setAttackPath for single app: ${appName}, err: ${err}`);
    }
  }

  async recalcImportanceWithResources() {
    try {
      for (const app of this.applications) {
        try {
          if (app.fakeApp) {
            continue;
          }

          const extra = {
            hasArtifact: false,
            hasOrchestrator: false,
            hasCloudResource: false,
            haskub: false,
          };

          if (app?.appInfo?.cloud?.cloudAppFlow) {
            if (app?.appInfo?.cloud.cloudAppFlow.length > 0) {
              extra.hasCloudResource = true;
            }
          }

          if (app?.appInfo?.artifactory?.artifactsAppFlow) {
            if (app.appInfo?.artifactory.artifactsAppFlow.length > 0) {
              extra.hasArtifact = true;
            }
          }

          if (app?.appInfo?.orchestrator?.orchestratorsAppFlow) {
            if (app.appInfo?.orchestrator.orchestratorsAppFlow.length > 0) {
              extra.hasOrchestrator = true;
            }
          }

          if (app?.appInfo?.kubernetes?.kubernetesAppFlow) {
            if (app.appInfo?.kubernetes.kubernetesAppFlow.length > 0) {
              extra.haskub = true;
            }
          }

          const cal = new RepoImportanceCalcHelper(this.uuid, this.orgName);
          const importanceCalc = await cal.getRepoImportance(
            app.appInfo.repo.code_repo.repoImportance.info,
            app.appInfo.repo.code_repo,
            extra,
          );
          app.appInfo.repo.code_repo.repoImportance = importanceCalc;

          this.resultsHandler.setImportance(app.appInfo.repo.code_repo.id, importanceCalc);
        } catch (err) {
          logger.error("failed to recalculate single repo importance with extra resources", err);
        }
      }
    } catch (e) {
      logger.error("failed to recalculate repo importance with extra resources", e);
    }
  }

  async openWikiProcessing() {
    if (!StatesHelper.Instance.openWikiEnable) {
      logger.info(`no need to run open wiki, policy is disabled`);
      return;
    }

    logger.info(`start handle open wiki processing`);

    const startTime = new Date().getTime();
    await this.openWikiHelper.setAllOpenWikiForRepos(this.applications);
    const elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));

    logger.info(`finish handle open wiki processing in ${elapsedTime} minutes`);

    await sendScannerPhaseTimeTelemetry(ScanPhaseTime.ScanOpenWikiPhaseTime, this.orgName, this.uuid, elapsedTime);
  }

  @PerformanceTelemetry()
  async AttachAppSources(applications: Application[]) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      logger.info(`try attach: ${applications.length} to sources, total cicd count: ${this.allCICD.length}`);

      this.allCICD.forEach(i => this.updateApplicationBasedOnCICD(i));

      //Connect external sec events on artifacts to a repo by name
      //Dor todo: connect this follow to connectArtifactsImageToAppByImage
      this.connectedArtifactsSecEventsForExternalEvents(applications);

      // to deprecate - rwriting new method
      await this.connectCloudCSPMToApp(applications);

      //Attach - Security Events to app
      const p1 = this.attachCodeRepoSevEvents(applications);
      //Attach - Artifacts to app
      const p2 = this.connectArtifactsImageToAppByImage(applications);
      //Attach - Cloud to app
      const p3 = this.connectCloudRunTimeContainerToApp(applications);
      await Promise.all([p1, p2, p3]);

      logger.info(
        `finish attach: ${applications.length} to sources, Artifact Integrity stats: ${JSON.stringify(this.integrityStats.stats, null, 4)}`,
      );
    } catch (err) {
      logger.info(`failed attach all apps to sources, err: ${err}`, err);
    }
  }

  @PerformanceTelemetry()
  async runPolicyOnAllApps() {
    try {
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "runPolicyOnAllApps before");
      logger.info(`try run policy on all apps: ${this.applications.length}`);

      await PromisePool.for(this.applications)
        .withConcurrency(50)
        .process(async (app: Application) => {
          await AsyncTracker.runWithAsyncTracker(async () => {
            AsyncTracker.setValue("ox-app-id", (app.appInfo?.repo?.code_repo as Repo)?.id);
            AsyncTracker.setValue("ox-app-name", (app.appInfo?.repo?.code_repo as Repo)?.name);
            try {
              logger.info(`star run policy on app: ${app.appInfo.repo.code_repo.fullName}`);
              await app.runAllPolicyForSingleApplication(Constant.execType.endScan);
            } catch (err) {
              logger.error(`failed runAllPolicyForSingleApplication, err: ${err}`);
            }
          });
        });

      logger.info(`finish run policy on all apps: ${this.applications.length}`);
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "runPolicyOnAllApps after");
    } catch (err) {
      logger.error(`failed run policy on all apps, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async sendToResolvedIssueValidation() {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }
      if (isLocalDevelopment()) {
        return;
      }
      if (!StatesHelper.Instance.isResolvedIssuesEnable) {
        logger.info(`resolved issues is off due to feature flag`);
        return;
      }

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "sendToResolvedIssueValidation before");
      const relevantApps = this.resultsHandler.relevantApps;

      const allApps = [...this.applications, ...this.fakeApplications];
      const proms = allApps.map(app => app.resolveIssueValidationHelper.sendToResolveIssues(app, relevantApps));
      await Promise.all(proms);

      logger.info(`finish send to resolved issue validation apps: ${allApps.length}`);
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "sendToResolvedIssueValidation after");
    } catch (err) {
      logger.error(`failed sendToResolvedIssueValidation apps, err: ${err}`);
    }
  }

  async enrichArtifactsData(imageName: string, imageTag: string, imageDigest: string, statsEnough: boolean = true) {
    //kosta
    return false;
  }

  async enrichArtifactsDataByDate(
    imageName: string,
    imageTag: string,
    imageDigest: string,
    imageDate: string,
    statsEnough: boolean = false,
  ) {
    //kosta
    return false;
  }

  async connectArtifactsImageToAppByImage(applications: Application[]) {
    try {
      logger.info(`try connected artifacts image to app by image`);
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `before connectArtifactsImageToAppByImage`);

      //Connect images to repo
      const p1 = this.connectArtifactsImageToApp(applications);
      //Collect call function graph as its needed for next step
      const p2 = this.collectCllGraphRes();
      await Promise.all([p1, p2]);

      await this.handleConnectedImagesToRepo();
      logger.info(`finish connected artifacts image to app by image`);
    } catch (err) {
      logger.error(`failed connectedArtifactsImageToAppAndRunBlame, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async connectArtifactsImageToApp(applications: Application[]) {
    try {
      if (process.env.IGNORE_CONNECT_IMAGES) {
        return;
      }

      const jobsCount = Object.keys(this.allCICDjobs).length;
      const isContainerEnrichmentDisabled =
        (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "ox-enrich-artifacts-feature")) ||
        this.allImagesFromRegistry.length <= jobsCount;

      StatesHelper.Instance.isContainerEnrichmentDisabled = isContainerEnrichmentDisabled;
      if (jobsCount == 0) {
        StatesHelper.Instance.isContainerEnrichmentDisabled = true;
        logger.info(`isContainerEnrichmentDisabled disable due to 0 jobs count`);
      }
      logger.info(`isContainerEnrichmentDisabled: ${isContainerEnrichmentDisabled}`);

      //prepare data for optimization
      const allAppsByName: Map<string, Application> = new Map<string, Application>();
      const allAppsByFullName: Map<string, Application> = new Map<string, Application>();
      const allAppsById: Map<string, Application> = new Map<string, Application>();
      let applicationsMap: Map<string, MatchResultString> = new Map<string, MatchResultString>();
      try {
        applicationsMap = applications.reduce((map, app) => {
          const repo: Repo = app.appInfo.repo.code_repo;
          return map.set(repo.name, `${repo.name}|${repo.id}`);
        }, new Map<string, MatchResultString>());

        for (const app of applications) {
          const repo: Repo = app.appInfo.repo.code_repo;
          if (!repo) {
            continue;
          }
          allAppsByName.set(repo.name, app);
          allAppsByFullName.set(repo.fullName, app);
          allAppsById.set(repo.id, app);
        }
      } catch (err) {
        logger.error(`failed prepare data for optimization, err: ${err}`);
      }

      logger.info(`try attach total image artifacts count: ${this.allImagesFromRegistry.length}, jobs count: ${jobsCount}`);

      const connectedRepos: Application[] = [];
      const handleSingleImage = async (imageInfo: ImageInfo) => {
        try {
          const image: ImageDetail = imageInfo.image;

          logger.info(`try attach image artifacts: ${image.name}, sec alerts count: ${imageInfo.securityEvents.length}`);

          let imageConnected = false;
          //Gadi - && !imageInfo.isDelta
          if (StatesHelper.Instance.isContainerEnable) {
            const matchingRepo: MatchResult = await AsyncTracker.runWithAsyncTracker(async () => {
              AsyncTracker.setValue("ox-image-name", image.name);
              AsyncTracker.setValue("ox-image-id", image.imageDigest);
              return await RepositoryMatcher.instance.findRepoForImage(image, applicationsMap);
            });

            //Just attach all images to each application for local debug process
            if (process.env.RUN_LOCAL && !matchingRepo) {
              const repoConnection: Application = allAppsById.entries().next().value[1];
              repoConnection.appInfo.artifactory.registryImage.push(imageInfo);
              imageInfo.securityEvents.forEach(i => {
                repoConnection.appInfo.artifactory.securityEvents.push(i);
              });
              imageConnected = true;
              connectedRepos.push(repoConnection);
              return;
            }

            if (matchingRepo) {
              image.dockerFilePath = matchingRepo.dockerfilePath;
              const repoConnection: Application = allAppsById.get(matchingRepo.id);
              if (repoConnection) {
                repoConnection.appInfo.artifactory.registryImage.push(imageInfo);
                imageInfo.securityEvents.forEach(i => {
                  repoConnection.appInfo.artifactory.securityEvents.push(i);
                });
                logger.info(
                  `repoMatcher, found connection between image: ${imageInfo.image.name} and app: ${
                    repoConnection.appInfo.repo.code_repo.name
                  }, match method: ${matchingRepo.method.toString()}, dockerfilePath: ${matchingRepo.dockerfilePath}`,
                );
                imageConnected = true;
                connectedRepos.push(repoConnection);
                return;
              } else {
                logger.error(
                  `repoMatcher, found connection between image: ${imageInfo.image.name}, but cannot find repo: ${matchingRepo.name}, by id: ${matchingRepo.id}`,
                );
              }
            }
          }

          if (jobsCount > 0 || process.env.DEBUG != undefined) {
            const digestOnly = image.imageDigest.split(":");
            const foundCicd = this.allCICDjobs[digestOnly.length === 2 ? digestOnly[1] : digestOnly[0]];

            //Found by hash as first priority
            if (foundCicd != undefined) {
              image.cicdFoundByHash = true;
              const repoName = foundCicd[0].repositories.repoName;
              let repoConnection: Application = allAppsByFullName.get(repoName);
              if (!repoConnection) {
                repoConnection = allAppsByName.get(repoName);
              }
              if (repoConnection) {
                repoConnection.appInfo.artifactory.registryImage.push(imageInfo);
                imageInfo.securityEvents.forEach(i => {
                  repoConnection.appInfo.artifactory.securityEvents.push(i);
                });
                logger.info(
                  `crawler, find cicd for artifactory image by hash: ${image.imageDigest}, image name: ${image.name} to repo ${repoName}`,
                );
                imageConnected = true;
                connectedRepos.push(repoConnection);
                return;
              } else {
                logger.error(
                  `crawler, cannot find cicd for artifactory image by hash: ${image.imageDigest}, image name: ${image.name} but cannot find repo ${repoName}`,
                );
              }
            }

            //Found by name in cicd job
            const cicdByName = this.allCICDjobsByImageName[image.name];
            if (cicdByName) {
              const repoName = cicdByName.repositories.repoName;
              let repoConnection: Application = allAppsByFullName.get(repoName);
              if (!repoConnection) {
                repoConnection = allAppsByName.get(repoName);
              }
              if (repoConnection) {
                repoConnection.appInfo.artifactory.registryImage.push(imageInfo);
                imageInfo.securityEvents.forEach(i => {
                  repoConnection.appInfo.artifactory.securityEvents.push(i);
                });
                logger.info(`crawler, find cicd for artifactory image by name: ${image.name} to repo ${repoName}`);
                image.cicdFoundByName = true;
                imageConnected = true;
                connectedRepos.push(repoConnection);
                return;
              } else {
                logger.error(`crawler, cannot find cicd for artifactory image by name: ${image.name} but cannot find repo: ${repoName}`);
              }
            }

            let type = "latest";
            if (image?.imageTags?.length) {
              if (image?.imageTags?.length > 0) {
                type = image.imageTags[0];
              }
            }
            let found = false;
            if (!isContainerEnrichmentDisabled) {
              found = image.imagePushedAt
                ? await this.enrichArtifactsDataByDate(image.name ?? image.repositoryName, type, image.imageDigest, image.imagePushedAt)
                : await this.enrichArtifactsData(image.name ?? image.repositoryName, type, image.imageDigest);
            } else {
              found = true;
            }
            if (found) {
              image.cicdFoundByHash = true;
            }

            //Try to find by name again in app list
            if (image.name) {
              let repoConnection: Application = allAppsByFullName.get(image.name);
              if (!repoConnection) {
                repoConnection = allAppsByName.get(image.name);
              }
              if (repoConnection) {
                repoConnection.appInfo.artifactory.registryImage.push(imageInfo);
                imageInfo.securityEvents.forEach(i => {
                  repoConnection.appInfo.artifactory.securityEvents.push(i);
                });
                logger.info(
                  `crawler, find cicd for artifactory image by name: ${image.imageDigest} to a repo, image name: ${image.name} to repo ${image.name}`,
                );
                image.cicdFoundByName = true;
                imageConnected = true;
                connectedRepos.push(repoConnection);
                return;
              }
            }
          }

          if (!imageConnected) {
            this.notConnectedImagesToApps.push(imageInfo);
            logger.info(
              `crawler, cannot find cicd for artifactory image at all, image hash: ${image.imageDigestWithoutPrefix}, image name: ${image.name}`,
            );
          }
        } catch (err) {
          this.notConnectedImagesToApps.push(imageInfo);
          logger.error(`failed in single artifactory connection cicd, name: ${imageInfo.image.name}, err: ${err}`);
        }
      };

      //For demo we dont need fake apps
      if (StatesHelper.Instance.isDemo) {
        this.notConnectedImagesToApps = [];
      }

      await PromisePool.for(this.allImagesFromRegistry).withConcurrency(100).process(handleSingleImage);

      logger.info(
        `finish attach total image artifacts count: ${this.allImagesFromRegistry.length}, attached: ${connectedRepos.length}, not attached: ${this.notConnectedImagesToApps.length}`,
      );

      //Try to attach artifact info to app
      await PromisePool.for(connectedRepos)
        .withConcurrency(10)
        .process(
          async (app: Application) =>
            await AsyncTracker.runWithAsyncTracker(async () => {
              AsyncTracker.setValue("ox-app-id", (app.appInfo?.repo?.code_repo as Repo)?.id);
              AsyncTracker.setValue("ox-app-name", (app.appInfo?.repo?.code_repo as Repo)?.name);
              try {
                await this.saveApplicationImageDataInDB(app, app.appInfo.artifactory.registryImage);
                return true;
              } catch (err) {
                logger.error(`failed saveApplicationImageDataInDB, err: ${err}`);
                return false;
              }
            }),
        );
    } catch (err) {
      logger.error(`failed in artifactory not found in cicd, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async createFakeAppsForSecurityAlerts(fakeApps: Application[]) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      const violatedEventsExternalSecEventsArr = Object.values(this.allUnattachedExternalCodeSecurityEvents) as any;

      logger.info(
        `start createFakeAppsForSecurityAlerts, violatedEventsExternalSecEventsArr: ${violatedEventsExternalSecEventsArr.length}`,
      );

      const apps: Application[] = [];

      for (const violatedEventsExternalSecEvents of violatedEventsExternalSecEventsArr) {
        violatedEventsExternalSecEvents.forEach(i => {
          i.violationInfo = `${i.violationInfo} in ${i.repoFullName} repository`;
          CveToolsService.instance.addToCveTools(i.repoFullName, i);
        });

        let appRepo = new Application(
          this.uuid,
          this.orgName,
          this.policyRules,
          this.jsonApplicationDiscoveryOverview,
          this.ruleExclusions,
          this.resultsHandler,
          this.blameQueue,
          this.secretValidationQueue,
          this.autoFixQueue,
          this.alertRecommendationQueue,
          this.iacVerificationQueue,
          this.scaVerificationQueue,
          this.openSourceInfoQueue,
          this.cachResovler,
          this.resolveIssueValidationQueue,
        );

        await this.setFakeAppInfo(violatedEventsExternalSecEvents[0].repoFullName, appRepo, CodeRepo);
        this.setFakeRepoInfo(appRepo);

        if (appRepo.appInfo.repo == null) {
          appRepo.appInfo.repo = {};
          appRepo.appInfo.repo[CodeRepoTypes[CodeRepoTypes.securityEvents]] = violatedEventsExternalSecEvents;
          apps.push(appRepo);
          continue;
        }

        const shouldRun = isDevelopment() || isLocalDevelopment();

        if (shouldRun) {
          const alreadyExist = fakeApps.find(
            i => i.appInfo.repo.code_repo.id.toLowerCase() === appRepo.appInfo.repo.code_repo.id.toLowerCase(),
          );

          if (alreadyExist) {
            appRepo = alreadyExist;
            logger.info(
              `setFakeApp: fake app already exist: ${alreadyExist.appInfo.repo.code_repo.name}, adding sec events to existing app`,
            );
          } else {
            fakeApps.push(appRepo);
            logger.info(`setFakeApp: new fake app detected: ${alreadyExist?.appInfo?.repo?.code_repo?.name}`); // "alreadyExist" value can be undefined if fakeApps is empty array
          }
        }

        appRepo.appInfo.repo[CodeRepoTypes[CodeRepoTypes.securityEvents]] = violatedEventsExternalSecEvents;
        apps.push(appRepo);
      }

      //Run policy on all fake apps of security events
      await PromisePool.for(apps)
        .withConcurrency(10)
        .process(
          async app =>
            await AsyncTracker.runWithAsyncTracker(async () => {
              AsyncTracker.setValue("ox-app-id", (app.appInfo?.repo?.code_repo as Repo)?.id);
              AsyncTracker.setValue("ox-app-name", (app.appInfo?.repo?.code_repo as Repo)?.name);
              await app.handleFakeAppFlowForCode();
              await app.runAllPolicyForUnattachedEvents();
            }),
        );
    } catch (err) {
      logger.error(`failed create fake apps for all security alerts, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async createFakeAppsForRepoUsers() {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }
      if (!GlobalCodeRepoData.Instance.getUsers()) {
        logger.info(`no run policy with allPublicRepos`);
        return;
      }

      logger.info(`start createFakeAppsForRepoUsers`);

      const appRepo = new Application(
        this.uuid,
        this.orgName,
        this.policyRules,
        this.jsonApplicationDiscoveryOverview,
        this.ruleExclusions,
        this.resultsHandler,
        this.blameQueue,
        this.secretValidationQueue,
        this.autoFixQueue,
        this.alertRecommendationQueue,
        this.iacVerificationQueue,
        this.scaVerificationQueue,
        this.openSourceInfoQueue,
        this.cachResovler,
        this.resolveIssueValidationQueue,
      );

      const gitCollectors = this.collectorManager.getConnectorByName([repoType.github]);
      if (gitCollectors.length == 0) {
        logger.info(`no need to set fake app per user, not github token`);
        return;
      }

      await this.setFakeAppInfo(`${RepoTypeName.github}-Members`, appRepo, CodeRepo);
      this.setFakeRepoInfo(appRepo, RepoTypeName.github);
      // avoid duplication
      appRepo.appInfo.repository.repoAppFlow = [appRepo.appInfo.repository.repoAppFlow[0]];

      let allOrgUsers: User[] = Object.values(GlobalCodeRepoData.Instance.getUsers()).flat() as any;
      if (!allOrgUsers) {
        allOrgUsers = [];
      }
      const formerUsersInfo: User[] = GlobalCodeRepoData.Instance.formerUsers;

      allOrgUsers = [...allOrgUsers, ...formerUsersInfo];
      if (allOrgUsers.length == 0) {
        return;
      }

      appRepo.appInfo.repo.code_repo.repoImportance.total = 70;
      logger.info(`set members fake app, res: ${70}, formerUsersInfo: ${formerUsersInfo.length}`);

      logger.info(`try run policy with allPublicRepos: ${allOrgUsers.length}`);
      appRepo.appInfo.repo[CodeRepoTypes[CodeRepoTypes.allPublicRepos]] = allOrgUsers;

      await appRepo.runAllPolicyForUnattachedEvents();
    } catch (err) {
      logger.error(`failed create fake apps for users, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async createFakeAppsForRepoSetting() {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }
      if (!GlobalCodeRepoData.Instance.getUsers()) {
        logger.info(`no run policy with github settings`);
        return;
      }

      logger.info(`start createFakeAppsForRepoSetting`);

      const gitCollectors = this.collectorManager.getConnectorByName([
        repoType.github,
        repoType.gitlab,
        repoType.bitbucket,
        repoType.azure,
      ]);

      for (const gitCollector of gitCollectors as any) {
        for (const org of gitCollector.getAllOrgs()) {
          const appRepo = new Application(
            this.uuid,
            this.orgName,
            this.policyRules,
            this.jsonApplicationDiscoveryOverview,
            this.ruleExclusions,
            this.resultsHandler,
            this.blameQueue,
            this.secretValidationQueue,
            this.autoFixQueue,
            this.alertRecommendationQueue,
            this.iacVerificationQueue,
            this.scaVerificationQueue,
            this.openSourceInfoQueue,
            this.cachResovler,
            this.resolveIssueValidationQueue,
          );

          let gitTypeName = RepoTypeName[gitCollector.token.name.toLowerCase()] || "Git";
          if (gitTypeName === RepoTypeName.azure) {
            gitTypeName = "azure repos (git)";
          }

          await this.setFakeAppInfo(`${gitTypeName}-Settings (${org.name})`, appRepo, CodeRepo);
          this.setFakeRepoInfo(appRepo, gitTypeName);

          appRepo.appInfo.repo.code_repo.gitRoles = this.roleHelper.getGitRoles(appRepo.appInfo.repo.code_repo.type.toLowerCase());

          appRepo.appInfo.repo.code_repo.org = org.name;
          appRepo.appInfo.repo.code_repo.orgId = org.id;

          // avoid duplication
          appRepo.appInfo.repository.repoAppFlow = [appRepo.appInfo.repository.repoAppFlow[0]];

          //Attach users per org
          const orgWithPrefix = `${gitTypeName.toLowerCase()}_${org.name}`;
          let allOrgUsers: User[] = GlobalCodeRepoData.Instance.getUsersByOrg(orgWithPrefix);
          if (!allOrgUsers) {
            allOrgUsers = [];
          }
          appRepo.appInfo.repo[CodeRepoTypes[CodeRepoTypes.allUsers]] = allOrgUsers;

          //Attach users per org
          appRepo.appInfo.repo[CodeRepoTypes[CodeRepoTypes.auditLog]] = GlobalCodeRepoData.Instance.auditLogBasedOnUser;
          appRepo.appInfo.repo[CodeRepoTypes[CodeRepoTypes.allPulls]] = GlobalCodeRepoData.Instance.UserPullRequest;
          appRepo.appInfo.repo[CodeRepoTypes[CodeRepoTypes.scopesRepoMap]] = GlobalCodeRepoData.Instance.scopesRepoMap;

          appRepo.appInfo.repo[CodeRepoTypes[CodeRepoTypes.allSecEvents]] = GlobalCodeRepoData.Instance.secEvents;

          //Attach repos per org
          let allOrgRepos = GlobalCodeRepoData.Instance.repos.filter(repo => repo.organization === org.name);

          if (!allOrgRepos) {
            allOrgRepos = [];
          }

          if (org.twoFactorEnabled === false) {
            appRepo.appInfo.repo.code_repo.isOrg2faEnabled = false;
          } else {
            appRepo.appInfo.repo.code_repo.isOrg2faEnabled = true;
          }

          appRepo.appInfo.repo[CodeRepoTypes[CodeRepoTypes.allOrgsRepos]] = allOrgRepos;

          try {
            const id = org.name;
            const res = GlobalCodeRepoData.Instance.orgToBp[id];
            if (res) {
              appRepo.appInfo.repo.code_repo.repoImportance.total = res;
              logger.info(`set orgToBp for org: ${id}, res: ${res}`);
            } else {
              appRepo.appInfo.repo.code_repo.repoImportance.total = 1;
            }
          } catch (err) {
            logger.error(`failed calc repoImportance for fake repo app, err: ${err}`);
          }

          await appRepo.runAllPolicyForUnattachedEvents();
        }
      }
    } catch (err) {
      logger.error(`failed create fake apps, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async createFakeAppsForRunTimeArtifactoryEvents(fakeApps: Application[]) {
    try {
      logger.info(`try createFakeAppsForRunTimeArtifactoryEvents, adding ${this.runtimeArtifactsSecurityEvents.length}`);
      const runTimeViolatedEventsArtifacts = this.runtimeArtifactsSecurityEvents;

      const aggByContainerRegistry = {};
      runTimeViolatedEventsArtifacts.forEach(i => {
        try {
          let key = `${i?.artifacts?.runningOnHost}`;
          if (i?.artifacts?.accountId && i?.artifacts?.runningOnHost) {
            key = `${i?.artifacts?.runningOnHost} - ${i?.artifacts?.accountId}`;
          }
          if (!key) {
            key = "Workload";
          }

          if (StatesHelper.Instance.aggCloudAlertsBaseOnOrg && i?.artifacts?.accountId) {
            key = `${i?.artifacts?.accountId}`;
          }

          if (aggByContainerRegistry[key]) {
            let item = aggByContainerRegistry[key];
            item.events.push(i);
          } else {
            const item = {
              events: [],
            };
            item.events.push(i);
            aggByContainerRegistry[key] = item;
          }
        } catch (err) {
          logger.error(`failed create single runTimeViolatedEventsArtifacts, err: ${err}`);
        }
      });

      logger.info(
        `start artifactory run time unattached event, violatedEventsArtifacts: ${runTimeViolatedEventsArtifacts.length}, registry count: ${
          Object.keys(aggByContainerRegistry).length
        }`,
      );

      for (const [registry, d] of Object.entries(aggByContainerRegistry)) {
        try {
          const data = d as any;

          let events = data.events;
          if (!events) {
            events = [];
          }

          if (events.length > 0) {
            let appCloud = new Application(
              this.uuid,
              this.orgName,
              this.policyRules,
              this.jsonApplicationDiscoveryOverview,
              this.ruleExclusions,
              this.resultsHandler,
              this.blameQueue,
              this.secretValidationQueue,
              this.autoFixQueue,
              this.alertRecommendationQueue,
              this.iacVerificationQueue,
              this.scaVerificationQueue,
              this.openSourceInfoQueue,
              this.cachResovler,
              this.resolveIssueValidationQueue,
            );

            let fakeAppName = `${registry}`;
            let type = registry;
            const env = events[0].cloudEnv;

            if (StatesHelper.Instance.aggCloudAlertsBaseOnOrg) {
              fakeAppName = `${getCloudProviderType(env)}-${fakeAppName}-Cloud`;
              type = `${getCloudProviderType(env)}`;
            }

            const ArtifactoryCopy = JSON.parse(JSON.stringify(Artifactory));
            ArtifactoryCopy.type = type;
            await this.setFakeAppInfo(fakeAppName, appCloud, ArtifactoryCopy, type);

            const alreadyExist = fakeApps.find(
              i => i.appInfo.repo.code_repo.id.toLowerCase() === appCloud.appInfo.repo.code_repo.id.toLowerCase(),
            );

            if (alreadyExist) {
              appCloud = alreadyExist;
            } else {
              fakeApps.push(appCloud);
            }

            //Add events
            if (!Array.isArray(appCloud.appInfo.artifactory.securityEvents)) {
              appCloud.appInfo.artifactory.securityEvents = [];
            }
            events.forEach(i => {
              appCloud.appInfo.artifactory.securityEvents.push(i);
            });
            if (!appCloud.appInfo.artifactory.registryImage) {
              appCloud.appInfo.artifactory.registryImage = [];
            }
          }
        } catch (err) {
          logger.error(`failed run single runTimeViolatedEventsArtifacts, err: ${err}`);
        }
      }

      logger.info(`finish createFakeAppsForRunTimeArtifactoryEvents`);
    } catch (err) {
      logger.error(`failed createFakeAppsForRunTimeArtifactoryEvents, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async createFakeAppsForArtifactoryEvents(fakeApps: Application[]) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      const startTime = new Date().getTime();
      const allUnattachedSecEvents = [];

      this.notConnectedImagesToApps.forEach(i => {
        allUnattachedSecEvents.push(i.securityEvents);
      });
      const flatten = allUnattachedSecEvents.flat();
      if (flatten.length) {
        logger.info(`before starting run sec events on fake artifact, adding ${flatten.length} to all unattached artifact events`);
        flatten.forEach(i => {
          this.allArtifactsSecurityEventsForExternalTools.push(i);
        });
      }

      logger.info(`allUnattachedArtifactsSecurityEvents, adding ${this.allArtifactsSecurityEventsForExternalTools.length}`);
      const violatedEventsArtifacts = this.allArtifactsSecurityEventsForExternalTools;

      let apps: Application[] = [];
      const aggByContainerRegistry = {};
      violatedEventsArtifacts.forEach(i => {
        let key = i?.artifacts?.registryName;
        if (!key) {
          key = "Artifactory-Storage";
        }

        const shouldRun = StatesHelper.Instance.isContainerEnable;
        if (!shouldRun) {
          key = "Artifactory-Storage";
        }

        if (aggByContainerRegistry[key]) {
          let item = aggByContainerRegistry[key];
          item.events.push(i);
        } else {
          const item = {
            events: [],
            images: [],
          };
          item.events.push(i);
          aggByContainerRegistry[key] = item;
        }
      });

      this.notConnectedImagesToApps.forEach(i => {
        let key = i?.image?.cloudEnv;
        if (!key) {
          key = "Artifactory-Storage";
        }

        if (aggByContainerRegistry[key]) {
          let item = aggByContainerRegistry[key];
          item.images.push(i);
        } else {
          const item = {
            events: [],
            images: [],
          };
          item.images.push(i);
          aggByContainerRegistry[key] = item;
        }
      });

      logger.info(
        `start artifactory unattached event, not found images in CICD: ${this.notConnectedImagesToApps.length}, violatedEventsArtifacts: ${
          violatedEventsArtifacts.length
        }, registry count: ${Object.keys(aggByContainerRegistry).length}`,
      );

      for (const [registry, d] of Object.entries(aggByContainerRegistry)) {
        const fakeAppName = `${registry}`;
        const data = d as any;

        let events = data.events;
        if (!events) {
          events = [];
        }
        let notFoundImagesInCICD = data.images;
        if (!notFoundImagesInCICD) {
          notFoundImagesInCICD = [];
        }

        if (events.length > 0 || notFoundImagesInCICD.length > 0) {
          let appArtifactory = new Application(
            this.uuid,
            this.orgName,
            this.policyRules,
            this.jsonApplicationDiscoveryOverview,
            this.ruleExclusions,
            this.resultsHandler,
            this.blameQueue,
            this.secretValidationQueue,
            this.autoFixQueue,
            this.alertRecommendationQueue,
            this.iacVerificationQueue,
            this.scaVerificationQueue,
            this.openSourceInfoQueue,
            this.cachResovler,
            this.resolveIssueValidationQueue,
          );

          const ArtifactoryCopy = JSON.parse(JSON.stringify(Artifactory));
          ArtifactoryCopy.type = registry;
          await this.setFakeAppInfo(fakeAppName, appArtifactory, ArtifactoryCopy, registry);

          const shouldRun = isDevelopment() || isLocalDevelopment();

          if (shouldRun) {
            const alreadyExist = fakeApps.find(
              i => i.appInfo.repo.code_repo.id.toLowerCase() === appArtifactory.appInfo.repo.code_repo.id.toLowerCase(),
            );

            if (alreadyExist) {
              logger.info(
                `setFakeApp: fake app already exist: ${alreadyExist.appInfo.repo.code_repo.name}, adding sec events to existing app`,
              );
              appArtifactory = alreadyExist;
            } else {
              logger.info(`setFakeApp: new fake app detected: ${appArtifactory?.appInfo?.repo?.code_repo?.name}`); // "alreadyExist" value can be undefined if fakeApps is empty array
              fakeApps.push(appArtifactory);
            }
          }

          appArtifactory.appInfo.artifactory.registryImage = notFoundImagesInCICD;
          appArtifactory.appInfo.artifactory.securityEvents = events as any;

          apps.push(appArtifactory);
        }
      }

      logger.info(`continue unattached event, apps: ${apps.length}`);

      await PromisePool.for(apps)
        .withConcurrency(50)
        .process(async appArtifactory =>
          AsyncTracker.runWithAsyncTracker(async () => {
            AsyncTracker.setValue("ox-app-id", (appArtifactory.appInfo.repo.code_repo as Repo)?.id);
            AsyncTracker.setValue("ox-app-name", (appArtifactory.appInfo.repo.code_repo as Repo)?.name);
            await this.runPolOnFakeArtifactsApps(appArtifactory);
          }),
        );

      const elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));

      await sendScannerPhaseTimeTelemetry(ScanPhaseTime.ScanSupplyChainTime, this.orgName, this.uuid, elapsedTime);

      logger.info(`finish artifactory unattached event, elapsed time: ${elapsedTime}`);
    } catch (err) {
      logger.error(`failed create fake apps for artifactory events, err: ${err}`);
    }
  }

  async runPolOnFakeArtifactsApps(appArtifactory: Application) {
    try {
      if (StatesHelper.Instance.skipHandleArtifactsOnFakeApps) {
        return;
      }

      mergeArtifactsForAppFlow(appArtifactory);

      //Gady uncomment when improved
      //await this.saveApplicationImageDataInDB(appArtifactory, this.notConnectedImagesToApps);

      await appArtifactory.handleFakeAppFlowForContainers();
      await appArtifactory.runAllPolicyForUnattachedEvents();
      await appArtifactory.saveSbomFromRegistryForAppScreen();
    } catch (err) {
      logger.error(`failed runPolOnFakeArtifactsApps, err: ${err}`);
    }
  }

  async generateSingleSbomForOrg() {
    try {
      const uniqueInfo = new Map<string, ExtendedSbomComponent>();

      //Get only unique once
      let totalUniqueLibs = 0;
      for (const i of this.applications) {
        try {
          const libs = await i.getSbomDataFromLocalDB();
          for (const lib of libs) {
            try {
              const key = `${lib.name}_${lib.version}`;
              if (uniqueInfo.has(key)) {
                continue;
              }
              uniqueInfo.set(key, lib);
              totalUniqueLibs++;
            } catch (err) {
              logger.error(`failed to set single unique sboms for: ${i.appInfo.repo.code_repo.fullName}, err: ${err}`);
            }
          }
        } catch (err) {
          logger.error(`failed to set all unique sboms for all repos, err: ${err}`);
        }
      }

      // just find first available tools array from all sboms
      const sbomEventWithTools = this.applications
        .flatMap(app => (app.appInfo.repo[ArtifactoryTypes[ArtifactoryTypes.sbom]] ?? []) as SbomEvent[])
        .find(sbomEvent => Array.isArray(sbomEvent?.sbom?.metadata?.tools));
      const tools = sbomEventWithTools?.sbom?.metadata?.tools ?? [];

      const components = [...uniqueInfo.values()]
        // remove extended properties
        .map(exc => ({
          "bom-ref": exc["bom-ref"],
          type: exc.type,
          name: exc.name,
          version: exc.version,
          purl: exc.purl,
          properties: exc.properties,
          licenses: exc.licenses,
        }))
        // cleanup null/undefined fields
        .map(c => {
          Object.keys(c).forEach(key => {
            if (c[key] === null || c[key] === undefined) {
              delete c[key];
            }
          });
          return c;
        })
        .sort((cA, cB) => (cA.name > cB.name ? 1 : -1));

      logger.info(`org sbom total unique count: ${totalUniqueLibs}`);

      return {
        bomFormat: "CycloneDX",
        specVersion: "1.4",
        serialNumber: "urn:uuid:4e3269f0-f5e8-4e7c-8399-f085eb269086",
        version: 1,
        components,
        metadata: {
          timestamp: new Date().toISOString(),
          tools: tools,
          component: {
            "bom-ref": this.orgName,
            name: this.orgName,
            type: SbomComponentType.Organization,
            properties: [],
          },
        },
        dependencies: [],
        vulnerabilities: [],
      };
    } catch (err) {
      logger.error(`failed to set sboms for all repos, err: ${err}`);
    }
    return null;
  }

  async saveApplicationImageDataInDB(app: Application, imagesInfo: ImageInfo[]): Promise<void> {
    let appId = "";
    try {
      appId = app.appInfo.repo.code_repo.id;

      return;
      // Gady to improve
      logger.info(`Skipping save image sbom for app: ${appId}`);

      const startTime = new Date().getTime();
      logger.info(`try set image info in DB for app: ${appId}`);

      const promisedSbomSaves = imagesInfo
        .map(i => i.sbomEvents.map(sbomEvent => this.resultsHandler.setSbom(appId, sbomEvent.sbom, AppSbomType.image, i.image)))
        .flat();
      await Promise.all(promisedSbomSaves);

      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
      logger.info(`finish set image info in DB for app: ${appId}, elapsedTime: ${elapsedTime}`);
    } catch (err) {
      logger.error(
        `failed to set sboms for images: ${appId}, ${imagesInfo.map(imageInfo => imageInfo.image.repositoryName).join(", ")} err: ${err}`,
      );
    }
  }

  @PerformanceTelemetry()
  async setOnFakeCloudSecEvents(fakeApps: Application[]) {
    try {
      const violatedEvents = this.allCloudSecurityEvents.filter(i => i.isViolation);

      for (const violatedEvent of violatedEvents) {
        if (!violatedEvent.cloudEnv) {
          logger.error(`failed setOnFakeCloudSecEvents, no cloud env`);
          continue;
        }

        let key = `${violatedEvent.cloudEnv}`;
        if (StatesHelper.Instance.aggCloudAlertsBaseOnOrg && violatedEvent.accountName) {
          key = `${violatedEvent.cloudEnv}_${violatedEvent.accountName}`;
        } else if (violatedEvent.accountName) {
          key = `${violatedEvent.cloudEnv}_${violatedEvent.accountName}`;
        }

        if (this.cloudEnvToCloudEvents[key] == undefined) {
          this.cloudEnvToCloudEvents[key] = [violatedEvent];
        } else {
          this.cloudEnvToCloudEvents[key].push(violatedEvent);
        }
      }

      for (const [key, value] of Object.entries(this.cloudEnvToCloudEvents)) {
        const events = value as any;

        if (events.length == 0) {
          continue;
        }

        const appCloud = new Application(
          this.uuid,
          this.orgName,
          this.policyRules,
          this.jsonApplicationDiscoveryOverview,
          this.ruleExclusions,
          this.resultsHandler,
          this.blameQueue,
          this.secretValidationQueue,
          this.autoFixQueue,
          this.alertRecommendationQueue,
          this.iacVerificationQueue,
          this.scaVerificationQueue,
          this.openSourceInfoQueue,
          this.cachResovler,
          this.resolveIssueValidationQueue,
        );

        const env = events[0].cloudEnv;
        let appName = `${getCloudProviderType(env)}-Cloud`;

        if (StatesHelper.Instance.aggCloudAlertsBaseOnOrg && events[0].accountName) {
          appName = `${getCloudProviderType(env)}-${events[0].accountName}-Cloud`;
        } else if (events[0].accountName) {
          appName = `${getCloudProviderType(env)}-${events[0].accountName}-Cloud`;
        }

        await this.setFakeAppInfo(appName, appCloud, CloudCollectorData, `${getCloudProviderType(env)}-Cloud`);

        //Add events
        if (!Array.isArray(appCloud.appInfo.cloud.cloudSecurityEvents)) {
          appCloud.appInfo.cloud.cloudSecurityEvents = [];
        }
        events.forEach(i => {
          appCloud.appInfo.cloud.cloudSecurityEvents.push(i);
        });

        fakeApps.push(appCloud);
      }
    } catch (err) {
      logger.error(`failed in cloud security events fake app, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async connectCloudRunTimeContainerToApp(applications: Application[]) {
    try {
      const connectedToRepoByCicd: Record<string, ImageContainerDetail> = {};
      const jobsCount = Object.keys(this.allCICDjobs).length;

      logger.info(`try attach total runtime container count: ${this.allUnattachedAWSRuntimeResources.size}, jobs count: ${jobsCount}`);

      if (jobsCount > 0 && this.allUnattachedAWSRuntimeResources.size <= jobsCount) {
        const isContainerEnrichmentDisabled = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "ox-enrich-artifacts-feature");
        const connectImagesOneByOne = async (awsRuntimeResources: ImageContainerDetail) => {
          try {
            const foundCicd = this.allCICDjobs[awsRuntimeResources.imageDigestWithoutPrefix];

            //Found by hash
            if (foundCicd != undefined) {
              logger.info(
                `crawler, find cicd for cloud image by hash: ${awsRuntimeResources.imageDigestWithoutPrefix}, image name: ${
                  awsRuntimeResources.containerImageInfo.image ?? awsRuntimeResources.containerImageInfo.repositoryName
                }`,
              );
              awsRuntimeResources.cicdFoundByHash = true;
              connectedToRepoByCicd[foundCicd[0].repositories.repoName] = awsRuntimeResources;

              if (awsRuntimeResources.objType == CloudTypes.EC2) {
                delete awsRuntimeResources.containerImageInfo;
              }
              return;
            }

            let cicdByName = this.allCICDjobsByImageName[awsRuntimeResources.imageNameWithoutTag];

            // Handle lambda containers
            if (awsRuntimeResources.objType == CloudTypes.lambda) {
              awsRuntimeResources.cicdFoundByName = false;

              //
              // Lambda's can be with regex names
              //
              for (const [regExKey, cicd] of this.regExImage) {
                try {
                  // Compiling regex on the fly can produce error, which needs to be handled
                  const regex = new RegExp(regExKey, "g");
                  const match = regex.exec(awsRuntimeResources.imageNameWithoutTag);
                  if (match != null) {
                    cicdByName = cicd;

                    // Special case: we found lambda by regex
                    await retainApplicationsForArtifactScreen(
                      regExKey,
                      awsRuntimeResources.imageNameWithoutTag,
                      awsRuntimeResources.taskDefinition?.CodeSize ?? "0",
                      awsRuntimeResources.link ?? "",
                      cicd,
                    );
                    break;
                  }
                } catch (err) {
                  logger.error(`Application Manager: failed to compile regular expression: ${JSON.stringify(regExKey)}`);
                }
              }

              if (cicdByName != undefined) {
                logger.info(`crawler, find cicd for Lambda cloud image by name: ${awsRuntimeResources.imageNameWithoutTag}`);

                delete awsRuntimeResources.containerImageInfo;

                connectedToRepoByCicd[cicdByName.repositories.repoName] = awsRuntimeResources;
              } else {
                let found = isContainerEnrichmentDisabled;

                //
                // Perform hard search, since we might have partial match (due to graphql nonsense)
                //
                for (const [key, value] of Object.entries(this.allCICDjobsByImageName)) {
                  if (key.includes(awsRuntimeResources.imageNameWithoutTag)) {
                    logger.info(`crawler, find cicd for Lambda cloud image by partial name: ${awsRuntimeResources.imageNameWithoutTag}`);

                    cicdByName = value;
                    delete awsRuntimeResources.containerImageInfo;
                    connectedToRepoByCicd[cicdByName.repositories.repoName] = awsRuntimeResources;

                    found = true;
                    break;
                  }
                }

                if (cicdByName == undefined) {
                  const hashedLambdaName = hash(awsRuntimeResources.imageNameWithoutTag);

                  const trailData = AWSCloudTrail().parseDateFromCloudTrailEvent(awsRuntimeResources.auditTrail.CloudTrailEvent);

                  if (!isContainerEnrichmentDisabled) {
                    found = await this.enrichArtifactsDataByDate(
                      awsRuntimeResources.imageNameWithoutTag,
                      "latest",
                      hashedLambdaName,
                      trailData,
                      true, // Stats enough to approve
                    );
                  }

                  if (found) {
                    logger.info(`crawler, find cicd for Lambda cloud image by date: ${awsRuntimeResources.imageNameWithoutTag}`);

                    delete awsRuntimeResources.containerImageInfo;
                  }
                }

                if (!found) {
                  if (!this.uniqueImagesSet.has(awsRuntimeResources.imageNameWithoutTag)) {
                    awsRuntimeResources.cicdFoundByName = true;
                    this.runTimeContainersNotConnected.push(awsRuntimeResources);

                    logger.info(
                      `crawler, did not find cicd for Lambda cloud image by any means: ${awsRuntimeResources.imageNameWithoutTag}`,
                    );

                    //
                    // Make sure we save the image name once
                    //
                    this.uniqueImagesSet.add(awsRuntimeResources.imageNameWithoutTag);
                  }
                }
              }

              return;
            }

            // Handle EC2
            if (awsRuntimeResources.objType == CloudTypes.EC2) {
              let imageNameWithoutTag = awsRuntimeResources.imageNameWithoutTag;
              let imageTag = awsRuntimeResources.taskDefinition.imageTag ? awsRuntimeResources.taskDefinition.imageTag : "latest";
              let imageArchitecture = awsRuntimeResources.taskDefinition.imageArchitecture;

              // Try to find in docker hub
              logger.info(
                `Looking for EC2 image in dockerhub ${imageNameWithoutTag}:${imageTag} digest: ${awsRuntimeResources.imageDigestWithoutPrefix}`,
              );

              let foundInDockerHub: DockerHubInfo | false = false;
              // For dockerhub testing only
              // const dockerhubTestOrgs = [
              //   "org_sNJmHNC78uX0h7S6",
              //   "org_fEOzt4wtsHlpODLs",
              //   "org_Xiq8OFfvwd5m5D0d",
              //   "org_8S3UyHBCiwfoWH2S",
              // ];
              // if (dockerhubTestOrgs.includes(this.orgName)) {
              if (imageNameWithoutTag && imageNameWithoutTag != "") {
                const dockerhubRequest: DockerhubRequest = {
                  imageName: imageNameWithoutTag,
                  imageTag: imageTag ?? "latest",
                  imageArchitecture: imageArchitecture ?? "amd64",
                };

                foundInDockerHub = await this.dockerhubHelper.sendAndWaitForRes(dockerhubRequest as DockerhubRequest, "aws", true);
              }
              // } else {
              //   logger.info(`This is not a dockerhub testing org, returning`);
              // }

              if (!foundInDockerHub) {
                // Do nothing for now, other checks come later
                logger.info(
                  `Didn't find EC2 image in dockerhub ${imageNameWithoutTag}:${imageTag} digest: ${awsRuntimeResources.imageDigestWithoutPrefix}`,
                );
              } else {
                logger.info(
                  `Found image EC2 in dockerhub ${imageNameWithoutTag}:${imageTag} digest: ${awsRuntimeResources.imageDigestWithoutPrefix}`,
                );
                awsRuntimeResources.taskDefinition = {
                  ...awsRuntimeResources.taskDefinition,
                  ...foundInDockerHub,
                };
                awsRuntimeResources.cicdFoundByName = true;
                awsRuntimeResources.cicdFoundInDockerHub = true;
                this.runTimeContainersNotConnected.push(awsRuntimeResources);
                return;
              }

              // Enrich by date
              logger.info(
                `Enriching EC2 artifact ${imageNameWithoutTag}:${imageTag} by date: ${awsRuntimeResources.taskDefinition.created}`,
              );
              let found = isContainerEnrichmentDisabled;

              if (!isContainerEnrichmentDisabled) {
                found = await this.enrichArtifactsDataByDate(
                  imageNameWithoutTag,
                  imageTag,
                  awsRuntimeResources.imageDigestWithoutPrefix,
                  awsRuntimeResources.taskDefinition.created,
                );
              }
              if (found) {
                logger.info(
                  `Found enrichment EC2 artifact ${imageNameWithoutTag}:${imageTag} by date: ${awsRuntimeResources.taskDefinition.created}`,
                );
                return;
              }
              logger.info(
                `Didn't find enrichment EC2 artifact ${imageNameWithoutTag}:${imageTag} hash by date: ${awsRuntimeResources.taskDefinition.created}`,
              );

              // Enrich by name
              logger.info(`Enriching EC2 artifact ${imageNameWithoutTag}:${imageTag} by name.`);
              if (!isContainerEnrichmentDisabled) {
                found = await this.enrichArtifactsData(imageNameWithoutTag, imageTag, awsRuntimeResources.imageDigestWithoutPrefix);
              }
              if (found) {
                logger.info(`Found enrichment EC2 artifact ${imageNameWithoutTag}:${imageTag} by name.`);
                return;
              }

              logger.info(`Didn't find enrichment EC2 artifact ${imageNameWithoutTag}:${imageTag} hash by name.`);

              if (cicdByName != undefined) {
                logger.info(`Found EC2 artifact ${imageNameWithoutTag}:${imageTag} by name.`);
                connectedToRepoByCicd[cicdByName.repositories.repoName] = awsRuntimeResources;
                awsRuntimeResources.cicdFoundByName = true;
              }
              this.runTimeContainersNotConnected.push(awsRuntimeResources);
              return;
            }

            //Try better with enhance because we found only by name
            if (cicdByName != undefined) {
              connectedToRepoByCicd[cicdByName.repositories.repoName] = awsRuntimeResources;

              let found = isContainerEnrichmentDisabled;

              //Fix OXDEV-9841
              if (awsRuntimeResources.auditTrail != undefined) {
                const trailData = AWSCloudTrail().parseDateFromCloudTrailEvent(awsRuntimeResources.auditTrail.CloudTrailEvent);

                if (!isContainerEnrichmentDisabled) {
                  found = await this.enrichArtifactsDataByDate(
                    awsRuntimeResources.imageNameWithoutTag,
                    awsRuntimeResources.imageDetail.imageTags.length > 0 ? awsRuntimeResources.imageDetail.imageTags[0] : "latest",
                    awsRuntimeResources.imageDigestWithoutPrefix,
                    trailData,
                  );
                }
              } else {
                if (!isContainerEnrichmentDisabled) {
                  found = await this.enrichArtifactsData(
                    awsRuntimeResources.imageNameWithoutTag,
                    awsRuntimeResources.imageDetail.imageTags.length > 0 ? awsRuntimeResources.imageDetail.imageTags[0] : "latest",
                    awsRuntimeResources.imageDigestWithoutPrefix,
                  );
                }
              }

              //Found by name only
              if (!found) {
                awsRuntimeResources.cicdFoundByName = true;
                logger.info(
                  `crawler, find cicd for cloud image by name: ${awsRuntimeResources.containerImageInfo.image}, hash: ${awsRuntimeResources.imageDigestWithoutPrefix}`,
                );
                //Found by hash
              } else {
                awsRuntimeResources.cicdFoundByHash = true;
                logger.info(
                  `crawler, find cicd for cloud image by hash: ${awsRuntimeResources.imageDigestWithoutPrefix}, image name: ${awsRuntimeResources.containerImageInfo.image}`,
                );
              }
              return;
            }

            let found = isContainerEnrichmentDisabled;

            if (awsRuntimeResources.auditTrail != undefined) {
              const trailData = AWSCloudTrail().parseDateFromCloudTrailEvent(awsRuntimeResources.auditTrail.CloudTrailEvent);

              if (!isContainerEnrichmentDisabled) {
                found = await this.enrichArtifactsDataByDate(
                  awsRuntimeResources.imageNameWithoutTag,
                  awsRuntimeResources.imageDetail.imageTags.length > 0 ? awsRuntimeResources.imageDetail.imageTags[0] : "latest",
                  awsRuntimeResources.imageDigestWithoutPrefix,
                  trailData,
                );
              }
            } else {
              //Try to enhance not found nothing yet
              if (!isContainerEnrichmentDisabled) {
                found = await this.enrichArtifactsData(
                  awsRuntimeResources.imageNameWithoutTag,
                  awsRuntimeResources.imageDetail.imageTags.length > 0 ? awsRuntimeResources.imageDetail.imageTags[0] : "latest",
                  awsRuntimeResources.imageDigestWithoutPrefix,
                );
              }
            }

            //Again not found by hash
            if (!found) {
              this.runTimeContainersNotConnected.push(awsRuntimeResources);
              logger.info(
                `crawler, cannot find cicd for cloud image at all, image hash: ${awsRuntimeResources.imageDigestWithoutPrefix}, name: ${awsRuntimeResources.containerImageInfo.image}`,
              );
              //Found by hash
            } else {
              awsRuntimeResources.cicdFoundByHash = true;
              logger.info(
                `crawler, find cicd for cloud image by hash: ${awsRuntimeResources.containerImageInfo.image}, hash: ${awsRuntimeResources.imageDigestWithoutPrefix}`,
              );
            }
          } catch (err) {
            logger.error(`failed in single cloud image connecting to cicd, err: ${err}`);
          }
        };

        const imagesToScan: ImageContainerDetail[] = [...this.allUnattachedAWSRuntimeResources.values()];

        await PromisePool.for(imagesToScan).withConcurrency(30).process(connectImagesOneByOne);
      } else {
        logger.info("skipping check for crawler cloud data due cicd list is empty");
      }

      //Try to attach some unattached events based on job info
      for (const [repoFullName, entry] of Object.entries(connectedToRepoByCicd)) {
        for (const app of applications) {
          if (app.appInfo.repo == null) {
            continue;
          }

          if (app.appInfo.repo.code_repo.fullName !== repoFullName) {
            continue;
          }
          app.appInfo.cloud.containerImage = [entry];
        }
      }
    } catch (err) {
      logger.error(`failed in cloud image not found in cicd, err: ${err}`);
    }

    // Format the dockerhub time to a readable string
    StatesHelper.Instance.scanInfoStats.dockerhubTimeAtFinalizing = millisToMinutesAndSeconds(
      StatesHelper.Instance.scanInfoStats.dockerhubTimeAtFinalizing,
    );

    logger.info(`finish attach total runtime container count: ${this.allUnattachedAWSRuntimeResources.size}`);
  }

  @PerformanceTelemetry()
  async setOnIntegrityCheck(fakeApps: Application[]) {
    try {
      //Check policy for unattached events
      if (this.runTimeContainersNotConnected.length > 0) {
        let appCloud = new Application(
          this.uuid,
          this.orgName,
          this.policyRules,
          this.jsonApplicationDiscoveryOverview,
          this.ruleExclusions,
          this.resultsHandler,
          this.blameQueue,
          this.secretValidationQueue,
          this.autoFixQueue,
          this.alertRecommendationQueue,
          this.iacVerificationQueue,
          this.scaVerificationQueue,
          this.openSourceInfoQueue,
          this.cachResovler,
          this.resolveIssueValidationQueue,
        );

        const cloudEnv = this.runTimeContainersNotConnected[0].cloudEnv.toUpperCase();
        await this.setFakeAppInfo(`${getCloudProviderType(cloudEnv)}-Cloud`, appCloud, CloudCollectorData, getCloudProviderType(cloudEnv));

        const alreadyExist = fakeApps.find(
          i => i.appInfo.repo.code_repo.id.toLowerCase() === appCloud.appInfo.repo.code_repo.id.toLowerCase(),
        );

        if (alreadyExist) {
          appCloud = alreadyExist;
        } else {
          fakeApps.push(appCloud);
        }

        //Add events to fake app
        if (!Array.isArray(appCloud.appInfo.cloud.containerImage)) {
          appCloud.appInfo.cloud.containerImage = [];
        }
        this.runTimeContainersNotConnected.forEach(i => {
          appCloud.appInfo.cloud.containerImage.push(i);
        });
      }
    } catch (err) {
      logger.error(`failed in cloud runtime container fake app, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async createFakeAppsForCloudEvents(fakeApps: Application[]) {
    if (StatesHelper.Instance.isPipelineScan) {
      return;
    }

    logger.info(`start cloud unattached event`);

    await this.setOnFakeCloudSecEvents(fakeApps);
    await this.createFakeAppsForRunTimeArtifactoryEvents(fakeApps);
    await this.setOnIntegrityCheck(fakeApps);

    logger.info(`total fake runtime cloud apps: ${fakeApps.length}`);

    await PromisePool.for(fakeApps)
      .withConcurrency(50)
      .process(
        async i =>
          await AsyncTracker.runWithAsyncTracker(async () => {
            AsyncTracker.setValue("ox-app-id", (i.appInfo?.repo?.code_repo as Repo)?.id);
            AsyncTracker.setValue("ox-app-name", (i.appInfo?.repo?.code_repo as Repo)?.name);
            await i.runAllPolicyForUnattachedEvents();
          }),
      );

    await sendScannerPhaseTimeTelemetry(
      ScanPhaseTime.ScanSupplyChainTime,
      this.orgName,
      this.uuid,
      StatesHelper.Instance.scanInfoStats.supplyChainTimeAtFinalizing,
    );

    logger.info(
      `finish cloud unattached event, elapsed time: ${StatesHelper.Instance.scanInfoStats.supplyChainTimeAtFinalizing} (in minutes)`,
    );
  }

  async setFakeAppInfo(appName: string, appRepo: Application, fakeRepo: any, type: string = "") {
    appRepo.appInfo.repo = {};

    const repo: Repo = JSON.parse(JSON.stringify(fakeRepo));
    repo.id = `*${appName}`;
    repo.name = `*${appName}`;
    repo.fullName = `*${appName}`;
    repo.realRepo = false;
    repo.type = type;
    repo.noneRelevantRepo = false;
    repo.excludedTagsIds = [];
    repo.appTags = [];

    appRepo.appInfo.repo["code_repo"] = repo;
    appRepo.fakeApp = true;

    const sharedDir = process.env.OX_SHARED_DATA == undefined ? "/var/shared-data" : process.env.OX_SHARED_DATA;
    const resolveIssuesValidation = `${sharedDir}/${this.orgName}/scan_${replaceAll(this.uuid, "-", "_")}/resolveIssue`;

    const typeForPath = "fakeRepo";
    let repoNameTrimmed = repo.name.trimEnd();
    repoNameTrimmed = `${repoNameTrimmed}_${uuid.v4()}`;
    repoNameTrimmed = replaceAll(repoNameTrimmed, " ", "_");
    const pathToRepo = typeForPath + "/" + repoNameTrimmed;

    repo.resolveIssuesValidationDir = resolveIssuesValidation + "/" + pathToRepo;

    repo.appOwners = this.resultsHandler.getAppOwners(appName);

    if (!this.allFakeApps.has(repo.id)) {
      logger.info(`setting fake app name: ${appName}, type: ${repo.type}`);
      StatesHelper.Instance.numberOfApps++;
      this.allFakeApps.add(repo.id);
      this.fakeApplications.push(appRepo);
    }

    setConfiguredProps(repo);

    const { tags, excludedTagsIds } = await TagsService.Instance.getAppTagsAndExclusions(this.orgName, repo.id);
    repo.excludedTagsIds = excludedTagsIds;
    repo.appTags = tags;

    if (repo?.appTags?.length) {
      logger.info(
        `fake repo: ${repo.name} tagsInfo: ${JSON.stringify(tags)}, tags: ${repo?.appTags?.length}, excludedTagsIds: ${
          repo?.excludedTagsIds?.length
        }`,
      );
    }

    if (repo.overrideRelevance === Relevance.IRRELEVANT) {
      try {
        logger.info(`fake repo: ${repo.name} has been set to not relevant by client`);
        //No need to continue after it
        repo.noneRelevantRepo = true;
        repo.repoImportance.res.irrelevantReasons.push(IrrelevantReason.SetByClient);
      } catch (err) {
        logger.error(`failed set repo: ${repo.name} as not relevant by client, err: ${err}`);
      }
    }
  }

  setFakeRepoInfo(appRepo: Application, gitTypeName?: RepoTypeName) {
    try {
      appRepo.appInfo.repo["code_repo"].type = gitTypeName || "Git";
      const repoAppFlow = new AppFlowRepo();
      repoAppFlow.system = gitTypeName || "Git";
      appRepo.appInfo.repository.repoAppFlow.push(repoAppFlow);
    } catch (err) {
      logger.error(`failed set fake code repo, err: ${err}`);
    }
  }

  async updateAppManagerRepoItem(repoObj: any) {
    try {
      const startTime = new Date().getTime();

      const repo: Repo = repoObj.code_repo;

      const repoApp: Application = this.createDefaultApp();

      repoApp.appInfo.repo = repoObj;

      await this.openWikiHelper.addOpenWikiRequest(repoApp, repo);

      const repoAppFlow = new AppFlowRepo();
      repoAppFlow.system = repo.type;
      repoAppFlow.latestDate = repo.lastPushTime;
      const c = new FoundLocation();
      c.foundIn = repo.fullName;
      c.link = repo.link;
      c.runBy = repo.ownerName;
      repoAppFlow.location.push(c);
      repoApp.appInfo.repository.repoAppFlow.push(repoAppFlow);

      this.totalRepoEvents++;

      //Try get what we can from repo info only
      mergeCICDForAppFlow(repoApp);
      mergeArtifactsForAppFlow(repoApp);
      mergeOrchestratorAppFlow(repoApp);
      mergeKubernetesAppFlow(repoApp);

      // fetch a set of policies for each monorepo child
      if (this.isPipelineScan && repo.monoRepoChild) {
        const dbApp = await this.mongoDBapplications.getApplicationById(repo.id);
        logger.info(`run app manager for for repo: ${repo.id} ${repoObj.code_repo.fullName} (monorepo child). app found in db: ${!!dbApp}`);

        const preprocessedPolicyRules = dbApp
          ? await PolicyService.Instance.getPipelinePoliciesByAppId(this.orgName, repo.id) // if app existed, fetch from API
          : PipeLineHelper.Instance.rootAppPolicies; // if app did not exist, take monorepo's parent policies

        const processedPolicyRules = this.rulesParser.processPolicyRulesForPipeLine(repo, preprocessedPolicyRules);
        repoApp.policyRules = processedPolicyRules;
      }

      const allEvents: SecurityEvent[] = repoObj[CodeRepoTypes[CodeRepoTypes.securityEvents]];
      const afterRemoveExcludedAlerts: SecurityEvent[] = allEvents.filter(i => !isExcludedAlert(i.fileName, i.filePath));
      const excludedAlerts = allEvents.length - afterRemoveExcludedAlerts.length;
      repoObj[CodeRepoTypes[CodeRepoTypes.securityEvents]] = afterRemoveExcludedAlerts;

      await repoApp.runAllPolicyForSingleApplication();

      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);

      logger.info(
        `finish run app manager for repo: ${repoObj.code_repo.fullName} in ${elapsedTime} minutes, excludedAlerts: ${excludedAlerts}, noneExcluded: ${afterRemoveExcludedAlerts.length}`,
      );
    } catch (err) {
      logger.error(`failed update repo via app manager for: ${repoObj.code_repo.fullName}, err: ${err}`);
    }
  }

  async updateAppManagerCloudItem(cloudObj: any) {
    try {
      const filteredEvents: CloudSecurityEvent[] = cloudObj.cloudSecurityEvents;
      filteredEvents.forEach(i => {
        this.allCloudSecurityEvents.push(i);
      });
      this.totalCloudEvents += filteredEvents.length;
    } catch (err) {
      logger.error(`failed update cloud via app manager, err: ${err}`);
    }
  }

  async updateAppManagerExternalSecurityItem(externalSecurityObj: any) {
    try {
      const securityEvents: SecurityEvent[] = externalSecurityObj[CodeRepoTypes[CodeRepoTypes.securityEvents]];
      if (securityEvents == undefined) {
        return;
      }

      logger.info(`trying to update external sec events count: ${securityEvents.length}}`);

      for (const securityEvent of securityEvents) {
        if (this.allUnattachedExternalCodeSecurityEvents[securityEvent.repoFullName] == undefined) {
          this.allUnattachedExternalCodeSecurityEvents[securityEvent.repoFullName] = [securityEvent];
        } else {
          this.allUnattachedExternalCodeSecurityEvents[securityEvent.repoFullName].push(securityEvent);
        }
      }

      const reposForLogging = new Set();
      const allUnattachedEvents = Object.values(this.allUnattachedExternalCodeSecurityEvents).flat() as any;

      allUnattachedEvents.forEach(i => reposForLogging.add(i.repoFullName));
      logger.info(
        `repos found for application manager: ${Array.from(reposForLogging).join(",,,")}, repos size: ${reposForLogging.size}, length: ${
          securityEvents.length
        }`,
      );
    } catch (err) {
      logger.error(`failed update external security events via app manager, err: ${err}`);
    }
  }

  async updateAppMangerCICDItem(cicd: CICD) {
    try {
      this.allCICD.push(cicd);
      this.totalCICDevents++;
    } catch (err) {
      logger.error(`failed update cicd via app manager, err: ${err}`);
    }
  }

  async updateAppMangerArtifactsItemForExternalTools(artifacts: any) {
    try {
      if (!artifacts.securityEvents) {
        return;
      }

      //Set excluded alerts before we set the alerts for app info
      const allEvents: SecurityEvent[] = artifacts.securityEvents;
      const afterRemoveExcludedAlerts: SecurityEvent[] = [];
      allEvents.forEach(i => {
        if (i.securitySubTypeAlertType !== SecurityAlertType.secrets) {
          afterRemoveExcludedAlerts.push(i);
          return;
        }
        if (!isExcludedAlert(i.fileName, i.filePath)) {
          afterRemoveExcludedAlerts.push(i);
          return;
        }
      });
      const excludedAlerts = (allEvents.length = afterRemoveExcludedAlerts.length);
      artifacts.securityEvents = afterRemoveExcludedAlerts;
      if (excludedAlerts != 0) {
        logger.info(`update app manager with all sec alerts for images items, excludedAlerts: ${excludedAlerts}`);
      }

      const artifactsSecurityEvents: SecurityEvent[] = artifacts.securityEvents;
      logger.info(`trying to update artifact external sec events count: ${artifactsSecurityEvents.length}}`);
      artifactsSecurityEvents.forEach(i => {
        if (i.securitySubTypeAlertType === SecurityAlertType.cloudRunTime) {
          this.runtimeArtifactsSecurityEvents.push(i);
        } else {
          this.allArtifactsSecurityEventsForExternalTools.push(i);
        }
      });
      logger.info(
        `update app manager with artifact sec items, new: ${artifacts.securityEvents.length}, total: ${this.allArtifactsSecurityEventsForExternalTools.length}`,
      );
    } catch (err) {
      logger.error(`failed update artifacts via app manager, err: ${err}`);
    }
  }

  async updateAppManagerWithImageItems(imagesInfo: ImageInfo[]) {
    try {
      //Unique images by sha
      type Hash = string;
      const uniqueSet = new Set<Hash>();
      this.allImagesFromRegistry.forEach(i => uniqueSet.add(i.image.imageDigestWithoutPrefix));
      for (const image of imagesInfo) {
        if (!uniqueSet.has(image.image.imageDigestWithoutPrefix)) {
          //Set excluded alerts before we set the alerts for app info
          const allEvents: SecurityEvent[] = image.securityEvents;
          const afterRemoveExcludedAlerts: SecurityEvent[] = [];
          allEvents.forEach(i => {
            if (i.securitySubTypeAlertType !== SecurityAlertType.secrets) {
              afterRemoveExcludedAlerts.push(i);
              return;
            }
            if (!isExcludedAlert(i.fileName, i.filePath)) {
              afterRemoveExcludedAlerts.push(i);
              return;
            }
          });
          image.securityEvents = afterRemoveExcludedAlerts;
          this.allImagesFromRegistry.push(image);
        }
      }
      logger.info(`update app manager with image items, new: ${imagesInfo.length}, total: ${this.allImagesFromRegistry.length}`);
    } catch (err) {
      logger.error(`failed update images, err: ${err}`);
    }
  }

  updateAppManagerWithDiscoverdCloudItems(cloudObj: any) {
    try {
      const runningAndActiveContainers = cloudObj.containers.filter(
        i => i.taskDefinition[0].lastStatus === "RUNNING" || i.taskDefinition[0].status === "ACTIVE",
      );
      logger.info(`found running and active containers count: ${runningAndActiveContainers.length}`);

      for (const runningAndActiveContainer of runningAndActiveContainers) {
        try {
          if (runningAndActiveContainer.taskDefinition.length === 0) {
            logger.warn(`failed to found running image with sha for cluster: ${runningAndActiveContainer.cluster}, taskDefinition empty`);
            continue;
          }

          const taskDefinition = runningAndActiveContainer.taskDefinition[0];
          let found = false;
          for (const containerImage of taskDefinition.containerDefinitions) {
            try {
              logger.info(`crawler, checking active image name: ${containerImage.image}`);

              // kyz: handle dockerhub images

              // Check the container image is "new" and dismiss the old stuff
              let foundByTag = false;
              let foundContainer;
              if (cloudObj.images) {
                const awsECRImages = cloudObj.images as Map<AWSEcrRepositoryName, { imageDetails: EcrImageDetail[] }>;

                if (awsECRImages.has(containerImage.image.split(":")[0])) {
                  const res = awsECRImages.get(containerImage.image.split(":")[0]);
                  if (res && res.imageDetails) {
                    for (const image of res.imageDetails) {
                      for (const tag of image.imageTags) {
                        if (containerImage.image.split(":")[1] === tag) {
                          foundByTag = true;
                          foundContainer = image;
                        }
                      }
                    }
                  }
                }
              }

              if (!foundByTag) {
                continue;
              }

              //Probably docker image from other location (not from ECR)
              if (foundContainer.imageDigest == undefined || foundContainer.imageDigest === "") {
                continue;
              }

              if (this.allUnattachedAWSRuntimeResourcesSha.has(foundContainer.imageDigest.replace("sha256:", ""))) {
                found = true;
                continue;
              }

              const imageContainerDetail = new ImageContainerDetail();
              //Set mandatory data for running service
              imageContainerDetail.containerImageInfo = foundContainer;
              imageContainerDetail.taskDefinition = taskDefinition;
              imageContainerDetail.cluster = "ECS Cluster";
              imageContainerDetail.region = runningAndActiveContainer.region;
              imageContainerDetail.imageDigestWithoutPrefix = foundContainer.imageDigest.replace("sha256:", "");
              imageContainerDetail.imageNameWithoutTag = containerImage.image.split(":")[0];

              if (cloudObj.imageAuditTrails.has(foundContainer.imageDigest)) {
                imageContainerDetail.auditTrail = cloudObj.imageAuditTrails.get(foundContainer.imageDigest).trailEvents;
              }

              imageContainerDetail.link = `https://${imageContainerDetail.region}.console.aws.amazon.com/ecs/v2/task-definitions/${taskDefinition.family}/${taskDefinition.revision}/containers`;

              found = true;

              logger.info(
                `crawler, found running image name: ${containerImage.image}, sha: ${imageContainerDetail.imageDigestWithoutPrefix}`,
              );

              //Add the found service with sha
              this.allUnattachedAWSRuntimeResources.set(imageContainerDetail.imageDigestWithoutPrefix, imageContainerDetail);
              this.allUnattachedAWSRuntimeResourcesSha.add(foundContainer.imageDigest);

              const imageName = containerImage.image.split(":")[0];

              const imageObj = cloudObj.images.get(imageName);
              if (imageObj == undefined) {
                logger.warn(`crawler, cannot find images details from registry map, image name: ${containerImage.image}`);
                break;
              }

              //Keep only with time
              let sorted = imageObj.imageDetails.filter(i => i.imagePushedAtInDays != -1);
              //Sort to have the newest first
              sorted = sorted.sort((a, b) => a.imagePushedAtInDays - b.imagePushedAtInDays);

              //Set last image available in registry
              let lastImageAvaliableInRegistry = sorted.length > 0 ? sorted[0] : null;
              imageContainerDetail.lastImageAvailableInRegistry = lastImageAvaliableInRegistry;

              //Set actual running image from registry
              imageContainerDetail.imageDetail = imageObj.imageDetails.find(i => i.imageDigest === foundContainer.imageDigest);
              if (imageContainerDetail.imageDetail == undefined) {
                imageContainerDetail.imageDetail = null;
                logger.error(
                  `crawler, cannot find image details from registry for name: ${containerImage.image}, hash: ${foundContainer.imageDigest}`,
                );
              } else {
                logger.info(
                  `crawler, found image details from registry for name: ${containerImage.image}, hash: ${foundContainer.imageDigest}`,
                );
              }

              break;
            } catch (err) {
              logger.error(
                `failed update all cloud discovered items via app manager, err: ${err}, container image: ${containerImage.image}`,
              );
            }
          }

          if (!found) {
            logger.warn(`failed to found image with sha for: ${taskDefinition.family}`);
          }
        } catch (err) {
          logger.error(`failed update all cloud discovered items via app manager, err: ${err}`);
        }
      }

      // Adding Lambda containers/
      const lambdaData = cloudObj.lambdaAuditTrails as Map<FunctionArn, AWSLambdaTrailData>;
      for (const [lambdaName, lambdaFunction] of lambdaData) {
        const lambdaContainerImageInfo: Container = {};
        lambdaContainerImageInfo.name = lambdaName;
        lambdaContainerImageInfo.image = lambdaFunction.lambda.FunctionArn ?? lambdaFunction.lambda.FunctionName;
        lambdaContainerImageInfo.lastStatus = "Deployed";

        const imageContainerDetail = new ImageContainerDetail();
        imageContainerDetail.imageNameWithoutTag = lambdaName;
        imageContainerDetail.containerImageInfo = lambdaContainerImageInfo;
        imageContainerDetail.imageDigestWithoutPrefix = lambdaFunction.lambda.CodeSha256 ?? "";
        imageContainerDetail.taskDefinition = lambdaFunction.lambda;
        imageContainerDetail.region = lambdaFunction.region;
        imageContainerDetail.cluster = "";
        imageContainerDetail.objType = CloudTypes.lambda;
        imageContainerDetail.objTypeStr = CloudTypes[CloudTypes.lambda];

        if (lambdaFunction.trailEvents.length > 0) {
          imageContainerDetail.auditTrail = lambdaFunction.trailEvents[0];
        }

        const region = imageContainerDetail.region;
        imageContainerDetail.link = `https://${region}.console.aws.amazon.com/lambda/home?${region}#/functions/${lambdaFunction.lambda.FunctionName}`;
        this.allUnattachedAWSRuntimeResources.set(imageContainerDetail.imageDigestWithoutPrefix, imageContainerDetail);

        if (lambdaFunction.lambda.CodeSha256 != undefined) {
          this.allUnattachedAWSRuntimeResourcesSha.add(lambdaFunction.lambda.CodeSha256);
        }
      }

      // Handle EC2
      const ec2Instances: Instances = cloudObj.ec2Images;
      this.updateAppManagerEC2(ec2Instances);

      logger.info(`crawler, adding to all unattached aws runtime resources count: ${this.allUnattachedAWSRuntimeResources.size}`);
    } catch (err) {
      logger.error(`failed update all items for all AWS runtime resources via app manager, err: ${err}`);
    }
  }

  private updateAppManagerEC2(ec2Instances) {
    for (const [instanceId, instance] of Object.entries(ec2Instances)) {
      for (const [imageId, image] of Object.entries(instance)) {
        const ec2ContainerImageInfo: Container = {};
        ec2ContainerImageInfo.name = image.image;
        const img = image.tag ? `${image.image}:${image.tag}` : `${image.image}`;
        ec2ContainerImageInfo.image = img;
        ec2ContainerImageInfo.lastStatus = "Running";

        const imageContainerDetail = new ImageContainerDetail();
        imageContainerDetail.imageNameWithoutTag = image.image;
        imageContainerDetail.containerImageInfo = ec2ContainerImageInfo;
        imageContainerDetail.imageDigestWithoutPrefix = image.sha.split(":")[1];
        imageContainerDetail.taskDefinition = {
          instanceId,
          imageId,
          imageTag: image.tag,
          created: image.created,
          imageArchitecture: image.architecture,
          // manifestSha: image.manifestSha,
        };
        imageContainerDetail.region = image.region;
        imageContainerDetail.cluster = "";
        imageContainerDetail.objType = CloudTypes.EC2;
        imageContainerDetail.objTypeStr = CloudTypes[CloudTypes.EC2];

        const region = imageContainerDetail.region;
        imageContainerDetail.link = `https://${region}.console.aws.amazon.com/ec2/v2/home?region=${region}#InstanceDetails:instanceId=${instanceId}`;
        this.allUnattachedAWSRuntimeResources.set(imageContainerDetail.imageDigestWithoutPrefix, imageContainerDetail);

        if (image.sha != undefined) {
          this.allUnattachedAWSRuntimeResourcesSha.add(image.sha);
        }
      }
    }
  }

  private connectCloudCSPMResourcesToJobsOutput(resource: string, job: CICDJob) {
    try {
      for (const artifact of job.parsedArtifacts) {
        if (artifact.name === resource) {
          logger.info(`Found resource: ${resource} in parsed artifact, in repo: ${job.repoName}`);
          return true;
        }
      }
    } catch (err) {
      logger.error(`failed to connect cloud cspm to app, err: ${err}`);
    }

    return false;
  }

  @PerformanceTelemetry()
  private async connectCloudCSPMToApp(applications: Application[]) {
    const uniqueIdsMatchedResources = new Set();

    try {
      logger.info(`try attach total cloud cspm security count: ${this.allCloudSecurityEvents.length}`);

      let filteredEvents: CloudSecurityEvent[] = this.allCloudSecurityEvents;

      if (StatesHelper.Instance.isMobiliy || StatesHelper.Instance.isEtoro) {
        let notFound = 0;
        let found = 0;
        let numOfTfFiles = 0;
        const repoConnected = new Set();
        const fileHelper: FileHelper = new FileHelper(this.uuid);
        const unattachedArtifactsSecurityEvents: CloudSecurityEvent[] = [];

        const optimizedAccountIdToAlert = {};
        for (const artifactsSecurityEvent of filteredEvents) {
          try {
            const accountId = artifactsSecurityEvent?.accountId?.toLowerCase();
            if (!accountId) {
              unattachedArtifactsSecurityEvents.push(artifactsSecurityEvent);
              notFound++;
              continue;
            }
            if (optimizedAccountIdToAlert[accountId]) {
              optimizedAccountIdToAlert[accountId].push(artifactsSecurityEvent);
            } else {
              optimizedAccountIdToAlert[accountId] = [artifactsSecurityEvent];
            }
          } catch (err) {
            unattachedArtifactsSecurityEvents.push(artifactsSecurityEvent);
            notFound++;
            logger.error(`failed attach single cspm runtime for optimized collection, err: ${err}`);
          }
        }

        logger.info(
          `finish for cspm runtime for optimized collection: ${Object.keys(optimizedAccountIdToAlert).length}, notFound: ${notFound}`,
        );

        for (const [name, entry] of Object.entries(optimizedAccountIdToAlert)) {
          const events = entry as CloudSecurityEvent[];
          try {
            const accountId = name.toLowerCase();
            let added = false;
            if (accountId) {
              for (const app of applications) {
                //No repo to match continue
                if (app.appInfo.repo == null) {
                  continue;
                }

                const repo: Repo = app.appInfo.repo.code_repo;
                const files: File[] = app.appInfo.repo[CodeRepoTypes[CodeRepoTypes.files]];
                if (!files) {
                  continue;
                }

                for (const file of files) {
                  try {
                    const toolNameToLower = file.name.toLowerCase();
                    const shouldCheck =
                      toolNameToLower.endsWith(".tf") || toolNameToLower.endsWith(".yml") || toolNameToLower.endsWith(".yaml");
                    if (!shouldCheck) {
                      continue;
                    }
                    //Check if include the account id
                    const zipSizeB = await this.fileHelper.getFileSize(file.path);
                    const zipSizeMB = zipSizeB / 1024 / 1024;
                    if (zipSizeMB > 5) {
                      logger.error(`skipping large file in repo: ${repo.fullName}, cspm file: ${file.path}, zipSizeMB: ${zipSizeMB}`);
                      continue;
                    }

                    const content = fileHelper.readFile(file.path);

                    numOfTfFiles++;
                    const index = content.indexOf(accountId);
                    if (index == -1) {
                      continue;
                    }
                    const iPreffix = index - 20 < 0 ? index : index - 20;
                    const iSuffix = index + 20 > content.length ? content.length : index + 20;
                    const lineContent = content.substring(iPreffix, iSuffix);
                    let extraInfo: ExtraInfo[] = [];
                    extraInfo.push({
                      key: "Snippet",
                      link: file.link,
                      snippet: {
                        fileName: file.fileNameWithoutDisk,
                        text: lineContent,
                        language: "",
                        snippetLineNumber: 0,
                      },
                    });

                    //Add
                    events.forEach(e => {
                      addSeverityCloudChangedReason(severityReasons.CloudResourceExistInDeploymentFile, e, extraInfo);
                      app.updateCloudItem(e, "reponame");
                      repoConnected.add(repo.fullName);
                    });
                    added = true;
                    break;
                  } catch (err) {
                    logger.error(`failed attach single cspm runtime on match, err: ${err}`);
                  }
                }
                if (added) {
                  break;
                }
              }
            }

            if (!added) {
              events.forEach(e => {
                unattachedArtifactsSecurityEvents.push(e);
              });
              notFound = notFound + events.length;
            } else {
              found = found + events.length;
            }
          } catch (err) {
            events.forEach(e => {
              unattachedArtifactsSecurityEvents.push(e);
            });
            notFound = notFound + events.length;
            notFound++;
            logger.error(`failed attach single cspm runtime, err: ${err}`);
          }
        }

        this.allCloudSecurityEvents = unattachedArtifactsSecurityEvents;
        filteredEvents = this.allCloudSecurityEvents;

        logger.info(
          `finish attach total unattached security events cspm count: ${
            this.allCloudSecurityEvents.length
          }, found: ${found}, not found: ${notFound}, numOfTfFiles: ${numOfTfFiles}, repoConnected: ${Array.from(repoConnected)}`,
        );
      }

      //Try to connect CLOUD ---> REPO
      for (const cloudSecurityEvent of filteredEvents) {
        try {
          for (const app of applications) {
            //No repo to match continue
            if (app.appInfo.repo == null) {
              continue;
            }

            const repo: Repo = app.appInfo.repo.code_repo;

            //Use repo name
            const resource = cloudSecurityEvent.resource.toLowerCase();
            if (
              (repo.fullName.toLowerCase().includes(resource) || resource.includes(repo.fullName.toLowerCase())) &&
              repo.fullName.length > 5
            ) {
              logger.info(
                `connection found repo to cloud based on resource ${cloudSecurityEvent.resource} and repo full name ${repo.fullName}}, service: ${cloudSecurityEvent.cloudService} `,
              );

              app.updateCloudItem(cloudSecurityEvent, "reponame");
              uniqueIdsMatchedResources.add(cloudSecurityEvent.id);
              break;
            }
            if ((repo.name.toLowerCase().includes(resource) || resource.includes(repo.name.toLowerCase())) && repo.name.length > 5) {
              logger.info(
                `connection found repo to cloud based on resource ${cloudSecurityEvent.resource} and repo name ${repo.name}}, service: ${cloudSecurityEvent.cloudService}`,
              );

              app.updateCloudItem(cloudSecurityEvent, "reponame");
              uniqueIdsMatchedResources.add(cloudSecurityEvent.id);
              break;
            }
          }
        } catch (err) {
          logger.error(`failed attach single cloud to repo, err: ${err}`);
        }
      }

      //Try to connect CLOUD ---> CICD
      for (const cloudSecurityEvent of filteredEvents) {
        try {
          //Dont add the same event more then one time
          if (uniqueIdsMatchedResources.has(cloudSecurityEvent.id)) {
            continue;
          }

          for (const app of applications) {
            if (app.appInfo.cicd == null) {
              continue;
            }
            if (app.appInfo.repo == null) {
              continue;
            }

            const jobs: CICDJob[] = app.appInfo.cicd.jobs;
            if (jobs.length == 0) {
              continue;
            }

            let added = false;
            for (const job of jobs) {
              const connectedJob = job.artifacts.find(i => i.includes(cloudSecurityEvent.resource));

              const tieBasedOnArtifacts = this.connectCloudCSPMResourcesToJobsOutput(cloudSecurityEvent.resource, job);

              if (connectedJob != undefined || tieBasedOnArtifacts) {
                added = true;
                app.updateCloudItem(cloudSecurityEvent, "jobcontent");
                uniqueIdsMatchedResources.add(cloudSecurityEvent.id);

                logger.info(
                  `connection found cicd to cloud event based inside job ${job.buildUrl}, resource ${cloudSecurityEvent.resource}, service: ${cloudSecurityEvent.cloudService} `,
                );
                break;
              }
            }
            //Attach only one cloud resource to a CICD
            if (added) {
              break;
            }
          }
        } catch (err) {
          logger.error(`failed attach single cloud to cicd, err: ${err}`);
        }
      }

      //Update unmatched events
      const unmatchedEvents = filteredEvents.filter(i => !uniqueIdsMatchedResources.has(i.id));
      logger.info(
        `finish attach total unattached cloud security count: ${unmatchedEvents.length}, matched: ${
          this.allCloudSecurityEvents.length - unmatchedEvents.length
        }`,
      );
      this.allCloudSecurityEvents = unmatchedEvents;
    } catch (err) {
      logger.error(`failed attach all cloud, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  connectedArtifactsSecEventsForExternalEvents(applications: Application[]) {
    logger.info(`try attach total security events artifacts count: ${this.allArtifactsSecurityEventsForExternalTools.length}`);

    const notFound = new Set();
    const found = new Set();

    try {
      const groupedArtifactsSecurityEvents = groupBy(this.allArtifactsSecurityEventsForExternalTools, (item: SecurityEvent) =>
        item.artifacts.repoFullName.toLowerCase(),
      );
      const validApplications = applications.filter(app => app.appInfo.repo);
      const allUnattachedArtifactsSecurityEvents: SecurityEvent[] = [];

      for (const [artifactRepo, events] of Object.entries(groupedArtifactsSecurityEvents)) {
        let added = false;
        for (let app of validApplications) {
          const repo: Repo = app.appInfo.repo.code_repo;
          const repoFullName =
            repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.fullName.toLowerCase() : repo.fullName.toLowerCase();
          const repoName = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.name.toLowerCase() : repo.name.toLowerCase();

          if (
            artifactRepo.endsWith(repoFullName) ||
            artifactRepo === repoName ||
            StringHelper.compareWords(StringHelper.extractWords(artifactRepo), StringHelper.extractWords(repoName))
          ) {
            found.add(repoFullName);
            app.updateArtifactItem(events);
            added = true;
            break;
          }
        }
        if (!added) {
          allUnattachedArtifactsSecurityEvents.push(...events);
          notFound.add(events[0].artifacts.repoFullName);
        }
      }

      this.allArtifactsSecurityEventsForExternalTools = allUnattachedArtifactsSecurityEvents;

      logger.info(
        `finish attach total unattached security events artifacts count: ${allUnattachedArtifactsSecurityEvents.length}, found: ${
          found.size
        }, not found: ${notFound.size}, not found info: ${Array.from(notFound).join(", ")}`,
      );
    } catch (err) {
      logger.error(`failed attach all artifacts, err: ${err}`);
    }
  }

  async connectRuntimeSecEventsBasedOnDeplyomentFiles(applications: Application[]) {
    if (!StatesHelper.Instance.isMobiliy) {
      return;
    }

    logger.info(`try attach total security events runtime count: ${this.runtimeArtifactsSecurityEvents.length}`);

    let notFound = 0;
    let found = 0;
    let numOfTfFiles = 0;
    const repoConnected = new Set();
    const fileHelper: FileHelper = new FileHelper(this.uuid);

    try {
      const unattachedArtifactsSecurityEvents: SecurityEvent[] = [];

      const optimizedAccountIdToAlert = {};
      for (const artifactsSecurityEvent of this.runtimeArtifactsSecurityEvents) {
        try {
          const accountId = artifactsSecurityEvent?.artifacts?.accountId?.toLowerCase();
          if (!accountId) {
            unattachedArtifactsSecurityEvents.push(artifactsSecurityEvent);
            notFound++;
            continue;
          }
          if (optimizedAccountIdToAlert[accountId]) {
            optimizedAccountIdToAlert[accountId].push(artifactsSecurityEvent);
          } else {
            optimizedAccountIdToAlert[accountId] = [artifactsSecurityEvent];
          }
        } catch (err) {
          unattachedArtifactsSecurityEvents.push(artifactsSecurityEvent);
          notFound++;
          logger.error(`failed attach single runtime for optimized collection, err: ${err}`);
        }
      }
      logger.info(
        `finish for runtime for optimized collection, err: ${Object.keys(optimizedAccountIdToAlert).length}, notFound: ${notFound}`,
      );

      for (const [name, entry] of Object.entries(optimizedAccountIdToAlert)) {
        const events = entry as SecurityEvent[];
        try {
          const accountId = name.toLowerCase();
          let added = false;
          if (accountId) {
            for (const app of applications) {
              //No repo to match continue
              if (app.appInfo.repo == null) {
                continue;
              }

              const repo: Repo = app.appInfo.repo.code_repo;
              const files: File[] = app.appInfo.repo[CodeRepoTypes[CodeRepoTypes.files]];
              if (!files) {
                continue;
              }

              for (const file of files) {
                try {
                  const toolNameToLower = file.name.toLowerCase();
                  const shouldCheck =
                    toolNameToLower.endsWith(".tf") || toolNameToLower.endsWith(".yml") || toolNameToLower.endsWith(".yaml");
                  if (!shouldCheck) {
                    continue;
                  }
                  //Check if include the account id
                  const zipSizeB = await this.fileHelper.getFileSize(file.path);
                  const zipSizeMB = zipSizeB / 1024 / 1024;
                  if (zipSizeMB > 5) {
                    logger.error(`skipping large file in repo: ${repo.fullName}, file: ${file.path}, zipSizeMB: ${zipSizeMB}`);
                    continue;
                  }

                  const content = fileHelper.readFile(file.path);
                  numOfTfFiles++;

                  numOfTfFiles++;
                  const index = content.indexOf(accountId);
                  if (index == -1) {
                    continue;
                  }
                  const iPreffix = index - 20 < 0 ? index : index - 20;
                  const iSuffix = index + 20 > content.length ? content.length : index + 20;
                  const lineContent = content.substring(iPreffix, iSuffix);
                  let extraInfo: ExtraInfo[] = [];
                  extraInfo.push({
                    key: "Snippet",
                    link: file.link,
                    snippet: {
                      fileName: file.fileNameWithoutDisk,
                      text: lineContent,
                      language: "",
                      snippetLineNumber: 0,
                    },
                  });

                  //Add
                  // dor deployment filter?
                  events.forEach(e => {
                    addSeverityChangedReason(severityReasons.CloudResourceExistInDeploymentFile, e, repo, extraInfo);
                    app.appInfo.artifactory.securityEvents.push(e);
                    repoConnected.add(repo.fullName);
                  });
                  added = true;
                  break;
                } catch (err) {
                  logger.error(`failed attach single runtime on match, err: ${err}`);
                }
              }
              if (added) {
                break;
              }
            }
          }

          if (!added) {
            events.forEach(e => {
              unattachedArtifactsSecurityEvents.push(e);
            });
            notFound = notFound + events.length;
          } else {
            found = found + events.length;
          }
        } catch (err) {
          events.forEach(e => {
            unattachedArtifactsSecurityEvents.push(e);
          });
          notFound = notFound + events.length;
          logger.error(`failed attach single runtime, err: ${err}`);
        }
      }

      this.runtimeArtifactsSecurityEvents = unattachedArtifactsSecurityEvents;

      logger.info(
        `finish attach total unattached security events runtimeruntime count: ${
          this.runtimeArtifactsSecurityEvents.length
        }, found: ${found}, not found: ${notFound}, numOfTfFiles: ${numOfTfFiles}, repoConnected: ${Array.from(repoConnected)}`,
      );
    } catch (err) {
      logger.error(`failed attach all artifacts, err: ${err}`);
    }
  }

  private updateApplicationBasedOnCICD(cicd: CICD) {
    try {
      //Add to global cicd list first
      const jobsInfo: CICDJob[] = cicd.jobs;
      for (const jobInfo of jobsInfo) {
        for (const parsedArtifact of jobInfo.parsedArtifacts) {
          try {
            const subTypeArtifact = parsedArtifact.subType.toLowerCase();
            if (subTypeArtifact !== "docker container" && subTypeArtifact !== "serverless" && subTypeArtifact !== "dotnet-lambda") {
              continue;
            }

            //
            // Special case for images that have unknown variables in their names
            //
            if (subTypeArtifact === "dotnet-lambda") {
              const regName = parsedArtifact.name.replace(/\$\{[_\-:a-zA-Z0-9]+\}/gm, "([\\-a-zA-Z0-9]*)");
              this.regExImage.set(regName, cicd);
              this.allCICDjobs[parsedArtifact.hash] = [cicd];
              continue;
            } else if (parsedArtifact.type === "SAM-Lambda") {
              this.regExImage.set(parsedArtifact.name, cicd);
              this.allCICDjobs[parsedArtifact.hash] = [cicd];
              continue;
            }

            if (parsedArtifact.name) {
              this.allCICDjobsByImageName[parsedArtifact.name] = cicd;
            }

            const key = parsedArtifact.hash;
            if (key == undefined || key == null || key === "") {
              continue;
            }
            if (this.allCICDjobs[key] == undefined) {
              this.allCICDjobs[key] = [cicd];
            } else {
              this.allCICDjobs[key].push(cicd);
            }
          } catch (err) {
            logger.error(`filed set cicd to connect cloud image, err: ${err}`);
          }
        }
      }

      const cicdRepo: CICDRepo = cicd.repositories;
      //Try to connect CICD ---> REPO
      for (const app of this.applications) {
        try {
          if (app.appInfo.repo == null) {
            continue;
          }

          const repo: Repo = app.appInfo.repo.code_repo;
          if (
            repo.fullName.toLowerCase() === cicdRepo.repoName.toLowerCase() ||
            repo.name.toLowerCase() === cicdRepo.repoName.toLowerCase()
          ) {
            app.appInfo.cicd = cicd;

            logger.info(`connection found repo to cicd based on cicd full name ${cicdRepo.repoName}`);

            break;
          }
        } catch (err) {
          logger.error(`failed attach single cicd, err: ${err}`);
        }
      }
    } catch (err) {
      logger.error(`failed attach all cicd, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async attachCodeRepoSevEvents(applications: Application[]) {
    try {
      logger.info(`try attach code repo sev events for: ${applications.length} count`);

      const startTime = new Date().getTime();

      let updatedApps = applications.map(app => this.updateApplicationBasedOnRepo(app));

      updatedApps = updatedApps.filter(i => i != null);

      logger.info(`attach code repo sev events for updatedApps: ${updatedApps.length} count`);

      await PromisePool.for(updatedApps)
        .withConcurrency(100)
        .process(
          async (app: Application) =>
            await AsyncTracker.runWithAsyncTracker(async () => {
              AsyncTracker.setValue("ox-app-id", (app.appInfo?.repo?.code_repo as Repo)?.id);
              AsyncTracker.setValue("ox-app-name", (app.appInfo?.repo?.code_repo as Repo)?.name);
              try {
                await app.runAllPolicyForSingleApplication(Constant.execType.codeSecurityExecutionAgain);
                return true;
              } catch (err) {
                logger.error(`failed runAllPolicyForSingleApplication, err: ${err}`);
                return false;
              }
            }),
        );

      const elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));
      StatesHelper.Instance.scanInfoStats.blameCodeAtFinalizing = `${elapsedTime} minutes`;

      logger.info(
        `attached code sec, elapsedTime: ${elapsedTime} repo count: ${updatedApps.length}, repos: ${updatedApps
          .map(i => i.appInfo.repo.code_repo.fullName)
          .join(", ")}`,
      );
    } catch (err) {
      logger.error(`attach code repo sev events, err: ${err}`);
    }
  }

  printStates() {
    try {
      let repoOnly = 0;
      let cicdOnly = 0;
      let cloudOnly = 0;
      let cloudAndCicd = 0;
      let cloudAndRepo = 0;
      let cicdAndRepo = 0;
      let all = 0;
      let numberOfAddedCloudItems = 0;
      let numberOfAddedCloudItemsBasedOnRepoName = 0;
      let numberOfAddedCloudItemsBasedOnJobConent = 0;

      for (const app of this.applications) {
        if (app.appInfo.cicd != null && app.appInfo.cloud != null && app.appInfo.repo != null) {
          all++;
        }
        if (app.appInfo.cicd != null && app.appInfo.cloud != null) {
          cloudAndCicd++;
        }
        if (app.appInfo.repo != null && app.appInfo.cloud != null) {
          cloudAndRepo++;
        }
        if (app.appInfo.repo != null && app.appInfo.cicd != null) {
          cicdAndRepo++;
        }
        if (app.appInfo.repo != null) {
          repoOnly++;
        }
        if (app.appInfo.cicd != null) {
          cicdOnly++;
        }
        if (app.appInfo.cloud != null) {
          cloudOnly++;
        }

        numberOfAddedCloudItems += app.numberOfAddedCloudItems;
        numberOfAddedCloudItemsBasedOnRepoName += app.numberOfAddedCloudItemsBasedOnRepoName;
        numberOfAddedCloudItemsBasedOnJobConent += app.numberOfAddedCloudItemsBasedOnJobsContent;
      }

      logger.info(
        `sum stats, sec alerts before policy eval with provider ${
          StatesHelper.Instance.totalCodeSecurityAlertsBeforePolicyEval
        }, summery: ${JSON.stringify(StatesHelper.Instance.alertsPerCategoryAndProvider)}`,
      );
      logger.info(`sum stats, sec alerts after blame ${StatesHelper.Instance.totalCodeSecurityAlertsAfterBlame}`);
      logger.info(`sum stats, sec alerts before policy eval but after parsing: ${JSON.stringify(StatesHelper.Instance.alertsPerCategory)}`);
      logger.info(
        `sum stats, sec alerts before policy eval and before parsing: ${JSON.stringify(StatesHelper.Instance.alertsPerCategoryFromTool)}`,
      );

      logger.info(
        `status app manager, apps with all: ${all}, cicd and cloud: ${cloudAndCicd},  cicd and repo: ${cicdAndRepo},  repo and cloud: ${cloudAndRepo}, apps with repo ${repoOnly}, apps with cicd ${cicdOnly}, apps with cloud ${cloudOnly}, allCloudSecurityEvents: ${
          this.allCloudSecurityEvents.length
        }, notAddedNotViolatedSecurityItems: ${
          Object.values(this.allUnattachedExternalCodeSecurityEvents).flat().length
        }, allArtifactsSecurityEventsForExternalTools: ${
          this.allArtifactsSecurityEventsForExternalTools.length
        } ,addCloudItems: ${numberOfAddedCloudItems}, numberOfAddedCloudItemsBasedOnRepoName: ${numberOfAddedCloudItemsBasedOnRepoName}, numberOfAddedCloudItemsBasedOnJobConent: ${numberOfAddedCloudItemsBasedOnJobConent}, totalCloudEvents: ${
          this.totalCloudEvents
        }, totalCICDevents: ${this.totalCICDevents}, totalCICDeventsWithJobs: ${this.totalCICDeventsWithJobs}, totalCICDJobsNumber: ${
          this.totalCICDJobsNumber
        }, totalRepoEvents: ${this.totalRepoEvents} `,
      );

      logger.info(`skipped clone repo count: ${StatesHelper.Instance.skippedClone.size}`);

      logger.info(`scan info: ${JSON.stringify(StatesHelper.Instance.scanInfoStats)}`);

      logger.info(
        `delta info: delta apps count: ${StatesHelper.Instance.scanInfoStats.deltaApps}, none delta apps count: ${StatesHelper.Instance.scanInfoStats.nonDeltaApps}`,
      );

      logger.info(
        `SBOM stats: total unique libs was: ${StatesHelper.Instance.allLibsCount}, saved sboms from code: ${StatesHelper.Instance.savedSbomsFromCode}, saved sboms from registry: ${StatesHelper.Instance.savedSbomsFromRegistry}`,
      );
      const missingLicensePercentage = Math.round((StatesHelper.Instance.sbomMissingLicense / StatesHelper.Instance.sbomTotal) * 100);
      const missingCopyrightPercentage = Math.round((StatesHelper.Instance.sbomMissingCopyright / StatesHelper.Instance.sbomTotal) * 100);
      logger.info(
        `SBOM stats: total ${StatesHelper.Instance.sbomTotal}, missing license ${StatesHelper.Instance.sbomMissingLicense} (${missingLicensePercentage}%), missing copyright ${StatesHelper.Instance.sbomMissingCopyright}  (${missingCopyrightPercentage}%)`,
      );
      logger.info(
        `Open Source warnings: ${
          Object.entries(StatesHelper.Instance.openSourceWarnings)
            .map(([warning, count]) => `${warning} - ${count}`)
            .join(" , ") || "none"
        }`,
      );

      logger.info(`policy category stats: ${JSON.stringify(StatesHelper.Instance.policyPerCatStats)}`);

      logger.info(`policy stats: ${JSON.stringify(StatesHelper.Instance.policyStats)}`);

      CveToolsService.instance.printStats();
    } catch (err) {
      logger.error(`failed to print unrelated apps`);
    }
  }

  getName(fullName: string) {
    try {
      const index = fullName.indexOf("/");
      if (index) fullName = fullName.substr(index + "/".length, fullName.length);
      return fullName.trimStart();
    } catch (err) {
      logger.error(`failed to get name for: ${fullName}, err: ${err}`);
    }
    return fullName;
  }

  private updateApplicationBasedOnRepo(foundRepoApp: Application) {
    const repo: Repo = foundRepoApp.appInfo.repo.code_repo;

    const repoFullNameHandleSpaces = repo.fullName.replaceAll(" ", "-").toLowerCase();
    const repoFullNameHandleDots = repo.fullName.replaceAll(".", "-").toLowerCase();
    const repoFullNameHandleDashes = repo.fullName.replaceAll("-", " ").toLowerCase();
    const repoFullNameHandleScan = repo.fullName.replaceAll("-scan", " ").toLowerCase();

    const repoFullName = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.fullName.toLowerCase() : repo.fullName.toLowerCase();
    const repoName = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.name.toLowerCase() : repo.name.toLowerCase();

    //Try to connect REPO ---> Security Events from external service
    let added = false;
    const temp = {};

    const secEvents: SecurityEvent[] = (Object.values(this.allUnattachedExternalCodeSecurityEvents) as any).flat();

    for (const securityEvent of secEvents) {
      {
        try {
          const projectFullNameToLowerCase = securityEvent.repoFullName.toLowerCase();
          const projectNameToLowerCase = this.getName(projectFullNameToLowerCase).toLowerCase();

          //By project name
          if (
            repoName === projectFullNameToLowerCase ||
            repoName === projectNameToLowerCase ||
            repoFullNameHandleScan === projectFullNameToLowerCase ||
            repoFullNameHandleScan === projectNameToLowerCase ||
            repoFullName === projectFullNameToLowerCase ||
            repoFullName === projectNameToLowerCase ||
            repoFullNameHandleDots === projectFullNameToLowerCase ||
            repoFullNameHandleDots === projectNameToLowerCase ||
            repoFullNameHandleSpaces === projectFullNameToLowerCase ||
            repoFullNameHandleSpaces === projectNameToLowerCase ||
            repoFullNameHandleDashes === projectFullNameToLowerCase ||
            repoFullNameHandleDashes === projectNameToLowerCase
          ) {
            added = true;
            foundRepoApp.updateExternalSecurityItem(securityEvent);
            continue;
          }

          //Pkg names maybe be same across repos so do this for no sca violations
          if (securityEvent.securityAlertType != SecurityAlertType.sca) {
            const fileName = securityEvent.fileName.toLowerCase();
            const uniqueFiles = this.jsonHelper.lookupArrayVal(foundRepoApp.appInfo.repo, CodeRepoTypes[CodeRepoTypes.uniqueFiles]);
            if (uniqueFiles.has(fileName)) {
              //Keep this on debug due to the amount of matches can happen
              logger.info(
                `connection found repo to security event based on file name ${fileName}, type: ${
                  securityEvent.securityAlertTypeStr
                } for repo ${repo.fullName}}, is mono repo match: ${repo.parentRepoOfMonoRepo != null}`,
              );
              added = true;
              foundRepoApp.updateExternalSecurityItem(securityEvent);
              continue;
            }
          }
        } catch (err) {
          logger.error(
            `failed to attach single security item for repo: ${repo.fullName}, sec event repo: ${
              securityEvent.repoFullName
            } err: ${err}, securityEvent: ${JSON.stringify(securityEvent)}`,
          );
        }

        //Add if not manage to find attachment
        if (temp[securityEvent.repoFullName]) {
          temp[securityEvent.repoFullName].push(securityEvent);
        } else {
          temp[securityEvent.repoFullName] = [securityEvent];
        }
      }
    }

    if (!added) {
      return null;
    }
    this.allUnattachedExternalCodeSecurityEvents = temp;

    return foundRepoApp;
  }

  private prepareDataForArtifactToCloudToRepo(events: SecurityEvent[] | CloudSecurityEvent[], containersFromSha, containersFromName) {
    try {
      if (!StatesHelper.Instance.isMatchingArtifactToCloud) {
        return;
      }

      //Cloud events
      events.forEach(event => {
        const sha = event.artifacts?.sha;
        let name = event.artifacts?.dockerFileInRunTime;

        //gcr to put the correct name
        if (sha && sha !== "N/A") {
          containersFromSha.set(sha, (containersFromSha.get(sha) || []).concat(event));
        }
        if (name) {
          name = path.basename(name);
          name = name.endsWith("-1") ? name.substring(0, name.length - 2) : name;
          containersFromName.set(name, (containersFromName.get(name) || []).concat(event));
        }
      });
    } catch (e) {
      logger.error(`failed to create maps for events`, e);
    }
  }

  @PerformanceTelemetry()
  private async handleConnectedImagesToRepo() {
    try {
      logger.info(`try run blame on all artifacts apps: ${this.applications.length}`);
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `before setArtifactSecurityEventsOnRepoApp`);

      const startTime = new Date().getTime();

      const containersFromRuntimeSha = new Map();
      const containersFromRuntimeName = new Map();

      const containersFromCspmSha = new Map();
      const containersFromCspmName = new Map();

      this.prepareDataForArtifactToCloudToRepo(this.runtimeArtifactsSecurityEvents, containersFromRuntimeSha, containersFromRuntimeName);

      //dor enable after
      //this.prepareDataForArtifactToCloudToRepo(this.allCloudSecurityEvents, containersFromCspmSha, containersFromCspmName);

      await PromisePool.for(this.applications)
        .withConcurrency(50)
        .process(async (app: Application) => {
          return AsyncTracker.runWithAsyncTracker(async () => {
            AsyncTracker.setValue("ox-app-id", (app.appInfo?.repo?.code_repo as Repo)?.id);
            AsyncTracker.setValue("ox-app-name", (app.appInfo?.repo?.code_repo as Repo)?.name);
            try {
              const secEvents: SecurityEvent[] = await app.getCashedSecEvents();

              //Order execution matter, dont change
              await app.setArtifactSecurityEventsOnRepoApp(secEvents);
              await app.setArtifactToCloudToRepo(secEvents, containersFromRuntimeName, containersFromRuntimeSha);
              await app.setCspmToRepo(secEvents, containersFromCspmName, containersFromCspmSha);

              app.setArtifactSecurityFactorsToAppSecEvents();

              //Attack path
              const issues = this.resultsHandler.appToIssuesMap.get(app.appInfo?.repo?.code_repo?.id);
              const images: ImageInfo[] = app?.appInfo?.artifactory?.registryImage ? app?.appInfo?.artifactory?.registryImage : [];
              await this.setAttackPath(issues, images, app);
            } catch (err) {
              logger.error(`failed single setArtifactSecurityEventsOnRepoApp, err: ${err}`);
            }
          });
        });

      this.runtimeArtifactsSecurityEvents = this.runtimeArtifactsSecurityEvents.filter(e => !e.correlatedCloudEvent);

      await this.connectRuntimeSecEventsBasedOnDeplyomentFiles(this.applications);

      const elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));
      StatesHelper.Instance.scanInfoStats.blameArtifactsAtFinalizing = `${elapsedTime} minutes`;

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `after setArtifactSecurityEventsOnRepoApp`);
      logger.info(`finish run blame on all artifacts apps`);
    } catch (err) {
      logger.error(`failed run blame on artifacts for all apps, err: ${err}`);
    }
  }

  private createDefaultApp(add: boolean = true) {
    const app = new Application(
      this.uuid,
      this.orgName,
      this.policyRules,
      this.jsonApplicationDiscoveryOverview,
      this.ruleExclusions,
      this.resultsHandler,
      this.blameQueue,
      this.secretValidationQueue,
      this.autoFixQueue,
      this.alertRecommendationQueue,
      this.iacVerificationQueue,
      this.scaVerificationQueue,
      this.openSourceInfoQueue,
      this.cachResovler,
      this.resolveIssueValidationQueue,
    );

    if (add) {
      this.applications.push(app);
    }
    return app;
  }
}

export default ApplicationsManager;
