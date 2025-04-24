import { getPoliciesCategoriesByOrder } from "@oxappsec/ox-consolidated-categories";
import FeatureFlags from "@oxappsec/ox-feature-flag";
import { Queue } from "bull";
import afPubSub from "../../appmgr/AFPubSub";
import ApplicationsManager from "../../appmgr/applicationsManager";
import ToolProgressBase from "../../codeOpenSourceTools/base/toolProgressBase";
import CollectorManager from "../../dal/collectorManager";
import { ScanStatus } from "../../entitis/commonTypes";
import { CacheResolver } from "../../helper/cache/cache.resolver";
import { deleteFolderAfterDoneWorkingForOnPrem } from "../../helper/commonUtils";
import { PerformanceTelemetry } from "../../helper/decorators/PerformanceTelemetry";
import DeltaScansHelper from "../../helper/deltaScan/deltaScansHelper";
import { isDevelopment, isK8Mode, isLocalDevelopment, isStaging } from "../../helper/envUtils";
import requestStats from "../../helper/github/requestStats";
import FileHelper from "../../helper/IO/fileHlper";
import MemoryMonitorHelper from "../../helper/IO/memoryMonitorHelper";
import JsonHelper from "../../helper/jsonHelper";
import { PipeLineHelper } from "../../helper/pipelineHelper";
import EnvQueueFactory from "../../helper/queue/envQueueFactory";
import Iqueue from "../../helper/queue/Iqueue";
import { RedisHelper } from "../../helper/redis/redisHelper";
import { ScanDoneService } from "../../helper/scanDone/ScanDoneService";
import ACMHelper from "../../helper/service/artifactCloudMatcherHelper";
import { DemoService } from "../../helper/service/demo-service.ts/api";
import GraphQlHelper from "../../helper/service/graphQlHelper";
import { Policy } from "../../helper/service/policy-service/types";
import { SettingsService } from "../../helper/service/scan-settings-service/service/settings-service";
import StatesHelper from "../../helper/statesHelper";
import {
  millisToMinutesAndSeconds,
  ScanMetric,
  ScanPhaseTime,
  sendDeltaScansTelemetry,
  sendPipelineScanPerformanceTelemetry,
  sendScannerPhaseTimeTelemetry,
  sendScannerStringTelemetry,
} from "../../helper/telemetry-utils";
import { ToolsExecutionStats } from "../../helper/toolExecutionStats";
import loggerImport from "../../logger";
import MongoActiveScan from "../../mongo/mongoActiveScan";
import MongoConnect from "../../mongo/mongoConnect";
import MongoDBapplications from "../../mongo/mongoDBapplications";
import OrgPolicyParser from "../org/ruleConfigParser";
import ResultsHandler from "../reporting/ResultsHandler";
import RuleExclusions from "./ruleExclusions";
import RulesParser from "./rulesParser";
const logger = loggerImport.getDebugLogger();

const isk8 = isK8Mode();
const onAWS = process.env.MONGO_CONN === "atlas";

class RulesManager {
  uuid: string;
  collectorManager: CollectorManager;
  orgPolicyParser: OrgPolicyParser;
  jsonHelper: JsonHelper;
  rulesParser: RulesParser;
  orgName: string;
  graphQlHelper: GraphQlHelper;

  mongoDBapplications: MongoDBapplications;
  applicationsManager: ApplicationsManager;
  fileHelper: FileHelper;
  securityToolsQueue: Iqueue;
  acmQueue: Iqueue;
  finishScan: boolean = false;

  mongoConnect: MongoConnect;
  mongoActiveScan: MongoActiveScan;
  toolProgressBase: ToolProgressBase;
  attackPathQueue: Iqueue;
  clonerQueue: Iqueue;
  deleteRepoQueue: Iqueue;
  blameQueue: Iqueue;
  autoFixQueue: Iqueue;
  dependencyGraphQueue: Iqueue;
  callGraphQueue: Iqueue;
  apiDiscoveryQueue: Iqueue;
  llmClientQueue: Iqueue;
  dockerfileScannerQueue: Iqueue;
  pip2poetryQueue: Iqueue;
  secretValidationQueue: Iqueue;
  alertRecommendationQueue: Iqueue;
  iacVerificationQueue: Iqueue;
  dockerhubQueue: Iqueue;
  scaVerificationQueue: Iqueue;
  openWikiQueue: Iqueue;
  resolveIssueValidationQueue: Iqueue;
  depJackingQueue: Iqueue;
  openSourceInfoQueue: Queue;
  resolvedIssuesQueue: Queue;
  retryScanQueue: Iqueue;
  sarifGenQueue: Iqueue;
  consistencyGenQueue: Iqueue;
  ruleExclusions: RuleExclusions;
  isScheduledScan: boolean = false;
  isPipelineScan: boolean = false;
  scanDate: Date = new Date();
  resultsHandler: ResultsHandler;
  deltaScansHelper: DeltaScansHelper;
  cachResolver: CacheResolver;
  verificationAndStarsQueue: Iqueue;
  awsCrawlerQueue: Iqueue;
  cloudGraphQueue: Iqueue;

  redisHelper: RedisHelper;

  constructor(
    uuid: string,
    collectorManager: CollectorManager,
    orgPolicyParser: OrgPolicyParser,
    orgName: string,
    mongoConnect: MongoConnect,
    isScheduledScan: boolean,
    isPipelineScan: boolean,
  ) {
    StatesHelper.Instance.uuid = uuid;
    this.uuid = uuid;
    this.collectorManager = collectorManager;
    this.orgPolicyParser = orgPolicyParser;
    this.mongoConnect = mongoConnect;
    this.jsonHelper = new JsonHelper(this.uuid);
    this.orgName = orgName;
    this.scanDate = new Date();
    this.fileHelper = new FileHelper(this.uuid);
    this.isScheduledScan = isScheduledScan;
    this.isPipelineScan = isPipelineScan;

    this.redisHelper = new RedisHelper("scan_time_execution", 60 * 60 * 24 * 60);

    this.toolProgressBase = new ToolProgressBase(this.uuid);
    StatesHelper.Instance.toolProgressBase = this.toolProgressBase;

    this.mongoActiveScan = new MongoActiveScan(this.uuid, this.orgName, mongoConnect);

    this.ruleExclusions = new RuleExclusions(this.uuid, this.orgName, this.isPipelineScan);

    this.cachResolver = new CacheResolver(this.orgName, mongoConnect);

    this.rulesParser = new RulesParser(
      this.uuid,
      this.orgPolicyParser.getOrgPolicy(),
      this.orgName,
      this.mongoConnect,
      this.collectorManager,
    );

    this.graphQlHelper = new GraphQlHelper(this.uuid, this.orgName);
    this.resultsHandler = new ResultsHandler(
      this.uuid,
      this.orgName,
      this.rulesParser,
      this.mongoConnect,
      this.collectorManager,
      this.isScheduledScan,
      this.isPipelineScan,
      this.graphQlHelper,
      this.ruleExclusions,
      this.mongoActiveScan,
    );
    this.deltaScansHelper = new DeltaScansHelper(this.uuid, this.orgName);
  }

  async setOldScanTimeExecution(type: string, elapsedTime: number) {
    try {
      const oldScanTimeExecution = (await this.redisHelper.findOne(this.orgName)) as any;

      if (type == "start") {
        if (oldScanTimeExecution != null) {
          let sorted = oldScanTimeExecution.sort((a, b) => new Date(b.date).getTime() - new Date(a.date).getTime());
          if (sorted.length > 5) {
            sorted = sorted.slice(0, 5);
          }
          StatesHelper.Instance.scanInfoStats.oldScanTimeExecution = sorted
            .map(i => {
              return `${i.elapsedTime} (${i.date}) id: ${i.scanId}`;
            })
            .join(", ");
        }
      } else {
        const item = {
          date: new Date(),
          elapsedTime: elapsedTime,
          scanId: this.uuid,
        };
        if (oldScanTimeExecution == null) {
          await this.redisHelper.setOne([item], this.orgName);
        } else if (oldScanTimeExecution != null) {
          oldScanTimeExecution.push(item);
          await this.redisHelper.setOne(oldScanTimeExecution, this.orgName);
        }
      }
    } catch (err) {
      logger.error(`failed set old scan time execution, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async run() {
    try {
      logger.info(`try run rule manager,  org name: ${this.orgName}`);

      this.setTaskForPrintMongoConnections();

      if (process.env.RUN_LOCAL) {
        StatesHelper.Instance.isFullScan = false;
      }

      //Set info for StatesHelper
      StatesHelper.Instance.uuid = this.uuid;
      StatesHelper.Instance.orgName = this.orgName;

      const startTime = new Date().getTime();

      await this.setOldScanTimeExecution("start", null);
      await this.setFeatureFlag();

      const sharedDir = process.env.OX_SHARED_DATA == undefined ? "/var/shared-data" : process.env.OX_SHARED_DATA;
      deleteFolderAfterDoneWorkingForOnPrem("main", `${sharedDir}/${StatesHelper.Instance.orgName}`);

      //Set specific env that shared as static values
      process.env.startCheckSecurityEventsFromDisk = "false";

      //Set mongo for this org
      await this.mongoConnect.setNewConnection();

      await this.ruleExclusions.parseExclusions();

      //Get all rules
      const policyRules: Policy[] = this.rulesParser.getRules();

      this.attackPathQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.blameQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.autoFixQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.secretValidationQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.alertRecommendationQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.iacVerificationQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.awsCrawlerQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.cloudGraphQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.dockerhubQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.scaVerificationQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.openWikiQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.resolveIssueValidationQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.depJackingQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.dependencyGraphQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.callGraphQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.apiDiscoveryQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.llmClientQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.dockerfileScannerQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.pip2poetryQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.openSourceInfoQueue = EnvQueueFactory.getNewQueue(process.env.OPEN_SOURCE_INFO_QUEUE);
      this.resolvedIssuesQueue = EnvQueueFactory.getNewQueue(process.env.RESOLVED_ISSUES_QUEUE);
      this.verificationAndStarsQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.retryScanQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);

      this.mongoDBapplications = new MongoDBapplications(this.uuid, this.orgName, this.mongoConnect);
      //Create app manger to handle policy and apps
      this.applicationsManager = new ApplicationsManager(
        this.uuid,
        this.orgName,
        this.rulesParser,
        policyRules,
        this.collectorManager.jsonApplicationDiscoveryOverview,
        this.ruleExclusions,
        this.resultsHandler,
        this.collectorManager,
        this.blameQueue,
        this.secretValidationQueue,
        this.autoFixQueue,
        this.deltaScansHelper,
        this.alertRecommendationQueue,
        this.iacVerificationQueue,
        this.dockerhubQueue,
        this.openWikiQueue,
        this.isPipelineScan,
        this.scaVerificationQueue,
        this.openSourceInfoQueue,
        this.cachResolver,
        this.verificationAndStarsQueue,
        this.mongoDBapplications,
        this.resolveIssueValidationQueue,
        this.attackPathQueue,
      );

      //Init objects for communication
      this.clonerQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.deleteRepoQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.sarifGenQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.consistencyGenQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.securityToolsQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);
      this.acmQueue = EnvQueueFactory.getQueue(this.uuid, this, this.orgName);

      StatesHelper.Instance.iqueue = this.securityToolsQueue;
      ACMHelper.Instance.ACMHelperQ = this.acmQueue;

      let topic = `tool-runner-${this.orgName}-${this.uuid}`;
      if (isK8Mode() || process.env.redisOnPrem != undefined) {
        topic = process.env.PUBSUB_TOPIC_NAME;
      }

      if (this.isPipelineScan) {
        await PipeLineHelper.Instance.init();
      }
      await this.attackPathQueue.init();
      await this.clonerQueue.init();
      await this.deleteRepoQueue.init();
      await this.blameQueue.init();
      await this.autoFixQueue.init();
      await this.secretValidationQueue.init();
      await SettingsService.Instance.init(this.orgName);
      await this.iacVerificationQueue.init();
      await this.dockerhubQueue.init();
      await this.awsCrawlerQueue.init();
      await this.cloudGraphQueue.init();
      await this.scaVerificationQueue.init();
      await this.openWikiQueue.init();
      await this.resolveIssueValidationQueue.init();
      await this.depJackingQueue.init();
      await this.alertRecommendationQueue.init();
      await this.sarifGenQueue.init();
      await this.consistencyGenQueue.init();
      await this.securityToolsQueue.init();
      await this.rulesParser.init(this.collectorManager.isDemo(), this.isPipelineScan);
      await this.resultsHandler.init();
      await this.dependencyGraphQueue.init();
      await this.callGraphQueue.init();
      await this.apiDiscoveryQueue.init();
      await this.llmClientQueue.init();
      await this.dockerfileScannerQueue.init();
      await this.pip2poetryQueue.init();
      await this.retryScanQueue.init();
      await this.verificationAndStarsQueue.init();
      await this.acmQueue.init();

      this.collectorManager.setCommunicationChanle(this);

      //Calc and collect all unique resources andf collect
      let uniqueResources = this.getUniqueResourcesMap(policyRules);

      //Collect all unique resources and run on them policy evaluations
      await this.collectorManager.collectAllResources(uniqueResources, this);

      logger.info(`finish run rule manager, org name: ${this.orgName}`);

      const { stats } = requestStats();
      logger.info(`finished run github requests for org ${this.orgName}, stats: ${JSON.stringify(stats)}`);

      StatesHelper.Instance.scanInfoStats.githubTotalRequests = stats.totalRequests;
      StatesHelper.Instance.scanInfoStats.githubRequestsCachedByEtagReturned = `${stats.successfulEtagRequest} (${
        stats.successfulEtagRequest ? Math.round((stats.successfulEtagRequest * 100) / stats.totalRequests) : 0
      }%)`;

      if (this.isPipelineScan) {
        await this.resultsHandler.setDonePipelineScan();
      } else {
        await this.resultsHandler.setDone();
      }
      this.finishScan = true;

      await this.collectorManager.jsonApplicationDiscoveryOverview.setDone();

      await this.mongoActiveScan.setDone();
      // If we ran a full scan, but it wasn't a pipeline scan, update isFullScan to false
      if (StatesHelper.Instance.isFullScan && !StatesHelper.Instance.isPipelineScan) {
        await this.graphQlHelper.init();
        await this.graphQlHelper.invokeConnectorsSetFullScan(false);
      }
      await this.resultsHandler.markSuccessfulScan();

      await ScanDoneService.Instance.publishScanDoneMessage(this.uuid, this.orgName, StatesHelper.Instance.scanType, ScanStatus.Succeeded);

      if (!StatesHelper.Instance.isPipelineScan) {
        await DemoService.Instance.cloneToSecondary(this.uuid, this.orgName);
      }

      await this.resultsHandler.setPostDone();

      await sendScannerStringTelemetry(ScanMetric.ScanSuccess, this.orgName, this.uuid, "scan finish");
      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);

      await this.setOldScanTimeExecution("end", elapsedTime);

      await sendScannerPhaseTimeTelemetry(ScanPhaseTime.ScanExecTime, this.orgName, this.uuid, Number(elapsedTime));

      await sendDeltaScansTelemetry(
        ScanMetric.DeltaScansMetric,
        this.orgName,
        this.uuid,
        StatesHelper.Instance.numberOfApps,
        StatesHelper.Instance.scanInfoStats.deltaApps,
        StatesHelper.Instance.scanInfoStats.nonDeltaApps,
      );

      await afPubSub.instance.destroy(this.uuid);
      await this.notifySarifGenerator();
      await this.notifyInconsistencyVerifier();
      await this.deleteAllFolders(true);
      if (!this.isPipelineScan) {
        await this.resultsHandler.onScanFinished();
      }

      StatesHelper.Instance.pipelineScanInfo.scannerExecutionTime = Number(((new Date().getTime() - startTime) / 1000).toFixed(2));
      if (StatesHelper.Instance.pipelineScanInfo.scannerTimeInQueue) {
        const end2endScan =
          StatesHelper.Instance.pipelineScanInfo.scannerTimeInQueue + StatesHelper.Instance.pipelineScanInfo.scannerExecutionTime;
        StatesHelper.Instance.pipelineScanInfo.end2endScan = Number(end2endScan.toFixed(2));
      }

      this.printStats();
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "finish rule manager");

      return true;
    } catch (err) {
      logger.error(`Error in run rule manager`, err);
      await this.handleError(err);
      return false;
    }
  }

  printStats() {
    try {
      this?.applicationsManager?.printStates();
      ToolsExecutionStats.printStats();

      logger.info(
        `finish scan, status: success, scanId: ${this.uuid} orgid: ${this.orgName}, orgName: ${
          StatesHelper.Instance.companyName
        }, pipelineScan: ${StatesHelper.Instance.isPipelineScan ? "true" : "false"}, isFullScan: ${
          StatesHelper.Instance.isFullScan ? "true" : "false"
        }, for repos: ${StatesHelper.Instance.pipelineScanInfo.repoName}, performance: ${
          StatesHelper.Instance.pipelineScanInfo.performance
        }`,
      );

      logger.info(
        `repos that used heavy tasks q  length: ${StatesHelper.Instance.uniqueReposForHeavyTasks.size}, info: ${Array.from(
          StatesHelper.Instance.uniqueReposForHeavyTasks,
        ).join(", ")}, totalIssues totalAggItems: ${StatesHelper.Instance.totalAggItems}, totalIssues: ${
          StatesHelper.Instance.totalIssues
        }, totalSilentIssuesAgg: ${StatesHelper.Instance.totalSilentIssuesAgg}, totalSilent: ${
          StatesHelper.Instance.totalSilent
        }, reducedDueToLargeAggItem: ${StatesHelper.Instance.reducedDueToLargeAggItem}, externalToolCount: ${JSON.stringify(
          StatesHelper.Instance.externalToolCount,
        )}`,
      );

      if (StatesHelper.Instance.isPipelineScan) {
        StatesHelper.Instance.pipelineScanInfo.services = ToolsExecutionStats.getItemForPipelineInfo();

        sendPipelineScanPerformanceTelemetry(this.orgName, this.uuid, StatesHelper.Instance.pipelineScanInfo);

        if (StatesHelper.Instance.pipelineScanInfo.end2endScan > 120) {
          logger.warn(
            `pipeline scan took more than 2 minutes: ${StatesHelper.Instance.pipelineScanInfo.end2endScan} seconds total, scanId:${StatesHelper.Instance.uuid}`,
          );
        }
      }
    } catch (err) {
      logger.error(`Error printStats: err: ${err}`);
    }
  }

  async setFeatureFlag() {
    let allCategories = getPoliciesCategoriesByOrder();

    for (const category of allCategories) {
      if (category.featureFlagKey) {
        const shouldShowCategory = await FeatureFlags.isFeatureEnabled.execute(this.orgName, category.featureFlagKey);
        if (shouldShowCategory) {
          StatesHelper.Instance.enableCategories.push(category);
        }
      } else {
        StatesHelper.Instance.enableCategories.push(category);
      }
    }

    if (StatesHelper.Instance.orgName.toLowerCase() === "org_mxHBvsQIe8saniL6".toLowerCase()) {
      StatesHelper.Instance.isFullScan = true;
    }

    if (StatesHelper.Instance.isMatchingArtifactToCloud) {
      await FeatureFlags.isFeatureEnabled.execute(this.orgName, "artifact-cloud-match");
      logger.info(`isMatchingArtifactToCloud enable`);
    }

    // match artifacts to cloud cspm dor refactor
    StatesHelper.Instance.dorCspm =
      StatesHelper.Instance.orgName === "org_e08aBbdBBkUVlSC0" || StatesHelper.Instance.orgName === "org_SHCed8jc0D3ct4kw";

    StatesHelper.Instance.isDemo =
      StatesHelper.Instance.orgName === "org_fEOzt4wtsHlpODLs" || // SmokeTest2 (dev)
      StatesHelper.Instance.orgName === "org_50BjX8T0nJZrF4sv" || // SmokeTest2 (dev) [For some reason we have another one]
      StatesHelper.Instance.orgName === "org_lr5xmDFD829DrFAK" || // Demo1 (dev)
      StatesHelper.Instance.orgName === "org_9nmsX94Wtjiex40n" || // DemoTemplate (stg)
      StatesHelper.Instance.orgName === "org_nEu9YXI2P5QVWmy4"; // DemoTemplate (prd)
    if (StatesHelper.Instance.isDemo) {
      logger.info(`demo org`);
    }

    //org_SWpml3xso7Sm86ZL
    StatesHelper.Instance.isInfenera = StatesHelper.Instance.orgName === "org_SWpml3xso7Sm86ZL";
    if (StatesHelper.Instance.isInfenera) {
      logger.info(`isInfenera enable`);
    }

    StatesHelper.Instance.isHilan =
      StatesHelper.Instance.orgName === "org_gdh23L8biqOs4AJ3" || StatesHelper.Instance.orgName === "org_du9GlunKmR68wa94";
    if (StatesHelper.Instance.isHilan) {
      logger.info(`isHilan enable`);
    }

    StatesHelper.Instance.skipHandleArtifactsOnFakeApps =
      StatesHelper.Instance.orgName === "org_rGAEZrbmN2ZO9jE1" || StatesHelper.Instance.orgName === "org_WU2Zmk72gpjw353A";
    if (StatesHelper.Instance.skipHandleArtifactsOnFakeApps) {
      logger.info(`skipHandleArtifactsOnFakeApps enable`);
    }

    StatesHelper.Instance.enableDiskDbFallback =
      isDevelopment() || isStaging() || (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "enable-diskdb-fallback"));
    if (StatesHelper.Instance.enableDiskDbFallback) {
      logger.info(`enableDiskDbFallback enable`);
    }

    StatesHelper.Instance.enableFallback =
      isDevelopment() ||
      isLocalDevelopment() ||
      (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "enable-fallback")) ||
      process.env.enableFallback != undefined;
    if (StatesHelper.Instance.enableFallback) {
      logger.info(`enableFallback enable`);
    }

    StatesHelper.Instance.useProwlerWithServices =
      StatesHelper.Instance.orgName === "org_JHTwgxNFPNdBKl7V" || // testAWS prod
      StatesHelper.Instance.orgName === "org_lr5xmDFD829DrFAK" || // demo1
      isLocalDevelopment() ||
      (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "useProwlerWithServices"));
    if (StatesHelper.Instance.useProwlerWithServices) {
      logger.info(`useProwlerWithServices enable`);
    }

    StatesHelper.Instance.isApiSecEnable =
      isDevelopment() || isLocalDevelopment() || (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "apiScanBackend"));
    if (StatesHelper.Instance.isApiSecEnable) {
      logger.info(`isApiSecEnable enable`);
    }
    StatesHelper.Instance.isResolvedIssuesEnable =
      isDevelopment() ||
      (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "resolvedIssuesRun")) ||
      StatesHelper.Instance.orgName === "org_3FaIb7kmXGVol1Vu";
    if (StatesHelper.Instance.isResolvedIssuesEnable) {
      logger.info(`isResolvedIssuesEnable enable`);
    }

    StatesHelper.Instance.containerSecResolvedIssuesEnabled = await FeatureFlags.isFeatureEnabled.execute(
      this.orgName,
      "containerSecResolvedIssues",
    );
    if (StatesHelper.Instance.containerSecResolvedIssuesEnabled) {
      logger.info(`containerSecResolvedIssuesEnabled enable`);
    }

    StatesHelper.Instance.useLightBlame =
      StatesHelper.Instance.orgName === "org_mxHBvsQIe8saniL6" ||
      StatesHelper.Instance.orgName === "org_GyFIbkZVK9BlDomY" ||
      StatesHelper.Instance.orgName === "org_Cn5ZNF5Q8g7qxlG3";
    if (StatesHelper.Instance.useLightBlame) {
      logger.info(`useLightBlame enable`);
    }

    StatesHelper.Instance.useAlertAggregation =
      isDevelopment() || (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "useAlertAggregation"));
    if (StatesHelper.Instance.useAlertAggregation) {
      logger.info(`useAlertAggregation enable`);
    }

    StatesHelper.Instance.isCharterBank =
      // isLocalDevelopment() ||
      (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "charter-bank")) ||
      StatesHelper.Instance.orgName === "org_iHVJfghFH2WHxlBW" || // Charter Bank (prd)
      StatesHelper.Instance.orgName === "org_NR5Qc3L3utEutB3M" || // CharterBankStg (stg)
      StatesHelper.Instance.orgName === "org_y4QQutfuc0o4i33I" ||
      StatesHelper.Instance.orgName === "org_y4QQutfuc0o4i33I"; // Charter bank (dev)
    if (StatesHelper.Instance.isCharterBank) {
      logger.info(`isCharterBank enable`);
    }

    StatesHelper.Instance.isWalmart =
      (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "walmart")) ||
      StatesHelper.Instance.orgName === "org_Hd9g0ixorMyUOKnm" ||
      StatesHelper.Instance.orgName === "org_8XtP5OPIOmGompDz";
    if (StatesHelper.Instance.isWalmart) {
      logger.info(`isWalmart enable`);
    }

    StatesHelper.Instance.waitForResolveIssues = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "waitForResolveIssues");
    if (StatesHelper.Instance.waitForResolveIssues) {
      logger.info(`waitForResolveIssues enable`);
    }

    const isSofi =
      StatesHelper.Instance.orgName === "org_OzKUKbi0r7M7QD0q" || // SoFi snykCli (dev)
      StatesHelper.Instance.orgName === "org_OGnen0NGujdIYjjc" || // sofiSnykPoc (prd)
      StatesHelper.Instance.orgName === "org_VEcO8vFdsYdBvExw" || // Ox Scanner Only (dev)
      StatesHelper.Instance.orgName === "org_9CasvRyNIlI7tKoO" || // sofiStg (stg)
      StatesHelper.Instance.orgName === "org_eUNVWYX9v85NsjhY" || // sofiSnyk (prd)
      StatesHelper.Instance.orgName === "org_ndNVFR7ySjxwcSPx" || // sofi (prd)
      StatesHelper.Instance.orgName === "org_Vil4FQdeI3sCrEyi"; // Gady Sofi (dev)
    StatesHelper.Instance.isSofi = isSofi;
    if (StatesHelper.Instance.isSofi) {
      logger.info(`externalCLIEnable, isSofi: ${isSofi}`);
    }

    StatesHelper.Instance.isMelio = StatesHelper.Instance.orgName === "org_H3phjPsMLNLLy3pj";
    if (StatesHelper.Instance.isMelio) {
      logger.info(`isMelio: ${StatesHelper.Instance.isMelio}`);
    }

    StatesHelper.Instance.aggCloudAlertsBaseOnOrg =
      isSofi || (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "agg-cloud-alerts-base-on-org"));
    if (StatesHelper.Instance.aggCloudAlertsBaseOnOrg) {
      logger.info(`aggCloudAlertsBaseOnOrg enable`);
    }

    StatesHelper.Instance.enableDigitalAssetsLogicForContainers =
      isDevelopment() ||
      isLocalDevelopment() ||
      isStaging() ||
      StatesHelper.Instance.orgName === "org_i3nV7z8k9DR0HW0F" ||
      (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "enable-black-duck-logic-base-on-release-notes"));
    if (StatesHelper.Instance.enableDigitalAssetsLogicForContainers) {
      logger.info(`enableBlackDuckLogicBaseImages`);
    }

    StatesHelper.Instance.isMobiliy =
      "org_pZv1Ka182YVwBoOL" === StatesHelper.Instance.orgName ||
      "org_f2iDNTgvMI2pVRJ9" === StatesHelper.Instance.orgName ||
      "org_WyL0Gs6iV83ejs9G" === StatesHelper.Instance.orgName;
    if (StatesHelper.Instance.isMobiliy) {
      logger.info(`isMobiliy enable`);
    }

    StatesHelper.Instance.isInfenera =
      "org_qM5zv16cCZb2qNsc".toLowerCase() === StatesHelper.Instance.orgName.toLowerCase() ||
      "org_SWpml3xso7Sm86ZL".toLowerCase() === StatesHelper.Instance.orgName.toLowerCase();
    if (StatesHelper.Instance.isInfenera) {
      logger.info(`isInfenera enable`);
    }

    StatesHelper.Instance.isEtoro = "org_cPA56fjQTEvphXHU" === StatesHelper.Instance.orgName;
    if (StatesHelper.Instance.isEtoro) {
      logger.info(`isEtoro enable`);
    }

    StatesHelper.Instance.isMoovit = "org_Tq5tmkOMJ1naSHoi" === StatesHelper.Instance.orgName;
    if (StatesHelper.Instance.isMoovit) {
      logger.info(`isMoovit enable`);
    }

    StatesHelper.Instance.isRepsol = "to be added" === StatesHelper.Instance.orgName;
    if (StatesHelper.Instance.isRepsol) {
      logger.info(`isRepsol enable`);
    }

    StatesHelper.Instance.isAttackPathEnable =
      isLocalDevelopment() || (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "attackPathEnabled"));
    if (StatesHelper.Instance.isAttackPathEnable) {
      logger.info(`isAttackPathEnable enable`);
    }

    StatesHelper.Instance.isNewAPIScanLogicEnable =
      isLocalDevelopment() || (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "newApiLogicEnabled"));
    if (StatesHelper.Instance.isNewAPIScanLogicEnable) {
      logger.info(`isNewAPIScanLogicEnable`);
    }

    StatesHelper.Instance.isCallGraphEnable =
      isLocalDevelopment() || (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "callGraphEnabled"));
    if (StatesHelper.Instance.isCallGraphEnable) {
      logger.info(`isCallGraphEnable enable`);
    }

    StatesHelper.Instance.isContainerEnable =
      isDevelopment() ||
      isLocalDevelopment() ||
      (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "container-security-feature")) ||
      (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "container-scan-enabled", true));
    if (StatesHelper.Instance.isContainerEnable) {
      logger.info(`isContainerEnable enable`);
    }

    // match artifacts to cloud sca
    //Container must be enable for this feature
    StatesHelper.Instance.isMatchingArtifactToCloud =
      (isDevelopment() || isLocalDevelopment() || StatesHelper.Instance.orgName === "org_yGeKVqt7FLHu6oy1") &&
      StatesHelper.Instance.isContainerEnable; // Anecdotes (prd)

    StatesHelper.Instance.dontChangeSeverity =
      (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxKeepOriginalSeverityForPipelineScans")) &&
      StatesHelper.Instance.isPipelineScan;
    if (StatesHelper.Instance.dontChangeSeverity) {
      logger.info(`dontChangeSeverity enable for pipeline scans`);
    }

    StatesHelper.Instance.isArtifactScreenShouldBeDroppedOnEveryScan = await FeatureFlags.isFeatureEnabled.execute(
      this.orgName,
      "oxDropArtifactScreenOnEveryScan",
    );

    if (StatesHelper.Instance.isArtifactScreenShouldBeDroppedOnEveryScan) {
      logger.info(`isArtifactScreenShouldBeDroppedOnEveryScan enable`);
    }

    StatesHelper.Instance.skipArtifactScreenRetention = await FeatureFlags.isFeatureEnabled.execute(
      this.orgName,
      "skipArtifactScreenRetention",
    );

    if (StatesHelper.Instance.skipArtifactScreenRetention) {
      logger.info(`skipArtifactScreenRetention is enabled`);
    }

    StatesHelper.Instance.dontChangeSeverity = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxKeepOriginalSeverity");
    if (StatesHelper.Instance.dontChangeSeverity && !StatesHelper.Instance.isPipelineScan) {
      logger.info(`dontChangeSeverity enable for regular scans`);
    }

    StatesHelper.Instance.canRunFastPipelineScan = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxCanRunFastScan");
    if (StatesHelper.Instance.canRunFastPipelineScan && StatesHelper.Instance.isPipelineScan) {
      logger.info(`canRunFastScan enable for pipeline scans`);
    }

    StatesHelper.Instance.canRunFastestPipelineScan = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxCanRunFastestScan");
    if (StatesHelper.Instance.canRunFastestPipelineScan && StatesHelper.Instance.isPipelineScan) {
      logger.info(`canRunFastestScans enable for pipeline scans`);
    }

    StatesHelper.Instance.useMongoDBOptimizedQueries =
      isDevelopment() || (await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxUseMongoDBOptimizedQueries"));
    if (StatesHelper.Instance.useMongoDBOptimizedQueries) {
      logger.info(`useMongoDBOptimizedQueries enable`);
    }

    StatesHelper.Instance.validateToolSchema = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "oxToolSchemaValidation");
    if (StatesHelper.Instance.validateToolSchema) {
      logger.info(`validateToolSchema enable`);
    }
    StatesHelper.Instance.shouldTrackSeverity = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "shouldTrackSeverity");
    if (StatesHelper.Instance.shouldTrackSeverity) {
      logger.info(`shouldTrackSeverity enable`);
    }
  }

  setTaskForPrintMongoConnections() {
    if (process.env.MONITOR_MONGO && isDevelopment()) {
      setInterval(this.printConnectionsT, 1000 * 60, this);
    }
  }
  printConnectionsT(ruleManger: RulesManager) {
    try {
      ruleManger.mongoConnect.printConnections();
    } catch (err) {
      logger.error(`failed print connections, err: ${err}`);
    }
  }

  async handleError(err) {
    let errInfo = err;

    try {
      const errStr = JSON.stringify(errInfo);

      if (this.finishScan) {
        logger.error(`analysis already finish ignore err: ${errStr}`, err);
        return;
      }

      logger.error(
        `finish scan, status: fail, scanId: ${this.uuid} orgid: ${this.orgName}, orgName: ${
          StatesHelper.Instance.companyName
        }, pipelineScan: ${StatesHelper.Instance.isPipelineScan ? "true" : "false"}, isFullScan: ${
          StatesHelper.Instance.isFullScan ? "true" : "false"
        }`,
      );

      if (this.orgName === "" || this.uuid === "") {
        logger.error(`rule manager handle error called with empty uid or org name. errStr: ${errStr}`, err);
      } else {
        await afPubSub.instance.destroy(this.uuid);
      }

      logger.error(`rule manager handle error called, errStr: ${errStr}`, err);

      if (this.finishScan) {
        logger.error(`race condition was catched, scanner already finish for this analysis, err thrown: ${errStr}`);
        return;
      }

      if (err.code == undefined) {
        errInfo = {
          code: 500,
          message: "unexpected error",
          description: err,
        };
      } else {
        if (Number.isNaN(err.code)) {
          errInfo = {
            code: 500,
            message: "unexpected error",
            description: err,
          };
        }
      }
      if (errInfo.message == undefined) {
        errInfo.message = "unexpected error";
      }
      if (errInfo.description == undefined) {
        errInfo.description = "";
      }

      await this.mongoConnect.setNewConnection();

      //Set done for megajson and discovery(will be removed soon)
      await this.collectorManager.jsonApplicationDiscoveryOverview.setDone();

      //Set done for rest of components
      await this.resultsHandler.onCancelScan();

      await ScanDoneService.Instance.publishScanDoneMessage(this.uuid, this.orgName, StatesHelper.Instance.scanType, ScanStatus.Failed);

      await this.deleteAllFolders(false);

      await sendScannerStringTelemetry(ScanMetric.ScanFail, this.orgName, this.uuid, errStr);
    } catch (err) {
      logger.error(`failed handle report on error`, err);
    }
  }

  async deleteAllFolders(jobSuccess: boolean) {
    try {
      const repoCleanupQ = EnvQueueFactory.getNewQueue(process.env.REPO_CLEANUP_QUEUE_KEY);
      logger.info("About to send msg to cleanup repo dirs");

      await repoCleanupQ.add(
        { orgId: this.orgName, scanId: this.uuid, jobSuccess },
        {
          delay: 60 * 60 * 1000, // 1 hour
        },
      );
      logger.info("Sent msg to cleaup repo dirs");
    } catch (err) {
      logger.error(`failed to send delete dirs, err: ${err}`);
    }
  }

  async notifySarifGenerator() {
    try {
      if (onAWS) {
        logger.info(`Sending sarif generator message upon scan completion`);

        if (typeof process.env.SARIF_GENERATOR_SERVICE_SQS_URL !== "undefined" && process.env.SARIF_GENERATOR_SERVICE_SQS_URL !== null) {
          const msg = {
            orgId: this.orgName,
            scanId: this.uuid,
          };

          const info = {
            url: process.env.SARIF_GENERATOR_SERVICE_SQS_URL,
            msg: msg,
          };

          logger.info(`Notifying sarif generator with (${msg.orgId}:${msg.scanId}) url: ${info.url}`);

          await this.sarifGenQueue.sendQueueMessage(info);

          logger.info(`Finished sending sarif generator message upon scan completion`);
        } else if (!process.env.DEBUG) {
          logger.error(`notifySarifGenerator: SARIF_GENERATOR_SERVICE_SQS_URL is not defined`);
        }
      }
    } catch (err) {
      logger.error(`Failed to notify Sarif Generator, err: ${err}`);
    }
  }

  async notifyInconsistencyVerifier() {
    try {
      if (onAWS) {
        logger.info(`Sending a message to the inconsistency verifier upon scan completion`);

        if (
          typeof process.env.INCONSISTENCY_VERIFIER_SERVICE_SQS_URL !== "undefined" &&
          process.env.INCONSISTENCY_VERIFIER_SERVICE_SQS_URL !== null
        ) {
          const msg = {
            orgId: this.orgName,
            scanId: this.uuid,
          };

          const info = {
            url: process.env.INCONSISTENCY_VERIFIER_SERVICE_SQS_URL,
            msg: msg,
          };

          logger.info(`Notifying inconsistency verifier with (${msg.orgId}:${msg.scanId}) url: ${info.url}`);

          await this.consistencyGenQueue.sendQueueMessage(info);

          logger.info(`Finished sending inconsistency verifier message upon scan completion`);
        } else if (!process.env.DEBUG) {
          logger.error(`notifyInconsistencyVerifier: INCONSISTENCY_VERIFIER_SERVICE_SQS_URL is not defined`);
        }
      } else {
        // TBD handle on-prem
        // Push redis message to the queue
      }
    } catch (err) {
      logger.error(`Failed to notify Inconsistency Verifier, err: ${err}`);
    }
  }

  getUniqueResourcesMap(policyRules: Policy[]): {} {
    let resources = {};
    let uniqueResources = new Set();

    try {
      logger.debug(`try get unique resources`);

      for (const policyRule of policyRules) {
        for (const resource of policyRule.resources) {
          if (resource.name == undefined || resource.type == undefined) {
            logger.warn(`resource name is empty, policy rule id: ${policyRule.policyId}`);
            continue;
          }

          const uniqueKey = resource.type + "_" + resource.name;
          if (uniqueResources.has(uniqueKey)) {
            continue;
          }

          uniqueResources.add(uniqueKey);

          if (resources.hasOwnProperty(resource.type)) {
            resources[resource.type].push(resource);
          } else {
            let items = [resource];
            resources[resource.type] = items;
          }
        }
      }

      logger.info(`finish get unique resources count: ${uniqueResources.size}`);
    } catch (err) {
      logger.error(`failed get unique resources, err: ${err}`);
      throw err;
    }
    return resources;
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 5);
  }
}

export default RulesManager;
