import {
  CategoryDisplayName,
  getCategoriesMap,
  getCategoriesWithGPTFixAvailable,
  getCategoryByName,
  getPoliciesCategoriesByOrder,
  OxCategoriesKeys,
  OxCategory,
} from "@oxappsec/ox-consolidated-categories";
import { getExclusionByCategory } from "@oxappsec/ox-consolidated-exclusions";
import { getTagsMap } from "@oxappsec/ox-consolidated-tags";
import { PromisePool } from "@supercharge/promise-pool/dist/promise-pool";
import { Queue } from "bull";
import crypto from "crypto";
import { differenceInCalendarDays } from "date-fns";
import _ from "lodash";
import { ulid } from "ulid";
import { v4 as uuidv4 } from "uuid";
import { Application as ApplicationAppManager } from "../../appmgr/application";
import CollectorBase from "../../dal/base/collectorBase";
import CollectorManager from "../../dal/collectorManager";
import { AppSbomType, Sbom } from "../../entitis/artifactoryTypes";
import { ImageDetail } from "../../entitis/cloudTypes";
import { Repo } from "../../entitis/codeRepoTypes";
import Constant from "../../entitis/constant";
import { CICDIssue, CICDIssueEnforcement, GPTInfo, Issue, IssueActionsType, SeverityHistoryInfo } from "../../entitis/issuesTypes";
import { EvalRepoPolicyRes, SecInfra, Severity, SeverityStr, SystemEnum } from "../../entitis/reportTypes";
import { ChangeReason, FixIssue, FixType, SeverityChange, severityReasons } from "../../entitis/service/blameTypes";
import { getAppFlow } from "../../helper/appFlow/appFlowHelper";
import { BP, SEVERITIES } from "../../helper/appPriority/repoImportanceCalcHelper";
import { checkObjectSize, splitToChunks } from "../../helper/commonUtils";
import { staticConnectors } from "../../helper/connectorsSpecific/tokensHelper";
import { PerformanceTelemetry } from "../../helper/decorators/PerformanceTelemetry";
import { isDevelopment, isLocalDevelopment } from "../../helper/envUtils";
import MemoryMonitorHelper from "../../helper/IO/memoryMonitorHelper";
import { PipeLineHelper } from "../../helper/pipelineHelper";
import { setNewIssueSeverityBasedOnBP } from "../../helper/policy/severityHelper";
import EnvQueueFactory from "../../helper/queue/envQueueFactory";
import Iqueue from "../../helper/queue/Iqueue";
import { GPTService, ReportService, TicketService } from "../../helper/service";
import { GPTResponse } from "../../helper/service/gpt-service/types";
import GraphQlHelper from "../../helper/service/graphQlHelper";
import { Policy } from "../../helper/service/policy-service/types";
import PrService from "../../helper/service/pr-service/api";
import { PullRequest } from "../../helper/service/pr-service/types";
import { UniqueIssue } from "../../helper/service/report-service/gql/get-unique-issues-query";
import { PipelineScanResult, SetPipelineDataInput } from "../../helper/service/report-service/types";
import { SettingsService } from "../../helper/service/scan-settings-service/service/settings-service";
import { Settings, SettingsSubType } from "../../helper/service/scan-settings-service/types";
import { SlackService } from "../../helper/service/slack/slack.service";
import { SlackNotification } from "../../helper/service/slack/slack.types";
import { TagsService } from "../../helper/service/tags-service/tags-service.service";
import { Ticket } from "../../helper/service/ticket-service/types";
import WorkflowHelper from "../../helper/service/workflowHelper";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import { ToolsExecutionStats } from "../../helper/toolExecutionStats";
import loggerImport from "../../logger";
import { CveToolsService } from "../../mongo/cve-tools.service";
import { DependencyGraphService } from "../../mongo/dependency-graph.service";
import { DependencyGraph } from "../../mongo/DependencyGraph.schema";
import MongoActiveScan from "../../mongo/mongoActiveScan";
import MongoConnect from "../../mongo/mongoConnect";
import MongoDBapplicationsConfigurations from "../../mongo/mongoDBapplicationsConfigurations";
import MongoDBreportUpdates3 from "../../mongo/mongoDBreportUpdates3";
import { SbomService } from "../../mongo/sbom/api";
import { SbomMongoDocument } from "../../mongo/sbom/types";
import aggregationColumns from "../rules/config/aggregation-columns.json";
import RuleExclusions from "../rules/ruleExclusions";
import RulesParser from "../rules/rulesParser";
import {
  AppHistoryScore,
  Application,
  CategoryItem,
  CategoryReason,
  DiscoverySystem,
  IssueAppData,
  ScanInfo,
  ScanProgress,
  ScanSummaryHistory,
  SecInfrastructure,
  SeveritiesObject,
  severityConst,
} from "./types";
import { isPipelineWorkflowsFeatureEnabledForOrg } from "../../helper/featureFlags/isPipelineWorkflowsFeatureEnabledForOrg";
import { ArtifactScreenService } from "../../mongo/artifact-screen/artifact-screen.service";
import { Artifact } from "../../mongo/artifact-screen/types/artifact-screen";

const logger = loggerImport.getDebugLogger();

/**
 * @description
  This class is responsible org saving scan results to mongo collections
 */

export default class ResultsHandler {
  private appToAllPolicies: Map<string, EvalRepoPolicyRes[]>;
  appToIssuesMap: Map<string, Issue[]>;
  private appToPoliciesIdsSet: Map<string, Set<string>>;
  private appToCollectorData: Map<string, Repo>;
  private appToApplicationObject: Map<string, Application>;
  private timeHelper: TimeHelper;
  private scanDate: Date = new Date();
  private discoverySystems: DiscoverySystem[] = [];
  private scanInfo: ScanInfo;
  private totalApps: number;
  public relevantApps: Set<string>;
  public irrelevantApps: Set<string>;
  private historyApplications: AppHistoryScore[] = [];
  private enabledPolicies: Policy[];
  private disabledPolicies: Policy[];
  private collectors: CollectorBase[];
  private clientToolsCount: Set<string>;
  private oxToolsCount: Set<string>;
  private appToIssuesNamesMap: Map<string, Set<string>>;
  private keepUpdating: boolean = true;
  private applicationsFromDB: Application[] = [];
  private readonly sbomService: SbomService;
  private readonly depGraphsService: DependencyGraphService;
  private readonly artifactScreenService: ArtifactScreenService;
  private tickets: Ticket[] = [];
  private uniqueIssues: UniqueIssue[] = [];
  private isIssuesFromPrevScan = false;
  private issuesIdsSet = new Set<string>();
  private prs: PullRequest[] = [];
  private gpts: GPTResponse[] = [];
  private slackNotifiactions: SlackNotification[] = [];
  private scanSummery: ScanSummaryHistory;
  private monorepoScanSettings: Settings;
  private importGithubTopics: Settings;
  private monorepoSplitByScanSettings: Settings;
  private revertScanQueue: Iqueue;
  private readonly detachedTickets: string[] = [];
  private totalIssues: Issue[] = [];

  //Workflow
  private workflowQueue: Queue;
  private workflowHelper: WorkflowHelper;

  // duplicate issues
  duplicateIssues = new Map<CategoryDisplayName, number>();

  maxIssues = 0;
  maxSize = 0;
  bpInfo: BP = new BP();

  mongoDBreport: MongoDBreportUpdates3;

  constructor(
    private readonly uuid: string,
    private readonly orgName: string,
    private readonly rulesParser: RulesParser,
    private readonly mongoConnect: MongoConnect,
    collectorManager: CollectorManager,
    private readonly isScheduledScan: boolean,
    public readonly isPipelineScan: boolean,
    private readonly graphQlHelper: GraphQlHelper,
    private readonly ruleExclusions: RuleExclusions,
    public readonly mongoActiveScan: MongoActiveScan,
  ) {
    this.appToAllPolicies = new Map();
    this.appToIssuesMap = new Map();
    this.appToCollectorData = new Map();
    this.appToApplicationObject = new Map();
    this.appToPoliciesIdsSet = new Map();
    this.relevantApps = new Set();
    this.irrelevantApps = new Set();
    this.clientToolsCount = new Set();
    this.oxToolsCount = new Set();
    this.collectors = collectorManager.collectors;
    this.appToIssuesNamesMap = new Map();
    this.sbomService = new SbomService(orgName, uuid, mongoConnect);
    this.depGraphsService = new DependencyGraphService(orgName, uuid, mongoConnect);
    this.artifactScreenService = new ArtifactScreenService(orgName, uuid, mongoConnect);
    this.graphQlHelper.init();

    this.mongoDBreport = new MongoDBreportUpdates3(uuid, orgName, mongoConnect);
    this.timeHelper = new TimeHelper(uuid);
    this.enabledPolicies = this.rulesParser.getRules();
    this.disabledPolicies = this.rulesParser.getDisabledPolicies();
    this.scanSummery = new ScanSummaryHistory(uuid, this.scanDate);
    this.revertScanQueue = EnvQueueFactory.getQueue(uuid, null, orgName);

    //Workflow
    if (process.env.WORKFLOW_MANAGER_QUEUE) {
      this.workflowQueue = EnvQueueFactory.getNewQueue(process.env.WORKFLOW_MANAGER_QUEUE);
      this.workflowHelper = new WorkflowHelper(this.workflowQueue, this.uuid, this.orgName);
    } else {
      logger.error(`WORKFLOW_MANAGER_QUEUE is not defined`);
    }
  }

  /**
   *
   * @param evalRepoRes Array of policies voilations for specific application
   * after all logic is done, update mongo relevant collections
   */
  @PerformanceTelemetry()
  async handleNewEvalRepoRes(evalRepoRes: EvalRepoPolicyRes[]) {
    try {
      const appId = evalRepoRes[0].collectorData.id;

      // register new application
      this.registerApp(evalRepoRes);

      // define the applicaiton object with all data attached to it
      this.initApplication(appId);

      // define all the issues from the response
      const res = await this.generateUniqueIssues(appId, evalRepoRes);
      const newIssues = res.activeSigs;

      //set app score after calculating issues
      this.setApplicaitonScores(appId);

      // counting tools
      this.toolsCounter(appId);

      // update scan info
      this.updateScanInfo();

      await this.saveToMongoOnNewEvalRepoRes(appId, newIssues);

      this.cleanMemory(evalRepoRes, newIssues);

      await this.handleSilentSigs(res, evalRepoRes);

      return true;
    } catch (e) {
      logger.error(`failed handle results on new eval response, error: ${e}`, e);
    }
    return false;
  }

  async handleSilentSigs(res, evalRepoRes: EvalRepoPolicyRes[]) {
    let fullName = "";
    try {
      fullName = evalRepoRes[0].collectorData.fullName;
      const appId = evalRepoRes[0].collectorData.id;
      let silentSigs: Issue[] = res.silentSigs;

      if (this.irrelevantApps.has(appId)) {
        return;
      }
      if (!silentSigs.length) {
        return;
      }

      if (silentSigs.length > 200) {
        logger.info(
          `found larger number > 200 of ${silentSigs.length} silent sigs, ${res.activeSigs.length} active sigs for repo: ${fullName}`,
        );
        silentSigs = silentSigs.slice(0, 200);
      } else {
        logger.info(`found ${silentSigs.length} silent sigs, ${res.activeSigs.length} active sigs for repo: ${fullName}`);
      }

      const chunkSize = 100;
      const chunks = [];

      for (let i = 0; i < silentSigs.length; i += chunkSize) {
        chunks.push(silentSigs.slice(i, i + chunkSize));
      }
      for (const chunk of chunks) {
        await this.mongoDBreport.addSilentSigIssues(appId, chunk);
      }
      return true;
    } catch (err) {
      logger.error(`failed handleSilentSigs, repoName: ${fullName}, error: ${err} `);
    }
  }

  async handleEvalRepoResForPipelineScan(evalRepoRes: EvalRepoPolicyRes[]) {
    try {
      const appId = evalRepoRes[0].collectorData.id;

      // register new application
      this.registerApp(evalRepoRes);

      // define the applicaiton object with all data attached to it
      this.initApplication(appId);

      const app = this.appToApplicationObject.get(appId);
      PipeLineHelper.Instance.enrichSummaryWithApp(app);
      await PipeLineHelper.Instance.getFullScanAppIssueIdsForApp(appId);

      // define all the issues from the response
      const newIssues = (await this.generateUniqueIssuesFromPolicyEval(appId, evalRepoRes)) as CICDIssue[];
      logger.info(`[handleEvalRepoResForPipelineScan] issues count: ${newIssues.length}`);

      await this.mongoDBreport.addCICDIssues(appId, newIssues);
      this.saveAppIssues(appId, newIssues);
      return true;
    } catch (e) {
      logger.error(`failed handle results on eval response for pipeline scan, error: ${e}`);
    }
    return false;
  }

  async init() {
    try {
      if (!process.env.SECURITY_SCAN_ONLY) {
        if (!this.isPipelineScan) {
          let uniqueIssues = await ReportService.Instance.getUniqueIssues(this.orgName);
          if (!uniqueIssues || uniqueIssues.length === 0) {
            uniqueIssues = await ReportService.Instance.getRawIssues(this.orgName);
            this.isIssuesFromPrevScan = true;
          }

          this.uniqueIssues = uniqueIssues;
        }

        await this.initApplicationsFromDB();

        this.prs = await PrService.Instance.getPrs(this.orgName);
        this.tickets = await TicketService.Instance.getAllTickets(this.orgName);
        this.gpts = await GPTService.Instance.getGPTs(this.orgName);
        this.slackNotifiactions = await SlackService.Instance.getSlackNotifications(this.orgName);
        const scanSettingsTemp = await SettingsService?.Instance?.settings?.getSettings?.settings;
        if (scanSettingsTemp !== null && scanSettingsTemp !== undefined) {
          this.monorepoScanSettings = scanSettingsTemp.find(obj => obj["settingsSubType"] === SettingsSubType.Monorepo);
          if (this.monorepoScanSettings && this.monorepoScanSettings.enabled != null && this.monorepoScanSettings.enabled != undefined) {
            StatesHelper.Instance.monoRepoSplit = this.monorepoScanSettings.enabled;
            logger.info(`set monoRepoSplit to: ${StatesHelper.Instance.monoRepoSplit}`);
          }

          this.monorepoSplitByScanSettings = scanSettingsTemp.find(obj => obj["settingsSubType"] === SettingsSubType.MonorepoSplitBy);
          if (this.monorepoSplitByScanSettings && Array.isArray(this.monorepoSplitByScanSettings.valueList)) {
            StatesHelper.Instance.monoRepoSplitByList = this.monorepoSplitByScanSettings.valueList;
            logger.info(`set monoRepoSplitByList to: ${StatesHelper.Instance.monoRepoSplitByList}`);
          }

          this.importGithubTopics = scanSettingsTemp.find(obj => obj["settingsSubType"] === SettingsSubType.GithubTopics);
          if (this.importGithubTopics && this.importGithubTopics.enabled != null && this.importGithubTopics.enabled != undefined) {
            StatesHelper.Instance.importGithubTopics = this.importGithubTopics.enabled;
            logger.info(`set import Github topics to: ${StatesHelper.Instance.importGithubTopics}`);
          }
        }
      }

      this.scanInfo = this.initScanInfo();
    } catch (e) {
      logger.error(`failed init updare collections, error: ${e}`);
    }
  }

  private async generateUniqueIssuesFromPolicyEval(appId: string, evalRepoRes: EvalRepoPolicyRes[]) {
    const newViolatedPolicies = this.createNewViolatedPolicies(evalRepoRes);
    const allIssues = await Promise.all(
      newViolatedPolicies.map(async v => {
        const violationAppData = this.getViolationAppData(v);
        const app: Application = this.appToApplicationObject.get(appId);
        const res = await this.generateIssuesFromSingleViolation(v.policyRes.list, violationAppData, app);
        return res;
      }),
    );
    const newIssues = this.concatAllApplicationIssues(allIssues);

    //Issue object
    return newIssues;
  }

  /**
   *
   * @param appId
   * @param evalRepoResx
   * @returns unique (not duplicated from previous application violations) issues array from current application violations
   */
  private async generateUniqueIssues(appId: string, evalRepoRes: EvalRepoPolicyRes[]) {
    const silentSigs = [];
    const activeSigs = [];
    let fullName = "";
    try {
      if (this.irrelevantApps.has(appId)) {
        return { activeSigs: activeSigs, silentSigs: silentSigs };
      }

      fullName = evalRepoRes[0].collectorData.fullName;

      const newIssues = await this.generateUniqueIssuesFromPolicyEval(appId, evalRepoRes);
      newIssues.forEach(i => {
        if (i.isSilent) {
          silentSigs.push(i);
        } else {
          activeSigs.push(i);
        }
      });

      this.updateIssuesFromUniqeIssues(activeSigs);
      this.enrichIssuesWithServicesData(activeSigs);

      this.saveAppIssues(appId, activeSigs);
    } catch (e) {
      logger.error(`failed to set issues for app: ${appId}, repoName: ${fullName}, error: ${e}`);
    }
    return { activeSigs: activeSigs, silentSigs: silentSigs };
  }

  private cleanMemory(evalRepoRes: EvalRepoPolicyRes[], issues: Issue[]) {
    try {
      //free memory of this collection
      for (const e of evalRepoRes) {
        e.policyRes.list = [];
      }

      issues.forEach(i => {
        i.aggColumns = [];
        i.aggItems = [];
        i.scaVulnerabilities = [];
        i.noneDirectSCAVulnerability = [];
        i.directSCAVulnerability = [];
        i.dependencyChain = [];
      });
    } catch (err) {
      logger.error(`failed clean memory, error: ${err}`);
    }
  }

  private concatAllApplicationIssues(allIssues: Issue[][]) {
    return allIssues.reduce((totalOfIssues, arrayOfIssues) => {
      totalOfIssues = totalOfIssues.concat(arrayOfIssues);
      return totalOfIssues;
    }, []);
  }

  private saveAppIssues(appId: string, issues: Issue[]) {
    try {
      this.appToIssuesMap.set(appId, this.appToIssuesMap.get(appId).concat(issues));
    } catch (e) {
      logger.error(`failed save application issues, error: ${e}`);
    }
  }

  /**
   *
   * @param appId
   * @param evalRepoRes
   * @returns array of new uniqe violations
   */
  private createNewViolatedPolicies(evalRepoRes: EvalRepoPolicyRes[]) {
    try {
      const violatedPolicies = evalRepoRes.filter(p => p.policyRes.violation && p.policyRes.list.length > 0);
      return violatedPolicies;
    } catch (e) {
      logger.error(`failed create new violated policies, err: ${e}`);
    }
    return [];
  }
  /**
   *
   * @param appId
   * init the application object to be store in mongo in applications collection
   */
  private initApplication(appId: string) {
    try {
      if (!this.isSeenAppBefore(appId)) {
        this.generateApplication(appId);
      }
      this.setAppConfigureDataFromDB(appId);

      this.updateRelvantIrrelvantApps(appId);

      this.setAppInventoryData(appId);

      this.setAppSecInfraData(appId);

      // this.setAppCategories(appId);
    } catch (e) {
      logger.error(`failed to init applicaiton,  app: ${appId}, error: ${e}`);
    }
  }

  private setAppConfigureDataFromDB(appId: string) {
    const appInDB = this.applicationsFromDB.find(app => app.appId === appId);
    if (appInDB) {
      const applicaiton = this.appToApplicationObject.get(appId);
      applicaiton.appOwners = appInDB.appOwners;
    }
  }

  private isSeenAppBefore(appId: string) {
    try {
      return this.relevantApps.has(appId) || this.irrelevantApps.has(appId);
    } catch (e) {
      logger.error(`failed to determine if seen application before, error: ${e}`);
    }
  }
  /**
   *
   * @param appId current app id
   * @param issues current issues
   *
   * @description
   * this function get called at the end of each app evaluation.
   * update/insert the application into mongo,
   * saving the issues into mongo,
   * update the discovery systems, violations by categories and scan info
   */

  private async saveToMongoOnNewEvalRepoRes(appId: string, issues: Issue[]) {
    try {
      if (!this.keepUpdating || !this.mongoDBreport.keepUpdating) {
        logger.info(`stop updating mongo (sigterm or cancel scan called)`);
        return;
      }

      await this.mongoDBreport.updateScanInfo(this.scanInfo);
      const application = this.appToApplicationObject.get(appId);
      await this.mongoDBreport.updateApplication(application);

      if (this.relevantApps.has(appId)) {
        issues.forEach(i => {
          this.scanSummery.addToAppSeverities(appId, i.severity);
          this.scanSummery.addToTotalSeverities(i.severity);
        });
        await this.mongoDBreport.addIssues(issues, appId);
        await this.mongoDBreport.updateScanSummery(this.scanSummery);
      }
    } catch (e) {
      logger.error(`failed save new app discovery to mongo, app: ${appId}, error: ${e}`);
    }
  }

  /**
   *
   * @param appId application id
   * @description setting application inventory data
   */
  private setAppInventoryData(appId: string) {
    try {
      const appData = this.appToCollectorData.get(appId);
      const appCloud = this.appToAllPolicies.get(appId)[0].cloud;
      const appK8 = this.appToAllPolicies.get(appId)[0]?.kubernetes;
      const currentApp = this.appToApplicationObject.get(appId);
      if ((appCloud && appCloud?.cloudAppFlow?.length > 0) || (appK8 && appK8?.kubernetesAppFlow?.length > 0)) {
        currentApp.deployedProd = true;
      }
      const intrvalInDaysForCreate = this.timeHelper.getTimeIntervalFronNowInDays(appData.createdAt);
      currentApp.daysSinceRepoCreation = intrvalInDaysForCreate;

      if (intrvalInDaysForCreate == -1 || intrvalInDaysForCreate <= 7) {
        currentApp.new = true;
      }
      const intrvalInDaysForPush = this.timeHelper.getTimeIntervalFronNowInDays(appData.lastPushTime);
      currentApp.daysSinceLastCodeChange = intrvalInDaysForPush;
      if (intrvalInDaysForPush == -1 || intrvalInDaysForPush <= 7) {
        currentApp.updated = true;
      }
    } catch (e) {
      logger.error(`failed set app inventory data, error: ${e}`);
    }
  }

  private setDiscoverdSystems() {
    try {
      this.initDiscoverySystems();
      // also here from the start
      const cicdArray = this.discoverySystems.find(i => i.type === SystemEnum.CICD).systems;
      const cloudArray = this.discoverySystems.find(i => i.type === SystemEnum.CLOUD).systems;
      const securityArray = this.discoverySystems.find(i => i.type === SystemEnum.SECURITY).systems;
      const registryArray = this.discoverySystems.find(i => i.type === SystemEnum.REGISTRY).systems;
      const repoArray = this.discoverySystems.find(i => i.type === SystemEnum.REPOSITORY).systems;

      const allReleveantApps = Array.from(this.relevantApps);

      for (const appId of allReleveantApps) {
        const collectorData = this.appToCollectorData.get(appId);
        const app = this.appToApplicationObject.get(appId);
        if (!collectorData) {
          // CICD
          for (const cicd of app.applicationFlows.cicdInfo) {
            try {
              const cicdTool = cicdArray.find(cicdTool => cicdTool.name === cicd.system);
              if (cicdTool === undefined) {
                cicdArray.push({
                  name: cicd.system,
                  count: 1,
                  applications: [app.appName],
                });
              } else {
                cicdTool.count++;
                cicdTool.applications.push(app.appName);
              }
            } catch (err) {
              logger.error(`failed set discover system cicd: ${JSON.stringify(cicd)}, error: ${err}`);
            }
          }

          //Repo
          if (collectorData.type) {
            const repoTool = repoArray.find(tool => tool.name.toLowerCase() === collectorData.type.toLowerCase());
            if (repoTool === undefined) {
              repoArray.push({
                name: collectorData.type,
                count: 1,
                applications: [app.appName],
              });
            } else {
              repoTool.count++;
              repoTool.applications.push(app.appName);
            }
          }

          //Artifacts
          for (const artifact of app.applicationFlows.artifacts) {
            try {
              const artifactTool = registryArray.find(tool => tool.name.toLowerCase() === artifact.system.toLowerCase());
              if (artifactTool === undefined) {
                registryArray.push({
                  name: artifact.system,
                  count: 1,
                  applications: [app.appName],
                });
              } else {
                artifactTool.count++;
                artifactTool.applications.push(app.appName);
              }
            } catch (err) {
              logger.error(`failed set discover system artifact: ${JSON.stringify(artifact)}, error: ${err}`);
            }
          }

          // SCA
          for (const tool of app.toolsCoverage) {
            try {
              if (tool.type != "sca") continue;
              const secTool = securityArray.find(secTool => secTool.name === tool.toolName);
              if (secTool === undefined) {
                securityArray.push({
                  name: tool.toolName,
                  count: 1,
                  applications: [app.appName],
                });
              } else {
                secTool.count++;
                secTool.applications.push(app.appName);
              }
            } catch (err) {
              logger.error(`failed set discover system tool: ${JSON.stringify(tool)}, error: ${err}`);
            }
          }

          // SAST
          for (const tool of app.toolsCoverage) {
            try {
              if (tool.type != "sast") continue;
              const sastTool = securityArray.find(secTool => secTool.name === tool.toolName);
              if (sastTool === undefined) {
                securityArray.push({
                  name: tool.toolName,
                  count: 1,
                  applications: [app.appName],
                });
              } else {
                sastTool.count++;
                sastTool.applications.push(app.appName);
              }
            } catch (err) {
              logger.error(`failed set discover system tool: ${JSON.stringify(tool)}, error: ${err}`);
            }
          }

          // CLOUD DEPLOYMENTS
          for (const cloudObj of app.applicationFlows.cloudDeployments) {
            try {
              const co = cloudArray.find(co => co.name.toLowerCase() == cloudObj.type.toLowerCase());
              if (co === undefined) {
                cloudArray.push({
                  name: cloudObj.type.toLowerCase() == "azure" ? "Azure Cloud" : cloudObj.type,
                  count: 1,
                  applications: [app.appName],
                });
              } else {
                co.count++;
                co.applications.push(app.appName);
              }
            } catch (err) {
              logger.error(`failed set discover system cloudObj: ${JSON.stringify(cloudObj)}, error: ${err}`);
            }
          }
          continue;
        }

        // Handle scanned app
        const { cloudDeployments, cicd, sast, sca } = collectorData;

        for (const cicdSt of app.applicationFlows.cicdInfo) {
          try {
            const cicdTool = cicdArray.find(cicdTool => cicdTool.name === cicdSt.system);
            if (cicdTool === undefined) {
              cicdArray.push({
                name: cicdSt.system,
                count: 1,
                applications: [app.appName],
              });
            } else {
              cicdTool.count++;
              cicdTool.applications.push(app.appName);
            }
          } catch (err) {
            logger.error(`failed set discover system cicdSt: ${JSON.stringify(cicdSt)}, error: ${err}`);
          }
        }

        //Repo
        if (collectorData.type) {
          const repoTool = repoArray.find(tool => tool.name.toLowerCase() === collectorData.type.toLowerCase());
          if (repoTool === undefined) {
            repoArray.push({
              name: collectorData.type,
              count: 1,
              applications: [app.appName],
            });
          } else {
            repoTool.count++;
            repoTool.applications.push(app.appName);
          }
        }

        for (const scaSt of sca) {
          try {
            const secTool = securityArray.find(secTool => secTool.name === scaSt);
            if (secTool === undefined) {
              securityArray.push({
                name: scaSt,
                count: 1,
                applications: [app.appName],
              });
            } else {
              secTool.count++;
              secTool.applications.push(app.appName);
            }
          } catch (err) {
            logger.error(`failed set discover system scaSt: ${JSON.stringify(scaSt)}, error: ${err}`);
          }
        }

        for (const sastSt of sast) {
          try {
            const sastTool = securityArray.find(secTool => secTool.name === sastSt);
            if (sastTool === undefined) {
              securityArray.push({
                name: sastSt,
                count: 1,
                applications: [app.appName],
              });
            } else {
              sastTool.count++;
              sastTool.applications.push(app.appName);
            }
          } catch (err) {
            logger.error(`failed set discover system sastSt: ${JSON.stringify(sastSt)}, error: ${err}`);
          }
        }

        for (const cloudObj in cloudDeployments) {
          try {
            const co = cloudArray.find(co => co.name.toLowerCase().includes(cloudObj.toLowerCase()));
            if (co === undefined) {
              cloudArray.push({
                name: cloudObj.toLowerCase().includes("azure") ? "Azure Cloud" : cloudObj,
                count: 1,
                applications: [app.appName],
              });
            } else {
              co.count++;
              co.applications.push(app.appName);
            }
          } catch (err) {
            logger.error(`failed set discover system cloudObj: ${JSON.stringify(cloudObj)}, error: ${err}`);
          }
        }

        for (const artifact of app.applicationFlows.artifacts) {
          try {
            const artifactTool = registryArray.find(tool => tool.name.toLowerCase() === artifact.system.toLowerCase());
            if (artifactTool === undefined) {
              registryArray.push({
                name: artifact.system,
                count: 1,
                applications: [app.appName],
              });
            } else {
              artifactTool.count++;
              artifactTool.applications.push(app.appName);
            }
          } catch (err) {
            logger.error(`failed set discover system artifact: ${JSON.stringify(artifact)}, error: ${err}`);
          }
        }
      }
    } catch (e) {
      logger.error(`failed to set discovery systems, error: ${e}`);
    }
  }

  /**
   *
   * @param vioaltion single policy violation
   * @returns all the issues from single violation
   */
  private async generateIssuesFromSingleViolation(rawIssue: any[], issueAppData: IssueAppData, appInfo: Application) {
    const appId = appInfo.appId;

    const app = this.appToApplicationObject.get(appId);
    if (!app) {
      logger.error(`something went wrong missing app id from appToApplicationObject, app: ${appId}`);
      return [];
    }
    let issues: Issue[] = [];
    let pipelineIssues: CICDIssue[] = [];
    const existInInOneOfTheIssues = new Set();
    const notExistInInOneOfTheIssues = new Set();

    const stats = { startTime: new Date().getTime() };

    for (const alert of rawIssue) {
      try {
        if (this.issuesIdsSet.has(alert.issueId)) {
          //logger.debug(`duplicated issueId!! issueId: ${alert.issueId} is already exists`);
          const cat = getPoliciesCategoriesByOrder().find(cat => cat.id === issueAppData.categoryId).displayName;
          const isExists = this.duplicateIssues.has(cat);
          if (!isExists) {
            this.duplicateIssues.set(cat, 0);
          }
          this.duplicateIssues.set(cat, this.duplicateIssues.get(cat) + 1);
          continue;
        }

        let item: Issue = {
          sId: this.uuid,
          scanId: this.uuid,
          sDate: this.scanDate,
          pId: issueAppData.policyId,
          iid: uuidv4(),
          pName: issueAppData.pName,
          severity: this.getSeverity(alert, issueAppData),
          iName: alert.name,
          iOwner: [],
          appConScore: 100,
          appName: issueAppData.appName,
          appId: issueAppData.appId,
          appType: issueAppData.appType,
          appBp: issueAppData.appBp,
          appOwners: app.appOwners || [],
          info: alert.info,
          originBranchName: issueAppData.originBranchName,
          recommendation: alert.recommendation,
          learnMore: [alert.moreInfoLink],
          connector: issueAppData.appType,
          resource: alert.resource,
          resourceType: alert.resource_type,
          extraInfo: alert.extraInfo,
          aggSummary: alert.aggregatedInfo.violationInfoTitle,
          aggColumns: aggregationColumns[alert.aggregatedInfo.columns],
          aggsType: alert.aggregatedInfo.columns,
          aggColumnsComment: alert.aggregatedInfo.violationInfoTitle,
          aggItems: alert.aggregatedInfo.aggregatedItems,
          // aggFileNames: alert?.aggregatedInfo?.aggregatedItems?.map(item => item?.fileName).filter(fileName => fileName !== undefined),
          detailedDescription: alert.detailedDescription,
          additionalTabs: alert?.additionalTabs ? alert?.additionalTabs : undefined,
          oscarData: alert.oscarData ? alert.oscarData : [],
          mainTitle: alert.mainTitle,
          secondTitle: alert.secondTitle,
          vioaltionInfoTitle: alert.aggregatedInfo.violationInfoTitle || "",
          exclusionCategory: alert.exclusionCategory,
          excludedByTool: false,
          ruleId: alert.ruleId,
          recommendedExclusions: getExclusionByCategory(alert.exclusionCategory).ruleExclusions,
          cwe: alert.cwe,
          version: alert.version,
          snippet: alert.snippet,
          issueOwners: alert.issueOwners,
          cweList: alert.cweList,
          excludedByApp: false,
          prDeatils: alert.prDeatils || null,
          excludedByPolicy: false,
          excludedByAlert: false,
          fixLink: alert.fixLink,
          appCreatedAt: app.createdAt,
          deployedProd: app.deployedProd,
          fixAppliedBy: alert.fixAppliedBy || "",
          publicVisibility: app.publicVisibility,
          lastCodeChange: app.lastCodeChange,
          appCategory: app.appCategory,
          isMonoRepoChild: app.isMonoRepoChild ? app.isMonoRepoChild : false,
          monoRepoParent: app.monoRepoParent ? app.monoRepoParent : "",
          fakeApp: app.fakeApp,
          issueId: alert.issueId,
          sources: alert.sources,
          tools: alert.tools,
          dependencyChain: alert.dependencyChain,
          publicExploitLink: alert.publicExploitLink,
          createdAt: this.scanDate,
          lastIssueSeenDate: this.scanDate,
          severityChangeReason: alert?.severityChangeReason ? alert.severityChangeReason : [],
          severityChangedReason: alert?.severityChangedReason
            ? alert.severityChangedReason.sort((a: ChangeReason, b: ChangeReason) => b.changeNumber - a.changeNumber)
            : [],
          scaVulnerabilities: alert?.scaVulnerabilitysTable ? alert.scaVulnerabilitysTable : [],
          severityChange: alert?.severityChange ? alert.severityChange : SeverityChange.NotApplicable,
          originalToolSeverity: alert?.originalToolSeverity ? alert.originalToolSeverity : "",
          tickets: [],
          categoryId: issueAppData.categoryId,
          categoryDisplayName: getPoliciesCategoriesByOrder().find(cat => cat.id === issueAppData.categoryId).displayName,
          cat: getPoliciesCategoriesByOrder().find(cat => cat.id === issueAppData.categoryId).displayName,
          repoId: issueAppData.repoId,
          organization: issueAppData.organization,
          repoName: issueAppData.repoRealName,
          countRule: alert.countRule,
          fixes: alert.fixes,
          overrightBP: alert.overrightBP,
          groupId: "",
          needToBeRemoved: false,
          reducedSeverity: false,
          noneDirectSCAVulnerability: alert.noneDirectSCAVulnerability ? alert.noneDirectSCAVulnerability : [],
          directSCAVulnerability: alert.directSCAVulnerability ? alert.directSCAVulnerability : [],
          allUniqueLibs: alert.allUniqueLibs ? alert.allUniqueLibs : [],
          indirectSupported: alert.indirectSupported ? alert.indirectSupported : false,
          issueActions: [alert.scaFixType],
          languageInfo: alert.languageInfo,
          slackNotification: [],
          scaTriggerPkg: alert.scaTriggerPkg ? alert.scaTriggerPkg : null,
          libId: alert.libId,
          isFixAvailable: false,
          isChatGPTFixable: false,
          isPRAvailable: false,
          isFixApplied: false,
          eventFromExternalTool: alert.eventFromExternalTool ? alert.eventFromExternalTool : false,
          tags: appInfo.tags || [],
          scanIssueStatus: "Unchanged",
          isFalsePositive: false,
          compliance: alert.compliance ? alert.compliance : [],
          allAggItemsIds: [],
          graphExists: alert.graphExists,
          blameExists: alert.blameExists,
          oxRecommendationExists: alert.oxRecommendationExists,
          commitInfoExists: alert.commitInfoExists,
          uniqueArtifacts: alert.uniqueArtifacts,
          secEventsSev: alert.secEventsSev || [],
          secretStatus: alert.secretStatus,
          correlatedIssueId: alert.correlatedIssueId,
          correlatedRegistry: alert.correlatedRegistry,
          dataRangeInDays: alert.dataRangeInDays,
          triggerPkgForResolveIssues: alert.triggerPkgForResolveIssues,
          scaFixType: alert.scaFixType,
          problematicPkg: alert.problematicPkg,
          ignoreResolve: alert.code_repo,
          isSilent: alert.isSilent,
        };

        try {
          if (alert?.aggregatedInfo && alert?.aggregatedInfo?.aggregatedItems && Array.isArray(alert.aggregatedInfo.aggregatedItems)) {
            item.aggFileNames = alert.aggregatedInfo.aggregatedItems.map(item => item?.fileName).filter(fileName => fileName !== undefined);
          }
        } catch (err) {} //do nothing

        item.aggregatedItemsId = this.generateAggregatedItemsId(item);

        if (!alert.isSilent) {
          if (this.excluded(item)) {
            continue;
          }

          if (item.aggItems && item.aggItems.length > 0) {
            item.aggregationsCount = item.aggItems.length;
            const aggIds = item.aggItems.map(aggItem => aggItem.aggId);
            item.allAggItemsIds = aggIds;

            StatesHelper.Instance.totalAggItems += item.aggItems.length;
          } else {
            StatesHelper.Instance.totalAggItems++;
          }
          StatesHelper.Instance.totalIssues++;

          this.removeAggItems(item);
          this.setIssueActions(item);
        }
        //Silent
        else {
          if (item.aggItems && item.aggItems.length > 0) {
            StatesHelper.Instance.totalSilentIssuesAgg += item.aggItems.length;
          } else {
            StatesHelper.Instance.totalSilentIssuesAgg++;
          }
          StatesHelper.Instance.totalSilent++;
        }

        if (this.isPipelineScan) {
          const cicdIssue = await PipeLineHelper.Instance.generateCICDIssue(
            item,
            alert,
            issueAppData,
            existInInOneOfTheIssues,
            notExistInInOneOfTheIssues,
            this.mongoDBreport,
            stats,
          );
          if (cicdIssue) {
            pipelineIssues.push(cicdIssue);
          }
        }

        //Save some stats for policy count
        if (StatesHelper.Instance.policyStats[item.pName]) {
          StatesHelper.Instance.policyStats[item.pName] += 1;
        } else {
          StatesHelper.Instance.policyStats[item.pName] = 1;
        }
        if (StatesHelper.Instance.policyPerCatStats[item.categoryDisplayName]) {
          StatesHelper.Instance.policyPerCatStats[item.categoryDisplayName] += 1;
        } else {
          StatesHelper.Instance.policyPerCatStats[item.categoryDisplayName] = 1;
        }

        if (isDevelopment()) {
          const objSize = checkObjectSize(item);
          //Bigger then in mb
          if (objSize > 5) {
            logger.warn(`huge object size: ${objSize} in mb, app name: ${item.appName}, id: ${appId}, issue: ${item.pName}`);
          }
        }

        issues.push(item);

        //Dont save in case silent
        if (!alert.isSilent) {
          ToolsExecutionStats.addResourcePolicyStats(item, app.appId, app.appName, "unknown");
          this.issuesIdsSet.add(item.issueId);

          //Save for stats
          ToolsExecutionStats.addToAlertSeverity(item);
        }
      } catch (e) {
        logger.error(`failed to genarate issue: ${e}, alert: ${JSON.stringify(alert)}`);
      }
    }

    if (this.isPipelineScan) {
      const elapsedTime = (new Date().getTime() - stats.startTime) / 1000;
      logger.info(`generateIssuesFromSingleViolation took ${elapsedTime} seconds`);
    }
    return this.isPipelineScan ? pipelineIssues : issues;
  }

  getSeverity(alert: any, issueAppData: any) {
    try {
      const severity = Math.floor(alert.severity) in Severity ? Math.floor(alert.severity) : issueAppData.severity;
      return severity;
    } catch (err) {
      logger.error(`failed to generate severity: ${err}`);
    }
    return alert.severity in Severity ? alert.severity : issueAppData.severity;
  }

  setIssueActions(item: Issue) {
    try {
      let isPrAvailable = false;
      if (
        item.snippet &&
        (item.cat !== "Open Source Security" ||
          (item?.languageInfo?.name === "Python" &&
            item.aggItems.every(
              (obj: any) =>
                obj.fileName &&
                (obj.fileName.endsWith("requirements.txt") ||
                  obj.fileName.endsWith("poetry.lock") ||
                  obj.fileName.endsWith("pyproject.toml") ||
                  obj.fileName.endsWith("setup.py") ||
                  obj.fileName.endsWith("Pipfile") ||
                  obj.fileName.endsWith("Pipfile.lock")),
            )) ||
          (item?.languageInfo?.name === "Go" && item.aggItems.every((obj: any) => obj.fileName && obj.fileName.endsWith("go.mod"))) ||
          (item?.languageInfo?.name === "JavaScript" &&
            item.aggItems &&
            item.aggItems.every((obj: any) => obj.fileName && obj.fileName.endsWith("package.json"))) ||
          (item?.languageInfo?.name === "Java" &&
            item.aggItems &&
            item.aggItems.every((obj: any) => obj.fileName && obj.fileName.endsWith("pom.xml"))) ||
          (item?.languageInfo?.name === "C#" &&
            item.aggItems &&
            item.aggItems.some((obj: any) => obj.fileName && !obj.fileName.endsWith("packages.lock.json"))) ||
          ((item?.languageInfo?.name === "C++" || item?.languageInfo?.name === "C") &&
            item.aggItems &&
            item.aggItems.every(
              (obj: any) =>
                obj.fileName &&
                (obj.fileName.endsWith(".cmake") ||
                  obj.fileName.endsWith("conanfile.txt") ||
                  obj.fileName.endsWith("conanfile.py") ||
                  obj.fileName.endsWith("spack.yaml")),
            )) ||
          (item?.languageInfo?.name === "Dockerfile" && item.aggItems) ||
          item.aggItems.every(
            (obj: any) =>
              obj.fileName &&
              (obj.fileName.endsWith(".gradle") || obj.fileName.endsWith(".gradle.kts") || obj.fileName.endsWith("Dependencies.kt")),
          ) ||
          // isDevelopment() ||
          isLocalDevelopment())
      ) {
        isPrAvailable =
          ///@ts-ignore
          item.aggItems?.some(i => i.isFixAvailable || i.isChatGPTFixable) || false;
      }

      if (item?.appType?.toLowerCase() === "Bitbucket-Stash".toLowerCase()) {
        isPrAvailable = false;
      }

      const isFixAvailable = !!item.fixes;
      const isFixApplied = item.isFixApplied;
      const isGPTAvailable = this.isGPTAvailable(item);
      const isGPTCreated = !!this.gpts.find(i => i.issueId === item.issueId);
      const issueActions: IssueActionsType[] = item.issueActions;
      if (isPrAvailable) issueActions.push(IssueActionsType.PrAvailable);
      if (isFixAvailable) issueActions.push(IssueActionsType.FixAvailable);
      if (isFixApplied) issueActions.push(IssueActionsType.FixApplied);
      if (isGPTAvailable) issueActions.push(IssueActionsType.GPTAvailable);
      if (isGPTCreated) issueActions.push(IssueActionsType.GPTCreated);

      item.isFixAvailable = isFixAvailable;
      item.issueActions = issueActions;
      item.isPRAvailable = isPrAvailable;
    } catch (e) {
      logger.error(`failed set issue actions. error: ${e}`);
    }
  }
  isGPTAvailable(item: Issue) {
    try {
      return getCategoriesWithGPTFixAvailable()
        .map(i => Number(i.id))
        .includes(item.categoryId);
    } catch (e) {
      logger.error(`failed to isGPTAvailable, error: ${e} `);
    }
    return false;
  }
  private removeAggItems(issue: Issue) {
    try {
      if (issue.aggItems) {
        if (issue.aggItems.length > Constant.MAX_AGG_ITEMS) {
          issue.totalAggItems = issue.aggItems.length;
          StatesHelper.Instance.reducedDueToLargeAggItem += issue.aggItems.length - Constant.MAX_AGG_ITEMS;
          const removedAggItems = issue.aggItems.splice(Constant.MAX_AGG_ITEMS);
          logger.info(`${removedAggItems.length} agg items were removed from issue: ${issue.issueId}`);
        }
      }
    } catch (e) {
      logger.error(`failed to remove agg items, error: ${e}`);
    }
  }

  //This function handle cases for single agg items
  isSingleAggItemExcluded(aggId: string, issuePId: string, issueId: string) {
    const aggItemExclusion = this.ruleExclusions.isAggItemExcluded(aggId, issuePId, issueId);
    if (aggItemExclusion) {
      if (aggItemExclusion.isActive) {
        logger.info(`Excluded agg item on the policy level, issuePId: ${issuePId}, issueId: ${issueId}, aggId: ${aggId}`);
        return true;
      }
      return false;
    }
    return false;
  }

  private excluded(item: Issue) {
    const issueExclusion = this.ruleExclusions.isIssueExcluded(item.issueId, item.reducedSeverity);
    if (issueExclusion) {
      if (issueExclusion.isActive)
        //Excluded
        return true;
      // set the exclusionId in the top level issue item
      item.exclusionId = issueExclusion.exclusionId;
    }
    if (item.aggItems) {
      const aggItems = item.aggItems.filter(aggItem => {
        const aggItemExclusion = this.ruleExclusions.isAggItemExcluded(aggItem.aggId, item.pId, item.issueId);
        if (aggItemExclusion) {
          if (aggItemExclusion.isActive) {
            return false;
          }
          aggItem.exclusionId = aggItemExclusion.exclusionId;
        }
        const applicationExclusion = this.ruleExclusions.isApplicationExcluded(aggItem, item);
        if (applicationExclusion) {
          if (applicationExclusion.isActive) {
            return false;
          }

          aggItem.exclusionId = applicationExclusion.exclusionId;
        }
        const globalExclusion = this.ruleExclusions.isGlobalExcluded(aggItem, item);
        if (globalExclusion) {
          if (globalExclusion.isActive) {
            return false;
          }
          aggItem.exclusionId = globalExclusion.exclusionId;
        }
        return true;
      });
      if (aggItems.length === 0) {
        logger.info(`EXCLUDED ALL AGGITEMS, issueId: ${item.issueId}, name: ${item.iName}, reduced severity: ${item.reducedSeverity}`);
        //Excluded
        return true;
      }
      item.aggItems = aggItems;
    }
    //Not Excluded
    return false;
  }

  private generateAggregatedItemsId(issue: Issue) {
    if (issue.aggItems) {
      const aggIds = issue.aggItems.map(aggItem => aggItem.aggId);
      const aggId = aggIds.join("-");
      const res = crypto.createHash("md5").update(aggId).digest("hex");
      return res;
    }
  }

  /**
   *```
   * @param evalRepoRes policies violation array
   * @description saving all application and violations data into maps with appId as key
   */
  private registerApp(evalRepoRes: EvalRepoPolicyRes[]) {
    const appId = evalRepoRes[0].collectorData.id;
    try {
      const app = this.appToApplicationObject.get(appId);
      this.appToAllPolicies.set(appId, evalRepoRes);
      this.appToCollectorData.set(appId, evalRepoRes[0].collectorData);
      if (app === undefined) {
        this.appToIssuesMap.set(appId, []);
        this.appToPoliciesIdsSet.set(appId, new Set());
        this.appToIssuesNamesMap.set(appId, new Set());
      }
    } catch (e) {
      logger.error(`failed to register app: ${appId}, error: ${e}`);
    }
  }

  private async setApiItemsSeverities() {
    try {
      const applicationsIds = Array.from(this.relevantApps);
      const apiItemsToUpdate = [];

      for (const appId of applicationsIds) {
        const issues = this.appToIssuesMap.get(appId) ?? [];

        const apiItems = await this.mongoDBreport.getApiItems(
          this.uuid,
          issues.flatMap(issue => issue.exposedByApiIds ?? []),
        );

        for (const apiItem of apiItems) {
          const exposedIssues = issues.filter(issue => issue.exposedByApiIds?.includes(apiItem.uuid));

          apiItem.issuesBySeverity = Object.entries(_.groupBy(exposedIssues, "severity")).reduce(
            (acc, [severity, issues]) => ({ ...acc, [severityConst[severity]]: issues.length }),
            {},
          ) as any as SeveritiesObject;
          apiItemsToUpdate.push(apiItem);
        }
      }

      await this.mongoDBreport.updateAllApiItems(apiItemsToUpdate);
    } catch (e) {
      logger.error(`[setApiItemsSeverities] failed add severities to apiItems, e: ${e}`);
    }
  }

  private setAppCategories(appId: string) {
    try {
      const application = this.appToApplicationObject.get(appId);
      application.categories = [];
      const issues = this.appToIssuesMap.get(appId) || [];
      application.totalIssues = issues.length;

      for (const issue of issues) {
        let categoryItem = application.categories.find(i => i.id === issue.categoryId);
        const order =
          StatesHelper.Instance.enableCategories.filter(cat => !cat.hideCategory).findIndex(cat => cat.id === issue.categoryId) + 1;
        const oxCategory = StatesHelper.Instance.enableCategories.find(cat => cat.id === issue.categoryId);
        if (categoryItem == undefined) {
          let newCatItem: CategoryItem = {
            categoryName: oxCategory.displayName,
            order: order,
            severities: {
              [SeverityStr.info]: 0,
              [SeverityStr.low]: 0,
              [SeverityStr.medium]: 0,
              [SeverityStr.high]: 0,
              [SeverityStr.critical]: 0,
              [SeverityStr.appox]: 0,
            },
            score: 0,
            total: 0,
            id: issue.categoryId,
            catId: issue.categoryId,
            isNa: false,
            reason: [],
          };
          categoryItem = newCatItem;
          application.categories.push(newCatItem);
        }

        categoryItem.severities[severityConst[issue.severity]] = categoryItem.severities[severityConst[issue.severity]] + 1;
        categoryItem.score = categoryItem.score + SEVERITIES[issue.severity];
        if (isNaN(categoryItem.score) || categoryItem.score === null) {
          logger.error(`category error, issueId: ${issue.issueId} has severity: ${issue.severity}`);
          categoryItem.score = 0;
        }
        categoryItem.total = categoryItem.total + 1;
      }

      StatesHelper.Instance.enableCategories
        .filter(cat => !cat.hideCategory)
        .forEach((cat, index) => {
          const isCategoryExits = !!application.categories.find(c => c.id === cat.id);
          if (!isCategoryExits) {
            const isAllPoliciesDisabled = this.isAllPoliciesDisabled(cat);
            const reason = this.isOneConnectorEnabled(cat, isAllPoliciesDisabled);
            const isNa = reason.length > 0;

            const catItem: CategoryItem = {
              id: cat.id,
              catId: cat.id,
              categoryName: cat.displayName,
              order: index + 1,
              severities: {
                [SeverityStr.low]: 0,
                [SeverityStr.medium]: 0,
                [SeverityStr.high]: 0,
                [SeverityStr.critical]: 0,
                [SeverityStr.appox]: 0,
                [SeverityStr.info]: 0,
              },
              score: 0,
              total: 0,
              isNa,
              reason,
            };
            application.categories.push(catItem);
          }
        });

      application.categories = application.categories.sort((c1, c2) => c1.order - c2.order);
    } catch (e) {
      logger.error(`failed add app categories, e: ${e}`);
    }
  }

  /**
   *
   * @param appId application id
   * @description generate and setting application object from collector data
   */
  private generateApplication(appId: string) {
    try {
      const collectorData = this.appToCollectorData.get(appId);
      const app = this.appToAllPolicies.get(appId);
      const application: Application = {
        risk: 0,
        securityPosture: 0,
        businessPriority: collectorData.repoImportance.total,
        originalBusinessPriority: collectorData.repoImportance.originalBp || 0,
        violationCount: 0,
        commitCount: collectorData.repoImportance.res.numberOfcommits,
        codeChanges: collectorData.repoImportance.res.codeChanges,
        pushCount: collectorData.repoImportance.res.pushCount,
        pullCount: collectorData.repoImportance.res.pullCount,
        userCount: collectorData.repoImportance.res.num_of_unique_user_with_commits,
        lastCodeChange: collectorData.repoImportance.res.lastCodeChange
          ? new Date(collectorData.repoImportance.res.lastCodeChange)
          : new Date(),
        categories: [],
        appId: collectorData.id,
        new: false,
        updated: false,
        deployedProd: false,
        publicVisibility: collectorData.privateVisability === false,
        relevant: collectorData.repoImportance.res.irrelevantReasons.length === 0 ? true : false,
        createdAt: new Date(collectorData.createdAt) || new Date(),
        languages: collectorData.languages,
        version: collectorData.repoImportance.res.extendedInfo.version,
        watchersCount: collectorData.watchersCount,
        creator: collectorData.repoImportance.info.creator,
        hasDownloads: collectorData.repoImportance.res.extendedInfo.has_downloads,
        forksCount: collectorData.repoImportance.res.extendedInfo.forks_count,
        type: collectorData.type,
        size: collectorData.repoImportance.res.repo_size_bytes,
        branchesCount: collectorData.repoImportance.info.branches,
        tagsCount: collectorData.repoImportance.info.numberOfTags,
        branch: collectorData.repoImportance.info.mainBranch,
        headSha: collectorData.headSha,
        yamlsCount: collectorData.repoImportance.info.numberOfYMLs,
        filesCount: collectorData.repoImportance.info.numberOfFiles,
        overrideRelevance: collectorData.overrideRelevance,
        overridePriority: collectorData.overridePriority,
        applicationFlows: getAppFlow(app[0]),
        secInfra: this.initAppSecInfra(),
        policiesViolationsBySeverity: [],
        appName: collectorData.fullName,
        repoName: collectorData.name,
        dockerfiles: collectorData.dockerfiles,
        scannedAt: this.scanDate,
        irrelevantReasons: collectorData.repoImportance.res.irrelevantReasons,
        scanId: this.uuid,
        appOwners: collectorData.appOwners || [],
        fakeApp: !collectorData.realRepo,
        appCategory: collectorData.appCategory,
        parentType: collectorData.parentType,
        isOverridingPriority: collectorData.isOverridingPriority,
        link: collectorData.link,
        isMonoRepoChild: collectorData.parentRepoOfMonoRepo !== null,
        monoRepoParent: collectorData?.parentRepoOfMonoRepo != null ? collectorData.parentRepoOfMonoRepo.fullName : "",
        monorepoChildrenCount: collectorData?.monorepoChildrenCount,
        monorepoChildrenAppIds: collectorData?.monorepoChildrenAppIds ? [...collectorData?.monorepoChildrenAppIds] : [],
        totalIssues: 0,
        repoRealName: collectorData.repoRealName,
        // tools coverage mock
        toolsCoverage: collectorData.toolsCoverage,
        repoId: collectorData.repoId,
        isOrgRepo: collectorData.isOrgRepo,
        organization: collectorData.organization,
        pipeline: collectorData.pipeline,
        pkgManagers: collectorData.pkgManagers,
        tags: [],
        cloneDir: collectorData.cloneDir,
        codeZipDir: collectorData.codeZipDir,
        severityChangedReason: collectorData.severityChangedReason,
      };
      this.setAppTags(application);

      //Debugr
      //logger.debug(`generated appId: ${application.appId}, appName: ${application.appName}, appType: ${application.type}`);

      this.validateApplication(application);
      this.appToApplicationObject.set(appId, application);
    } catch (e) {
      logger.error(`failed generate application ${appId}, error: ${e}`);
    }
  }

  setRepoTags(severityChangedReason: ChangeReason[], repo: Repo) {
    try {
      if (!StatesHelper.Instance.isEKSEnabled) {
        return;
      }

      const appId = repo.id;
      const app = this.appToApplicationObject.get(appId);
      const { appTags, excludedTagsIds } = repo;

      for (const changeReason of severityChangedReason) {
        if (!changeReason.tagId) {
          continue;
        }
        const tag = getTagsMap()[changeReason.tagId];
        if (!tag) {
          logger.error(`missing ox pre define tag in add tag for tagId: ${changeReason.tagId}, repo: ${repo.fullName}`);
          continue;
        }
        let isExists = false;
        if (appTags) {
          isExists = appTags.some(i => i.tagId === tag.tagId);
        }
        if (isExists) {
          //Debug
          // logger.info(`tagId already exists by user config. tagId: ${tag.tagId}, repo: ${repo.fullName}`);
          continue;
        }
        app.tags.push({ ...tag, appliedBy: "support@ox.security" });
      }

      if (app.tags) {
        app.tags = app.tags.filter(i => !excludedTagsIds.includes(i.tagId));

        if (app.tags.find(i => i.tagId === severityReasons.internetdExposedAPI.tagId)) {
          app.tags = app.tags.filter(i => i.tagId !== severityReasons.internetExposedSystem.tagId);
        }

        if (appTags) {
          app.tags.push(...appTags);
          app.tags = _.uniqBy(app.tags, "tagId");
        }
      }
    } catch (err) {
      logger.error(`failed set all app tags, repo: ${repo.fullName}`);
    }
  }

  setAppTags(app: Application) {
    try {
      const repo = this.appToCollectorData.get(app.appId);
      if (!repo) {
        logger.error(`missing repo. appId: ${app.appId}`);
        return;
      }
      const { severityChangedReason } = app;
      const { appTags, excludedTagsIds } = repo;
      if (severityChangedReason) {
        for (const changeReason of severityChangedReason) {
          if (changeReason.requiredHits === undefined) {
            //Debug
            // logger.info(`severity change reason hits is undefined. se: ${changeReason.shortName}`);
          }
          if (changeReason.extraInfo.length >= changeReason.requiredHits) {
            if (changeReason.tagId) {
              const tag = getTagsMap()[changeReason.tagId];
              if (!tag) {
                logger.error(`missing ox pre define tag. tagId: ${changeReason.tagId}`);
                continue;
              }

              let isExists = false;
              if (appTags) {
                isExists = appTags.some(i => i.tagId === tag.tagId);
              }
              if (isExists) {
                logger.info(`tagId already exists by user config. tagId: ${tag.tagId}`);
                continue;
              }
              isExists = app.tags?.some(i => i.tagId === tag.tagId) || false;
              if (isExists) {
                logger.info(`tagId already exists by prev change reason. tagId: ${tag.tagId}`);
                continue;
              }
              if (!app.tags) {
                app.tags = [];
              }
              app.tags.push({ ...tag, appliedBy: "support@ox.security" });
            }
          }
        }
      }

      if (app.tags) {
        app.tags = app.tags.filter(i => !excludedTagsIds.includes(i.tagId));
        if (appTags) {
          app.tags.push(...appTags);
          app.tags = _.uniqBy(app.tags, "tagId");
        }
      }
    } catch (e) {
      logger.error(`failed to setAppTags. appId:${app.appId} error: ${e}`);
    }
  }

  private validateApplication(applicaiton: Application) {
    try {
      const date = applicaiton.createdAt.getTime();
      if (isNaN(date)) {
        applicaiton.createdAt = new Date();
      }
    } catch (e) {
      logger.error(`failed to validate application, error: ${e}`);
    }
  }

  /**
   *
   * @param appId application id
   * @description set the application risk score based on its related issues
   */
  private setApplicaitonScores(appId: string) {
    try {
      const applicaiton = this.appToApplicationObject.get(appId);
      applicaiton.risk = 0;
      applicaiton.securityPosture = 0;
      this.setAppCategories(appId);
    } catch (e) {
      logger.error(`failed to set application scores, app: ${appId}, error: ${e}`);
    }
  }
  /**
   * @description update the scan info during scan for gradual updates
   */
  updateScanInfo(isDone: boolean = false) {
    try {
      this.setScanStats(isDone);
      this.setOrgScore();
      this.setAlerts();
      this.setScannedApps();
      this.setIsDone(isDone);
      this.updateToolsCountOutput();
      this.disableCancelScan();
    } catch (e) {
      logger.error(`failed to update scan info, error: ${e}`);
    }
  }

  async updateScanInfoStateWithDBupdate() {
    if (StatesHelper.Instance.isPipelineScan) {
      return;
    }

    this.setScanStats(false);
    await this.mongoDBreport.updateScanInfo(this.scanInfo);
  }

  private setScanStats(isDone: boolean = false) {
    try {
      this.scanInfo.appsRelevant = this?.relevantApps?.size;
      this.scanInfo.appsNotRelevant = this?.irrelevantApps?.size;
      this.scanInfo.appsTotal = this.totalApps;
      this.scanInfo.scanType = StatesHelper.Instance.scanType;
      this.scanInfo.scanStartDate = StatesHelper.Instance.scanStartDate;
      this.scanInfo.scanFinishDate = StatesHelper.Instance.scanFinishDate = new Date();

      if (StatesHelper.Instance.isFinalizing) {
        this.scanInfo.progressType = "finalizing";
      }
      if (StatesHelper.Instance.isAttachResources && !StatesHelper.Instance.isFinalizing) {
        this.scanInfo.progressType = "connectDataSources";
      }
      if (!this.scanInfo.scanProgressItems) {
        this.scanInfo.scanProgressItems = [];
      }
      //Repo
      if (this.scanInfo.appsTotal > 0) {
        let itemRepo = this.scanInfo.scanProgressItems.find(i => i.phase === "repo");
        if (!itemRepo) {
          itemRepo = new ScanProgress();
          itemRepo.phase = "repo";
          itemRepo.order = 1;
          this.scanInfo.scanProgressItems.push(itemRepo);
        }
        itemRepo.total = this.scanInfo.appsTotal;

        let appsRelevant = 0;
        let appsNoneRelevant = 0;
        if (this.scanInfo.appsRelevant != undefined) {
          appsRelevant = this.scanInfo.appsRelevant;
        }
        if (this.scanInfo.appsNotRelevant != undefined) {
          appsNoneRelevant = this.scanInfo.appsNotRelevant;
        }
        itemRepo.count = appsNoneRelevant + appsRelevant;
      }
      //Image
      if (StatesHelper.Instance.scanInfoStats.totalImages > 0) {
        let itemArtifact = this.scanInfo.scanProgressItems.find(i => i.phase === "artifact");
        if (!itemArtifact) {
          itemArtifact = new ScanProgress();
          itemArtifact.phase = "artifact";
          itemArtifact.order = 2;
          this.scanInfo.scanProgressItems.push(itemArtifact);
        }
        itemArtifact.count = StatesHelper.Instance.artifactScanCountProgress;
        itemArtifact.total = StatesHelper.Instance.scanInfoStats.totalImages;
      }
      //Cloud
      if (StatesHelper.Instance.cloudScanTotalCount > 0) {
        let itemCloud = this.scanInfo.scanProgressItems.find(i => i.phase === "cloud");
        if (!itemCloud) {
          itemCloud = new ScanProgress();
          itemCloud.phase = "cloud";
          itemCloud.order = 3;
          this.scanInfo.scanProgressItems.push(itemCloud);
        }
        itemCloud.count = StatesHelper.Instance.cloudScanCountProgress;
        itemCloud.total = StatesHelper.Instance.cloudScanTotalCount;
      }
      if (StatesHelper.Instance.externalToolsApisRunningTotal > 0) {
        let externalTools = this.scanInfo.scanProgressItems.find(i => i.phase === "externalTools");
        if (!externalTools) {
          externalTools = new ScanProgress();
          externalTools.phase = "externalTools";
          externalTools.order = 4;
          this.scanInfo.scanProgressItems.push(externalTools);
        }
        externalTools.count = StatesHelper.Instance.externalToolsApisRunningProgress;
        externalTools.total = StatesHelper.Instance.externalToolsApisRunningTotal;
      }

      this.scanInfo.scanProgressItems = this.scanInfo.scanProgressItems.sort((a, b) => a.order - b.order);

      if (isDone) {
        this.scanInfo.policyPerCatStats = JSON.stringify(StatesHelper.Instance.policyPerCatStats);
      }

      if (StatesHelper.Instance.scanInfoStats.artifactAndParserExecution > 0) {
        StatesHelper.Instance.scanInfoStats.artifactAndParserExecution = Math.floor(
          StatesHelper.Instance.scanInfoStats.artifactAndParserExecution / 60,
        );
      }

      const maxSize = 3;
      if (StatesHelper.Instance.scanInfoStats.failedBlameRepoNames.length > maxSize) {
        StatesHelper.Instance.scanInfoStats.failedBlameRepoNames = StatesHelper.Instance.scanInfoStats.failedBlameRepoNames.slice(
          0,
          maxSize,
        );
      }
      if (StatesHelper.Instance.scanInfoStats.failedClonesRepoNames.length > maxSize) {
        StatesHelper.Instance.scanInfoStats.failedClonesRepoNames = StatesHelper.Instance.scanInfoStats.failedClonesRepoNames.slice(
          0,
          maxSize,
        );
      }
      if (StatesHelper.Instance.scanInfoStats.failedSecretRepoNames.length > maxSize) {
        StatesHelper.Instance.scanInfoStats.failedSecretRepoNames = StatesHelper.Instance.scanInfoStats.failedSecretRepoNames.slice(
          0,
          maxSize,
        );
      }
      if (StatesHelper.Instance.scanInfoStats.failedAutoFixRepoNames.length > maxSize) {
        StatesHelper.Instance.scanInfoStats.failedAutoFixRepoNames = StatesHelper.Instance.scanInfoStats.failedAutoFixRepoNames.slice(
          0,
          maxSize,
        );
      }
      if (StatesHelper.Instance.scanInfoStats.timeoutOpenSourceRepoNames.length > maxSize) {
        StatesHelper.Instance.scanInfoStats.timeoutOpenSourceRepoNames =
          StatesHelper.Instance.scanInfoStats.timeoutOpenSourceRepoNames.slice(0, maxSize);
      }
      if (StatesHelper.Instance.scanInfoStats.timeoutClonesRepoNames.length > maxSize) {
        StatesHelper.Instance.scanInfoStats.timeoutClonesRepoNames = StatesHelper.Instance.scanInfoStats.timeoutClonesRepoNames.slice(
          0,
          maxSize,
        );
      }
      if (StatesHelper.Instance.scanInfoStats.failedBlameTimeoutRepoNames.length > maxSize) {
        StatesHelper.Instance.scanInfoStats.failedBlameTimeoutRepoNames =
          StatesHelper.Instance.scanInfoStats.failedBlameTimeoutRepoNames.slice(0, maxSize);
      }
      if (StatesHelper.Instance.scanInfoStats.failedSecretTimeoutRepoNames.length > maxSize) {
        StatesHelper.Instance.scanInfoStats.failedSecretTimeoutRepoNames =
          StatesHelper.Instance.scanInfoStats.failedSecretTimeoutRepoNames.slice(0, maxSize);
      }
      if (StatesHelper.Instance.scanInfoStats.failedAutoFixTimeoutRepoNames.length > maxSize) {
        StatesHelper.Instance.scanInfoStats.failedAutoFixTimeoutRepoNames =
          StatesHelper.Instance.scanInfoStats.failedAutoFixTimeoutRepoNames.slice(0, maxSize);
      }
      if (StatesHelper.Instance.scanInfoStats.failedDependencyGraphBatchesNames.length > maxSize) {
        StatesHelper.Instance.scanInfoStats.failedDependencyGraphBatchesNames =
          StatesHelper.Instance.scanInfoStats.failedDependencyGraphBatchesNames.slice(0, maxSize);
      }
      if (StatesHelper.Instance.scanInfoStats.failedDependencyGraphTimeoutRepoNames.length > maxSize) {
        StatesHelper.Instance.scanInfoStats.failedDependencyGraphTimeoutRepoNames =
          StatesHelper.Instance.scanInfoStats.failedDependencyGraphTimeoutRepoNames.slice(0, maxSize);
      }

      StatesHelper.Instance.scanInfoStats.scanId = this.uuid;
      StatesHelper.Instance.scanInfoStats.setCategories(this.duplicateIssues);
      const res = this.removeNotUsedFields(StatesHelper.Instance.scanInfoStats);
      this.scanInfo.scanInfoStats = JSON.stringify(res);
    } catch (e) {
      logger.error(`setScanStats failed to update scan stats, err: ${e}`);
    }
    return {};
  }

  private removeNotUsedFields(fields) {
    try {
      const jsStr = JSON.stringify(fields);
      const js = JSON.parse(jsStr);
      const newJs = {};
      for (const [e, entry] of Object.entries(js)) {
        if (Array.isArray(entry)) {
          if (entry.length == 0) {
            continue;
          }
        }
        if (!isNaN(entry as any)) {
          if (entry == 0) {
            continue;
          }
        }
        newJs[e] = entry;
      }
      return newJs;
    } catch (err) {
      logger.error(`removeNotUsedFields, err: ${err}`);
    }
    return {};
  }

  private disableCancelScan() {
    try {
      if (this.scanInfo.scannedApps > this.totalApps / 2) {
        this.scanInfo.cancelScan = false;
      }
    } catch (e) {
      logger.error(`failed to disable cancel scan, error: ${e}`);
    }
  }

  private setIsDone(isDone: boolean) {
    this.scanInfo.isDone = isDone;
  }

  /**
   * @description update the scan info object with tools count
   */
  private updateToolsCountOutput() {
    try {
      const allInfraCount = this.collectors.filter(i => !i.token.isTool).length;
      const allToolsCount = this.clientToolsCount.size + this.oxToolsCount.size;

      this.scanInfo.systemsLine1 = `${allInfraCount + allToolsCount} systems discovered: ${allInfraCount} infrastructure / ${
        this.clientToolsCount.size
      } security tools`;
      this.scanInfo.systemsLine2 = `${this.oxToolsCount.size} additional security tools added by OX`;
    } catch (e) {
      logger.error(`failed on updateToolsCountOutput error: ${e}`);
    }
  }
  /**
   * @description set the alerts for the scan info object
   */
  private setAlerts() {
    try {
      this.initScanInfoSeverityAlerts();
      const applicaitons = this.getApplications();
      for (const applicaiton of applicaitons) {
        const { appId } = applicaiton;
        if (!this.isReleventApp(appId)) {
          continue;
        }
        const issues = this.appToIssuesMap.get(appId);
        issues.forEach(issue => this.addIssueToSeverity(issue));
      }
    } catch (e) {
      logger.error(`failed to set alerts, error: ${e}`);
    }
  }

  private addIssueToSeverity(issue: Issue) {
    try {
      const severitiesAlerts = this.scanInfo.severitiesAlerts;
      const sevObj = severitiesAlerts.find(i => i.severity === issue.severity);
      sevObj.alerts++;
    } catch (e) {
      logger.error(
        `failed to add issue to severity, error: ${e}, severity: ${issue.severity}, app name: ${issue.appName}, main title: ${issue.mainTitle}`,
      );
    }
  }

  // Init Scan info details
  private initScanInfo() {
    let scanInfo: ScanInfo;

    try {
      scanInfo = {
        scanDate: this.scanDate,
        scanId: this.uuid,
        appsTotal: this.totalApps,
        scanProgressItems: [],
        progressType: "",
        isScheduledScan: this.isScheduledScan,
        policyCount: this.rulesParser.getRules().length,
        systemsLine1: `0 systems discovered: 0 infrastructure / 0 security tools`,
        systemsLine2: `0 additional security tools added by OX`,
        policiesLine1: `${this.enabledPolicies.length} policy rules created & tuned to your org`,
        policiesLine2: `${this.disabledPolicies.length} additional policy rules can be enabled`,
        score: 0,
        appsNotRelevant: 0,
        appsRelevant: 0,
        severitiesAlerts: [],
        error: "",
        successfulScan: false,
        scannedApps: 0,
        isDone: false,
        cancelScan: true,
        // scanType value arrives from connector msg, on local we will not have a msg.
        scanType: null,
        scanStartDate: this.scanDate,
        scanFinishDate: null,
        scanInfoStats: "",
        policyPerCatStats: "",
      };
      return scanInfo;
    } catch (e) {
      logger.error(`failed to init scan info, error: ${e}`);
    }
    return scanInfo;
  }
  /**
   *
   * @param flows final flows from all external sources
   * @description this functions handles all extra calculation needed at the end of a scan
   */
  async setDone() {
    try {
      logger.info(`at set done`);

      // update applications flows
      this.updateAppliationsFlows();

      this.setDiscoverdSystems();

      // update applications buisness priority
      this.updateApplicaitonsBp();

      // update applications issues scores since we updated applications bps
      this.updateApplicationsIssuesSeverity();
      this.updateApplicationsSeverity();

      await this.setApiItemsSeverities();

      //Remove all not needed issues
      const issuesToRemove: Issue[] = this.removeAllExcludedIssues();

      await this.removeIssuesById(issuesToRemove);

      this.initHistoryApplications();

      this.updateScanInfo(true);

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "before saveToMongoOnSetDone");
      await this.saveToMongoOnSetDone();

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "before saveUniqueIssues");
      await this.saveUniqueIssues();

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "before compareResultsFromLastScan");
      await this.compareResultsFromLastScan();

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "before detachedTickets");
      await TicketService.Instance.detachedTickets(this.orgName, this.detachedTickets);

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "before resetOxTags");
      const oxAppsTags = this.createOxAppsTags();
      await TagsService.Instance.resetOxTags(this.orgName, oxAppsTags);

      //Send notification for workflow service to start working and wait for it to finish
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "before handleWorkflow");
      await this.handleWorkflow();

      logger.info(`finish set done`);
    } catch (e) {
      logger.error(`failed to set done , error: ${e}`);
    }
  }

  async setPostDone() {
    try {
      const shouldRun = isDevelopment() || isLocalDevelopment();
      if (!shouldRun) {
        return;
      }

      logger.info(`try setPostDone`);
      await this.setHistoryIssueData(this.totalIssues);
      logger.info(`finish setPostDone`);
    } catch (err) {
      logger.error(`failed setPostDone , error: ${err}`);
    }
  }

  async compareResultsFromLastScan() {
    //TODO dvir
    return;
  }

  private createOxAppsTags() {
    const map: Map<string, string[]> = new Map();
    for (const app of this.getApplications()) {
      const oxTags = app.tags.filter(i => i.isOxTag && i.appliedBy === "support@ox.security");
      for (const oxTag of oxTags) {
        const arr = map.get(oxTag.tagId);
        if (!arr) {
          map.set(oxTag.tagId, [app.appId]);
        } else {
          arr.push(app.appId);
        }
      }
    }
    return map;
  }

  private async handleWorkflow() {
    try {
      logger.info(`[ResultsHandler] try set workflows`);
      await this.workflowHelper.setWorkflowInfo();
      logger.info(`[ResultsHandler] finish set workflows`);
    } catch (err) {
      logger.error(`[ResultsHandler] failed handle workflow for all apps, error: ${err}`);
      StatesHelper.Instance.scanInfoStats.failedHandleWorkflowApps = 999;
    }
  }

  private async removeIssuesById(issuesToRemove: Issue[]) {
    try {
      logger.info(`issuesToRemove: ${issuesToRemove.length}`);
      const proms = issuesToRemove.map(issue => {
        this.mongoDBreport.removeIssueById(issue);
      });
      await Promise.all(proms);
    } catch (err) {}
  }

  private removeAllExcludedIssues() {
    const issuesToRemove: Issue[] = [];
    try {
      const allApps = this.getApplications();
      for (const app of allApps) {
        try {
          const relevantIssues: Issue[] = [];
          const appIssues: Issue[] = this.appToIssuesMap.get(app.appId);
          for (const singleIssue of appIssues) {
            try {
              //Remove issues in this cases
              if (singleIssue.needToBeRemoved) {
                issuesToRemove.push(singleIssue);
                continue;
              }
              relevantIssues.push(singleIssue);
            } catch (err) {
              logger.error(`failed remove single app issue: ${app.appName}, issue: ${singleIssue.issueId} error: ${err}`);
              StatesHelper.Instance.scanInfoStats.failedSetNewSeverity++;
            }
          }
          //Set new issues
          this.appToIssuesMap.set(app.appId, relevantIssues);
        } catch (err) {
          logger.error(`failed remove single app issues: ${app.appName}, error: ${err}`);
          StatesHelper.Instance.scanInfoStats.failedSetNewSeverity++;
        }
      }
    } catch (err) {
      logger.error(`failed remove single all apps issues, error: ${err}`);
      StatesHelper.Instance.scanInfoStats.failedSetNewSeverity++;
    }
    this.updateApplicationsSeverities(issuesToRemove);
    return issuesToRemove;
  }

  updateApplicationsSeverities(issuesToRemove: Issue[]) {
    try {
      issuesToRemove.forEach(i => {
        this.scanSummery.reduceFromTotalIssues(i.severity);
        this.scanSummery.reduceFromAppSeverities(i.appId, i.severity);
        const { appId } = i;
        const app = this.appToApplicationObject.get(appId);
        app.totalIssues--;
        const cat = app.categories.find(c => c.catId === i.categoryId);
        cat.total--;
        cat.severities[severityConst[i.severity]]--;
      });
    } catch (e) {
      logger.error(`failed to updateApplicationsSeverities, error: ${e}`);
    }
  }

  private async saveUniqueIssues() {
    try {
      logger.info(`try get done saving to mongo unique issues`);

      const allRelevantAppsIssues = this.getAllRelevantIssues();
      const chunks = splitToChunks(allRelevantAppsIssues, 2000);

      logger.info(`try set done saving to mongo unique issues: ${allRelevantAppsIssues.length}, chunks: ${chunks.length}`);

      let index = 0;
      for (const chunk of chunks) {
        index++;
        logger.info(`try set done saving to mongo unique issues, chunk: ${index}, chunk size: ${chunk.length}`);
        await this.mongoDBreport.addUniqueIssues(chunk);
      }

      logger.info(`finish set done saving to mongo unique issues: ${allRelevantAppsIssues.length}, chunks: ${chunks.length}`);
    } catch (e) {
      logger.error(`failed save unique issues, error: ${e}`);
    }
  }

  private getAllRelevantIssues() {
    let allIssues: Issue[] = [];
    try {
      const allAppsIssues = this.getApplications()
        .filter(app => app.relevant)
        .map(app => this.appToIssuesMap.get(app.appId));
      allAppsIssues.forEach(appIssues => {
        allIssues = allIssues.concat(appIssues);
      });
    } catch (e) {
      logger.error(`failed getting all apps issues`);
      return [];
    }
    return allIssues;
  }

  /**
   * @description init the history applications to be saved in mongo at the end of the scan
   */
  private initHistoryApplications() {
    try {
      const applicaitons = this.getApplications();
      const historyApplications = applicaitons.map(app => this.generateAppHistoryScore(app));

      this.historyApplications = this.historyApplications.concat(historyApplications);
    } catch (e) {
      logger.error(`failed save app history, error: ${e}`);
    }
  }

  /**
   *
   * @param appId the id of the current application
   * updating the relevant/irrelevant apps sets
   */
  private updateRelvantIrrelvantApps(appId: string) {
    try {
      const app = this.appToApplicationObject.get(appId);
      app.relevant ? this.relevantApps.add(appId) : this.irrelevantApps.add(appId);
    } catch (e) {
      logger.error(`failed to update relevant/irrelevant apps, app: ${appId}, error: ${e} `);
    }
  }
  /**
   * set the org score during the scan- gradual update
   */
  private setOrgScore() {
    try {
      const applicaitons = Array.from(this.appToApplicationObject.values());
      let numerator = 0,
        denominator = 0;
      for (const applicaiton of applicaitons) {
        if (!applicaiton.relevant) {
          continue;
        }
        const normalizedAppBp = this.getNormalizedAppBp(applicaiton);
        const appScore = normalizedAppBp * applicaiton.risk;
        numerator += appScore;
        denominator += normalizedAppBp;
      }
      const orgScore = numerator / denominator;
      if (isNaN(orgScore)) {
        this.scanInfo.score = 0;
      } else {
        this.scanInfo.score = orgScore;
      }
    } catch (e) {
      logger.error(`failed to set org score, error: ${e}`);
    }
  }

  private getNormalizedAppBp(app: Application) {
    try {
      return app.businessPriority / 100;
    } catch (e) {
      logger.error(`faield to normilize app bp, error: ${e}`);
    }
    return 0;
  }

  private initScanInfoSeverityAlerts() {
    try {
      this.scanInfo.severitiesAlerts = [
        {
          severity: Severity.INFO,
          alerts: 0,
        },
        {
          severity: Severity.LOW,
          alerts: 0,
        },
        {
          severity: Severity.MEDIUM,
          alerts: 0,
        },
        {
          severity: Severity.HIGH,
          alerts: 0,
        },
        {
          severity: Severity.CRITICAL,
          alerts: 0,
        },
        {
          severity: Severity.APPOXALYPSE,
          alerts: 0,
        },
      ];
    } catch (e) {
      logger.error(`faield init scan info sevirities aletrs`);
    }
  }
  private initDiscoverySystems() {
    try {
      const systems = Object.values(SystemEnum).map(s => {
        const system: DiscoverySystem = {
          type: s,
          systems: [],
          scanId: this.uuid,
        };
        return system;
      });
      this.discoverySystems = systems;
    } catch (e) {
      logger.error(`failed init discovery systems, error: ${e}`);
    }
  }

  private generateAppHistoryScore(app: Application) {
    try {
      const apphistoryScore: AppHistoryScore = {
        score: app.risk,
        date: this.scanDate,
        appId: app.appId,
        appName: app.appName,
        businessPriority: app.businessPriority,
        new: app.new,
        updated: app.updated,
        deployedProd: app.deployedProd,
        publicVisibility: app.publicVisibility,
        relevant: app.relevant,
        isScheduledScan: this.isScheduledScan,
        createdAt: app.createdAt,
        lastCodeChange: app.lastCodeChange,
        daysSinceLastCodeChange: app.daysSinceLastCodeChange,
        daysSinceRepoCreation: app.daysSinceRepoCreation,
        scanId: this.uuid,
        fakeApp: app.fakeApp,
        appCategory: app.appCategory,
        parentType: app.parentType,
      };
      return apphistoryScore;
    } catch (e) {
      logger.error(`faield to generate app history score, app: ${app.appId}, error: ${e}`);
    }
  }
  private setAppSecInfraData(appId: string) {
    try {
      const appData = this.appToCollectorData.get(appId);
      const appCloud = this.appToAllPolicies.get(appId)[0].cloud;
      const application = this.appToApplicationObject.get(appId);

      const sast = this.getSecInfraObj(application, SecInfra.SAST);
      const sca = this.getSecInfraObj(application, SecInfra.SCA);
      const iac = this.getSecInfraObj(application, SecInfra.IAC);
      const cspm = this.getSecInfraObj(application, SecInfra.CSPM);
      const secretSearch = this.getSecInfraObj(application, SecInfra.SECRET_SEARCH);

      if (application.fakeApp) {
        sast.na = 1;
        sca.na = 1;
        iac.na = 1;
        secretSearch.na = 1;
        cspm.na = 1;
        return;
      }

      // sast
      if (appData.secInfra.sast.sast.byOx) {
        sast.byOx = 1;
      }

      if (appData.secInfra.sast.sast.byClient) {
        sast.byClient = 1;
      }

      if (appData.secInfra.sast.sast.nc) {
        sast.nc = 1;
      }

      if (appData.secInfra.sast.sast.na) {
        sast.na = 1;
      }

      // sca
      if (appData.secInfra.sca.sca.byOx) {
        sca.byOx = 1;
      }

      if (appData.secInfra.sca.sca.byClient) {
        sca.byClient = 1;
      }

      if (appData.secInfra.sca.sca.nc) {
        sca.nc = 1;
      }

      if (appData.secInfra.sca.sca.na) {
        sca.na = 1;
      }

      // iac
      if (appData.secInfra.iac.byOx) {
        iac.byOx = 1;
      }

      if (appData.secInfra.iac.byClient) {
        iac.byClient = 1;
      }

      if (appData.secInfra.iac.nc) {
        iac.nc = 1;
      }

      if (appData.secInfra.iac.na) {
        iac.na = 1;
      }

      //cspm
      if (appCloud != null && appData.oxSecurityTools.oxCspmTools.length) {
        cspm.byOx = 1;
      }

      if (appCloud != null && appData.cspm.length) {
        cspm.byClient = 1;
      }

      if (appCloud != null && !appData.oxSecurityTools.oxCspmTools.length && !appData.cspm.length) {
        cspm.nc = 1;
      }

      if (appCloud == null) {
        cspm.na = 1;
      }

      // secrets
      if (appData.oxSecurityTools.oxSecretsTools.length) {
        secretSearch.byOx = 1;
      }

      if (appData.secrets.length) {
        secretSearch.byClient = 1;
      }

      if (!appData.oxSecurityTools.oxSecretsTools.length && !appData.secrets.length) {
        secretSearch.nc = 1;
      }
    } catch (e) {
      logger.error(`failed on function setAppSecInfraData for overview json error: ${e}`);
    }
  }
  private initAppSecInfra() {
    const categorisMap = getCategoriesMap();
    const res: SecInfrastructure[] = [
      {
        id: getCategoryByName("Code Security").id,
        categoryName: getCategoryByName("Code Security").displayName,
        label: SecInfra.SAST,
        order: 2,
        byOx: 0,
        byClient: 0,
        nc: 0,
        na: 0,
      },
      {
        id: getCategoryByName("Open Source Security").id,
        categoryName: getCategoryByName("Open Source Security").displayName,
        label: SecInfra.SCA,
        order: 3,
        byOx: 0,
        byClient: 0,
        nc: 0,
        na: 0,
      },
      {
        id: getCategoryByName("Infrastructure as Code Scan").id,
        categoryName: getCategoryByName("Infrastructure as Code Scan").displayName,
        label: SecInfra.IAC,
        order: 4,
        byOx: 0,
        byClient: 0,
        nc: 0,
        na: 0,
      },
      {
        id: getCategoryByName("Secret/PII Scan").id,
        categoryName: getCategoryByName("Secret/PII Scan").displayName,
        label: SecInfra.SECRET_SEARCH,
        order: 1,
        byOx: 0,
        byClient: 0,
        nc: 0,
        na: 0,
      },
      {
        id: getCategoryByName("Cloud Security").id,
        categoryName: getCategoryByName("Cloud Security").displayName,
        label: SecInfra.CSPM,
        order: 6,
        byOx: 0,
        byClient: 0,
        nc: 0,
        na: 0,
      },
    ];
    return res;
  }

  private getSecInfraObj(app: Application, label: SecInfra) {
    try {
      const res = app.secInfra.find(i => i.label === label);
      if (res == undefined) {
        return null;
      }
      return res;
    } catch (e) {
      logger.error(`failed on function getSecInfraObj for overview json error: ${e}`);
    }
  }
  /**
   * update the issues score at the end of the scan after we recalculated the applications BPs
   */
  private updateApplicationsIssuesSeverity() {
    try {
      if (this.bpInfo.max > 0 && !this.bpInfo.setOnce) {
        this.bpInfo.setOnce = true;
        this.bpInfo.multiplayerFactor = this.bpInfo.maxFactor / this.bpInfo.max;
        logger.info(`business priority :${this.bpInfo.multiplayerFactor}`);
      }

      const allApplications = this.getApplications();
      allApplications.filter(app => this.isReleventApp(app.appId)).forEach(app => this.updateSingleAppIssuesSeverity(app));
    } catch (e) {
      logger.error(`failed update all applications issues severity, error: ${e}`);
    }
  }

  private updateSingleAppIssuesSeverity(app: Application) {
    try {
      if (!app.isOverridingPriority) {
        if (app.overrideRelevance && app.businessPriority === 0) {
          app.businessPriority = 1;
        }

        if (this.bpInfo.max > 0) {
          const newBp = app.businessPriority * this.bpInfo.multiplayerFactor;
          app.businessPriority = newBp >= 100 ? 100 : newBp;
          app.originalBusinessPriority = app.businessPriority;
        }
      }

      const appIssues: Issue[] = this.appToIssuesMap.get(app.appId);
      const { businessPriority } = app;
      if (businessPriority <= 0) {
        return;
      }

      appIssues.forEach(issue => {
        issue.appConScore = 100; //romanzit
        issue.appBp = businessPriority;
        setNewIssueSeverityBasedOnBP(issue, app, this.rulesParser, this.scanSummery);
      });

      this.totalIssues = [...this.totalIssues, ...appIssues];
    } catch (e) {
      logger.error(`faield update single app issues scores, app: ${app.appId}, error: ${e}`);
    }
  }

  private async saveToMongoOnSetDone() {
    try {
      logger.info(`try set done saving to mongo on set done`);

      if (!this.keepUpdating) {
        return false;
      }

      await this.mongoDBreport.updateSystems(this.discoverySystems);
      await this.mongoDBreport.updateAllIssues(this.totalIssues);
      await this.mongoDBreport.updateScanInfo(this.scanInfo);
      await this.mongoDBreport.updateScanSummery(this.scanSummery);
      await this.mongoDBreport.updateAllApplications(this.getApplications());
      await this.mongoDBreport.addAppsHistoryScores(this.historyApplications);

      logger.info(`finish set done saving to mongo on set done`);

      return true;
    } catch (e) {
      logger.error(`failed set done, error: ${e}`);
    }
    return false;
  }

  private isReleventApp(appId: string) {
    try {
      return this.relevantApps.has(appId);
    } catch (e) {
      logger.error(`faield at isRelevantApp, error: ${e}`);
    }
    return false;
  }

  setImportance(appId: string, importanceCalc: any) {
    try {
      const collectorData = this.appToCollectorData.get(appId);
      collectorData.repoImportance = importanceCalc;
    } catch (e) {
      logger.error(`failed to recalculate repo importance with extra resources, appId: ${appId}`, e);
    }
  }

  private updateApplicaitonsBp() {
    try {
      const allApplications = this.getApplications();
      allApplications.forEach(application => {
        try {
          const { appId } = application;
          const bp = this.appToCollectorData.get(appId).repoImportance.total;
          if (!bp || application.fakeApp) {
            return;
          }
          logger.info(`updated bp for repo: ${application.appName} to ${bp}`);
          application.businessPriority = bp;
          application.originalBusinessPriority = this.appToCollectorData.get(appId).repoImportance.originalBp || 0;
          //Max bp that smaller then 97
          if (this.bpInfo.max < bp && this.bpInfo.maxFactor > bp) {
            this.bpInfo.max = bp;
          }
        } catch (err) {
          logger.error(`faield to update single appliations bp, app: ${application.appName}, error: ${err}`);
        }
      });
    } catch (e) {
      logger.error(`faield to update all appliations bp, error: ${e}`);
    }
  }

  private updateAppliationsFlows() {
    try {
      const allApplications = this.getApplications();
      allApplications.forEach(application => {
        const app = this.appToAllPolicies.get(application.appId);
        if (!app) {
          logger.info("No app unchanged app");
          return;
        }

        application.applicationFlows = getAppFlow(app[0]);
      });
    } catch (e) {
      logger.error(`failed to update applications flows, error: ${e}`);
    }
  }

  private updateApplicationsSeverity() {
    try {
      const applicationsIds = Array.from(this.relevantApps);
      applicationsIds.forEach(appId => this.setApplicaitonScores(appId));
    } catch (e) {
      logger.error(`failed to update applicaiton scores`);
    }
  }

  private getApplications() {
    return Array.from(this.appToApplicationObject.values());
  }

  async handleUnattachedEvents(evalRepoRes: EvalRepoPolicyRes[]) {
    try {
      await this.handleNewEvalRepoRes(evalRepoRes);
    } catch (e) {
      logger.error(`failed to handle unattached events, error: ${e}`);
    }
  }

  private getViolationAppData(violation: EvalRepoPolicyRes) {
    try {
      const issueAppData: IssueAppData = {
        policyId: violation.policyRes.policy_id,
        pName: violation.policyRes.name,
        severity: violation.policyRes.severity,
        appName: violation.collectorData.fullName,
        appId: violation.collectorData.id,
        appType: violation.collectorData.type,
        connector: violation.collectorData.type,
        originBranchName: violation.collectorData.repoImportance.info.mainBranch,
        exclusionCategory: violation.policyRes.exclusionCategory,
        appBp: violation.collectorData.repoImportance.total,
        categoryId: violation.policyRes.categoryId,
        sourceBranch: violation.collectorData.pipelineScanInfo?.sourceBranch,
        targetBranch: violation.collectorData.pipelineScanInfo?.targetBranch,
        repoId: violation.collectorData.repoId,
        repoRealName: violation.collectorData.repoRealName,
        organization: violation.collectorData.organization,
      };
      return issueAppData;
    } catch (e) {
      logger.error(`failed set issue app data, error:${e}`);
    }
    return null;
  }

  setTotalApps(totalApps: number) {
    this.totalApps = totalApps;
  }

  getTotalApps() {
    return this.totalApps;
  }

  /**
   * @description counts the tools by ox and by client
   */
  toolsCounter(appId) {
    const appData = this.appToCollectorData.get(appId);

    if (!appData) {
      logger.info("No appData unchanged app");
      return;
    }

    if (!appData.realRepo) {
      return;
    }

    try {
      const clientTools = [...appData.sast, ...appData.sca, ...appData.iac, ...appData.secrets, ...appData.cspm];
      const oxTools = Object.values(appData.oxSecurityTools).flat();

      for (const tool of oxTools as any[]) {
        this.oxToolsCount.add(tool.name.toLowerCase());
      }

      for (const tool of clientTools) {
        if (!this.oxToolsCount.has(tool.toLowerCase())) {
          this.clientToolsCount.add(tool.toLowerCase());
        }
      }
    } catch (err) {
      logger.error(`toolsCounter error, app:${appId},  ${err}`);
    }
  }

  private setScannedApps() {
    try {
      this.scanInfo.scannedApps = this.getApplications().length;
    } catch (e) {
      logger.error(`failed set scanned apps, error: ${e}`);
    }
  }

  async onCancelScan() {
    try {
      this.keepUpdating = false;
      logger.info(`Reverting scan upon cancel`);

      this.mongoDBreport.disableModels();
      await this.revertScanQueue.init();
      await this.revertScanQueue.sendQueueMessage({
        url: process.env.SCAN_REVERT_QUEUE,
        msg: { jobId: ulid().toLowerCase(), orgId: this.orgName, scanId: this.uuid, retries: 3 },
      });
    } catch (e) {
      const errInfo = `failed to on cancel scan, error: ${e}`;
      logger.error(errInfo);
    }
    return false;
  }

  async markSuccessfulScan() {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }
      this.scanInfo.successfulScan = true;
      await this.mongoDBreport.updateScanInfo(this.scanInfo);
      logger.info(`Marked successfull scan`);
    } catch (e) {
      logger.error(`failed to mark successfull scan, error: ${e}`);
    }
  }

  async onScanFinished() {
    try {
      await this.sbomService.removeOldSboms();
      const res = await this.mongoDBreport.removeOldScanData();
      await CveToolsService.instance.saveMapToDb();

      logger.info(`scan finish. is managed to delete old scans data: ${res}`);
      return res;
    } catch (e) {
      logger.error(`failed to on scan finished, error: ${e}`);
    }
    return false;
  }

  async initApplicationsFromDB() {
    try {
      logger.info(`init application from db`);
      const mongoDBapplicationsConfigurations = new MongoDBapplicationsConfigurations(this.uuid, this.orgName, this.mongoConnect);
      const res = await mongoDBapplicationsConfigurations.getApplicationsFromDB();
      this.applicationsFromDB = res;
    } catch (e) {
      logger.error(`failed get applications from DB ${e}`);
    }
  }

  getAppOwners(appId: string) {
    try {
      if (appId === "") {
        return [];
      }

      const app = this.applicationsFromDB.find(app => app.appId === appId);
      if (app) {
        return app.appOwners;
      }
    } catch (e) {
      logger.error(`failed to get app owners, error: ${e}`);
    }
    return [];
  }

  async setSbom(appId: string, sbom: Sbom, type: AppSbomType, imageDetailOrRepo: ImageDetail | Repo) {
    try {
      const result = await this.mongoDBreport.setSbom(appId, this.uuid, this.scanDate, sbom, type, imageDetailOrRepo);
      if (result) {
        return true;
      }
    } catch (e) {
      logger.error(`failed to set sbom, error: ${e}`);
      return false;
    }
  }

  async setOrgSbom(sbom: Sbom) {
    try {
      const result = await this.mongoDBreport.setOrgSbom(this.uuid, this.scanDate, sbom);
      if (result) {
        return true;
      } else {
        logger.error(`failed to save org sbom, res: ${result}`);
      }
    } catch (e) {
      logger.error(`failed to set org sbom, error: ${e}`);
      return false;
    }
  }

  private isAllPoliciesDisabled(cat: OxCategory) {
    return this.rulesParser.getRules().filter(i => i.catId === cat.id).length === 0;
  }
  private isOneConnectorEnabled(category: OxCategory, isAllPoliciesDisabled: boolean) {
    const res: CategoryReason[] = [];
    if (isAllPoliciesDisabled) {
      res.push(CategoryReason.NoPolicies);
    }
    if (!category.isConnectorCategory) {
      return res;
    }
    if (category.id === 8) {
      return [];
    }
    if (category.id === 11) {
      const isOneClientToolEnabled = staticConnectors.some(c => c.family === OxCategoriesKeys.Registry && !c.comingSoon && !c.isOxBuiltIn);
      if (!isOneClientToolEnabled) {
        res.push(CategoryReason.NoArtifactory);
      }
      return res;
    }

    if (category.id === 15) {
      const isOneClientToolEnabled = staticConnectors.some(
        c => c.family === OxCategoriesKeys.CloudSecurity && !c.comingSoon && !c.isOxBuiltIn,
      );
      if (isOneClientToolEnabled) {
        return res;
      }
      const isCloudDeploymentEnabled = staticConnectors.some(c => c.family === OxCategoriesKeys.CloudDeployment && !c.comingSoon);
      if (!isCloudDeploymentEnabled) {
        res.push(CategoryReason.NoCloud);
      }

      const isOneOxToolEnable = staticConnectors.some(c => c.family === OxCategoriesKeys.CloudSecurity && !c.comingSoon && c.isOxBuiltIn);
      if (!isOneOxToolEnable) {
        res.push(CategoryReason.NoSecTools);
      }
      return res;
    }

    if (category.id === 3) {
      return res;
    }

    if (category.id === 4) {
      const isOneClientToolEnabled = staticConnectors.some(
        c => c.family === OxCategoriesKeys.CodeSecurity && !c.comingSoon && !c.isOxBuiltIn,
      );
      if (isOneClientToolEnabled) {
        return res;
      }
      res.push(CategoryReason.NoSystems);
      const isOneOxToolEnable = staticConnectors.some(c => c.family === OxCategoriesKeys.CodeSecurity && !c.comingSoon && c.isOxBuiltIn);
      if (isOneOxToolEnable) {
        return [];
      }
      res.push(CategoryReason.NoSecTools);
      return res;
    }
    if (category.id === 7) {
      const isOneOxToolEnable = staticConnectors.some(c => c.family === OxCategoriesKeys.SBOM && !c.comingSoon);
      if (!isOneOxToolEnable) {
        res.push(CategoryReason.NoSecTools);
      }
      return res;
    }
    if (category.id === 6) {
      const isOneClientToolEnabled = staticConnectors.some(
        c => c.family === OxCategoriesKeys.OpenSourceSecurity && !c.comingSoon && !c.isOxBuiltIn,
      );
      if (isOneClientToolEnabled) {
        return res;
      }
      res.push(CategoryReason.NoSystems);
      const isOneOxToolEnable = staticConnectors.some(
        c => c.family === OxCategoriesKeys.OpenSourceSecurity && !c.comingSoon && c.isOxBuiltIn,
      );
      if (isOneOxToolEnable) {
        return [];
      }
      res.push(CategoryReason.NoSecTools);
      return res;
    }
    if (category.id === 5) {
      const isOneOxToolEnable = staticConnectors.some(c => c.family === OxCategoriesKeys.SecretScan && !c.comingSoon);
      if (!isOneOxToolEnable) {
        res.push(CategoryReason.NoSecTools);
      }
      return res;
    }

    // if (category.id === 11) {
    //   return res;
    // }

    return res;
  }

  updateAllAppsCollectionInRam(apps: ApplicationAppManager[]) {
    try {
      apps.forEach(app => this.updateSingleAppsCollectionInRam(app));
    } catch (err) {
      logger.error("Failed update app collection in ram", err);
    }
  }

  updateSingleAppsCollectionInRam(apps: ApplicationAppManager) {
    let appName = "";

    try {
      const repo: Repo = apps.appInfo.repo.code_repo;
      appName = repo.fullName;
      const applicaiton: Application = this.appToApplicationObject.get(repo.id);
      applicaiton.toolsCoverage = repo.toolsCoverage;
    } catch (err) {
      logger.error(`Failed update app collection in ram for app: ${appName}`, err);
    }
  }

  async addSboms(sboms: SbomMongoDocument[]) {
    return await this.sbomService.addSboms(sboms);
  }

  async saveDependencyGraphs(repoName: string, graphs: DependencyGraph[]): Promise<void> {
    if (!graphs.length) {
      return;
    }
    const { totalNodes, totalEdges } = graphs.reduce(
      ({ totalNodes, totalEdges }, graph) => ({
        totalNodes: totalNodes + graph?.nodes?.length ?? 0,
        totalEdges: totalEdges + graph?.edges?.length ?? 0,
      }),
      { totalNodes: 0, totalEdges: 0 },
    );
    const startTime = Date.now();
    await this.depGraphsService.addGraphs(graphs);
    await this.depGraphsService.removeOldGraphs(graphs[0].appId);
    logger.info(
      `Saved ${graphs.length} dep graphs for repo ${repoName} (${Date.now() - startTime}ms) - nodes ${totalNodes} edges ${totalEdges}`,
    );
  }

  async getSbomsByAppId(appId: string, appName: string) {
    return await this.sbomService.getSbomsByAppId(appId, appName);
  }

  private updateIssuesFromUniqeIssues(issues: Issue[]) {
    try {
      let dateBefore = new Date(new Date().setDate(new Date().getDate() - 14));
      if (!this.uniqueIssues || this.uniqueIssues.length === 0) {
        for (const issue of issues) {
          issue.isNewIssue = true;
          issue.newDate = this.scanDate;
          issue.scanIssueStatus = "New";
        }
        return;
      }
      for (const issue of issues) {
        const dbIssue = this.uniqueIssues.find(i => i.issueId === issue.issueId);
        if (dbIssue) {
          issue.isNewIssue = false;
          if (dbIssue.comment) {
            issue.comment = dbIssue.comment;
            issue.issueActions.push(IssueActionsType.Comment);
          }
          if (dbIssue.overrideSeverity) {
            issue.severity = dbIssue.severity;
            issue.originalSeverity = dbIssue.originalSeverity;
            issue.overrideSeverity = dbIssue.overrideSeverity;
            issue.issueActions.push(IssueActionsType.ChangedSeverity);
          }
          if (dbIssue.isFalsePositive) {
            issue.issueActions.push(IssueActionsType.ReportedAsFalsePositive);
            issue.isFalsePositive = true;
          }
          if (dbIssue.createdAt) {
            issue.createdAt = new Date(this.isIssuesFromPrevScan ? parseInt(dbIssue.createdAt) : dbIssue.createdAt);
          }

          // logic for updates issues
          if (dbIssue.aggregationsCount && issue.aggregationsCount) {
            if (dbIssue.aggregationsCount > issue.aggregationsCount) {
              issue.decreasedAt = new Date(this.scanDate);
              issue.increasedAt = null;
            } else if (dbIssue.aggregationsCount < issue.aggregationsCount) {
              issue.increasedAt = new Date(this.scanDate);
              issue.decreasedAt = null;
            } else {
              if (dbIssue.increasedAt) {
                issue.increasedAt = new Date(dbIssue.increasedAt);
              } else if (dbIssue.decreasedAt) {
                issue.decreasedAt = new Date(dbIssue.decreasedAt);
              } else {
                //debug
                // logger.warn(`missing decreased / increased at date for issue ${issue.issueId}`);
              }
            }
          }

          //updated/new issue status
          const lastIssueSeenDate = dbIssue.lastIssueSeenDate ? new Date(dbIssue.lastIssueSeenDate) : new Date(dbIssue.sDate);

          if (typeof dbIssue.prevSeverity === "number") {
            issue.prevSeverity = dbIssue.prevSeverity;
            if (issue.severity > issue.prevSeverity) {
              issue.issueActions.push(IssueActionsType.SeverityIncreased);
            } else if (issue.severity < issue.prevSeverity) {
              issue.issueActions.push(IssueActionsType.SeverityDecreased);
            }
          }
          const diff = differenceInCalendarDays(lastIssueSeenDate, dateBefore);
          if (diff && diff <= 0) {
            issue.isNewIssue = true;
            issue.newDate = this.scanDate;
            issue.scanIssueStatus = "New";
          } else if (dbIssue.aggFileNames?.length === 0 && issue.aggFileNames?.length === 0) {
            //old logic
            if (dbIssue.aggregatedItemsId && issue.aggregatedItemsId) {
              if (dbIssue.aggregatedItemsId !== issue.aggregatedItemsId) {
                issue.scanIssueStatus = "Updated";
              } else {
                issue.scanIssueStatus = "Unchanged";
              }
            } else {
              issue.scanIssueStatus = "Unchanged";
            }
          } else if (dbIssue.aggFileNames?.length > 0 || issue.aggFileNames?.length > 0) {
            //new logic for checking relevant fileName
            //@ts-ignore
            const aggFileNames = issue.aggFileNames;
            const uniqueIssueFileNames = dbIssue.aggFileNames;
            const uniqueCounts = uniqueIssueFileNames?.reduce((counts, name) => {
              counts[name] = (counts[name] || 0) + 1;
              return counts;
            }, {});

            const aggCounts = aggFileNames?.reduce((counts, name) => {
              counts[name] = (counts[name] || 0) + 1;
              return counts;
            }, {});

            const keysInAggCounts = aggCounts ? Object.keys(aggCounts) : [];
            const keysInUniqueCounts = uniqueCounts ? Object.keys(uniqueCounts) : [];
            if (
              keysInAggCounts.length !== keysInUniqueCounts.length ||
              !keysInAggCounts.every(key => aggCounts[key] === uniqueCounts[key])
            ) {
              issue.scanIssueStatus = "Updated";
            } else {
              issue.scanIssueStatus = "Unchanged";
            }
          }

          //dvir fix
          // temorary
          // if (dbIssue.newDate === null || dbIssue === undefined) {
          //   if (dbIssue.createdAt) {
          //     issue.newDate = new Date(dbIssue.createdAt);
          //   }
          // } else {
          //   issue.newDate = new Date(dbIssue.newDate);
          // }
          issue.newDate = this.scanDate;
        } else {
          issue.isNewIssue = true;
          issue.scanIssueStatus = "New";
          issue.newDate = this.scanDate;
        }
      }
    } catch (e) {
      logger.error(`failed to update issues with prev scan issues data, org: ${this.orgName}, error: ${e}`);
    }
  }

  private async enrichIssuesWithServicesData(issues: Issue[]) {
    try {
      issues.forEach(issue => {
        if (this.prs && this.prs.length > 0) {
          const issuePr = this.prs.find(pr => pr.issueId === issue.issueId);
          if (issuePr) {
            const fixIssue: FixIssue = {
              fixType: FixType.PullRequest,
              activeFix: {
                fixId: issuePr.prId,
                fixURL: issuePr.prURL,
              },
            };
            issue.fixIssue = fixIssue;
            issue.issueActions.push(IssueActionsType.PrCreated);
          }
        }

        let isssueTickets: Ticket[];
        if (issue.categoryDisplayName === "Open Source Security") {
          isssueTickets = this.tickets.filter(i => i.issueId === issue.issueId);
        } else {
          isssueTickets = this.tickets.filter(i => i.issueId === issue.issueId && !i.detach);
        }

        const slackNotifications = this.slackNotifiactions.filter(slack => slack.issueId === issue.issueId);
        const issueGPT = this.gpts.find(i => i.issueId === issue.issueId);
        if (issueGPT) {
          const gptInfo: GPTInfo = {
            gptResponse: issueGPT.response,
            user: issueGPT.createdBy,
            createdAt: issueGPT.createdAt ? new Date(issueGPT.createdAt) : null,
          };
          issue.gptInfo = gptInfo;
        }
        issue.slackNotification = slackNotifications;

        if (isssueTickets.length > 0) {
          if (!issue.aggItems || issue.aggItems.length === 0) {
            issue.tickets = isssueTickets;
          } else {
            for (const ticket of isssueTickets) {
              const { aggItemsIds } = ticket;
              const issueAggItemsIds = issue.aggItems?.map(i => i.aggId) || [];
              let stillRelevant = false;
              for (const aggItemId of aggItemsIds) {
                const includes = issueAggItemsIds.includes(aggItemId);
                if (includes || issue.categoryDisplayName === "Open Source Security") {
                  issue.tickets.push(ticket);
                  stillRelevant = true;
                  break;
                }
              }
              if (!stillRelevant) {
                logger.info(`ticket: ${ticket.ticketId} is not relevant. detaching ticket`);
                this.detachedTickets.push(ticket.ticketId);
              }
            }
          }
        }

        if (issue.tickets.length > 0) {
          issue.issueActions.push(IssueActionsType.TicketCreated);
        }

        if (slackNotifications.length > 0) {
          issue.issueActions.push(IssueActionsType.SlackNotification);
        }
      });
    } catch (e) {
      logger.error(`failed to enrichIssuesWithServicesData, error :${e}`);
    }
  }

  async setHistoryIssueData(issues: Issue[]) {
    try {
      await PromisePool.for(issues)
        .withConcurrency(200)
        .process(async (issue: Issue) => {
          const ChangeReasons = issue.severityChangedReason.map(i => {
            return {
              shortName: i.shortName,
              changeNumber: i.changeNumber,
              shouldBeSeverityFactor: i.shouldBeSeverityFactor,
            };
          });

          const historyObj: SeverityHistoryInfo = {
            severityDateChange: issue.sDate || new Date(),
            scanId: StatesHelper.Instance.uuid,
            severity: issue.severity,
            severityChangeIds: ChangeReasons,
            originalToolSeverity: issue.originalToolSeverity,
            originalSeverity: issue.originalSeverity,
          };
          await this.mongoDBreport.updateSeverityHistory(issue.issueId, historyObj, issue.iName, issue.pName);
        });

      await this.mongoDBreport.delete2mOlderSeverityHistories();
    } catch (err) {
      logger.error(`failed setHistoryIssueData, error :${err}`);
    }
  }

  // TODO: remove verbose logs
  async updatePipelineIssuesPostWorkflow() {
    const appIds = this.getApplications().map(app => app.appId);

    logger.info(`[updatePipelineIssuesPostWorkflows] issues for total ${appIds.length} apps will be processed`);

    for (const appId of appIds) {
      const cachedIssues = this.appToIssuesMap.get(appId) as CICDIssue[];

      logger.info(`[updatePipelineIssuesPostWorkflows] total ${cachedIssues.length} issues for appId ${appIds} exist in scanner cache`);

      // no point querying db
      if (cachedIssues.length === 0) {
        continue;
      }

      // we need to fetch lastest updated for issues from DB since they are propagated through report-service
      const dbIssues = await this.mongoDBreport.getCICDIssues(appId, this.uuid);

      logger.info(`[updatePipelineIssuesPostWorkflows] total ${dbIssues.length} issues for appId ${appIds} fetched from db`);

      const dbIssueToIssueIdMap = dbIssues.reduce((m, dbIssue) => {
        m.set(dbIssue.issueId, dbIssue);
        return m;
      }, new Map<string, CICDIssue>());

      const updatedIssues: CICDIssue[] = [];
      for (const cachedIssue of cachedIssues) {
        const { issueId } = cachedIssue;
        const dbIssue = dbIssueToIssueIdMap.get(issueId);

        if (!dbIssue) {
          logger.warn(`[updatePipelineIssuesPostWorkflows] issue ${issueId} for appId ${appIds} not found in db`);
          continue;
        }

        if (dbIssue.enforcement === CICDIssueEnforcement.Pending) {
          logger.warn(`[updatePipelineIssuesPostWorkflows] issue ${issueId} for appId ${appIds} has Pending enforcement, dropping issue`);
          continue;
        }

        logger.info(
          `[updatePipelineIssuesPostWorkflows] issue ${issueId} for appId ${appIds} has ${dbIssue.enforcement} enforcement, updating issue`,
        );

        const updatedIssue = {
          ...cachedIssue,
          enforcement: dbIssue.enforcement,
        };

        updatedIssues.push(updatedIssue);
      }

      logger.info(
        `[updatePipelineIssuesPostWorkflows] total ${updatedIssues.length} out of original ${cachedIssues.length} for appId ${appIds} will be put into scanner cache`,
      );

      this.appToIssuesMap.set(appId, updatedIssues);
    }
  }

  async savePipelineInfo() {
    try {
      if (!StatesHelper.Instance.isPipelineScan) {
        return;
      }
      logger.info(`try save pipeline info, info: ${JSON.stringify(PipeLineHelper.Instance.pipelineSummary)}`);
      await this.mongoDBreport.addPipelineSummery(PipeLineHelper.Instance.pipelineSummary);
      logger.info(`finish save pipeline info`);
    } catch (err) {
      logger.error(`failed ave pipeline info, err: ${err}`);
    }
  }

  async setDonePipelineScan() {
    try {
      logger.info(`start setDonePipelineScan, orgId: ${this.orgName}`);

      // if workflow feature is enabled (determined in the helper itself), we need to await it prior to analyzing results
      if (await isPipelineWorkflowsFeatureEnabledForOrg.isEnabled(this.orgName)) {
        await this.handleWorkflow();
        await this.updatePipelineIssuesPostWorkflow();
      }

      const { jobId, jobTriggeredAt, jobUrl, jobTriggeredBy } = PipeLineHelper.Instance.pipelineScanJobInfo;

      const appsIds = this.getApplications().map(app => app.appId);

      appsIds
        .flatMap(appId => (this.appToIssuesMap.get(appId) ?? []) as CICDIssue[]) // for every issue of every app add data to summary
        .forEach(issue => PipeLineHelper.Instance.generateSummeryFromIssue(issue));

      await this.savePipelineInfo();

      const appIdPipelineDatas = appsIds.map(appId => {
        const issues = this.appToIssuesMap.get(appId) as CICDIssue[];
        if (!issues) return { appId, payload: null };

        const payload = new SetPipelineDataInput();
        payload.pipelineJobId = jobId;
        payload.pipelineJobTriggeredAt = jobTriggeredAt;
        payload.pipelineJobUrl = jobUrl;
        payload.pipelineIssuesCount = issues.length;
        payload.pipelineJobTriggeredBy = jobTriggeredBy;

        if (issues.length === 0) {
          payload.pipelineScanResult = PipelineScanResult.none;
        } else if (issues.some(i => i.enforcement === CICDIssueEnforcement.Block)) {
          payload.pipelineScanResult = PipelineScanResult.block;
        } else payload.pipelineScanResult = PipelineScanResult.monitor;

        StatesHelper.Instance.pipelineScanInfo.enforcement = payload.pipelineScanResult.toString();

        return { appId, payload };
      });

      const promises = appIdPipelineDatas.map(({ appId, payload }) => {
        if (payload === null) return;

        return ReportService.Instance.setPipelineData(this.orgName, appId, payload);
      });

      await Promise.all(promises);
    } catch (e) {
      logger.error(`failed setDonePipelineScan, orgId:${this.orgName}, error: ${e} `);
    }
  }

  async saveArtifactScreen(artifacts: Artifact[]): Promise<void> {
    try {
      await this.artifactScreenService.setArtifactScreen(artifacts);
    } catch (error) {
      logger.error(`failed saveArtifactScreen, error:`, error);
    }
  }
}
