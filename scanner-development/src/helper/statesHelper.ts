import { CategoryDisplayName, OxCategory } from "@oxappsec/ox-consolidated-categories";
import ToolProgressBase from "../codeOpenSourceTools/base/toolProgressBase";
import { resourceType, SecurityAlertType } from "../entitis/codeRepoTypes";
import { ScanType } from "../entitis/service/connector-message-types";
import loggerImport from "../logger";
import { Tool } from "../policy/rules/code/policyRulesBase";
import Iqueue from "./queue/Iqueue";
import { ScanMetric, sendScannerStringTelemetry } from "./telemetry-utils";
import { Resource } from "./toolExecutionStats";
const logger = loggerImport.getDebugLogger();

interface RepoSizeStats {
  leanCodeZip: number;
  repoInfoJson: number;
  gitInfoJson: number;
}

export enum PerformanceType {
  detailed = "Detailed Scan",
  regular = "Regular Scan",
  fast = "Fast Scan",
  fastest = "Fastest Scan",
}

export class PipelineInfo {
  repoName: string;
  sourceType: string;
  scannerTimeInQueue: number;
  numberOfFilesScanned: number;
  scannerExecutionTime: number;
  end2endScan: number;
  performance: PerformanceType; //details, regular, fast, fastest
  filesModifiedInPullRequest = {
    isPullRequest: false,
    enabled: false,
    fetched: false,
    timedOut: false,
    fileCount: -1,
    execution: -1,
  };
  services: Resource;
  enforcement: string;
}

class ScanInfoStats {
  //Skipped due to delta scan
  ScanInQueueTime: string = "";
  skippedAppsDueToDeltaScan: number = 0;
  longestTimeWaitInQueue: string = "";
  repoScanTime: string = "";
  cicdScanTime: string = "";
  artifactTime: number = 0;
  totalImages: number = 0;
  totalCloudScanTime: string = "";
  totalFinalizingTime: string = "";
  blameArtifactsAtFinalizing: string = "";
  blameCodeAtFinalizing: string = "";
  supplyChainTimeAtFinalizing: number = 0;
  dockerhubTimeAtFinalizing: number = 0;
  dockerhubNumTimeouts: number = 0;
  dockerhubNumFails: number = 0;
  prowlerTime: string = "";
  oxCrawlerTime: string = "";
  artifactAndParserExecution: number = 0;
  audiLogTime: number = 0;
  auditLogsCount: number = 0;
  mongoErrors: number = 0;
  oldScanTimeExecution: string = "";
  hugeNodeCount: number = 0;
  scaNoTriggerPackage: number = 0;
  deltaApps: number = 0;
  nonDeltaApps: number = 0;
  numberOfToolsCalls: number = 0;
  pkgIndirectCount: number = 0;
  resolveIssuesRepos: number = 0;

  imageScanTimeInMinutes: string;

  timeoutForAllTools: number = 0;
  failedProcessSingleRepo: number = 0;
  failedProcessSingleCICD: number = 0;
  failedProcessSingleCloud: number = 0;

  skippedClonesDueToCash: number = 0;
  sendToClone: number = 0;

  //Clone
  failedClones: number = 0;
  failedClonesRepoNames: string[] = [];
  timeoutClones: number = 0;
  timeoutClonesRepoNames: string[] = [];

  // OpenSource
  failedOpenSource = 0;
  failedOpenSourceRepoNames: string[] = [];
  timeoutOpenSource = 0;
  timeoutOpenSourceRepoNames: string[] = [];

  //Blame
  failedBlameBatches: number = 0;
  failedBlameRepoNames: string[] = [];
  failedBlameTimeout: number = 0;
  failedBlameTimeoutRepoNames: string[] = [];

  //Secret validation
  failedSecretBatches: number = 0;
  failedSecretRepoNames: string[] = [];
  failedSecretTimeout: number = 0;
  failedSecretTimeoutRepoNames: string[] = [];

  //Cloud Graph
  failedCloudGraphBatches: number = 0;
  failedCloudGraphTimeout: number = 0;

  //Resolve issues validation
  failedResolvedIssuesValidation: number = 0;
  failedResolvedIssuesValidationTimeout: number = 0;

  //Auto fix
  failedAutoFixBatches: number = 0;
  failedAutoFixRepoNames: string[] = [];
  failedAutoFixTimeout: number = 0;
  failedAutoFixTimeoutRepoNames: string[] = [];

  //Open Wiki fix
  failedOpenWiki: number = 0;
  wikiProcessTime: number = 0;
  wikiReposNotFound: number = 0;

  //Alet recommendation
  failedAlertRecommendationBatches: number = 0;
  failedAlertRecommendationRepoNames: string[] = [];
  failedAlertRecommendationTimeout: number = 0;
  failedAlertRecommendationTimeoutRepoNames: string[] = [];

  //Dep jacking alerts
  failedDepJackingBatches: number = 0;
  failedDepJackingRepoNames: string[] = [];
  failedDepJackingTimeout: number = 0;
  failedDepJackingTimeoutRepoNames: string[] = [];

  //Iac Verification
  failedIacValidatorBatches: number = 0;
  failedIacValidatorRepoNames: string[] = [];
  failedIacValidatorTimeout: number = 0;
  failedIacValidatorTimeoutRepoNames: string[] = [];

  //Sca Verification
  failedScaValidatorBatches: number = 0;
  failedScaValidatorRepoNames: string[] = [];
  failedScaValidatorTimeout: number = 0;
  failedScaValidatorTimeoutRepoNames: string[] = [];

  //Dependency Graph
  failedDependencyGraphBatches: number = 0;
  failedDependencyGraphBatchesNames: string[] = [];
  failedDependencyGraphTimeout: number = 0;
  failedDependencyGraphTimeoutRepoNames: string[] = [];

  //Call Graph
  failedCallGraphBatches: number = 0;
  failedCallGraphBatchesNames: string[] = [];
  failedCallGraphTimeout: number = 0;
  failedCallGraphTimeoutRepoNames: string[] = [];

  //API Discovery
  failedAPIDiscoveryBatches: number = 0;
  failedAPIDiscoveryBatchesNames: string[] = [];
  failedAPIDiscoveryTimeout: number = 0;
  failedAPIDiscoveryTimeoutRepoNames: string[] = [];

  //Attack Path
  failedAttackPathBatches: number = 0;
  failedAttackPathBatchesNames: string[] = [];
  failedAttackPathTimeout: number = 0;
  failedAttackPathTimeoutRepoNames: string[] = [];

  //Dockerfile Scanner
  failedDockerfileScannerBatches: number = 0;
  failedDockerfileScannerBatchesNames: string[] = [];
  failedDockerfileScannerTimeout: number = 0;
  failedDockerfileScannerTimeoutRepoNames: string[] = [];

  //Llm Client
  failedLlmClientBatches: number = 0;
  failedLlmClientBatchesNames: string[] = [];
  failedLlmClientTimeout: number = 0;
  failedLlmClientTimeoutRepoNames: string[] = [];

  //pip2poetry
  failedPip2poetryBatches: number = 0;
  failedPip2poetryBatchesNames: string[] = [];
  failedPip2poetryTimeout: number = 0;
  failedPip2poetryTimeoutRepoNames: string[] = [];

  noGraph: number = 0;
  failedCalcGraph: number = 0;

  scanId: string;
  reducedSeverity: number = 0;
  hardCodedSeverityLogic: number = 0;
  removedAlertsDueToReduceSeverity: number = 0;
  failedSetNewSeverity: number = 0;
  failedHandleWorkflowApps: number = 0;

  // GitHubRequests
  githubTotalRequests: number = 0;
  githubRequestsCachedByEtagReturned: string = "";

  // Github GraphQL
  githubGraphqlPrimaryRateLimitWait = 0;
  githubGraphqlSecondaryRateLimitWait = 0;
  githubGraphqlTotalPullRequests = 0;
  githubGraphqlQueries = 0;

  setCategories(duplicateIssues: Map<CategoryDisplayName, number>) {
    for (const prop of duplicateIssues.keys()) {
      const duplicatesAsString = duplicateIssues.get(prop).toString();
      this[prop] = duplicatesAsString;
    }
  }
}

class StatesHelper {
  private static _instance: StatesHelper;

  orgName: string;
  uuid: string;
  isDemo: boolean = false;

  //tools
  private toolsCount: number = 0;
  private totalTools: number = 0;
  private numberOfFailedCriticalTools: number = 0;
  totalAggItems = 0;
  totalIssues = 0;
  totalSilent = 0;
  totalSilentIssuesAgg = 0;
  reducedDueToLargeAggItem = 0;

  isZerto = false;
  isApiSecEnable = false;
  aggCloudAlertsBaseOnOrg = false;
  skipHandleArtifactsOnFakeApps = false;
  isResolvedIssuesEnable = false;
  isContainerEnable = false;
  containerSecResolvedIssuesEnabled = false;
  useLightBlame = false;
  useAlertAggregation = false;
  enableDigitalAssetsLogicForContainers = false;
  isMobiliy = false;
  isInfenera = false;
  dontChangeSeverity = false;
  isAttackPathEnable = false;
  isNewAPIScanLogicEnable = false;
  isCallGraphEnable = false;
  isArtifactScreenShouldBeDroppedOnEveryScan = false;
  skipArtifactScreenRetention = false;
  isSofi = false;
  isMelio = false;
  isCharterBank = false;
  isWalmart = false;
  waitForResolveIssues = false;
  enableDiskDbFallback = false;
  enableFallback = false;
  isEtoro = false;
  isMoovit = false;
  isHilan = false;
  isRepsol = false;

  isContainerEnrichmentDisabled = false;
  canRunFastPipelineScan = false;
  canRunFastestPipelineScan = false;
  useMongoDBOptimizedQueries = false;
  useProwlerWithServices = false;
  shouldTrackSeverity = false;
  validateToolSchema = false;

  // dor flags
  isMatchingArtifactToCloud = false;
  dorCspm = false;

  //For onPrem
  allReposOfGitlabOnPrem = [];

  //Stats
  longestTimeHangingInQ = 0;
  cloudTotal: number = 0;
  SEMGREPHEAVY_QUEUE_KEY_HEAVY_TASK_CPU: number = 4;
  SEMGREP_QUEUE_KEY_CPU: number = 3;
  scanInfoStats: ScanInfoStats = new ScanInfoStats();
  scanInfoStatsHelper = {};

  //Sync for progress
  artifactScanCountProgress: number = 0;
  cloudScanCountProgress: number = 0;
  externalToolsProgress: number = 0;
  externalToolsApisRunningProgress: number = 0;

  cloudScanTotalCount: number = 0;
  externalToolsTotalCount: number = 0;
  externalToolsApisRunningTotal: number = 0;
  isFinalizing: boolean = false;
  isAttachResources: boolean = false;

  numberOfApps: number = 0;
  publicReposCount: number = 0;
  isCheckMarxEnable: boolean = false;

  monoRepoSplit: boolean = true;
  monoRepoSplitByList: string[] = null;
  importGithubTopics: boolean = false;

  //Stats for logging and consist results
  totalCodeSecurityAlertsBeforePolicyEval = 0;
  totalCodeSecurityAlertsAfterBlame = 0;
  alertsPerCategoryAndProvider = {};
  alertsPerCategory = {};
  alertsPerCategoryFromTool = {};
  clonedRepos = {};
  skippedClone = new Set();

  //SBOM
  allLibsCount = 0;
  openSourceWarnings: Record<string, number> = {};
  savedSbomsFromCode = 0;
  savedSbomsFromRegistry = 0;
  sbomMissingLicense = 0;
  sbomMissingCopyright = 0;
  sbomTotal = 0;

  //Snyk
  externalToolCount = {};

  //Configuration
  tooByCatLowEnabled = {};
  isScheduledScan = false;
  concurrentRepoScans: number = 105;
  isFullScan = process.env.RUN_FULL_SCAN != undefined ? true : false;
  isPipelineScan = false;
  uniqueReposForHeavyTasks = new Set();
  scanType: ScanType = null;

  numberOfChangedMiddSeverity = 0;

  // scan
  totalScanTime: number = 0;
  scanStartDate: Date;
  scanFinishDate: Date;
  policyStats = {};
  policyPerCatStats = {};
  public readonly failedToolsMap: Map<string, Set<Tool>> = new Map();
  public globalApisFails: Set<Tool | resourceType> = new Set();
  failedExternalTools = new Set<Tool>();

  //Costumer specific
  companyName: string;
  pathToSSHKeyGerrit: string;

  //Policy
  policyForQueryPullsByDays: number;
  policyForQueryPullsByDaysSkippedRequests: number = 0;
  numberOfVersionsToSkip: number = 0;
  openWikiEnable: boolean = false;
  includeForkedPublicRepos: boolean = false;
  reposMainBranchDoesntRequireCodeReviewViolationCount: number = 0;
  noReposMainBranchDoesntRequireCodeReviewViolationCount: number = 0;
  commonUserPrefixSuffix = {};

  // fileNames (license, security.md, CODEOWNERS)
  filesToRead = new Map();

  //prowler
  pathToProlwerSecretsFolder: string;
  iqueue: Iqueue;
  toolProgressBase: ToolProgressBase;

  //cloud graph
  isEKSEnabled: boolean = false;

  //Connector specific
  numberOfAllowedRequests: number = -1;
  cicdConnectorsNames = new Set();

  orgsWithAuditLogs = new Set();
  dependabotEnable: boolean = false;
  githubSastEnable: boolean = false;
  githubSecretDetectionEnable: boolean = false;
  gitlabSastEnable: boolean = false;
  gitlabSecretDetectionEnable: boolean = false;
  gitLabDependencyScanningEnable: boolean = false;

  //pipeline information
  pipelineScanInfo: PipelineInfo = new PipelineInfo();

  ignoreIrrelevantAppsForExternalSecProduct = new Set();

  //Should run Skopeo with SelfSigned Certificate support
  allowSkopeoToAcceptSelfSignedCertificate = false;

  //Special case when we need to update DNS resolution (Talk to KYZ)
  dnsNameOverride = ""; // Example: 217.65.37.141 mng-harbor-core.rw.co.il

  readonly enableCategories: OxCategory[] = [];

  //Resolve issues
  failedArtifactsScan = new Set<string>();

  //Pii counter
  piiEventsCounter = {};

  //Kong connector
  kongHostUrl = "";
  kongToken = "";

  //Solace connector
  solaceUsername = "";
  solacePassword = "";

  private constructor() {
    this.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.iac]] = false;
    this.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.secrets]] = false;
    this.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.cspm]] = false;
    this.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.sast]] = false;
    this.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.dast]] = false;
    this.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.sca]] = false;
    this.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.container]] = false;
  }

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  isOrgHaveAuditLogs(orgName: string) {
    try {
      const haveLogs = this.orgsWithAuditLogs.has(orgName);
      return haveLogs;
    } catch (e) {
      logger.error(`${e}`);
    }
    return false;
  }

  setConcurrentRepoScans() {
    try {
      if (StatesHelper.Instance.isScheduledScan) {
        if (process.env.MAX_CONCURRENT_REPO_SCANS_SCHEDULED != undefined) {
          const num = parseInt(process.env.MAX_CONCURRENT_REPO_SCANS_SCHEDULED);
          logger.info(`using MAX_CONCURRENT_REPO_SCANS_SCHEDULED : ${num}`);
          if (!isNaN(num)) {
            this.concurrentRepoScans = num;
          }
        }
      } else {
        if (process.env.MAX_CONCURRENT_REPO_SCANS_SCHEDULED != undefined) {
          const num = parseInt(process.env.MAX_CONCURRENT_REPO_SCANS_MANUAL);
          logger.info(`using MAX_CONCURRENT_REPO_SCANS_MANUAL : ${num}`);
          if (!isNaN(num)) {
            this.concurrentRepoScans = num;
          }
        }
      }
      logger.info(`using concurrent repo scans: ${this.concurrentRepoScans}`);
    } catch (err) {
      logger.error(`failed to set concurrent repo scans, using default: ${this.concurrentRepoScans}, err: ${err}`);
    }
  }

  setSemgrepCPU() {
    try {
      logger.info(
        `SEMGREP_QUEUE_KEY_CPU from env: ${process.env["SEMGREP_QUEUE_KEY_CPU"]}, SEMGREPHEAVY_QUEUE_KEY_HEAVY_TASK_CPU from env: ${process.env["SEMGREPHEAVY_QUEUE_KEY_HEAVY_TASK_CPU"]}`,
      );

      if (process.env["SEMGREP_QUEUE_KEY_CPU"]) {
        let numStr = process.env["SEMGREP_QUEUE_KEY_CPU"];
        let num;
        if (numStr.endsWith("m")) {
          numStr = numStr.replace("m", "");
          numStr = (Number(numStr) / 1000).toFixed(0);
          num = Number(numStr);
        }
        if (!isNaN(num)) {
          this.SEMGREP_QUEUE_KEY_CPU = num;
          logger.info(`using SEMGREP_QUEUE_KEY_CPU from env: ${this.SEMGREP_QUEUE_KEY_CPU}`);
        }
      } else {
        logger.info(`using SEMGREP_QUEUE_KEY_CPU default: ${this.SEMGREP_QUEUE_KEY_CPU}`);
      }
      if (process.env["SEMGREPHEAVY_QUEUE_KEY_HEAVY_TASK_CPU"]) {
        let numStr = process.env["SEMGREPHEAVY_QUEUE_KEY_HEAVY_TASK_CPU"];
        let num;
        if (numStr.endsWith("m")) {
          numStr = numStr.replace("m", "");
          numStr = (Number(numStr) / 1000).toFixed(0);
          num = Number(numStr);
        }
        if (!isNaN(num)) {
          this.SEMGREPHEAVY_QUEUE_KEY_HEAVY_TASK_CPU = num;
          logger.info(`using SEMGREPHEAVY_QUEUE_KEY_HEAVY_TASK_CPU from env: ${this.SEMGREPHEAVY_QUEUE_KEY_HEAVY_TASK_CPU}`);
        }
      } else {
        logger.info(`using SEMGREPHEAVY_QUEUE_KEY_HEAVY_TASK_CPU default: ${this.SEMGREPHEAVY_QUEUE_KEY_HEAVY_TASK_CPU}`);
      }
    } catch (err) {
      logger.error(`failed to set semgrep cpu, using default, err: ${err}`);
    }
  }

  addFailedTool(tool: Tool, repoId: string) {
    try {
      if (!StatesHelper.Instance.failedToolsMap.get(repoId)) {
        const set = new Set<Tool>();
        set.add(tool);
        StatesHelper.Instance.failedToolsMap.set(repoId, set);
      } else {
        const val = StatesHelper.Instance.failedToolsMap.get(repoId);
        val.add(tool);
      }
    } catch (e) {
      logger.error(`Could not add failed tool ${tool} to map of repoId: ${repoId}, err:${e}`);
    }
  }

  addToAppsCount(numberOfApps: number) {
    this.numberOfApps += numberOfApps;
    logger.info(`states, adding new  numberOfApps: ${numberOfApps}`);
    this.refreshToolsCount();
  }

  addTotalTools(toolsName: string, criticalTool: boolean) {
    if (!criticalTool) {
      return;
    }
    this.toolsCount++;
    this.refreshToolsCount();
  }

  addNumberOfFailedCriticalTools(toolName: string, repoName: string, criticalTool: boolean) {
    if (!criticalTool) {
      logger.info(`stats, adding number of failed tools for repo: ${repoName}, toolName: ${toolName}`);
      return;
    }

    this.numberOfFailedCriticalTools++;
    logger.info(
      `states, adding number of failed critical tools for repo: ${repoName}, toolName: ${toolName}, total count: ${this.numberOfFailedCriticalTools}`,
    );
  }

  private refreshToolsCount() {
    this.totalTools = this.numberOfApps * this.toolsCount;
  }

  getTimeoutForProcessRepoBasedOnAPIlimits() {
    try {
      if (this.numberOfAllowedRequests === -1) {
        return;
      }
      if (this.numberOfAllowedRequests < 5001) {
        return 1000 * 60 * 60 * 2;
      }
    } catch (err) {
      logger.error(`failed to get timeout for process repo based on API limits err: ${err}`);
    }
  }

  async criticalErrorExist() {
    try {
      if (this.numberOfApps < 10) {
        return false;
      }

      const failedClones = this.scanInfoStats.failedClones / this.numberOfApps;
      if (this.numberOfApps > 0) {
        if (failedClones > 0.2) {
          const errStr = `mark should exit due to failed clones count: ${failedClones}, number of failed clones: ${this.scanInfoStats.failedClones}, number of repos: ${this.numberOfApps}`;
          logger.info(errStr);

          await sendScannerStringTelemetry(ScanMetric.ScanFail, this.orgName, this.uuid, errStr);

          return true;
        }
      }

      if (this.totalTools > 0) {
        const failedTools = this.numberOfFailedCriticalTools / this.totalTools;
        if (failedTools > 0.2) {
          const errStr = `mark should exit due to failed tools count: ${failedTools}, numberOfFailedCriticalTools: ${this.numberOfFailedCriticalTools}, number of failed clones: ${this.scanInfoStats.failedClones}, number of repos: ${this.numberOfApps}`;
          logger.info(errStr);

          await sendScannerStringTelemetry(ScanMetric.ScanFail, this.orgName, this.uuid, errStr);

          return true;
        }
      }
    } catch (err) {
      logger.error(`failed check critical error exist, err: ${err}`);
    }
    return false;
  }
}

export default StatesHelper;
