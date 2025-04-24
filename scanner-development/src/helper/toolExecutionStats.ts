import fs from "fs";
import { Issue } from "../entitis/issuesTypes";
import loggerImport from "../logger";
import StatesHelper from "./statesHelper";
import FileHelper from "./IO/fileHlper";
import { isDevelopment, isLocalDevelopment } from "./envUtils";
import { IoTThingsGraph } from "aws-sdk";
const logger = loggerImport.getDebugLogger();

export class ToolExecutionStats {
  constructor(readonly toolName: string, readonly dir?: string) {}

  /** Time that took for tool-runner to pick job from Q */
  timeInQ: number;
  /** Time for tool-runner to pre-process the request */
  timePreProcess: number;
  /** Time for actual tool to run */
  timeProcess: number;
  /** Time for tool-runner to post-process the request */
  timePostProcess: number;
  /** Time from when scanner sends message till picks up response */
  timeTotal: number;
  status: ToolError;
  errorCode: number = -1;

  //Tool res
  rawToolAlert: number = 0;
  oxAlertsFromToolAlerts: number = 0;

  requestId: string = "";
}

export class PolicyStats {
  policyName: string = "";

  //Tool stats
  aggregatedItems: number = 0;
  issues: number = 0;

  originalSeverity = {
    appox: 0,
    critical: 0,
    high: 0,
    mid: 0,
    low: 0,
    info: 0,
  };

  issuesSeverity = {
    appox: 0,
    critical: 0,
    high: 0,
    mid: 0,
    low: 0,
    info: 0,
  };
}

export class AlertStatsPerCategory {
  cat: string;
  appox: number = 0;
  critical: number = 0;
  high: number = 0;
  mid: number = 0;
  low: number = 0;
  info: number = 0;
}

export class AlertStatsPerRepo {
  repoName: string;
  cats: AlertStatsPerCategory[] = [];
}

export class AlertStats {
  totalAlert: number;
  scanId: string;
  repos: AlertStatsPerRepo[] = [];
}

export enum ToolError {
  Timeout = "tool-timeout-(Contact-Tool-Owner)",
  FailedFileFound = "tool-fail-file-found=(Contact-Tool-Owner)",
  ResFileNotFound = "tool-file-not-exist-on-disk-(Contact-Tool-Owner)",
  SendToQueue = "failed-send-q-(Contact-DEVOPS)",
  NeverReturnFromQueue = "never-return-from-q-(Contact-DEVOPS)",
  Generic = "generic-error-(Contact-Tool-Owner)",
}

const severityMap = new Map();
severityMap.set(0, "info");
severityMap.set(1, "low");
severityMap.set(2, "mid");
severityMap.set(3, "high");
severityMap.set(4, "critical");
severityMap.set(5, "appox");

const toolSeverityMap = new Map();
toolSeverityMap.set("Info", "info");
toolSeverityMap.set("Low", "low");
toolSeverityMap.set("Medium", "mid");
toolSeverityMap.set("High", "high");
toolSeverityMap.set("Critical", "critical");
toolSeverityMap.set("Appoxalypse", "appox");

export type ResourceType = "repo" | "artifact" | "cloud" | "unknown";
export class Resource {
  constructor(public readonly id: string, public readonly name: string, public readonly type: ResourceType) {}

  toolExecutionStats: ToolExecutionStats[] = [];
  policyStats: PolicyStats[] = [];
  alertFromCashTime: number = -1;
  //Resource info
  isDelta: boolean = false;

  isPayingCustomer: boolean;
  totalAlertsNumber: number = 0;
  gitType: string;

  longestTime_inQ: number = -1;
  longestTime_inQTool: string = "";
  longestTime_PreProcess: number = -1;
  longestTime_PreProcessTool: string = "";
  longestTime_Execution: number = -1;
  longestTime_ExecutionTool: string = "";
  longestTime_PostProcess: number = -1;
  longestTime_PostProcessTool: string = "";
  longestTime_total: number = -1;
  longestTime_totalTool: string = "";
}

export interface IFullScanToolInfo {
  toolSuccess: number;
  toolError: number;
  toolTimeout: number;
  toolStats: {
    toolName: string;
    toolSuccess: number;
    toolError: number;
    toolTimeout: number;
    avgTimeInQ: number;
    avgExecTime: number;
  }[];
}
export class FullScanToolInfo {
  constructor(public readonly toolName: string) {}
  /** total requests that succeeded for the tool  */
  toolSuccess: number = 0;
  /** total requests that failed for the tool  */
  toolError: number = 0;
  /** total requests that had timeout for the tool  */
  toolTimeout: number = 0;
  /** total time in queue for the tool  */
  totalTimeInQ: number = 0;
  /** total execution time for the tool  */
  totalExecTime: number = 0;
  /** total requests that sent to the tool  */
  count: number = 0;

  private getAverageTime(totalTime: number) {
    const averageTime = totalTime / this.count;
    return isNaN(averageTime) ? 0 : averageTime;
  }

  public updateToolExecutionStats(tool: ToolExecutionStats) {
    this.toolSuccess += tool.status === undefined ? 1 : 0;
    this.toolError += tool.status !== undefined ? 1 : 0;
    this.toolTimeout += tool.status === ToolError.Timeout ? 1 : 0;
    this.totalTimeInQ += tool.timeInQ ?? 0;
    this.totalExecTime += tool.timeTotal ?? 0;
    this.count += 1;
  }

  public getToolStats() {
    return {
      toolName: this.toolName,
      toolSuccess: this.toolSuccess,
      toolError: this.toolError,
      toolTimeout: this.toolTimeout,
      avgTimeInQ: this.getAverageTime(this.totalTimeInQ),
      avgExecTime: this.getAverageTime(this.totalExecTime),
    };
  }
}

export class ToolsExecutionStats {
  private static resourceExecution: Record<string, Resource> = {};
  public static alertStats: AlertStats = new AlertStats();

  static alertOnPreviousScansDrift() {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      const resFile = `${process.env.OX_GLOBAL_DATA}/keep/${StatesHelper.Instance.orgName}/alertSummery/alertSummeryInfo.js`;
      if (!fs.existsSync(resFile)) {
        logger.info(`alertOnPreviousScansDrift, no resFile: ${resFile}`);
        return;
      }

      const data = fs.readFileSync(resFile, "utf8");
      const prevScan: AlertStats = JSON.parse(data);
      let driftErrorString = "";
      let driftPassRepoSet = new Set();
      let driftPassCounter = 0;
      let r;

      let diffDriftPercentage = 10;
      if (process.env.DIFF_DRIFT_PERCENTAGE) {
        diffDriftPercentage = parseInt(process.env.DIFF_DRIFT_PERCENTAGE) as number;
      }

      try {
        for (const repo of this.alertStats.repos) {
          const prevScanRepoStats = prevScan.repos.find(i => i.repoName === repo.repoName);
          if (!repo.cats.length || !prevScanRepoStats.cats.length) {
            if (!repo.cats.length) {
              logger.info(`alertOnPreviousScansDrift: repo stats from current scan doesn't contain categories array: ${repo.repoName}`);
            }
            if (!prevScanRepoStats.cats.length) {
              logger.info(`alertOnPreviousScansDrift: repo stats from prev scan doesn't contain categories array: ${repo.repoName}`);
            }
            continue;
          }

          for (const cat of repo.cats) {
            const prevScanCatsStats = prevScanRepoStats.cats.find(i => i.cat === cat.cat);
            if (!prevScanCatsStats) {
              logger.info(`alertOnPreviousScansDrift: repo stats of prev scan doesn't contain category ${cat.cat}, repo: ${repo.repoName}`);
              continue;
            }

            const severities = ["info", "low", "mid", "high", "critical", "appox"];
            for (const severity of severities) {
              const prevScanSeverityStats = prevScanCatsStats[severity];
              const currentScanSeverityStats = cat[severity];
              const diffPrecentage = Math.abs((1 - currentScanSeverityStats / prevScanSeverityStats) * 100);
              if (currentScanSeverityStats < 3 || prevScanSeverityStats < 3) {
                continue;
              }
              if (diffPrecentage > diffDriftPercentage) {
                if (driftPassRepoSet.size == 5) {
                  driftPassCounter++;
                  continue;
                }
                driftPassRepoSet.add(repo.repoName);
                driftErrorString = driftErrorString.concat(
                  `found ${diffPrecentage}% drift between previous and current scan for repo: ${repo.repoName}, category: ${cat.cat}, severity: ${severity}, previous scan alerts count: ${prevScanSeverityStats}, current scan alerts count: ${currentScanSeverityStats} \n`,
                );
              }
            }
          }
        }
      } catch (err) {
        logger.error(`alertOnPreviousScansDrift: failed calculating alert percentage drift between previous and current scan, err: ${err}`);
      }

      driftErrorString = driftErrorString.concat(`current scanId: ${StatesHelper.Instance.uuid}, prev scanId: ${prevScan.scanId}.`);

      logger.info(
        `${driftErrorString}\n ${
          driftPassRepoSet.size == 5 ? `${driftPassCounter} more repos also had large drift between previous and current scan` : ""
        }`,
      );

      if (prevScan.totalAlert > StatesHelper.Instance.totalIssues) {
        r = (1 - StatesHelper.Instance.totalIssues / prevScan.totalAlert) * 100;
        if (r > diffDriftPercentage) {
          logger.warn(
            `large drift base on: ${diffDriftPercentage} percentage, current scanId: ${StatesHelper.Instance.uuid}, current issue alerts: ${StatesHelper.Instance.totalIssues}, percentage, prev scanId: ${prevScan.scanId}, current issue alerts: ${prevScan.totalAlert}, diff: ${r}`,
          );
          return;
        }
      }
      if (prevScan.totalAlert < StatesHelper.Instance.totalIssues) {
        r = (1 - prevScan.totalAlert / StatesHelper.Instance.totalIssues) * 100;
        if (r > diffDriftPercentage) {
          logger.warn(
            `large drift base on: ${diffDriftPercentage} percentage, current scanId: ${StatesHelper.Instance.uuid}, current issue alerts: ${StatesHelper.Instance.totalIssues}, percentage, prev scanId: ${prevScan.scanId}, current issue alerts: ${prevScan.totalAlert}, diff: ${r}`,
          );
          return;
        }
      }

      logger.info(
        `minor drift base on: ${diffDriftPercentage} percentage, current scanId: ${StatesHelper.Instance.uuid}, current issue alerts: ${StatesHelper.Instance.totalIssues}, percentage, prev scanId: ${prevScan.scanId}, current issue alerts: ${prevScan.totalAlert}, diff: ${r}`,
      );
    } catch (err) {
      logger.error(`alertOnPreviousScansDrift, err: ${err}`);
    } finally {
      this.saveTotalAlertsForNextScan();
    }
  }

  static addRepoStatsForCat(repoAlertsStats: AlertStatsPerRepo, category: string, alertSeverity: string) {
    const catAlertsForRepo = repoAlertsStats.cats.find(cat => cat.cat === category);
    if (catAlertsForRepo) {
      catAlertsForRepo[alertSeverity]++;
      return;
    }
    const repoCatAlertsStats: AlertStatsPerCategory = new AlertStatsPerCategory();
    repoCatAlertsStats.cat = category;
    repoCatAlertsStats[alertSeverity]++;
    repoAlertsStats.cats.push(repoCatAlertsStats);
  }

  static addToAlertSeverity(issue: Issue) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      const alertSeverity = severityMap.get(issue.severity);
      const alertCat = issue.cat;
      const repoName = issue.fakeApp ? issue.appName : issue.repoName;
      const alertsRepos = this.alertStats.repos;
      let repoAlertsStats = alertsRepos.find(repo => repo.repoName === repoName);

      if (repoAlertsStats) {
        this.addRepoStatsForCat(repoAlertsStats, alertCat, alertSeverity);
        return;
      }

      repoAlertsStats = new AlertStatsPerRepo();
      repoAlertsStats.repoName = repoName;
      this.alertStats.repos.push(repoAlertsStats);
      this.addRepoStatsForCat(repoAlertsStats, alertCat, alertSeverity);
    } catch (err) {
      logger.error(`failed running addToAlertSeverity, repo:${issue.appName}, err:${err}`);
    }
  }

  static saveTotalAlertsForNextScan() {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      const resFile = `${process.env.OX_GLOBAL_DATA}/keep/${StatesHelper.Instance.orgName}/alertSummery/alertSummeryInfo.js`;
      const fileHelper: FileHelper = new FileHelper("");
      fileHelper.deleteFile(resFile);
      logger.info(`saveTotalAlertsForNextScan delete file: ${resFile}`);

      this.alertStats.totalAlert = StatesHelper.Instance.totalIssues;
      this.alertStats.scanId = StatesHelper.Instance.uuid;

      const str = JSON.stringify(this.alertStats);
      fileHelper.write(resFile, str);
      logger.info(`saveTotalAlertsForNextScan save: ${str} file: ${resFile}`);
    } catch (err) {
      logger.error(`saveTotalAlertsForNextScan, err: ${err}`);
    }
  }

  static getItemForFullScanInfo(): IFullScanToolInfo {
    const toolsMap: Record<string, FullScanToolInfo> = {};
    const resources = Object.values(this.resourceExecution) as Resource[];

    for (const resource of resources) {
      for (const tool of resource.toolExecutionStats) {
        try {
          if (!toolsMap[tool.toolName]) {
            toolsMap[tool.toolName] = new FullScanToolInfo(tool.toolName);
          }
          toolsMap[tool.toolName].updateToolExecutionStats(tool);
        } catch (error) {
          logger.error(`failed iterating tool in getItemForFullScanInfo, err: ${error}`);
        }
      }
    }

    try {
      const toolStats = Object.values(toolsMap).map(tool => tool.getToolStats());
      const data = {
        toolSuccess: toolStats.reduce((acc, tool) => acc + tool.toolSuccess, 0),
        toolError: toolStats.reduce((acc, tool) => acc + tool.toolError, 0),
        toolTimeout: toolStats.reduce((acc, tool) => acc + tool.toolTimeout, 0),
        toolStats: toolStats,
      };
      return data;
    } catch (error) {
      logger.error(`failed getItemForFullScanInfo, err: ${error}`);
      return null;
    }
  }

  static getItemForPipelineInfo() {
    try {
      const resources = Object.values(this.resourceExecution) as Resource[];

      let resourceWithLongestTime;
      let longestTime = 0;

      for (const resource of resources) {
        if (longestTime < resource.longestTime_total) {
          longestTime = resource.longestTime_total;
          resourceWithLongestTime = resource;
          logger.info(`getItemForPipelineInfo: longest time resource changed to: ${resource.name}, with longestTime: ${longestTime}`);
        }
      }

      const resourceForPipeline = this.initalResourceStatsForPipeline(resourceWithLongestTime);

      const toolsUsed = new Set<string>();
      for (const request of resourceWithLongestTime.toolExecutionStats) {
        const toolName = request.toolName;

        if (!toolsUsed.has(toolName)) {
          logger.info(`adding tool for pipeline stats, toolName: ${toolName}`);

          this.initialToolStatsForPipeline(resourceForPipeline, request);
          toolsUsed.add(toolName);
          continue;
        }
        resourceForPipeline[`${toolName}_requestsCount`]++;

        if (resourceForPipeline[`${toolName}_timeInQ`].time < request.timeInQ) {
          resourceForPipeline[`${toolName}_timeInQ`] = request.timeInQ;
          resourceForPipeline[`${toolName}_timeInQ_requestId`] = request.requestId;
        }

        if (resourceForPipeline[`${toolName}_timePreProcess`].time < request.timePreProcess) {
          resourceForPipeline[`${toolName}_timePreProcess`] = request.timePreProcess;
          resourceForPipeline[`${toolName}_timePreProcess_requestId`] = request.requestId;
        }

        if (resourceForPipeline[`${toolName}_timeExecution`].time < request.timeProcess) {
          resourceForPipeline[`${toolName}_timeExecution`] = request.timeProcess;
          resourceForPipeline[`${toolName}_timeExecution_requestId`] = request.requestId;
        }

        if (resourceForPipeline[`${toolName}_timePostProcess`].time < request.timePostProcess) {
          resourceForPipeline[`${toolName}_timePostProcess`] = request.timePostProcess;
          resourceForPipeline[`${toolName}_timePostProcess_requestId`] = request.requestId;
        }

        if (resourceForPipeline[`${toolName}_timeTotal`].time < request.timeTotal) {
          resourceForPipeline[`${toolName}_timeTotal`] = request.timeTotal;
          resourceForPipeline[`${toolName}_timeTotal_requestId`] = request.requestId;
        }
      }

      return resourceForPipeline;
    } catch (err) {
      logger.error(`failed getItemForPipelineInfo, err: ${err}`);
    }
  }

  private static initalResourceStatsForPipeline(resource: Resource) {
    const resourceForPipeline = new Resource(resource.id, resource.name, resource.type);

    resourceForPipeline.longestTime_inQ = resource.longestTime_inQ;
    resourceForPipeline.longestTime_inQTool = resource.longestTime_inQTool;
    resourceForPipeline.longestTime_PreProcess = resource.longestTime_PreProcess;
    resourceForPipeline.longestTime_PreProcessTool = resource.longestTime_PreProcessTool;
    resourceForPipeline.longestTime_Execution = resource.longestTime_Execution;
    resourceForPipeline.longestTime_ExecutionTool = resource.longestTime_ExecutionTool;
    resourceForPipeline.longestTime_PostProcess = resource.longestTime_PostProcess;
    resourceForPipeline.longestTime_PostProcessTool = resource.longestTime_PostProcessTool;
    resourceForPipeline.longestTime_total = resource.longestTime_total;
    resourceForPipeline.longestTime_totalTool = resource.longestTime_totalTool;
    resourceForPipeline.isDelta = resource.isDelta;
    resourceForPipeline.gitType = resource.gitType;
    resourceForPipeline.alertFromCashTime = resource.alertFromCashTime;

    return resourceForPipeline;
  }

  private static initialToolStatsForPipeline(resourceForPipeline: Resource, request: ToolExecutionStats) {
    try {
      const toolName = request.toolName;

      if (
        isNaN(request.timeInQ) ||
        isNaN(request.timePreProcess) ||
        isNaN(request.timeProcess) ||
        isNaN(request.timePostProcess) ||
        isNaN(request.timeTotal)
      ) {
        logger.info(
          `found NaN, timeinQ: ${request.timeInQ}, preProcess: ${request.timePreProcess}, execution: ${request.timeProcess}, postProcess: ${request.timePostProcess}, total: ${request.timeTotal}, resource: ${resourceForPipeline.name}`,
        );
      }

      resourceForPipeline[`${toolName}_timeInQ`] = isNaN(request.timeInQ) ? 0 : request.timeInQ;
      resourceForPipeline[`${toolName}_timeInQ_requestId`] = request.requestId;

      resourceForPipeline[`${toolName}_timePreProcess`] = isNaN(request.timePreProcess) ? 0 : request.timePreProcess;
      resourceForPipeline[`${toolName}_timePreProcess_requestId`] = request.requestId;

      resourceForPipeline[`${toolName}_timeExecution`] = isNaN(request.timeProcess) ? 0 : request.timeProcess;
      resourceForPipeline[`${toolName}_timeExecution_requestId`] = request.requestId;

      resourceForPipeline[`${toolName}_timePostProcess`] = isNaN(request.timePostProcess) ? 0 : request.timePostProcess;
      resourceForPipeline[`${toolName}_timePostProcess_requestId`] = request.requestId;

      resourceForPipeline[`${toolName}_timeTotal`] = isNaN(request.timeTotal)
        ? resourceForPipeline[`${toolName}_timeExecution`] +
          resourceForPipeline[`${toolName}_timeInQ`] +
          resourceForPipeline[`${toolName}_timePreProcess`] +
          resourceForPipeline[`${toolName}_timePostProcess`]
        : request.timeTotal;

      resourceForPipeline[`${toolName}_timeTotal_requestId`] = request.requestId;

      resourceForPipeline[`${toolName}_requestsCount`] = 1;
    } catch (err) {
      logger.error(`failed initialToolStatsForPipeline, err: ${err}`);
    }
  }

  static addResourceDelta(resourceName: string, resourceId: string, resourceType: ResourceType, isDelta: boolean, repoType: string) {
    try {
      const resource: Resource = this.getByKey(resourceId, resourceName, resourceType, repoType);
      resource.isDelta = isDelta;
    } catch (err) {
      logger.error(
        `failed set addResource - resourceType: ${resourceType}, resourceName: ${resourceName}, resourceId: ${resourceId}, err: ${err}`,
        err,
      );
    }
  }

  static addResourcePolicyStats(issue: Issue, resourceId: string, resourceName: string, resourceType: ResourceType) {
    try {
      const resource: Resource = this.getByKey(resourceId, resourceName, resourceType);
      const policyStats: PolicyStats = this.getToolExecutionStatsByPolicyName(resource, issue.pName);

      policyStats.issues++;
      policyStats.aggregatedItems += issue.aggItems ? issue.aggItems.length : 0;

      let originalSeverity;
      const severity = severityMap.get(issue.severity);
      if (issue.originalSeverity) {
        originalSeverity = severityMap.get(issue.originalSeverity);
      } else {
        originalSeverity = toolSeverityMap.get(issue.originalToolSeverity);
      }
      policyStats.originalSeverity[originalSeverity]++;
      policyStats.issuesSeverity[severity]++;
    } catch (err) {
      logger.error(
        `failed set addResourcePolicyStats - resourceType: ${resourceType}, resourceName: ${resourceName}, resourceId: ${resourceId}, issueId: ${issue.pName} ,err: ${err}`,
        err,
      );
    }
  }

  static addExecutionStateOnFail(
    requestId: string,
    toolName: string,
    resourceName: string,
    resourceId: string,
    resourceType: ResourceType,
    dir: string,
    elapsedTime: number,
    errStatus: ToolError,
    errorCode: number = -1,
    criticalTool: false = false,
  ) {
    try {
      logger.error(
        `failed reported - tool: ${toolName}, resourceType: ${resourceType}, resourceName: ${resourceName}, resourceId: ${resourceId}, dir: ${dir}, elapsedTime: ${elapsedTime}, errStatus: ${errStatus}, errorCode: ${errorCode}`,
      );

      const resource: Resource = this.getByKey(resourceId, resourceName, resourceType);
      const tool: ToolExecutionStats = this.getToolExecutionStatsByToolRequestId(resource, requestId, toolName, dir);
      tool.errorCode = errorCode;
      tool.status = errStatus;

      StatesHelper.Instance.addNumberOfFailedCriticalTools(toolName, resourceName, criticalTool);
      this.setResStatsInfo(toolName, errStatus, resourceName, resourceId, resourceType);
      this.sendTelemetry(resource, tool, false);
      this.adjustToolTimeStatsToSeconds(tool);
    } catch (err) {
      logger.error(
        `failed set addExecutionStateOnFail - tool: ${toolName}, resourceType: ${resourceType}, resourceName: ${resourceName}, resourceId: ${resourceId}, dir: ${dir}, elapsedTime: ${elapsedTime}, errStatus: ${errStatus}, errorCode: ${errorCode}. err: ${err}`,
        err,
      );
    }
  }

  static addExecutionStateOfAlertsNumber(
    requestId: string,
    resourceName: string,
    resourceId: string,
    resourceType: ResourceType,
    toolName: string,
    dir: string,
    beforeFilter: number,
    afterFilter: number,
  ) {
    try {
      const resource: Resource = this.getByKey(resourceId, resourceName, resourceType);
      const tool: ToolExecutionStats = this.getToolExecutionStatsByToolRequestId(resource, requestId, toolName, dir);
      tool.rawToolAlert += beforeFilter;
      tool.oxAlertsFromToolAlerts += afterFilter;
      resource.totalAlertsNumber += afterFilter;
    } catch (err) {
      logger.error(
        `failed set addExecutionStateOfAlertsNumber - resourceType: ${resourceType}, resourceName: ${resourceName}, resourceId: ${resourceId}. toolName: ${toolName}, dir: ${dir}, err: ${err}`,
        err,
      );
    }
  }

  static addExecutionStateOfCache(
    resourceName: string,
    resourceId: string,
    resourceType: ResourceType,
    timeGettingFromCash: number,
    cashType: string,
  ) {
    try {
      const resource: Resource = this.getByKey(resourceId, resourceName, resourceType);
      resource.alertFromCashTime = timeGettingFromCash;
    } catch (err) {
      logger.error(
        `failed set addExecutionStateOfCash - resourceType: ${resourceType}, resourceName: ${resourceName}, resourceId: ${resourceId}. cashType: ${cashType}, err: ${err}`,
        err,
      );
    }
  }

  static addToExecutionStatsFromFile(
    resFile: string,
    requestId: string,
    toolName: string,
    resourceName: string,
    resourceId: string,
    resourceType: ResourceType,
    dir: string,
    failedCollection: Set<string>,
  ) {
    try {
      const resource: Resource = this.getByKey(resourceId, resourceName, resourceType);
      const tool: ToolExecutionStats = this.getToolExecutionStatsByToolRequestId(resource, requestId, toolName, dir);

      this.setToolStatsFromFile(resFile, resource, tool, failedCollection);
      this.sendTelemetry(resource, tool, true);
      this.adjustToolTimeStatsToSeconds(tool);
    } catch (err) {
      logger.error(
        `failed set addExecutionStateOnFail - tool: ${toolName}, resourceType: ${resourceType}, resourceName: ${resourceName}, resourceId: ${resourceId}. err: ${err}`,
        err,
      );
    }
  }

  static printStats() {
    try {
      this.alertOnPreviousScansDrift();

      const shouldRun = StatesHelper.Instance.isPipelineScan;
      if (!shouldRun) {
        return;
      }

      logger.info(`try printStats for resourceExecution`);
      for (const resource of Object.values(this.resourceExecution)) {
        this.adjustResourceTimeStatsToSeconds(resource);
        logger.info(`resource info: ${JSON.stringify(resource)}`);
      }
      logger.info(`finish printStats for resourceExecution`);
    } catch (err) {
      logger.error(`failed printStats for resourceExecution, err: ${err}`, err);
    }
  }

  //Private methods
  private static getToolExecutionStatsByToolRequestId(resource: Resource, requestId: string, toolName: string, dir: string) {
    let tool: ToolExecutionStats = resource.toolExecutionStats.find(i => i.requestId.toLowerCase() === requestId.toLowerCase());
    if (!tool) {
      tool = new ToolExecutionStats(toolName.toLowerCase(), dir);
      tool.requestId = requestId;
      resource.toolExecutionStats.push(tool);
    }
    return tool;
  }

  private static sendTelemetry(resource: Resource, tool: ToolExecutionStats, success: boolean): void {
    logger.info(`[ToolTelemetry]`, {
      "ox-tool-name": tool.toolName,
      "ox-tool-success": success,
      "ox-tool-resource-type": resource.type,
      "ox-tool-resource-id": resource.id,
      "ox-tool-resource-name": resource.name,
      "ox-tool-resource-delta": resource.isDelta,
      "ox-tool-resource-error": tool.status,
      "ox-tool-time-in-queue": tool.timeInQ,
      "ox-tool-time-pre-process": tool.timePreProcess,
      "ox-tool-time-process": tool.timeProcess,
      "ox-tool-time-post-process": tool.timePostProcess,
      "ox-tool-time-total": tool.timeTotal,
    });
  }

  private static adjustToolTimeStatsToSeconds(tool: ToolExecutionStats) {
    tool.timeInQ = Number((tool.timeInQ / 1000).toFixed(2));
    tool.timePreProcess = Number((tool.timePreProcess / 1000).toFixed(2));
    tool.timeProcess = Number((tool.timeProcess / 1000).toFixed(2));
    tool.timePostProcess = Number((tool.timePostProcess / 1000).toFixed(2));
    tool.timeTotal = Number((tool.timeTotal / 1000).toFixed(2));
  }

  private static adjustResourceTimeStatsToSeconds(resource: Resource) {
    resource.longestTime_inQ = Number((resource.longestTime_inQ / 1000).toFixed(2));
    resource.longestTime_PreProcess = Number((resource.longestTime_PreProcess / 1000).toFixed(2));
    resource.longestTime_Execution = Number((resource.longestTime_Execution / 1000).toFixed(2));
    resource.longestTime_PostProcess = Number((resource.longestTime_PostProcess / 1000).toFixed(2));
    resource.longestTime_total = Number((resource.longestTime_total / 1000).toFixed(2));
  }

  private static getToolExecutionStatsByPolicyName(resource: Resource, policyName: string): PolicyStats {
    let policyStats: PolicyStats = resource.policyStats.find(i => i.policyName.toLowerCase() === policyName.toLowerCase());
    if (!policyStats) {
      policyStats = new PolicyStats();
      policyStats.policyName = policyName.toLowerCase();
      resource.policyStats.push(policyStats);
    }
    return policyStats;
  }

  private static getByKey(id: string, resourceName: string, resourceType: ResourceType, repoType?: string): Resource {
    if (!this.resourceExecution[id]) {
      const item: Resource = new Resource(id, resourceName, resourceType);
      item.gitType = repoType;
      this.resourceExecution[id] = item;
    }

    return this.resourceExecution[id];
  }

  private static setToolStatsFromFile(
    resFile: string,
    resource: Resource,
    toolExecutionStats: ToolExecutionStats,
    failedCollection: Set<string>,
  ): void {
    const toolName = toolExecutionStats.toolName;
    let data: string;

    try {
      data = fs.readFileSync(resFile, "utf8");

      if (data) {
        const message = JSON.parse(data);

        if (message.startTime && message.body?.putInQueueTime) {
          const toolInQ = isNaN(message.startTime - message.body.putInQueueTime) ? 0 : message.startTime - message.body.putInQueueTime;
          toolExecutionStats.timeInQ = toolInQ;
          if (resource.longestTime_inQ < toolInQ) {
            resource.longestTime_inQ = toolInQ;
            resource.longestTime_inQTool = toolName;
          }
        }

        if (message.startTime && message.localCopyEndTime) {
          const toolRunnerPreProcess = isNaN(message.localCopyEndTime - message.startTime)
            ? 0
            : message.localCopyEndTime - message.startTime;
          toolExecutionStats.timePreProcess = toolRunnerPreProcess;
          if (resource.longestTime_PreProcess < toolRunnerPreProcess) {
            resource.longestTime_PreProcess = toolRunnerPreProcess;
            resource.longestTime_PreProcessTool = toolName;
          }
        }

        if (message.localCopyEndTime && message.toolExecEndTime) {
          const toolProcess = isNaN(message.toolExecEndTime - message.localCopyEndTime)
            ? 0
            : message.toolExecEndTime - message.localCopyEndTime;
          toolExecutionStats.timeProcess = toolProcess;
          if (resource.longestTime_Execution < toolProcess) {
            resource.longestTime_Execution = toolProcess;
            resource.longestTime_ExecutionTool = toolName;
          }
        }

        if (message.toolExecEndTime && message.endTime) {
          const toolRunnerPostProcess = isNaN(message.endTime - message.toolExecEndTime) ? 0 : message.endTime - message.toolExecEndTime;
          toolExecutionStats.timePostProcess = toolRunnerPostProcess;
          if (resource.longestTime_PostProcess < toolRunnerPostProcess) {
            resource.longestTime_PostProcess = toolRunnerPostProcess;
            resource.longestTime_PostProcessTool = toolName;
          }
        }

        const totalTime =
          toolExecutionStats.timeInQ +
          toolExecutionStats.timePreProcess +
          toolExecutionStats.timeProcess +
          toolExecutionStats.timePostProcess;
        toolExecutionStats.timeTotal = totalTime;
        if (totalTime > resource.longestTime_total) {
          resource.longestTime_total = totalTime;
          resource.longestTime_totalTool = toolName;
        }

        let isError = false;
        if (message.res) {
          const error = JSON.parse(message.res);
          if (error.scanStatus.toLowerCase() === "timeout") {
            toolExecutionStats.status = ToolError.Generic;
            toolExecutionStats.errorCode = 3;
            failedCollection.add(toolName);
            isError = true;
          } else if (error.scanStatus.toLowerCase() === "fail") {
            toolExecutionStats.status = ToolError.Generic;
            toolExecutionStats.errorCode = 2;
            failedCollection.add(toolName);
            isError = true;
          }

          if (error?.execErrorCode != undefined) {
            toolExecutionStats.errorCode = error?.execErrorCode?.toString();
          }

          if (!isError) {
            logger.info(
              `tool ${toolName} reported success from disk file, tool: ${toolName}, name: ${resource.name}, id: ${resource.id}, type: ${resource.type}, dir: ${toolExecutionStats.dir} errStatus: ${toolExecutionStats.status}, errorCode: ${toolExecutionStats.errorCode}, timeProcess: ${toolExecutionStats.timeProcess}, totalTime: ${totalTime}`,
            );
          }
        }
      } else {
        logger.error(`no data for tool: ${toolName}`);
      }
    } catch (err) {
      logger.error(`failed set setToolInfoFromFile for tool: ${toolName}, fileData: ${data}, resFilePath: ${resFile}, err: ${err}`, err);
    }
  }

  private static setResStatsInfo(toolName: string, stat: string, resourceName: string, resourceId: string, resourceType: ResourceType) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      StatesHelper.Instance.addFailedTool(toolName as any, resourceId);

      const key = `${stat}${toolName.toUpperCase()}`;
      if (StatesHelper.Instance.scanInfoStats[key]) {
        StatesHelper.Instance.scanInfoStats[key] = StatesHelper.Instance.scanInfoStats[key] + 1;
      } else {
        StatesHelper.Instance.scanInfoStats[key] = 1;
      }
      const keyRepo = `${stat}_${toolName.toUpperCase()}_${resourceType}`;
      if (StatesHelper.Instance.scanInfoStats[keyRepo]) {
        if (StatesHelper.Instance.scanInfoStats[keyRepo].length < 4) {
          StatesHelper.Instance.scanInfoStats[keyRepo].push(resourceName);
        }
      } else {
        StatesHelper.Instance.scanInfoStats[keyRepo] = [resourceName];
      }
    } catch (err) {
      logger.error(
        `failed set res stats info ${stat} for: ${toolName} resourceName ${resourceName}, resourceType: ${resourceType} err: ${err}`,
        err,
      );
    }
  }
}
