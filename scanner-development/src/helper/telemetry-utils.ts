import telemetry, { TelemetryInput, TelemetryTags, TelemetryType } from "@oxappsec/ox-unified-telemetry";
import loggerImport from "../logger";
import StatesHelper, { PipelineInfo } from "./statesHelper";
import { isLocalDevelopment } from "./envUtils";
import { ScannerTelemetryType } from "@oxappsec/ox-unified-telemetry";
import { ToolsExecutionStats } from "./toolExecutionStats";

const logger = loggerImport.getDebugLogger();
let debug = process.env.DEBUG != undefined;
const LONG_TERM_TIMEOUT = 30000;

export const sendScannerStringTelemetry = async (ScanMetric: ScanMetric, OrgId: string, ScanID: string, messageTelemetry: string) => {
  try {
    if (debug) {
      return;
    }

    const toolStats = ToolsExecutionStats.getItemForFullScanInfo();

    const longTermScannerInfo: ScannerTelemetryType = {
      orgId: OrgId,
      orgDisplayName: process.env.companyName,
      scanId: ScanID,
      scanType: !isLocalDevelopment() ? StatesHelper.Instance.scanType : "full",
      metricName: ScanMetric,
      telemetryType: TelemetryType.Count,
      tags: {
        toolStats,
        isScheduledScan: StatesHelper.Instance.isScheduledScan,
        message: messageTelemetry.replace(/['"]+/g, ""),
        numberOfApps: StatesHelper.Instance.numberOfApps || 0,
      },
      //toolInfo: StatesHelper.Instance.pipelineScanToolStats,
      points: [{ time: new Date(), value: 1 }],
    };

    logger.info(`Sending scanner telemetry, orgId: ${OrgId}, scanId: ${ScanID}, message: ${JSON.stringify(longTermScannerInfo)}`);
    await telemetry.longTerm.sendScannerTelemetry(longTermScannerInfo, LONG_TERM_TIMEOUT);

    const telemetryInput: TelemetryInput = {
      metricName: ScanMetric,
      telemetryType: TelemetryType.Count,
      tags: [
        `${TelemetryTags.OrgId}:${OrgId}`,
        `${TelemetryTags.ScanId}:${ScanID}`,
        `${TelemetryTags.OrgDisplayName}:${process.env.companyName}`,
        `scanType:${StatesHelper.Instance.scanType}`,
        `isScheduledScan:${StatesHelper.Instance.isScheduledScan}`,
        `msg:${messageTelemetry.replace(/['"]+/g, "")}`,
      ],
      points: [[new Date().getTime() / 1000, 1]],
    };

    telemetry.v2.send(telemetryInput);
  } catch (error) {
    logger.error("fail to send scanner telemetry ", error);
  }
};

export const sendScannerFailedProcessSingleRepoTelemetry = async (OrgId: string, ScanID: String, RepoName: string) => {
  try {
    if (debug) {
      return;
    }

    const telemetryInput: TelemetryInput = {
      metricName: ScanMetric.Error,
      telemetryType: TelemetryType.Count,
      tags: [
        `${TelemetryTags.OrgId}:${OrgId}`,
        `${TelemetryTags.ScanId}:${ScanID}`,
        `${TelemetryTags.OrgDisplayName}:${process.env.companyName}`,
        `scanType:${StatesHelper.Instance.scanType}`,
        `errorName:${ScanErrorName.FailedProcessSingleRepo}`,
        `repoName:${RepoName}`,
      ],
      points: [[new Date().getTime() / 1000, 1]],
    };

    await telemetry.send(telemetryInput);
  } catch (error) {
    logger.error("fail to send scanner telemetry ", error);
  }
};

export const sendScannerMongoErrorTelemetry = async (ScanErrorName: any, message: string, OrgId: string, ScanID: String) => {
  try {
    if (debug) {
      return;
    }

    const telemetryInput: TelemetryInput = {
      metricName: ScanMetric.MongoError,
      telemetryType: TelemetryType.Count,
      tags: [
        `${TelemetryTags.OrgId}:${OrgId}`,
        `${TelemetryTags.ScanId}:${ScanID}`,
        `${TelemetryTags.OrgDisplayName}:${process.env.companyName}`,
        `scanType:${StatesHelper.Instance.scanType}`,
        `errorName:${ScanErrorName}`,
        `errorMessage:${message.replace(/['"]+/g, "")}`,
      ],
      points: [[new Date().getTime() / 1000, 1]],
    };

    telemetry.v2.send(telemetryInput);
  } catch (error) {
    logger.error("fail to send scanner telemetry ", error);
  }
};

export const sendScannerPhaseTimeTelemetry = async (ScanPhaseTime: ScanPhaseTime, OrgId: string, ScanID: String, value: number) => {
  try {
    if (debug) {
      return;
    }

    const scanPhaseInfo = {
      orgId: OrgId,
      orgDisplayName: process.env.companyName,
      scanId: ScanID as string,
      scanType: !isLocalDevelopment() ? StatesHelper.Instance.scanType : "full",
      metricName: ScanMetric.ScanPhasesTime,
      telemetryType: TelemetryType.Count,
      tags: {
        isScheduledScan: StatesHelper.Instance.isScheduledScan,
        ElapsedTime: value,
        ScanPhasesTime: ScanPhaseTime,
      },
      // points: [[new Date().getTime() / 1000, value]],
      points: [{ time: new Date(), value: 1 }],
    };

    logger.info(`Sending ScanPhaseTime telemetry, orgId: ${OrgId}, scanId: ${ScanID}, message: ${JSON.stringify(scanPhaseInfo)}`);
    await telemetry.longTerm.sendScannerTelemetry(scanPhaseInfo, LONG_TERM_TIMEOUT);

    const telemetryInput: TelemetryInput = {
      metricName: ScanMetric.ScanPhasesTime,
      telemetryType: TelemetryType.Count,
      tags: [
        `${TelemetryTags.OrgId}:${OrgId}`,
        `${TelemetryTags.ScanId}:${ScanID}`,
        `${TelemetryTags.OrgDisplayName}:${process.env.companyName}`,
        `scanType:${StatesHelper.Instance.scanType}`,
        `isScheduledScan:${StatesHelper.Instance.isScheduledScan}`,
        `ElapsedTime:${value}`,
        `ScanPhasesTime:${ScanPhaseTime}`,
      ],
      points: [[new Date().getTime() / 1000, value]],
    };

    telemetry.v2.send(telemetryInput);
  } catch (error) {
    logger.error("fail to send scanner telemetry ", error);
  }
};

export const sendScannerTimeTelemetry = async (ScanMetric: ScanMetric, OrgId: string, ScanID: string, value: number) => {
  try {
    if (debug) {
      return;
    }

    const scannerTimeInfo = {
      orgId: OrgId,
      orgDisplayName: process.env.companyName,
      scanId: ScanID as string,
      scanType: !isLocalDevelopment() ? StatesHelper.Instance.scanType : "full",
      metricName: ScanMetric,
      telemetryType: TelemetryType.Count,
      tags: {},
      // points: [[new Date().getTime() / 1000, value]],
      points: [{ time: new Date(), value: 1 }],
    };

    logger.info(`Sending scanner time telemetry, orgId: ${OrgId}, scanId: ${ScanID}, message: ${JSON.stringify(scannerTimeInfo)}`);
    await telemetry.longTerm.sendScannerTelemetry(scannerTimeInfo, LONG_TERM_TIMEOUT);

    const telemetryInput: TelemetryInput = {
      metricName: ScanMetric,
      telemetryType: TelemetryType.Count,
      tags: [
        `${TelemetryTags.OrgId}:${OrgId}`,
        `${TelemetryTags.ScanId}:${ScanID}`,
        `${TelemetryTags.OrgDisplayName}:${process.env.companyName}`,
        `scanType:${StatesHelper.Instance.scanType}`,
      ],
      points: [[new Date().getTime() / 1000, value]],
    };

    telemetry.v2.send(telemetryInput);
  } catch (error) {
    logger.error("fail to send scanner telemetry ", error);
  }
};

export const sendDeltaScansTelemetry = async (
  ScanMetric: ScanMetric,
  OrgId: string,
  ScanID: string,
  totalApps: number,
  unchangedApplications: number,
  changedApplications: number,
) => {
  try {
    if (debug) {
      return;
    }

    const deltaScanInfo = {
      orgId: OrgId,
      orgDisplayName: process.env.companyName,
      scanId: ScanID as string,
      scanType: !isLocalDevelopment() ? StatesHelper.Instance.scanType : "delta",
      metricName: ScanMetric,
      telemetryType: TelemetryType.Count,
      tags: {
        totalApps: totalApps,
        unchangedApplications: unchangedApplications,
        changedApplications: changedApplications,
      },
      // points: [[new Date().getTime() / 1000, 1]],
      points: [{ time: new Date(), value: 1 }],
    };

    logger.info(`Sending scanner time telemetry, orgId: ${OrgId}, scanId: ${ScanID}, message: ${JSON.stringify(deltaScanInfo)}`);
    await telemetry.longTerm.sendScannerTelemetry(deltaScanInfo, LONG_TERM_TIMEOUT);

    const telemetryInput: TelemetryInput = {
      metricName: ScanMetric,
      telemetryType: TelemetryType.Count,
      tags: [
        `${TelemetryTags.OrgId}:${OrgId}`,
        `${TelemetryTags.ScanId}:${ScanID}`,
        `${TelemetryTags.OrgDisplayName}:${process.env.companyName}`,
        `scanType:${StatesHelper.Instance.scanType}`,
        `totalApps:${totalApps}`,
        `unchangedApplications:${unchangedApplications}`,
        `changedApplications:${changedApplications}`,
      ],
      points: [[new Date().getTime() / 1000, 1]],
    };

    telemetry.v2.send(telemetryInput);
  } catch (error) {
    logger.error("fail to send scanner delta scans telemetry ", error);
  }
};

export const millisToMinutesAndSeconds = millis => {
  const date = new Date(millis);
  let seconds = date.getSeconds();
  let secondStr = seconds.toString();
  if (seconds < 10) {
    secondStr = `0${seconds}`;
  }
  const res = `${date.getMinutes()}.${secondStr}`;
  const numRes = Number(res);
  return numRes;
};

export const sendPipelineScanPerformanceTelemetry = async (orgId: string, scanId: string, pipelineInfo: PipelineInfo) => {
  if (debug) return;

  try {
    const summaryKeysToReport: (keyof PipelineInfo)[] = [
      "repoName",
      "scannerTimeInQueue",
      "scannerExecutionTime",
      "end2endScan",
      "performance",
      "numberOfFilesScanned",
      "enforcement",
      "sourceType",
    ];
    const summaryTags = summaryKeysToReport.map(key => `${key}:${pipelineInfo[key]}`);

    const serviceExecutionTimeTags = Object.entries(ToolsExecutionStats.getItemForPipelineInfo()).map(([key, value]) => `${key}:${value}`);
    const filesModifiedInPullRequestTags = Object.entries(pipelineInfo.filesModifiedInPullRequest).map(
      ([key, value]) => `filesModifiedInPullRequest_${key}:${value}`,
    );

    const telemetryInput: TelemetryInput = {
      metricName: ScanMetric.PipelineScanPerformance,
      telemetryType: TelemetryType.Count,
      tags: [
        `${TelemetryTags.ScanId}:${scanId}`,
        `${TelemetryTags.OrgId}:${orgId}`,
        `${TelemetryTags.OrgDisplayName}:${process.env.companyName}`,
        ...serviceExecutionTimeTags,
        ...summaryTags,
        ...filesModifiedInPullRequestTags,
      ],
      points: [[new Date().getTime() / 1000, 1]],
    };

    telemetry.v2.send(telemetryInput);
  } catch (error) {
    logger.error("fail to send scanner telemetry ", error);
  }
};

export const stopSendingTelemetry = async () => {
  await telemetry.v2.flush();
};

export enum ScanPhaseTime {
  ScanDiscoveryPhaseTime = "Scan-Discovery-Phase",
  ScanRepoPhaseTime = "Scan-Repository-Phase",
  ScanCicdPhaseTime = "Scan-CICD-Phase",
  ScanArtifactsPhaseTime = "Scan-Artifacts-Phase",
  ScanCloudPhaseTime = "Scan-Cloud-Phase",
  ScanCloudProwlerPhaseTime = "Scan-Cloud-Prowler-Phase",
  ScanSummeryPhaseTime = "Scan-Summery-And-Finish-Phase",
  ScanFromStartToMsg = "Scan-From-Start-To-Msg",
  ScanExecTime = "ScanExecTime",
  ScanSbomPhaseTime = "ScanSbomPhaseTime",
  ScanOpenWikiPhaseTime = "ScanOpenWikiPhaseTime",
  ScanSupplyChainTime = "ScanSupplyChainTime",
  ScanToolTimeInQueue = "ScanToolTimeInQueue",
}

export enum ScanErrorName {
  UncaughtException = "Uncaught-Exception",
  SIGTERMshutdonw = "SIGTERM-Shutdown",
  FailedGetAllPolicy = "Failed-Get-All-Policys",
  FailedGetAllExclusions = "Failed-Get-All-Exclusions",
  FailedAddSinglExclusions = "Failed-Add-Single-Exclusions-Type",
  FailedUpdateDoneForDiscovery = "Failed-Update-Done-For-Discovery-Phase",
  FailedRevertScanData = "Failed-Revert-Scan-Data",
  FailedUpdateDoneForOverview = "Failed-Update-Done-For-Overview-Phase",
  FailedUpdateDoneForDetails = "Failed-Update-Done-For-Details-Phase",
  FailedGetRepoImportance = "Failed-Get-Repo-Importance",
  FailedUpdateDB = "Failed-Update-DB",
  FailedRemoveActiveScan = "Failed-Remove-Active-Scan",
  FailedCheckCnacelScan = "Failed-Check-Cancel-Active-Scan",
  FailedQueryPolicy = "Failed-Fetch-Policies-From-Policy-Service",
  FailedQueryCategories = "Failed-Fetch-Categories-From-Policy-Service",
  FailedSendSQSmsg = "Failed-Send-SQS-msg",
  FailedSendRedisMsg = "Failed-Send-Redis-Msg",
  FailedCreateRedisPupSub = "Failed-Create-Redis-PupSub",
  FailedCreateKinesisPupSub = "Failed-Create-Kinesis-PupSub",
  FailedReceiveKinesisMsg = "Failed-Receive-Kinesis-Msg",
  FailedSetAWScred = "Failed-Set-AWS-Credentials",
  FailedCreateCollector = "Failed-Create-Collector",
  FailedCollectAllRepos = "Failed-Collect-All-Repos",
  FailedCollectAllCicds = "Failed-Collect-All-CICD",
  FailedCollectAllArtifacts = "Failed-Collect-All-Artifacts",
  FailedCollectAllExternal = "Failed-Collect-All-External",
  FailedCollectAllCloud = "Failed-Collect-All-Cloud",
  FailedRunSinglePolicy = "Failed-Run-Single-Policy",
  FailedParseToolResults = "Failed-Parse-Tool-Results",
  ToolTimeout = "Tool-Timeout",
  ToolFailed = "Tool-Failed",
  ExclusionError = "Failed-Set-Exclusion",
  FailedClone = "Failed-Clone-Scanner",
  FailedCloneExternalService = "Failed-Clone-By-External-Service",
  FailedCloneDueToTimeout = "Failed-clone-due-to-timeout",
  FailedGetAllCategories = "Failed-Get-All-Categories",
  HighMemory = "High-Memory",
  FailedQueryApplications = "Failed-Get-Applications",
  FailedQueryIssues = "Failed-Get-Issues",
  FailedQueryMonorepoSplits = "Failed-Get-Monorepo-Splits",
  FailedSaveScanDataToMogno = "Failed-save-scan-data-to-mongo",
  FailedDeleteScanDataFromMogno = "Failed-delete-scan-data-from-mongo",
  FailedBlameBatches = "Failed-blame-batches",
  FailedBlameTimeout = "Failed-blame-timeout",
  FailedSecretBatches = "Failed-secret-batches",
  FailedSecretTimeout = "Failed-secret-timeout",
  FailedAutoFixBatches = "Failed-autofix-batches",
  FailedAutoFixTimeout = "Failed-autofix-timeout",
  FailedOpenWikiBatches = "Failed-openwiki-batches",
  FailedOpenWikiTimeout = "Failed-openwiki-timeout",
  FailedDependencyGraphBatches = "Failed-dependency-graph-batches",
  FailedDependencyGraphTimeout = "Failed-dependency-graph-timeout",
  FailedCallGraphBatches = "Failed-call-graph-batches",
  FailedAPIDiscoveryTimeout = "Failed-API-discovery-timeout",
  FailedAPIDiscoveryBatches = "Failed-API-discovery-batches",
  FailedLlmClientTimeout = "Failed-llm-client-timeout",
  FailedLlmClientBatches = "Failed-llm-client-batches",
  FailedAttackPathTimeout = "Failed-Attack-Path-timeout",
  FailedAttackPathBatches = "Failed-Attack-Path-batches",
  FailedCallGraphTimeout = "Failed-call-graph-timeout",
  FailedDockerfileScannerBatches = "Failed-dockerfile-scanner-batches",
  FailedDockerfileScannerTimeout = "Failed-dockerfile-scanner-timeout",
  FailedPip2poetryBatches = "Failed-pip2poetry-batches",
  FailedAWSinfoBatches = "Failed-awsInfo-batches",
  FailedCloudGraphBatches = "Failed-cloudGraph-batches",
  FailedCloudGraphTimeout = "Failed-cloudGraph-timeout",
  FailedPip2poetryTimeout = "Failed-pip2poetry-timeout",
  FailedProcessSingleRepo = "Failed-process-single-repo",
  FailedResolveIssueValidationTimeout = "Failed-resolve-issues-timeout",
  FailedResolveIssueValidation = "Failed-resolve-issues",
}

export enum ScanMetric {
  Error = "Error",
  ScanSuccess = "ScanSuccess",
  ScanFail = "ScanFail",
  ScanMemory = "ScanMemory",
  ScanPhasesTime = "ScanPhasesTime",
  FirstDiscoveryItemTime = "FirstDiscoveryItemTime",
  FirstOverviewItemTime = "FirstOverviewItemTime",
  MongoError = "MongoError",
  ToolExitCodeMetric = "ToolExitCodeMetric",
  DeltaScansMetric = "DeltaScansMetric",
  SeverityAndRelevantMetric = "SeverityAndRelevantMetric",
  EC2Metric = "EC2Metric",
  CancelScan = "CancelScan",
  PipelineScanPerformance = "PipelineScanPerformance",
}
