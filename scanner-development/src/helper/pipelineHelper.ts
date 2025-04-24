import _ from "lodash";
import { AlertSeverity, PullRequest } from "../entitis/codeRepoTypes";
import { Nullable } from "../entitis/commonTypes";
import Constant from "../entitis/constant";
import { CICDIssue, CICDIssueEnforcement, CICDIssueStatus, Issue, PipelineSummary, PipelineSummeryEventType } from "../entitis/issuesTypes";
import { Severity } from "../entitis/reportTypes";
import { ScannerMessage } from "../entitis/service/connector-message-types";
import loggerImport from "../logger";
import { Application, IssueAppData } from "../policy/reporting/types";
import { adaptLibName, getConnector } from "./commonUtils";
import { PolicyService } from "./service/policy-service/api";
import { PipelineOptionId, Policy } from "./service/policy-service/types";
import { ReportService } from "./service/report-service/api";
import StringHelper from "./stringHelper";
import { millis } from "./time-unit-utils";
import TimeHelper from "./timeHelper";
import { PolicySecurityScanAggItem } from "../policy/rules/code/policySecurityScan";
import { isDevelopment, isLocalDevelopment } from "./envUtils";
import MongoDBreportUpdates3 from "../mongo/mongoDBreportUpdates3";
import StatesHelper, { PerformanceType } from "./statesHelper";
import { PolicySbomCodeLicensesAggItem } from "../policy/rules/code/policySbomCodeLicenses";
import { constants } from "node:buffer";
import { isPipelineWorkflowsFeatureEnabledForOrg } from "./featureFlags/isPipelineWorkflowsFeatureEnabledForOrg";

const logger = loggerImport.getDebugLogger();

enum CICDType {
  AzureDevOps = "AzureDevOps",
  GitHubActions = "GitHubActions",
  GitHubApp = "GitHubApp",
  GitLabCICD = "GitLabCICD",
  Jenkins = "Jenkins",
  BitbucketPipelines = "BitbucketPipelines",
}

export class ConfigForSpecificPolicy {
  repoId: string;
  repoName: string;
  hackPolicyForPipelineScan = {};
}

interface InputPipelineScanJobInfo {
  cicdType: CICDType;
  jobId: string;
  jobTriggeredAt: string;
  jobTriggeredBy: string;
  jobTriggeredReason: string;
  jobUrl?: string;
  pullRequestId?: string;
  pullRequestUrl?: string;
  sourceBranchUrl?: string;
  targetBranchUrl?: string;
  performance: PerformanceType;
}

interface ParsedPipelineScanJobInfo extends InputPipelineScanJobInfo {
  jobTriggeredAtDate: Nullable<Date>;
}

export class PipeLineHelper {
  private static _instance: PipeLineHelper;
  repoId: string; // original repo information. in case of regular repos matches appId field. in case of monorepos does not
  repoName: string; // original repo information. in case of regular repos matches appName field. in case of monorepos does not
  sourceBranch: string;
  targetBranch: string;
  orgId: string;
  uuid: string;
  url: string;
  pipelineScanJobInfo: Nullable<ParsedPipelineScanJobInfo> = null;
  performance: PerformanceType = PerformanceType.regular;

  // populated on init for regular repos, enriched for monorepo children after split
  currentFullScanAppIssueIdsPerApp: Map<string, Set<string>> = new Map();
  // set of policies for repo (app), in case of monorepo, these are policies for the parent
  // will be used for children if children are not detected during regular scan, which means they do not have their own set of policies available on UI
  rootAppPolicies: Policy[] = [];
  // null if uninitialized; sha is not a merge commit and thus no pull requests were found; method wasn't implemented for SCM provider
  private pullRequestIntroducingMergeCommit: PullRequest | null = null;

  pipelineSummary: PipelineSummary = new PipelineSummary();

  configForSpecificPolicy: ConfigForSpecificPolicy[] = [];

  // timeout from connectors message (user provided)
  timeout: Nullable<number> = null;
  // boolean set to true if timeout is reached
  private scanTimedOut: boolean = false;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  printPolicySpecificConfig() {
    try {
      if (this.configForSpecificPolicy.length == 0) {
        logger.info(`no need to print specific policy config`);
        return;
      }

      this.configForSpecificPolicy.forEach(i => {
        const forLog = {};
        for (const [name, entry] of Object.entries(i.hackPolicyForPipelineScan)) {
          forLog[name] = (entry as Policy).name;
        }
        logger.info(`print policy specific config, repo name: ${i.repoName}, id: ${i.repoId}, config: ${JSON.stringify(forLog)}`);
      });
    } catch (err) {
      logger.error(`failed print policy specific config: ${err}`);
    }
  }

  private getPipelineScanJobInfo(info: string): ParsedPipelineScanJobInfo {
    if (!info) {
      logger.warn("no pipelineScanJobInfo passed in scanner message");
      return null;
    }

    try {
      const input: InputPipelineScanJobInfo = JSON.parse(info);
      const parsed: ParsedPipelineScanJobInfo = {
        ...input,
        jobTriggeredAtDate: TimeHelper.isoDateStringToDate(input.jobTriggeredAt),
      };

      if (parsed.jobTriggeredAtDate === null) {
        logger.warn(`unable to parse jobTriggeredAt: ${input.jobTriggeredAt}`);
      }

      logger.info("successfully parsed pipelineScanJobInfo from scanner message: " + info);
      return parsed;
    } catch (e) {
      logger.error("unable to parse pipelineScanJobInfo from scanner message", e);
      return null;
    }
  }

  getSpecificConfiguForPolicy(policy: Policy, severityAlert: Severity, repoId: string, repoName: string) {
    const isSca = policy.policyId === "oxPolicy_securityScan_120";
    const isCicd = policy.policyId === "oxPolicy_CICD_general_1";
    const isSecretHistory = policy.policyId === "oxPolicy_securityScan_secrets_history_1";
    const isSecret = policy.policyId === "oxPolicy_securityScan_secrets_1";
    const isIac = policy.policyId === "oxPolicy_securityScan_55";
    const isSast = policy.policyId === "oxPolicy_securityScan_205";
    const isScaDocker = policy.policyId === "oxPolicy_deployment_221";

    const shouldCheckPol = isSca || isCicd || isSecret || isSecretHistory || isIac || isSast || isScaDocker;
    if (!shouldCheckPol) {
      return;
    }

    const hackPolicyForPipelineScan: ConfigForSpecificPolicy = this.configForSpecificPolicy.find(i => i.repoId === repoId);
    if (!hackPolicyForPipelineScan) {
      throw `cannot set severity for pipeline specific policy due to cannot find repo id: ${repoId}, name: ${repoName}, policy id
       ${policy.policyId}, name: ${policy.name}`;
    }

    let res;
    if (isSast) {
      if (severityAlert === Severity.INFO) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.sastInfoSeverity];
      }
      if (severityAlert === Severity.LOW) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.sasttLowSeverity];
      }
      if (severityAlert === Severity.MEDIUM) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.sastMidSeverity];
      }
      if (severityAlert === Severity.HIGH) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.sastHighSeverity];
      }
      if (severityAlert === Severity.CRITICAL) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.sastCriticalSeverity];
      }
      if (severityAlert === Severity.APPOXALYPSE) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.sastAppoxSeverity];
      }
    }
    if (isIac) {
      if (severityAlert === Severity.INFO) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.iacInfoSeverity];
      }
      if (severityAlert === Severity.LOW) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.iactLowSeverity];
      }
      if (severityAlert === Severity.MEDIUM) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.iacMidSeverity];
      }
      if (severityAlert === Severity.HIGH) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.iacHighSeverity];
      }
      if (severityAlert === Severity.CRITICAL) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.iacCriticalSeverity];
      }
      if (severityAlert === Severity.APPOXALYPSE) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.iacAppoxSeverity];
      }
    }

    if (isScaDocker) {
      if (severityAlert === Severity.INFO) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.scaDockerInfoSeverity];
      }
      if (severityAlert === Severity.LOW) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.scaDockerLowSeverity];
      }
      if (severityAlert === Severity.MEDIUM) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.scaDockerMidSeverity];
      }
      if (severityAlert === Severity.HIGH) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.scaDockerHighSeverity];
      }
      if (severityAlert === Severity.CRITICAL) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.scaDockerCriticalSeverity];
      }
      if (severityAlert === Severity.APPOXALYPSE) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.scaDockerAppoxlSeverity];
      }
    } else if (isSca) {
      if (severityAlert === Severity.INFO) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.scaInfoSeverity];
      }
      if (severityAlert === Severity.LOW) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.scaLowSeverity];
      }
      if (severityAlert === Severity.MEDIUM) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.scaMidSeverity];
      }
      if (severityAlert === Severity.HIGH) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.scaHighSeverity];
      }
      if (severityAlert === Severity.CRITICAL) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.scaCriticalSeverity];
      }
      if (severityAlert === Severity.APPOXALYPSE) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.scaAppoxlSeverity];
      }
    } else if (isCicd) {
      if (severityAlert === Severity.INFO) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.generalCICDInfoSeverity];
      }
      if (severityAlert === Severity.LOW) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.generalCICDLowSeverity];
      }
      if (severityAlert === Severity.MEDIUM) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.generalCICDMidSeverity];
      }
      if (severityAlert === Severity.HIGH) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.generalCICDHighSeverity];
      }
      if (severityAlert === Severity.CRITICAL) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.generalCICDCriticalSeverity];
      }
      if (severityAlert === Severity.APPOXALYPSE) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.generalCICDAppoxSeverity];
      }
    } else if (isSecret) {
      if (severityAlert === Severity.INFO) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.secretInfoSeverity];
      }
      if (severityAlert === Severity.LOW) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.secretLowSeverity];
      }
      if (severityAlert === Severity.MEDIUM) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.secretMidSeverity];
      }
      if (severityAlert === Severity.HIGH) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.secretHighSeverity];
      }
      if (severityAlert === Severity.CRITICAL) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.secretCriticalSeverity];
      }
      if (severityAlert === Severity.APPOXALYPSE) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.secretAppoxSeverity];
      }
    } else if (isSecretHistory) {
      if (severityAlert === Severity.INFO) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.secretHistoryInfoSeverity];
      }
      if (severityAlert === Severity.LOW) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.secretHistoryLowSeverity];
      }
      if (severityAlert === Severity.MEDIUM) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.secretHistoryMidSeverity];
      }
      if (severityAlert === Severity.HIGH) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.secretHistoryHighSeverity];
      }
      if (severityAlert === Severity.CRITICAL) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.secretHistoryCriticalSeverity];
      }
      if (severityAlert === Severity.APPOXALYPSE) {
        res = hackPolicyForPipelineScan.hackPolicyForPipelineScan[Constant.secretHistoryAppoxSeverity];
      }
    }

    if (!res) {
      throw `cannot set severity for pipeline specific policy, id ${policy.policyId}, isSca: ${isSca}, isSca: ${isCicd} name: ${policy.name}`;
    }

    return res as Policy;
  }

  setDataFromScannerMessage(scannerMsg: ScannerMessage) {
    if (isDevelopment()) {
      logger.info(`setDataFromScannerMessage scanner message: ${JSON.stringify(scannerMsg)}`);
    }
    const connector = getConnector(scannerMsg);
    this.repoId = Object.values(connector.monitoredResources)[0].id;
    this.repoName = Object.values(connector.monitoredResources)[0].name;
    this.sourceBranch = Object.values(connector.monitoredResources)[0].sourceBranch;
    this.targetBranch = Object.values(connector.monitoredResources)[0].targetBranch;
    this.url = connector.hostURL;
    this.pipelineScanJobInfo = this.getPipelineScanJobInfo(scannerMsg.pipelineScanJobInfo);
    this.timeout = scannerMsg.timeout ?? null;
    this.performance = scannerMsg.performance;

    this.generateSummery();
  }

  async init() {
    await this.getFullScanAppIssueIdsForApp(this.repoId);

    this.rootAppPolicies = await PolicyService.Instance.getPipelinePoliciesByAppId(this.orgId, this.repoId);
  }

  async getFullScanAppIssueIdsForApp(appId: string) {
    // we already fetched issues for this application, don't do it again
    // when repo is not a monorepo will be called 2 times with same appId
    // otherwise will be called with monorepo children ids
    if (this.currentFullScanAppIssueIdsPerApp.has(appId)) return;

    const issueIds = await ReportService.Instance.getCurrentFullScanIssuesIds(this.orgId, appId);
    this.currentFullScanAppIssueIdsPerApp.set(appId, new Set(issueIds));
  }

  public async generateCICDIssue(
    issue: Issue,
    alert: any,
    appData: IssueAppData,
    existInInOneOfTheIssues: any,
    notExistInInOneOfTheIssues: any,
    mongoDBreportUpdates3: MongoDBreportUpdates3,
    stats: any,
  ) {
    try {
      const isPipelineWorkflowsFeatureEnabled = await isPipelineWorkflowsFeatureEnabledForOrg.isEnabled(this.orgId);

      const { issueId } = issue;
      const appIssueIdsSet = this.currentFullScanAppIssueIdsPerApp.get(appData.appId) ?? new Set();
      let isOld = appIssueIdsSet.has(issueId);
      let isNew = !isOld;

      // can drop issues likes this only when pipeline workflows are not enabled
      if (!isPipelineWorkflowsFeatureEnabled) {
        if (isNew && alert.newIssuesPipelineOptionId === PipelineOptionId.Disable) {
          logger.info(
            `issueId: ${issueId} is a new issue and according to policy its disabled. dropping issue, app: ${appData.appName}, policy: ${appData.pName}`,
          );
          return null;
        }
        if (isOld && alert.oldIssuesPipelineOptionId === PipelineOptionId.Disable) {
          logger.info(
            `issueId: ${issueId} is an old issue and according to policy its disabled. dropping issue, app: ${appData.appName}, policy: ${appData.pName}`,
          );
          return null;
        }
      }

      if (isNew) {
        if (await this.isIssueOld(issue, appData, stats)) {
          isNew = false;
          isOld = true;
        }
      }

      if (isNew) {
        logger.info(`issueId: ${issueId} is a new issue, app: ${appData.appName}, policy: ${appData.pName}`);
      }
      if (isOld) {
        logger.info(`issueId: ${issueId} is an old issue, app: ${appData.appName}, policy: ${appData.pName}`);
      }

      const originalIssueId = (" " + issueId).slice(1);

      // used when pipeline workflows are not enabled. at some point will be deprecated completely
      const scannerEnforcement =
        (isOld && alert.oldIssuesPipelineOptionId === PipelineOptionId.Block) ||
        (isNew && alert.newIssuesPipelineOptionId === PipelineOptionId.Block)
          ? CICDIssueEnforcement.Block
          : CICDIssueEnforcement.Monitor;

      const enforcement = isPipelineWorkflowsFeatureEnabled ? CICDIssueEnforcement.Pending : scannerEnforcement;

      const cicdIssue: CICDIssue = {
        ...issue,
        // extend cicd issueId with scanId as prefix
        issueId: StringHelper.combineStrings(this.uuid, issueId),
        originalIssueId,
        isBlocking: enforcement === CICDIssueEnforcement.Block, // deprecated, use `enforcement`
        enforcement,
        sourceBranch: appData.sourceBranch,
        targetBranch: appData.targetBranch,
        cicdIssueStatus: isNew ? CICDIssueStatus.New : CICDIssueStatus.Old,
        jobId: alert.pipelineScanJobInfo?.jobId,
        jobTriggeredAt: alert.pipelineScanJobInfo?.jobTriggeredAt,
        jobTriggeredAtDate: alert.pipelineScanJobInfo?.jobTriggeredAtDate,
        jobTriggeredBy: alert.pipelineScanJobInfo?.jobTriggeredBy,
        jobTriggeredReason: alert.pipelineScanJobInfo?.jobTriggeredReason,
        jobUrl: alert.pipelineScanJobInfo?.jobUrl,
        pullRequestId: alert.pipelineScanJobInfo?.pullRequestId,
        pullRequestUrl: alert.pipelineScanJobInfo?.pullRequestUrl,
      };

      return cicdIssue;
    } catch (e) {
      logger.error(`failed to generate cicd issue, app: ${appData.appName}, policy: ${appData.pName}, err: ${e}`);
      return null;
    }
  }

  async isIssueOld(currentIssueFromPipelineScan: Issue, appData: IssueAppData, stats: any) {
    try {
      const relevantSCAPolicies = ["oxPolicy_securityScan_120"];

      const relevantSbomPolicies = [
        "oxPolicy_codeSbomLicensesIndirect_1",
        "oxPolicy_codeSbomLicenses_1",
        "oxPolicy_sbomNeedUpdatingIndirect_1",
        "oxPolicy_sbomNeedUpdating_1",
        "oxPolicy_sbomDownloads_1",
        "oxPolicy_sbomDownloadsIndirect_1",
        "oxPolicy_sbomDeprecatedIndirect_1",
        "oxPolicy_sbomDeprecated_1",
      ];

      const repoName = appData.repoRealName;

      const scaPol = relevantSCAPolicies.includes(currentIssueFromPipelineScan.pId);
      if (scaPol) {
        const aggItems = currentIssueFromPipelineScan.aggItems as any;
        if (aggItems) {
          for (const aggItem of aggItems) {
            const currentAggItem = aggItem as PolicySecurityScanAggItem;
            let pkgName = adaptLibName(currentAggItem.pkgName);
            let version = currentAggItem.installedVersion;
            if (currentAggItem.isOldEvent) {
              logger.info(
                `isIssueOld: pkg and version already found in older issues. repo: ${repoName}, pkg: ${pkgName}, version: ${version}, issueType: SCA`,
              );
              continue;
            }
            logger.info(
              `isIssueOld: pkg and version didn't found in older issues (New).repo: ${repoName}, pkg: ${pkgName}, version: ${version}, issueType: SCA`,
            );
            //Found at least one that new
            return false;
          }
        }
        let elapsedTime = (new Date().getTime() - stats.startTime) / 1000;
        if (elapsedTime > 5) {
          logger.error(
            `generating issue took more than 5 seconds: ${elapsedTime} seconds for issue:${currentIssueFromPipelineScan.issueId}, repoId: ${appData.repoId}, repoName: ${appData.repoRealName}`,
          );
        }
        logger.info(`isIssueOld: didn't find new package, return old issue, repo: ${repoName}, issueType: SCA`);
        return true;
      }

      const sbomPol = relevantSbomPolicies.includes(currentIssueFromPipelineScan.pId);
      if (sbomPol) {
        const aggItems = currentIssueFromPipelineScan.aggItems as any;
        if (aggItems) {
          for (const aggItem of aggItems) {
            const currentAggItem = aggItem as PolicySbomCodeLicensesAggItem;
            let pkgName = adaptLibName(currentAggItem.libName);
            let version = currentAggItem.libVersion;
            if (currentAggItem.isOldEvent) {
              logger.info(
                `isIssueOld: pkg and version already found in older issues. repo: ${repoName}, pkg: ${pkgName}, version: ${version}, issueType: SBOM`,
              );
              continue;
            }
            logger.info(
              `isIssueOld: pkg and version didn't found in older issues (New).repo: ${repoName}, pkg: ${pkgName}, version: ${version}, issueType: SBOM`,
            );
            //Found at least one that new
            return false;
          }
        }
        let elapsedTime = (new Date().getTime() - stats.startTime) / 1000;
        if (elapsedTime > 5) {
          logger.error(
            `generating issue took more than 5 seconds: ${elapsedTime} seconds for issue:${currentIssueFromPipelineScan.issueId}, repoId: ${appData.repoId}, repoName: ${appData.repoRealName}`,
          );
        }
        logger.info(`isIssueOld: didn't find new package, return old issue, repo: ${repoName}, issueType: SBOM`);
        return true;
      }
    } catch (e) {
      logger.error(`failed to check isIssueOld, app: ${appData.appName}, policy: ${appData.pName}, err: ${e}`);
    }
    return false;
  }

  generateSummery() {
    this.pipelineSummary.jobId = this.pipelineScanJobInfo?.jobId;
    this.pipelineSummary.jobTriggeredAt = this.pipelineScanJobInfo?.jobTriggeredAt;
    this.pipelineSummary.jobTriggeredBy = this.pipelineScanJobInfo?.jobTriggeredBy;
    this.pipelineSummary.jobTriggeredReason = this.pipelineScanJobInfo?.jobTriggeredReason;
    this.pipelineSummary.jobUrl = this.pipelineScanJobInfo?.jobUrl;
    this.pipelineSummary.pullRequestId = this.pipelineScanJobInfo?.pullRequestId;
    this.pipelineSummary.pullRequestUrl = this.pipelineScanJobInfo?.pullRequestUrl;
    this.pipelineSummary.sourceBranch = this.sourceBranch;
    this.pipelineSummary.targetBranch = this.targetBranch;
    this.pipelineSummary.sourceBranchUrl = this.pipelineScanJobInfo?.sourceBranchUrl;
    this.pipelineSummary.targetBranchUrl = this.pipelineScanJobInfo?.targetBranchUrl;
    this.pipelineSummary.eventType = this.targetBranch ? PipelineSummeryEventType.PullRequest : PipelineSummeryEventType.Push;
    this.pipelineSummary.scanId = this.uuid;
    this.pipelineSummary.performance = this.performance;
  }

  enrichSummaryWithApp(app: Application) {
    const exists = !!this.pipelineSummary.apps.find(existingApp => existingApp.appId === app.appId);

    if (exists) return;

    const pipelineSummaryApp = {
      appId: app.appId,
      appName: app.appName,
      appType: app.type,
    };

    this.pipelineSummary.apps.push(pipelineSummaryApp);
  }

  private generateSummeryFromPullRequestIntroducingMergeCommit(pullRequest: PullRequest | null) {
    if (pullRequest === null) return;

    this.pipelineSummary.pullRequestId = pullRequest.id;
    this.pipelineSummary.pullRequestUrl = pullRequest.link;

    // double checking that we didn't fetch a PR for a merge commit sha when a target branch was there before overriding event type
    if (this.targetBranch) return;

    this.pipelineSummary.eventType = PipelineSummeryEventType.Merge;
    logger.info(JSON.stringify(this.pipelineSummary));
  }

  generateSummeryFromIssue(cicdIssue: CICDIssue) {
    try {
      const { enforcement, cicdIssueStatus, severity } = cicdIssue;

      this.pipelineSummary.totalIssues++;
      if (enforcement === CICDIssueEnforcement.Block) {
        this.pipelineSummary.totalBlockingIssues++;
        this.pipelineSummary.result = "Block";
      }

      if (this.pipelineSummary.result !== "Block") {
        this.pipelineSummary.result = "Monitor";
      }

      if (severity == AlertSeverity.Appoxalypse) {
        if (cicdIssueStatus === CICDIssueStatus.New) {
          this.pipelineSummary.newIssuesCountAppoxalypse++;
        } else {
          this.pipelineSummary.existingIssuesCountAppoxalypse++;
        }
      }
      if (severity == AlertSeverity.Critical) {
        if (cicdIssueStatus === CICDIssueStatus.New) {
          this.pipelineSummary.newIssuesCountCritical++;
        } else {
          this.pipelineSummary.existingIssuesCountCritical++;
        }
      }
      if (severity == AlertSeverity.High) {
        if (cicdIssueStatus === CICDIssueStatus.New) {
          this.pipelineSummary.newIssuesCountHigh++;
        } else {
          this.pipelineSummary.existingIssuesCountHigh++;
        }
      }
      if (severity == AlertSeverity.Medium) {
        if (cicdIssueStatus === CICDIssueStatus.New) {
          this.pipelineSummary.newIssuesCountMedium++;
        } else {
          this.pipelineSummary.existingIssuesCountMedium++;
        }
      }
      if (severity == AlertSeverity.Low) {
        if (cicdIssueStatus === CICDIssueStatus.New) {
          this.pipelineSummary.newIssuesCountLow++;
        } else {
          this.pipelineSummary.existingIssuesCountLow++;
        }
      }
    } catch (err) {
      logger.error(`failed to generate pipeline summery, err: ${err}`);
    }
  }

  public setPullRequestIntroducingMergeCommit(pullRequest: PullRequest | null) {
    this.pullRequestIntroducingMergeCommit = pullRequest;
    this.generateSummeryFromPullRequestIntroducingMergeCommit(pullRequest);
  }

  // in bitbucket, provided jobTriggeredBy is a uuid {f313ae8b-c1ea-4177-a081-b362781cbaaa}. we fetch human-readable info on the scanner
  public setJobTriggeredBy(jobTriggeredBy: string | null) {
    if (!jobTriggeredBy) return;

    this.pipelineScanJobInfo.jobTriggeredBy = jobTriggeredBy;
    this.pipelineSummary.jobTriggeredBy = jobTriggeredBy;
  }

  public setScanTimeout() {
    if (!_.isFinite(this.timeout)) return; // value not provided by connectors

    setTimeout(() => {
      this.scanTimedOut = true;
    }, millis.from.minutes(this.timeout));
  }

  public shouldTimeOutScan() {
    return this.scanTimedOut;
  }

  extractOriginalIssueId(issueId: string) {
    try {
      const splitterIssueId = issueId.split("-");
      const newIssueIdSplitted = splitterIssueId.splice(5);
      const originalIssueId = newIssueIdSplitted.join("-");

      const regexExp = /^[0-9a-fA-F]{8}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{4}\b-[0-9a-fA-F]{12}$/gi;
      const uid = splitterIssueId.join("-");
      const isUid = regexExp.test(uid);
      if (isUid) return originalIssueId;
      return issueId;
    } catch (e) {
      logger.error(`failed to split issueId: ${issueId}, e: ${e}`);
      return issueId;
    }
  }
}
