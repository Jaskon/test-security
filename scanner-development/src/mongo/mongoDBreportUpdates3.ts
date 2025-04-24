import { PromisePool } from "@supercharge/promise-pool/dist/promise-pool";
import mongoose from "mongoose";
import pRetry from "p-retry";
import { ApiSecurityItem } from "../entitis/apiTypes";
import { AppSbom, AppSbomType, Sbom } from "../entitis/artifactoryTypes";
import { AttackGraph } from "../entitis/attackPathTypes";
import { ImageDetail } from "../entitis/cloudTypes";
import { Repo } from "../entitis/codeRepoTypes";
import {
  CICDIssueDocument,
  Issue,
  IssueDocument,
  PipelineSummary,
  PipelineSummeryDocument,
  SeverityHistoryInfo,
  SeverityHistoryItem,
} from "../entitis/issuesTypes";
import { OrgSbom } from "../entitis/sbomTypes";
import { sleep } from "../helper/commonUtils";
import { compress } from "../helper/compression/zStream";
import { PerformanceTelemetry } from "../helper/decorators/PerformanceTelemetry";
import { isDevelopment, isLocalDevelopment } from "../helper/envUtils";
import MemoryMonitorHelper from "../helper/IO/memoryMonitorHelper";
import StatesHelper from "../helper/statesHelper";
import { ScanErrorName, sendScannerMongoErrorTelemetry } from "../helper/telemetry-utils";
import loggerImport from "../logger";
import {
  AppHistoryScore,
  Application,
  DiscoverySystem,
  IScanSummaryHistory,
  ScanInfo,
  ScanSummaryHistory,
} from "../policy/reporting/types";
import MongoConnect from "./mongoConnect";
import MongoModel from "./mongoModel";
import {
  AggItem,
  ApiSecurityItemHistorySchema,
  ApiSecurityItemSchema,
  AppHistoricalScoreSchema,
  ApplicationSchema,
  AppSbomSchema,
  AttackGraphSchema,
  CICDIssueSchema,
  DiscoverySystemSchema,
  IssueSchema,
  OrgSbomSchema,
  PipelineSchema,
  PrevIssueSchema,
  ScanInfoSchema,
  ScanSummaryHistorySchema,
  SeverityHistorySchema,
  SilentSigIssueSchema,
  UniqueIssueSchema,
} from "./schemas";

const logger = loggerImport.getDebugLogger();

class MongoDBreportUpdates3 {
  mongoConnect: MongoConnect;
  uuid: string;
  org: string;
  totalBatch: number;
  lastUpdateTime: number;
  Application: MongoModel<Application> = null;
  ScanInfo: MongoModel<ScanInfo> = null;
  DiscoverySystem: MongoModel<DiscoverySystem> = null;
  AppHistoricalScore: MongoModel<AppHistoryScore> = null;
  // Issue: MongoModel<IssueDocument> = null;
  CurrentIssue: MongoModel<IssueDocument> = null;
  SeverityHistory: MongoModel<SeverityHistoryItem> = null;
  CICDIssue: MongoModel<CICDIssueDocument> = null;
  SilentSigIssue: MongoModel<Issue> = null;
  PipelineSummary: MongoModel<PipelineSummeryDocument> = null;
  AppSbom: MongoModel<AppSbom> = null;
  AttackGraph: MongoModel<AttackGraph> = null;
  OrgSbom: MongoModel<OrgSbom> = null;
  UniqueIssue: MongoModel<Issue> = null;
  PrevIssue: MongoModel<Issue> = null;
  APiSecurity: MongoModel<ApiSecurityItem> = null;
  APiSecurityHistory: MongoModel<ApiSecurityItem> = null;
  cachedIssues: Issue[] = [];
  ScanSummaryHistory: MongoModel<IScanSummaryHistory> = null;
  public keepUpdating = true;
  constructor(uuid: string, orgName: string, mongoConnect: MongoConnect) {
    this.org = orgName;
    this.uuid = uuid;
    this.mongoConnect = mongoConnect;
    this.totalBatch = 1;
    this.lastUpdateTime = new Date().getTime();

    this.Application = new MongoModel("applications", [{ schemaName: "applications", schema: ApplicationSchema }], this.org, this.uuid);

    this.ScanInfo = new MongoModel("scan-info", [{ schemaName: "scan-info", schema: ScanInfoSchema }], this.org, this.uuid);

    this.DiscoverySystem = new MongoModel(
      "discovery-system",
      [{ schemaName: "discovery-system", schema: DiscoverySystemSchema }],
      this.org,
      this.uuid,
    );

    this.AppHistoricalScore = new MongoModel(
      "app-history-score",
      [{ schemaName: "app-history-score", schema: AppHistoricalScoreSchema }],
      this.org,
      this.uuid,
    );

    this.APiSecurity = new MongoModel(
      "api-security",
      [{ schemaName: "api-security", schema: ApiSecurityItemSchema }],
      this.org,
      this.uuid,
      null,
      true,
    );

    this.APiSecurityHistory = new MongoModel(
      "api-security-history",
      [{ schemaName: "api-security-history", schema: ApiSecurityItemHistorySchema }],
      this.org,
      this.uuid,
      null,
      true,
    );

    this.CurrentIssue = new MongoModel("current-issues", [{ schemaName: "current-issues", schema: IssueSchema }], this.org, this.uuid);

    this.CICDIssue = new MongoModel("cicd-issue", [{ schemaName: "cicd-issue", schema: CICDIssueSchema }], this.org, this.uuid);

    this.PipelineSummary = new MongoModel(
      "pipeline-summaries",
      [{ schemaName: "pipeline-summaries", schema: PipelineSchema }],
      this.org,
      this.uuid,
    );
    this.SilentSigIssue = new MongoModel(
      "silent-signature-issues",
      [{ schemaName: "silent-signature-issues", schema: SilentSigIssueSchema }],
      this.org,
      this.uuid,
    );

    this.AppSbom = new MongoModel("app-sbom", [{ schemaName: "app-sbom", schema: AppSbomSchema }], this.org, this.uuid);
    this.AttackGraph = new MongoModel("attack-graphs", [{ schemaName: "attack-graphs", schema: AttackGraphSchema }], this.org, this.uuid);
    this.OrgSbom = new MongoModel("org-sbom", [{ schemaName: "org-sbom", schema: OrgSbomSchema }], this.org, this.uuid);
    this.UniqueIssue = new MongoModel("unique-issues", [{ schemaName: "unique-issues", schema: UniqueIssueSchema }], this.org, this.uuid);
    this.PrevIssue = new MongoModel("prev-issues", [{ schemaName: "prev-issues", schema: PrevIssueSchema }], this.org, this.uuid);
    this.ScanSummaryHistory = new MongoModel(
      "scan-summary-history",
      [{ schemaName: "scan-summary-history", schema: ScanSummaryHistorySchema }],
      this.org,
      this.uuid,
    );
    this.SeverityHistory = new MongoModel(
      "issue-severity-history",
      [{ schemaName: "issue-severity-history", schema: SeverityHistorySchema }],
      this.org,
      this.uuid,
    );
  }

  getDifferenceInSeconds(date1, date2) {
    const diffInMs = Math.abs(date2 - date1);
    return diffInMs / 1000;
  }

  async getApiItems(scanId: string, apiIds: string[]) {
    let apiItems: ApiSecurityItem[] = [];
    try {
      await pRetry(
        async () => {
          await this.APiSecurity.verifyConnection(this.mongoConnect);
          apiItems = await this.APiSecurity.model.find({ scanId, uuid: apiIds });
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.APiSecurity.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to get api items, scanId: ${scanId}, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedQueryIssues, errMsg, this.org, this.uuid);
    }

    return apiItems;
  }

  async updateAllApiItems(apiItems: ApiSecurityItem[]) {
    try {
      if (!this.keepUpdating || this.APiSecurity === null) {
        logger.info(`skip updating all applications (sigterm or cancel scan called)`);
        return true;
      }
      logger.info(`try updateAllApiItems`);

      await this.APiSecurity.verifyConnection(this.mongoConnect);

      const promises = apiItems.map(apiItem => {
        return this.updateApiItem(apiItem);
      });

      return (await Promise.all(promises)).every(i => i);
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed update all applications, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
      return false;
    }
  }

  async updateApiItem(apiItem: ApiSecurityItem) {
    if (this.APiSecurity === null || !this.keepUpdating) {
      logger.info(`skip updating application (sigterm or cancel scan called)`);
      return true;
    }
    try {
      await pRetry(
        async () => {
          await this.APiSecurity.verifyConnection(this.mongoConnect);

          const res = await this.APiSecurity.model
            .updateOne()
            .where("uuid")
            .equals(apiItem.uuid)
            .where("scanId")
            .equals(apiItem.scanId)
            .set({ issuesBySeverity: apiItem.issuesBySeverity })
            .setOptions({ upsert: true })
            .exec();
          return true;
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.APiSecurity.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;

      const errMsg = `Failed update schema ApiSecurity, err: ${err}, apiItem: ${apiItem.uuid}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async doesOldIssueContainPkg(libName: string, libVersion: string, repoId: string, issue: Issue): Promise<boolean> {
    try {
      await this.CurrentIssue.verifyConnection(this.mongoConnect);
      let result;

      const innerFilter = { $elemMatch: { libName, libVersion } };
      if (StatesHelper.Instance.orgName === "org_Tq5tmkOMJ1naSHoi") {
        delete innerFilter.$elemMatch.libVersion;
      }
      result = await this.CurrentIssue.model.findOne(
        { categoryId: issue.categoryId, repoId, [issue.categoryId === 7 ? "aggItems" : "scaVulnerabilities"]: innerFilter },
        { _id: 1 },
      );

      logger.info(
        `doesOldIssueContainPkg: result of pkgName: ${libName}, version: ${libVersion}, repoId: ${repoId}, id:${
          result?._id
        } is: ${!!result}`,
      );

      return !!result;
    } catch (err) {
      logger.error(`Mongo failed finding issue with packagName: ${libName}, version: ${libVersion}, err: ${err}`, err);
      return false;
    }
  }

  async updateApplication(application: Application) {
    if (this.Application === null || !this.keepUpdating) {
      logger.info(`skip updating application (sigterm or cancel scan called)`);
      return true;
    }
    try {
      await pRetry(
        async () => {
          await this.Application.verifyConnection(this.mongoConnect);

          logger.debug(`saving app id: ${application.appId}, appName: ${application.appName}, appType: ${application.type}`);

          const res = await this.Application.model
            .updateOne()
            .where("appId")
            .equals(application.appId)
            .where("scanId")
            .equals(application.scanId)
            .set({ ...application })
            .setOptions({ upsert: true })
            .exec();

          this.Application.firstUpdateHappen = true;
          return true;
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.Application.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;

      const errMsg = `Failed update schema Application, err: ${err}, app: ${application.appName}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async updateScanInfo(scanInfo: ScanInfo) {
    try {
      if (!this.keepUpdating || this.ScanInfo === null) {
        logger.info(`skip updating scan info (sigterm or cancel scan called)`);
        return true;
      }
      if (!this.ScanInfo.firstUpdateHappen) {
        this.ScanInfo.firstUpdateHappen = true;
        await pRetry(
          async () => {
            await this.ScanInfo.verifyConnection(this.mongoConnect);
            if (StatesHelper.Instance.useMongoDBOptimizedQueries) {
              const bulkInsert = this.ScanInfo.model.collection.initializeUnorderedBulkOp();
              bulkInsert.insert(new this.ScanInfo.model(scanInfo));
              await bulkInsert.execute();
            } else {
              await this.ScanInfo.model.create(scanInfo);
            }
            return true;
          },
          {
            retries: 2,
            onFailedAttempt: async () => {
              await this.ScanInfo.verifyConnection(this.mongoConnect);
            },
          },
        );
      } else {
        await pRetry(
          async () => {
            await this.ScanInfo.verifyConnection(this.mongoConnect);
            const { scanId } = scanInfo;
            if (StatesHelper.Instance.useMongoDBOptimizedQueries) {
              const bulkInsert = this.ScanInfo.model.collection.initializeUnorderedBulkOp(); //tomerzaidler
              bulkInsert.find({ scanId }).updateOne({ $set: { ...scanInfo } });
              await bulkInsert.execute();
            } else {
              await this.ScanInfo.model
                .updateOne()
                .where("scanId")
                .equals(scanId)
                .set({ ...scanInfo })
                .exec();
            }
            return true;
          },
          {
            retries: 2,
            onFailedAttempt: async () => {
              await this.ScanInfo.verifyConnection(this.mongoConnect);
            },
          },
        );
      }
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;

      const errMsg = `Failed update schema ScanInfo, org: ${this.org}, err: ${err}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async updateSystems(discoverySystems: DiscoverySystem[]) {
    try {
      if (!this.keepUpdating || this.DiscoverySystem === null) {
        logger.info(`skip updating systems (sigterm or cancel scan called)`);
        return true;
      }
      logger.info(`try updateSystems`);

      if (!this.DiscoverySystem.firstUpdateHappen) {
        this.DiscoverySystem.firstUpdateHappen = true;
        await pRetry(
          async () => {
            await this.DiscoverySystem.verifyConnection(this.mongoConnect);
            if (StatesHelper.Instance.useMongoDBOptimizedQueries) {
              const bulkInsert = this.DiscoverySystem.model.collection.initializeUnorderedBulkOp(); //tomerzaidler
              for (const ds of discoverySystems) {
                bulkInsert.insert(ds);
              }
              await bulkInsert.execute();
            } else {
              const results = discoverySystems.map(ds => {
                return this.DiscoverySystem.model.create(ds);
              });
              await Promise.all(results);
            }
            return true;
          },
          {
            retries: 2,
            onFailedAttempt: async () => {
              await this.DiscoverySystem.verifyConnection(this.mongoConnect);
            },
          },
        );
      } else {
        await pRetry(
          async () => {
            await this.DiscoverySystem.verifyConnection(this.mongoConnect);
            if (StatesHelper.Instance.useMongoDBOptimizedQueries) {
              const bulkInsert = this.DiscoverySystem.model.collection.initializeUnorderedBulkOp(); //tomerzaidler
              for (const ds of discoverySystems) {
                bulkInsert
                  .find({ type: ds.type, scanId: ds.scanId })
                  .upsert()
                  .updateOne({ $set: { systems: ds.systems } });
              }
              await await bulkInsert.execute();
            } else {
              const results = discoverySystems.map(ds => {
                return this.DiscoverySystem.model
                  .updateOne()
                  .where("type")
                  .equals(ds.type)
                  .where("scanId")
                  .equals(ds.scanId)
                  .set({ systems: ds.systems, scanId: ds.scanId })
                  .setOptions({ upsert: true })
                  .exec();
              });
              await Promise.all(results);
            }
            this.DiscoverySystem.firstUpdateHappen = true;
            return true;
          },
          {
            retries: 2,
            onFailedAttempt: async () => {
              await this.DiscoverySystem.verifyConnection(this.mongoConnect);
            },
          },
        );
      }
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`Failed update schema DiscoverySystem, org: ${this.org}, err: ${err}`);
      logger.error(`db connect status code: ${this.mongoConnect.connection.readyState}`);
    }
    return false;
  }

  async addIssues(issues: Issue[], appId: string) {
    try {
      if (!this.keepUpdating || this.CurrentIssue === null) {
        logger.info(`skip updating issue (sigterm or cancel scan called)`);
        return true;
      }
      await this.CurrentIssue.verifyConnection(this.mongoConnect);

      await PromisePool.for(issues)
        .withConcurrency(30)
        .process(async (issue: Issue) => {
          try {
            await this.addCurrentIssue(issue);
            return true;
          } catch (err) {
            logger.error(`failed addCurrentIssue from prom pool, err: ${err}`);
            return false;
          }
        });
      return true;
    } catch (e) {
      logger.error(`failed to add issues, app: ${appId}, error: ${e}`);
    }
    return false;
  }

  private async addCurrentIssue(issue: Issue) {
    try {
      if (!this.keepUpdating || this.CurrentIssue === null) {
        logger.info(`skip adding current issue (sigterm or cancel scan called)`);
      }

      await pRetry(
        async () => {
          const currentIssue = await this.CurrentIssue.model.create(issue);
          issue.currentIssueMongoId = currentIssue._id;
          return true;
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.CurrentIssue.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      logger.error(
        `issueId: ${issue.issueId} repoName: ${issue.appName} tool: ${issue.resource} snippet len: ${
          issue.snippet.length
        } snippet size: ${getObjectSizeInMB(issue.snippet)} , error is ${e}`,
        e,
      );
      ///@ts-ignore
      const realMatches = issue.aggItems?.map(i => i.realMatch as string);
      ///@ts-ignore
      const matches = issue.aggItems?.map(i => i.match as string);
      const errMsg = `failed to addCurrentIssue, aggItemsSize: ${getObjectSizeInMB(issue.aggItems)}. realMatches size: ${getObjectSizeInMB(
        realMatches,
      )}. matches size: ${getObjectSizeInMB(matches)} issueId: ${issue.issueId}. aggItems len: ${issue.aggItems?.length || 0}. appId:${
        issue.appId
      }. size: ${getObjectSizeInMB(issue)} error: ${e}`;
      logger.error(errMsg, e);
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async removeIssueById(issue: Issue) {
    try {
      await this.CurrentIssue.verifyConnection(this.mongoConnect);
      const prom2 = this.CurrentIssue.model.findByIdAndDelete(issue.currentIssueMongoId).exec();
      await prom2;
      return true;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to remove issue by id, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedDeleteScanDataFromMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async addCICDIssues(appId: string, issues: Issue[]) {
    try {
      if (!this.keepUpdating || this.CICDIssue === null) {
        logger.info(`skip updating CICD issues (sigterm or cancel scan called)`);
        return true;
      }
      await pRetry(
        async () => {
          await this.CICDIssue.verifyConnection(this.mongoConnect);
          await this.CICDIssue.model.insertMany(issues);
          return true;
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.CICDIssue.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to add cicd issues, app: ${appId}, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async getCICDIssues(appId: string, scanId: string): Promise<CICDIssueDocument[]> {
    let cicdIssues: CICDIssueDocument[] = [];
    try {
      await pRetry(
        async () => {
          await this.CICDIssue.verifyConnection(this.mongoConnect);
          cicdIssues = await this.CICDIssue.model.find({ appId, scanId });
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.CICDIssue.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to get cicd issues, app: ${appId}, scanId: ${scanId}, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedQueryIssues, errMsg, this.org, this.uuid);
    }
    return cicdIssues;
  }

  async addPipelineSummery(pipelineSummery: PipelineSummary) {
    try {
      if (!this.keepUpdating || this.PipelineSummary === null) {
        logger.info(`skip pipeline summary (sigterm or cancel scan called)`);
        return true;
      }
      await pRetry(
        async () => {
          await this.PipelineSummary.verifyConnection(this.mongoConnect);
          const res = await this.PipelineSummary.model.create(pipelineSummery);
          return true;
        },
        { retries: 2, onFailedAttempt: async () => await this.PipelineSummary.verifyConnection(this.mongoConnect) },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to add pipeline summery issues, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async addAppsHistoryScores(appHistoryScores: AppHistoryScore[]) {
    try {
      if (!this.keepUpdating || this.AppHistoricalScore === null) {
        logger.info(`skip updating app history (sigterm or cancel scan called)`);
        return true;
      }
      logger.info(`try addAppsHistoryScores`);

      await pRetry(
        async () => {
          await this.AppHistoricalScore.verifyConnection(this.mongoConnect);
          if (StatesHelper.Instance.useMongoDBOptimizedQueries) {
            const bulkInsert = this.AppHistoricalScore.model.collection.initializeUnorderedBulkOp(); //tomerzaidler
            for (const appHistoryScore of appHistoryScores) {
              bulkInsert.insert(appHistoryScore);
            }
            await bulkInsert.execute();
          } else {
            await this.AppHistoricalScore.model.insertMany(appHistoryScores);
          }
          return true;
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.AppHistoricalScore.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to add applications history data, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }
  async updateAllIssues(issues: Issue[]) {
    try {
      if (!this.keepUpdating || this.CurrentIssue === null) {
        logger.info(`skip updating all issue (sigterm or cancel scan called)`);
        return true;
      }

      logger.info(`try updateAllIssues`);

      await pRetry(
        async () => {
          await this.CurrentIssue.verifyConnection(this.mongoConnect);
          // if (StatesHelper.Instance.useMongoDBOptimizedQueries) {
          //   const bulkInsert = this.CurrentIssue.model.collection.initializeUnorderedBulkOp(); //
          //   for (const issue of issues) {
          //     bulkInsert
          //       .find({ _id: issue.currentIssueMongoId })
          //       .upsert()
          //       .updateOne({
          //         $set: {
          //           severity: issue.severity,
          //           severityChangeReason: issue.severityChangeReason, //romanzit remove this
          //           severityChangedReason: issue.severityChangedReason,
          //           severityChange: issue.severityChange,
          //           originalToolSeverity: issue.originalToolSeverity,
          //           appBp: issue.appBp,
          //           correlatedIssueId: issue.correlatedIssueId,
          //           sources: issue.sources,
          //           correlatedRegistry: issue.correlatedRegistry,
          //           exposedByApiIds: issue.exposedByApiIds,
          //           exposedByApiItems: issue.exposedByApiItems,
          //         },
          //       });
          //   }
          //   await bulkInsert.execute();
          // } else {
          // }
          await PromisePool.for(issues)
            .withConcurrency(100)
            .process(async (issue: Issue) => {
              try {
                await this.updateSingleCurrentIssue(issue);
                return true;
              } catch (err) {
                logger.error(`failed addCurrentIssue from prom pool, err: ${err}`);
                return false;
              }
            });

          return true;
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.CurrentIssue.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed update all issues, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  private async updateSingleCurrentIssue(issue: Issue) {
    try {
      await pRetry(
        async () => {
          await this.CurrentIssue.verifyConnection(this.mongoConnect);
          await this.UniqueIssue.verifyConnection(this.mongoConnect);

          if (StatesHelper.Instance.shouldTrackSeverity) {
            logger.info(`enter updateSingleCurrnetIssue: ${issue.issueId} org: ${this.org}`);

            const oldIssue = await this.CurrentIssue.model
              .findOne<Issue>({ issueId: issue.issueId, scanId: { $not: { $eq: this.uuid } } })
              .exec();

            if (oldIssue) {
              logger.info(`in updateSingleCurrnetIssue: ${issue.issueId}`);

              const currentIssueToUpdate = this.CurrentIssue.model.findByIdAndUpdate(issue.currentIssueMongoId);
              logger.info(
                `updateSingleCurrnetIssue about to compare severity: ${issue.severity} oldIssue: ${oldIssue.severity}, issueId: ${issue.issueId}`,
              );

              if (oldIssue.severity !== issue.severity) {
                logger.info(
                  `compared updateSingleCurrnetIssue: ${issue.issueId} severity changed from ${oldIssue.severity} to ${issue.severity}`,
                );

                const oldSeverityChangesKeys = oldIssue.severityChangedReason.reduce((arr: Set<string>, i) => {
                  arr.add(i.shortName + i.changeNumber);
                  return arr;
                }, new Set<string>());

                const newSeverityChangesKeys = issue.severityChangedReason.reduce((arr: Set<string>, i) => {
                  arr.add(i.shortName + i.changeNumber);
                  return arr;
                }, new Set<string>());

                const severityChangeHistory = {
                  severity: issue.severity,
                  date: new Date().getTime(),
                  originalToolSeverity: issue.originalToolSeverity,
                  severityChangeReasonsAdded: issue.severityChangedReason
                    .filter(i => !oldSeverityChangesKeys.has(i.shortName + i.changeNumber))
                    .map(i => ({ reason: i.reason, shortName: i.shortName, changeNumber: i.changeNumber })),
                  severityChangeReasonsRemoved: oldIssue.severityChangedReason
                    .filter(i => !newSeverityChangesKeys.has(i.shortName + i.changeNumber))
                    .map(i => ({ reason: i.reason, shortName: i.shortName, changeNumber: i.changeNumber })),
                };

                // remove older than 2 months to avoid large array
                const severityChangeHistoryNotExpired = oldIssue.severityChangeHistory
                  ? oldIssue.severityChangeHistory.filter(i => {
                      const diff = new Date().getTime() - i.date.getTime();
                      const diffDays = diff / (1000 * 3600 * 24);
                      return diffDays < 60;
                    })
                  : [];

                await currentIssueToUpdate
                  .set({
                    severityChangeHistory: oldIssue.severityChangeHistory
                      ? [...severityChangeHistoryNotExpired, severityChangeHistory]
                      : [severityChangeHistory],
                  })
                  .exec();

                logger.info(`update severity updateSingleCurrnetIssue: ${issue.issueId}`);
              } else {
                await currentIssueToUpdate.set({
                  severityChangeHistory: oldIssue.severityChangeHistory,
                });
              }
            }
          }

          const res = await this.CurrentIssue.model
            .findByIdAndUpdate(issue.currentIssueMongoId)
            .set({
              severity: issue.severity,
              severityChangeReason: issue.severityChangeReason, //romanzit remove this
              severityChangedReason: issue.severityChangedReason,
              severityChange: issue.severityChange,
              originalToolSeverity: issue.originalToolSeverity,
              appBp: issue.appBp,
              correlatedIssueId: issue.correlatedIssueId,
              sources: issue.sources,
              correlatedRegistry: issue.correlatedRegistry,
              exposedByApiIds: issue.exposedByApiIds,
              exposedByApiItems: issue.exposedByApiItems,
            })
            .setOptions({ upsert: true })
            .exec();

          return true;
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.CurrentIssue.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      ///@ts-ignore
      const realMatches = issue.aggItems?.map(i => i.realMatch as string);
      ///@ts-ignore
      const matches = issue.aggItems?.map(i => i.match as string);
      const errMsg = `failed to updateSingleCurrentIssue, aggItemsSize: ${getObjectSizeInMB(
        issue.aggItems,
      )}. realMatches size: ${getObjectSizeInMB(realMatches)}. matches size: ${getObjectSizeInMB(matches)} issueId: ${
        issue.issueId
      }. aggItems len: ${issue.aggItems?.length || 0}. appId:${issue.appId}. size: ${getObjectSizeInMB(issue)} error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async updateAllApplications(applications: Application[]) {
    try {
      if (!this.keepUpdating || this.Application === null) {
        logger.info(`skip updating all applications (sigterm or cancel scan called)`);
        return true;
      }
      logger.info(`try updateAllApplications`);

      await this.Application.verifyConnection(this.mongoConnect);
      if (StatesHelper.Instance.useMongoDBOptimizedQueries) {
        const bulkInsert = this.Application.model.collection.initializeUnorderedBulkOp();
        for (const app of applications) {
          bulkInsert
            .find({ appId: app.appId, scanId: app.scanId })
            .upsert()
            .updateOne({ $set: new this.Application.model(app) });
        }
        await bulkInsert.execute();
        return true;
      } else {
        const promises = applications.map(app => {
          return this.updateApplication(app);
        });

        const res = await Promise.all(promises);
        return res.every(i => i);
      }
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed update all applications, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async addUniqueIssues(issues: Issue[]) {
    try {
      if (!this.keepUpdating || this.UniqueIssue === null) {
        logger.info(`skip adding unique issue (sigterm or cancel scan called)`);
        return true;
      }
      await this.UniqueIssue.verifyConnection(this.mongoConnect);
      const proms = issues.map(i => this.upsertUniqeSingleIssue(i));
      await Promise.all(proms);
      return true;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to add unique issues, error : ${e}`);
    }
    return false;
  }

  private async upsertUniqeSingleIssue(issue: Issue) {
    try {
      if (!this.keepUpdating || this.UniqueIssue === null) {
        logger.info(`skip upserting unique issue (sigterm or cancel scan called)`);
        return true;
      }
      await pRetry(
        async () => {
          try {
            await this.UniqueIssue.model.create(issue);
            return true;
          } catch (e) {
            if (e.code === 11000) {
              await this.updateUniqeIssue(issue);
              return true;
            } else {
              throw e;
            }
          }
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.UniqueIssue.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to upsert single uniqe issue, issueId: ${issue.issueId}, appId: ${issue.appId}, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  private async updateUniqeIssue(issue: Issue) {
    try {
      if (!this.keepUpdating || this.UniqueIssue === null) {
        logger.info(`skip updating unique issue (sigterm or cancel scan called)`);
        return true;
      }

      await pRetry(
        async () => {
          // const existingIssue = await this.UniqueIssue.model.findOne({ issueId: issue.issueId }, { severity: 1, severityChangedReason: 1 });
          const { issueId } = issue;
          const update: Partial<Issue> = {
            aggregatedItemsId: issue.aggregatedItemsId,
            updated: issue.updated,
            lastIssueSeenDate: issue.lastIssueSeenDate,
            aggFileNames: issue.aggFileNames && issue.aggFileNames.length > 0 ? issue.aggFileNames : [],
            aggregationsCount: issue.aggregationsCount,
            increasedAt: issue.increasedAt,
            decreasedAt: issue.decreasedAt,
            newDate: issue.newDate,
            prevSeverity: issue.severity,
          };

          // const isDev = isDevelopment() || isLocalDevelopment();
          // if (isDev && this.org === "org_mC72M341wk2b0aL9") {
          //   logger.info(`enter updateUniqeIssue: ${issue.issueId} isDev: ${isDev} org: ${this.org}`);

          //   const uniqueIssue = await this.UniqueIssue.model.findOne<Issue>({ issueId: issue.issueId }).exec();

          //   if (uniqueIssue && uniqueIssue.severity !== issue.severity) {
          //     logger.info(`compared updateUniqeIssue: ${issue.issueId} severity changed from ${uniqueIssue.severity} to ${issue.severity}`);

          //     const severityChangeHistory = {
          //       severity: issue.severity,
          //       date: new Date().getTime(),
          //       severityChangeReason: issue.severityChangeReason,
          //     };

          //     await this.UniqueIssue.model
          //       .updateOne(
          //         { issueId },
          //         {
          //           $addToSet: {
          //             severityChangeHistory: [severityChangeHistory],
          //           },
          //         },
          //       )
          //       .exec();

          //     logger.info(`update severity updateUniqeIssue: ${issue.issueId}`);
          //   }
          // }

          await this.UniqueIssue.model.findOneAndUpdate<Issue>().where("issueId").equals(issueId).set(update).exec();
          return true;
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.UniqueIssue.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to update single uniqe issue, issueId: ${issue.issueId} error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async removeOldScanData() {
    try {
      const filter = {
        $or: [{ scanId: { $ne: this.uuid } }, { scanId: { $exists: false } }],
      };
      const res = await Promise.all([
        this.removeApplications(filter),
        this.removeOldCurrentIssues(filter),
        this.removeDiscoverySystems(filter),
        this.removeAppsSbom(filter),
        this.removeApiSecurity(filter),
        this.removeOldSilentSigIssues(filter),
      ]);
      return res.every(i => i);
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to remove old scan data, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedDeleteScanDataFromMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async removeApplications(filter) {
    try {
      await this.Application.verifyConnection(this.mongoConnect);
      await this.Application.model.deleteMany(filter).exec();
      return true;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to delete applications, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedDeleteScanDataFromMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async removeOldCurrentIssues(filter, batchSize = 1000, delayForBatch = 2000, counter = 1) {
    try {
      await this.CurrentIssue.verifyConnection(this.mongoConnect);
      const issuesToDel = await this.CurrentIssue.model.find(filter, { _id: 1 }).limit(batchSize).exec();
      if (issuesToDel.length > 0) {
        await this.CurrentIssue.model
          .deleteMany({
            _id: { $in: issuesToDel.map(doc => doc._id) },
          })
          .exec();
        await sleep(delayForBatch);
        await this.removeOldCurrentIssues(filter, batchSize, delayForBatch, counter + 1);
      }
      return true;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to delete old current issues, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedDeleteScanDataFromMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async removeOldSilentSigIssues(filter, batchSize = 1000, delayForBatch = 2000, counter = 1) {
    try {
      await this.SilentSigIssue.verifyConnection(this.mongoConnect);
      const issuesToDel = await this.SilentSigIssue.model.find(filter, { _id: 1 }).limit(batchSize).exec();
      if (issuesToDel.length > 0) {
        await this.SilentSigIssue.model
          .deleteMany({
            _id: { $in: issuesToDel.map(doc => doc._id) },
          })
          .exec();
        await sleep(delayForBatch);
        await this.removeOldSilentSigIssues(filter, batchSize, delayForBatch, counter + 1);
      }
      return true;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to removeOldSilentSigIssues, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedDeleteScanDataFromMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async removeDiscoverySystems(filter) {
    try {
      await this.DiscoverySystem.verifyConnection(this.mongoConnect);
      await this.DiscoverySystem.model.deleteMany().where(filter).exec();
      return true;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to delete discovery systems, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedDeleteScanDataFromMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  private async removeAppsSbom(filter) {
    try {
      await this.AppSbom.verifyConnection(this.mongoConnect);
      await this.AppSbom.model.deleteMany(filter).exec();
      return true;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to delete app sbom, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedDeleteScanDataFromMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  async setSbom(appId: string, scanId: string, scanDate: Date, sbom: Sbom, type: AppSbomType, imageDetailOrRepo: ImageDetail | Repo) {
    try {
      if (!this.keepUpdating || this.AppSbom === null) {
        logger.info(`skip updating sboms (sigterm or cancel scan called)`);
        return true;
      }

      await this.AppSbom.verifyConnection(this.mongoConnect);
      const imageDetailOrRepoPayload = type === AppSbomType.image ? { imageDetail: imageDetailOrRepo } : { repo: imageDetailOrRepo };
      await this.AppSbom.model.create({
        appId,
        scanId,
        scanDate,
        sbom,
        type,
        ...imageDetailOrRepoPayload,
      });
      return true;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to set sbom, db connect status code: ${this.mongoConnect.connection.readyState}, er:${e}`);
    }
    return false;
  }

  async setOrgSbom(scanId: string, scanDate: Date, sbom: Sbom) {
    try {
      if (!this.keepUpdating || this.OrgSbom === null) {
        logger.info(`skip updating org sboms (sigterm or cancel scan called)`);
        return true;
      }
      const compressed = await compress(JSON.stringify(sbom));
      const bytes = Buffer.byteLength(compressed, "utf-8");
      //14 mb
      if (bytes > 14000000) {
        logger.error(`cannot save org sbom due to size, bytes: ${bytes}`);
        return;
      }

      logger.info(`finish compress sbom for org, bytes: ${bytes}`);

      await this.OrgSbom.verifyConnection(this.mongoConnect);
      await this.OrgSbom.model.findOneAndUpdate(
        {
          scanId,
        },
        {
          scanDate,
          sbom: compressed,
        },
        { upsert: true },
      );
      return true;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to set org sbom, error: ${e}, db connect status code: ${this.mongoConnect.connection.readyState}`);
    }
    return false;
  }

  disableModels() {
    try {
      logger.info(`disable mongo models, no more writing scan data to mongo`);
      this.keepUpdating = false;
      this.ScanInfo = null;
      this.Application = null;
      this.DiscoverySystem = null;
      this.AppHistoricalScore = null;
      this.CurrentIssue = null;
      this.AppSbom = null;
      this.UniqueIssue = null;
      this.ScanSummaryHistory = null;
      this.CICDIssue = null;
      this.PipelineSummary = null;
      this.OrgSbom = null;
      this.SilentSigIssue = null;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to disable models, error: ${e}`);
    }
  }

  async updateScanSummery(scanSummary: ScanSummaryHistory) {
    try {
      if (!this.keepUpdating || this.ScanSummaryHistory === null) {
        logger.info(`skip updating scan summary (sigterm or cancel scan called)`);
        return true;
      }
      if (!this.ScanSummaryHistory.firstUpdateHappen) {
        this.ScanSummaryHistory.firstUpdateHappen = true;
        await pRetry(
          async () => {
            await this.ScanSummaryHistory.verifyConnection(this.mongoConnect);
            const obj = scanSummary.get();
            if (StatesHelper.Instance.useMongoDBOptimizedQueries) {
              const bulkInsert = this.ScanSummaryHistory.model.collection.initializeUnorderedBulkOp(); //tomerzaidler
              bulkInsert.insert(obj);
              await bulkInsert.execute();
            } else {
              await this.ScanSummaryHistory.model.create(obj);
            }
            return true;
          },
          {
            retries: 2,
            onFailedAttempt: async () => {
              await this.ScanSummaryHistory.verifyConnection(this.mongoConnect);
            },
          },
        );
      } else {
        await pRetry(
          async () => {
            await this.ScanSummaryHistory.verifyConnection(this.mongoConnect);
            const obj = scanSummary.get();
            if (StatesHelper.Instance.useMongoDBOptimizedQueries) {
              const bulkInsert = this.ScanSummaryHistory.model.collection.initializeUnorderedBulkOp(); //tomerzaidler
              bulkInsert.find({ scanId: obj.scanId }).updateOne({ $set: { ...obj } });
              await bulkInsert.execute();
            } else {
              await this.ScanSummaryHistory.model.findOneAndUpdate({ scanId: obj.scanId }, { ...obj });
            }
            return true;
          },
          {
            retries: 2,
            onFailedAttempt: async () => {
              await this.ScanSummaryHistory.verifyConnection(this.mongoConnect);
            },
          },
        );
      }
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to set sbom, db connect status code: ${this.mongoConnect.connection.readyState}, er:${e}`);
    }
    return false;
  }

  @PerformanceTelemetry()
  async copyOldIssues() {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }
      if (StatesHelper.Instance.isResolvedIssuesEnable) {
        logger.info(`copying old scan issues to prev issues`);
        await this.CurrentIssue.model.aggregate([{ $match: { scanId: { $ne: this.uuid } } }, { $out: "prev-issues" }]);
      }
      await MemoryMonitorHelper.Instance.printSnapshot(this.uuid, this.uuid, `after copyOldIssues`);
    } catch (e) {
      logger.error(`failed copy old issues`, e);
    }
  }

  private async removeApiSecurity(filter) {
    try {
      await this.APiSecurity.verifyConnection(this.mongoConnect);
      await this.APiSecurity.model.deleteMany(filter).exec();
      return true;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to delete api security, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedDeleteScanDataFromMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  public async addAPiSecurity(apisSecurity: ApiSecurityItem[]) {
    try {
      if (!this.keepUpdating || this.APiSecurity === null) {
        logger.info(`skip updating api security (sigterm or cancel scan called)`);
        return true;
      }
      await pRetry(
        async () => {
          await this.APiSecurity.verifyConnection(this.mongoConnect);
          await this.APiSecurity.model.insertMany(apisSecurity);
          return true;
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.APiSecurity.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to addAPiSecurity, db connect status code: ${this.mongoConnect.connection.readyState}, er:${e}`);
    }
    return false;
  }

  public async addAPiSecurityHistory(apisSecurityHistory: ApiSecurityItem[], appId: string) {
    try {
      if (!this.keepUpdating || this.APiSecurityHistory === null) {
        logger.info(`skip updating api security history (sigterm or cancel scan called)`);
        return true;
      }
      await pRetry(
        async () => {
          await this.APiSecurityHistory.verifyConnection(this.mongoConnect);
          await this.APiSecurityHistory.model.deleteMany({ appId: appId });
          await this.APiSecurityHistory.model.insertMany(apisSecurityHistory);
          return true;
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.APiSecurityHistory.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to addAPiSecurityHistory, db connect status code: ${this.mongoConnect.connection.readyState}, er:${e}`);
    }
    return false;
  }

  public async getAPiSecurityHistory(appId: string): Promise<ApiSecurityItem[]> {
    let apiHistory: ApiSecurityItem[] = [];
    try {
      if (!this.keepUpdating || this.APiSecurityHistory === null) {
        logger.info(`skip getting api security history (sigterm or cancel scan called)`);
        return [];
      }
      await pRetry(
        async () => {
          await this.APiSecurityHistory.verifyConnection(this.mongoConnect);
          apiHistory = await this.APiSecurityHistory.model.find({ appId: appId });
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.APiSecurityHistory.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to getAPiSecurityHistory, db connect status code: ${this.mongoConnect.connection.readyState}, er:${e}`);
    }
    return apiHistory;
  }

  public async getAggItems(mongoId): Promise<AggItem[]> {
    let aggItems: AggItem[] = [];
    try {
      if (!this.keepUpdating || this.CurrentIssue === null) {
        logger.info(`skip getAggItems (sigterm or cancel scan called)`);
        return [];
      }
      await pRetry(
        async () => {
          await this.CurrentIssue.verifyConnection(this.mongoConnect);
          const issues = await this.CurrentIssue.model.find({ _id: mongoId });
          if (issues && issues.length > 0) {
            aggItems = issues[0]?.aggItems;
          } else {
            logger.error(`failed to getAggItems, failed to find issue by mongo Id ${mongoId}`);
          }
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.CurrentIssue.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to getAggItems, db connect status code: ${this.mongoConnect.connection.readyState}, er:${e}`);
    }
    return aggItems;
  }

  public async addAttackGraphs(attackGraphs: AttackGraph[], scanId: string, appId: string) {
    try {
      if (!this.keepUpdating || this.AttackGraph === null) {
        logger.info(`skip updating attack graphs (sigterm or cancel scan called)`);
        return true;
      }
      await pRetry(
        async () => {
          await this.AttackGraph.verifyConnection(this.mongoConnect);
          await this.AttackGraph.model.insertMany(attackGraphs);
          await this.AttackGraph.model.deleteMany({ scanId: { $ne: scanId }, appId: appId });
          return true;
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.AttackGraph.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to AttackGraphs, db connect status code: ${this.mongoConnect.connection.readyState}, er:${e}`);
    }
    return false;
  }

  async updateSeverityHistory(issueId: string, historyInfo: SeverityHistoryInfo, iName: string, pName: string) {
    try {
      await pRetry(
        async () => {
          await this.SeverityHistory.verifyConnection(this.mongoConnect);
          const doc: SeverityHistoryItem = {
            issueId,
            history: [historyInfo],
            firstSeenStat: historyInfo,
            issueName: iName,
            issuePolicyName: pName,
          };
          try {
            await this.SeverityHistory.model.create(doc);
            return true;
          } catch (e) {
            if (e.code === 11000) {
              await this.SeverityHistory.model
                .findOneAndUpdate(
                  { issueId: issueId },
                  {
                    $push: { history: historyInfo },
                  },
                  { upsert: true },
                )
                .exec();
              return true;
            } else {
              throw e;
            }
          }
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.SeverityHistory.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      const errMsg = `failed to updateSeverityHistory, issueId: ${issueId} error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }

  //deleting and updating the severity histories which are older than two months old
  async delete2mOlderSeverityHistories() {
    try {
      const batchSize = 1000;
      const twoMonthsAgo = new Date();
      twoMonthsAgo.setMonth(twoMonthsAgo.getMonth() - 2);
      twoMonthsAgo.setUTCHours(0, 0, 0, 0);

      await pRetry(
        async () => {
          await this.SeverityHistory.verifyConnection(this.mongoConnect);
          const totalDocuments = await this.SeverityHistory.model.countDocuments();
          let processedDocuments = 0;
          while (processedDocuments < totalDocuments) {
            await this.SeverityHistory.model.aggregate([
              { $skip: processedDocuments },
              { $limit: batchSize },
              {
                $set: {
                  history: {
                    $filter: {
                      input: "$history",
                      as: "h",
                      cond: {
                        $gte: ["$$h.severityDateChange", twoMonthsAgo],
                      },
                    },
                  },
                },
              },
              { $merge: { into: "issue-severity-histories", whenMatched: "replace" } },
            ]);
            processedDocuments += batchSize;
          }
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.SeverityHistory.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      const errMsg = `failed to delete2mOlderSeverityHistories. error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
      return false;
    }
  }

  async addSilentSigIssues(appId: string, issues: Issue[]) {
    try {
      if (!this.keepUpdating || this.SilentSigIssue === null) {
        logger.info(`skip updating addSilentSigIssues (sigterm or cancel scan called)`);
        return true;
      }
      await pRetry(
        async () => {
          await this.SilentSigIssue.verifyConnection(this.mongoConnect);
          await this.SilentSigIssue.model.insertMany(issues);
          return true;
        },
        {
          retries: 2,
          onFailedAttempt: async () => {
            await this.SilentSigIssue.verifyConnection(this.mongoConnect);
          },
        },
      );
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errMsg = `failed to addSilentSigIssues, app: ${appId}, error: ${e}`;
      logger.error(errMsg);
      await sendScannerMongoErrorTelemetry(ScanErrorName.FailedSaveScanDataToMogno, errMsg, this.org, this.uuid);
    }
    return false;
  }
}

export default MongoDBreportUpdates3;

function getObjectSizeInMB(obj) {
  // Convert the object to a JSON string
  const jsonString = JSON.stringify(obj);

  // Convert the string to bytes
  const bytes = new TextEncoder().encode(jsonString).length;

  // Convert bytes to megabytes
  const megabytes = bytes / (1024 * 1024);

  // Return the result as a string with 2 decimal places
  return megabytes.toFixed(2) + " MB";
}
