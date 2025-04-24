import { GetIssuesRes, GetSingleIssueRes } from "@oxappsec/ox-artifact-manager/lib/src/artifact-manager/types/issues-types";
import loggerImport from "../../../../logger";
import { ServiceBase } from "../../serviceBase";
import {
  getContainerIssuesQuery,
  getCurrentFullScanIssuesIds,
  getRawIssuesQuery,
  GetRawIssuesRes,
  getSingleIssueQuery,
  getUniqueIssuesQuery,
  GetUniqueIssuesRes,
} from "../gql";
import { GetCurrentFullScanIssuesIds } from "../gql/get-current-scan-issues-ids";
import setPipelineDataQuery from "../gql/set-pipeline-data-query";
import { SetPipelineDataInput, SetPipelineDataRes } from "../types";

const logger = loggerImport.getDebugLogger();
const REPORT_SERVICE_HOST_URL = process.env.REPORT_SERVICE_HOST_URL || "";

export class ReportService extends ServiceBase {
  constructor() {
    super(REPORT_SERVICE_HOST_URL);
  }

  private static _instance: ReportService;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  async getContainerIssues(orgId: string): Promise<GetIssuesRes> {
    try {
      await this.setAuthHeader();

      logger.info(`getting container issues for orgId: ${orgId}, report service URL :${REPORT_SERVICE_HOST_URL}`);

      const res = await this.gqlClient.request<GetIssuesRes>(getContainerIssuesQuery, {
        getIssuesInput: {
          owners: [],
          offset: 0,
          limit: 10000,
          filters: {
            categories: ["12"],
          },
        },
        orgId: orgId,
      });

      logger.info(`Found ${res.getIssues.issues?.length ?? 0} container issues for orgId: ${orgId}`);

      return res;
    } catch (e) {
      logger.error(`failed to get getContainerIssues issues: ${orgId}. error: ${e}`);
    }
    return null;
  }

  async getSingleIssueContainerHashes(orgId: string, issueId: string): Promise<GetSingleIssueRes> {
    try {
      await this.setAuthHeader();
      const res = await this.gqlClient.request<GetSingleIssueRes>(getSingleIssueQuery, {
        getSingleIssueInput: {
          issueId: issueId,
        },
        orgId: orgId,
      });

      logger.debug(
        `Found ${res.getSingleIssueInfo?.aggregations?.items?.length ?? "zero"} hashes for container issue: ${issueId} for orgId: ${orgId}`,
      );

      if (res.getSingleIssueInfo?.aggregations?.items?.length) {
        logger.debug(`Container hash: ${JSON.stringify(res.getSingleIssueInfo?.aggregations?.items)}`);
      }

      return res;
    } catch (e) {
      logger.error(`failed to get getSingleIssueContainerHashes issues: ${orgId}. error: ${e}`);
    }
    return null;
  }

  async getUniqueIssues(orgId: string) {
    try {
      await this.setAuthHeader();
      logger.info(`report service URL :${REPORT_SERVICE_HOST_URL}`);
      logger.info(`getting unique issues orgId: ${orgId}`);
      const res = await this.gqlClient.request<GetUniqueIssuesRes>(getUniqueIssuesQuery, {
        orgId,
      });

      return res.getUniqueIssues;
    } catch (e) {
      logger.error(`failed to get unique issues: ${orgId}`, e);
    }
    return null;
  }

  async getCurrentFullScanIssuesIds(orgId: string, appId?: string): Promise<string[]> {
    try {
      await this.setAuthHeader();
      logger.info(`getting getCurrentFullScanIssuesIds appId ${appId} orgId: ${orgId}`);
      const res = await this.gqlClient.request<GetCurrentFullScanIssuesIds>(getCurrentFullScanIssuesIds, {
        orgId,
        appId,
      });

      logger.info(`getCurrentFullScanIssuesIds appId ${appId} count ${res.getRawIssues.length} orgId ${orgId}`);

      return res.getRawIssues.map(i => i.issueId);
    } catch (e) {
      logger.error(`failed to getCurrentFullScanIssuesIds appId ${appId} orgId ${orgId}. error: ${e}`);
    }
    return [];
  }

  async getRawIssues(orgId: string) {
    try {
      await this.setAuthHeader();
      const res = await this.gqlClient.request<GetRawIssuesRes>(getRawIssuesQuery, {
        orgId,
      });

      return res.getRawIssues;
    } catch (e) {
      logger.error(`failed to get raw issues: ${orgId}. error: ${e}`);
    }
    return [];
  }

  async setPipelineData(orgId: string, appId: string, setPipelineDataInput: SetPipelineDataInput) {
    try {
      await this.setAuthHeader();
      logger.info(`start setPipelineData, appId: ${appId} orgId: ${orgId}`);
      const res = await this.gqlClient.request<SetPipelineDataRes>(setPipelineDataQuery, {
        orgId,
        appId,
        setPipelineDataInput,
      });

      return res.setPipelineData;
    } catch (e) {
      logger.error(`failed setPipelineData, appId: ${appId}, orgId: ${orgId}, error: ${e}`);
    }
    return null;
  }
}
