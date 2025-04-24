import loggerImport from "../../../../logger";
import { ServiceBase } from "../../serviceBase";
import { GetAlertExclusionsByMode, GetAlertExclusionsByModeVariables } from "../types";
import { getAlertExclusionsByMode } from "../gql";
import { OxExclusionMode } from "@oxappsec/ox-consolidated-exclusions";

const logger = loggerImport.getDebugLogger();
const EXCLUSION_SERVICE_HOST_URL = process.env.EXCLUSION_SERVICE_HOST_URL || "";

export class ExclusionService extends ServiceBase {
  private constructor() {
    super(EXCLUSION_SERVICE_HOST_URL);
  }

  private static _instance: ExclusionService;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  async getAlertExclusionsByMode(orgId: string, exclusionMode: OxExclusionMode) {
    try {
      if (EXCLUSION_SERVICE_HOST_URL) {
        await this.setAuthHeader();
        if (exclusionMode === OxExclusionMode.pipelineScan) {
          logger.info(`fetching ALL exclusions`);
        } else if (exclusionMode === OxExclusionMode.fullScan) {
          logger.info(`fetching only full scan exclusions`);
        }

        logger.info(`exclusion service URL :${EXCLUSION_SERVICE_HOST_URL}`);
        logger.info(`getting exclusions orgId: ${orgId}`);

        const res = await this.gqlClient.request<GetAlertExclusionsByMode, GetAlertExclusionsByModeVariables>(getAlertExclusionsByMode, {
          orgId,
          exclusionMode,
        });

        return res.getAlertExclusionsByMode.exclusions;
      }
    } catch (e) {
      logger.error(`failed to get exclusions, orgId: ${orgId}. error: ${e}`);
    }
    return [];
  }
}
