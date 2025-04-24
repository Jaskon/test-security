import loggerImport from "../../../../logger";
import { ServiceBase } from "../../serviceBase";
import { getAllGPTQuery } from "../gql/get-all-query";
import { GPTResponse } from "../types";

const logger = loggerImport.getDebugLogger();
const GPT_SERVICE_HOST_URL = process.env.GPT_SERVICE_HOST_URL || "missing gpt service url";

export class GPTService extends ServiceBase {
  private constructor() {
    super(GPT_SERVICE_HOST_URL);
  }

  private static _instance: GPTService;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  async getGPTs(orgId: string) {
    try {
      await this.setAuthHeader();
      const res = await this.gqlClient.request<{ getAll: { gpts: GPTResponse[] } }>(getAllGPTQuery, {
        orgId,
      });

      return res.getAll.gpts || [];
    } catch (e) {
      logger.error(`failed to get gpts. orgId: ${orgId}`, e);
    }
    return [];
  }
}
