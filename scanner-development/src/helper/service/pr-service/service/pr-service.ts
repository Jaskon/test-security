import loggerImport from "../../../../logger";
import { ServiceBase } from "../../serviceBase";
import { getAllPrs } from "../gql/get-all-prs-query";
import { GetAllPullRequestsRes } from "../types";

const logger = loggerImport.getDebugLogger();
const PR_SERVICE_HOST_URL = process.env.PR_SERVICE_HOST_URL;

export class PrService extends ServiceBase {
  private constructor() {
    super(PR_SERVICE_HOST_URL);
  }

  private static _instance: PrService;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  async getPrs(orgId: string) {
    try {
      await this.setAuthHeader();
      const res = await this.gqlClient.request<GetAllPullRequestsRes>(getAllPrs, {
        orgId,
      });

      return res.getAllPullRequests.prs || [];
    } catch (e) {
      logger.error(`failed to get pull requests for pr service. orgId: ${orgId}`, e);
    }
    return [];
  }
}
