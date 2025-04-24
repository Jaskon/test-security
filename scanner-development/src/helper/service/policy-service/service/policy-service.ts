import loggerImport from "../../../../logger";
import { ServiceBase } from "../../serviceBase";
import { getPipelinePoliciesByAppIdQuery, getSelectedPoliciesForActiveProfile } from "../gql";
import { GetPipelinePoliciesByAppIdRes } from "../gql/get-pipeline-policies-by-appid";
import { GetSelectedPoliciesForActiveProfile } from "../types";

const logger = loggerImport.getDebugLogger();
const POLICY_SERVICE_HOST_URL = process.env.POLICY_SERVICE_HOST_URL || "";

export class PolicyService extends ServiceBase {
  private constructor() {
    try {
      super(POLICY_SERVICE_HOST_URL);
    } catch (err) {
      logger.error(`failed PolicyService. error: ${err}`);
    }
  }

  private static _instance: PolicyService;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  async getPipelinePoliciesByAppId(orgId: string, appId: string) {
    try {
      await this.setAuthHeader();
      logger.info(`policy service URL :${POLICY_SERVICE_HOST_URL}`);
      logger.info(`getting pipeline policies, appId: ${appId}, orgId: ${orgId}`);
      const vars = { appId, orgId };
      const res = await this.runQueryWithRetry<GetPipelinePoliciesByAppIdRes>(
        getPipelinePoliciesByAppIdQuery,
        vars,
        "fetching pipeline policies",
      );

      return res.getPipelinePoliciesByAppId;
    } catch (e) {
      logger.error(`failed to get pipeline policies, appId: ${appId}, orgId: ${orgId}. error: ${e}`);
    }
    return null;
  }

  async getSelectedPolicies(orgId: string) {
    try {
      await this.setAuthHeader();
      logger.info(`getting selected policies orgId: ${orgId}`);
      const vars = { orgId };
      const res = await this.runQueryWithRetry<GetSelectedPoliciesForActiveProfile>(
        getSelectedPoliciesForActiveProfile,
        vars,
        "fetching policies",
      );

      return res.getSelectedPoliciesForActiveProfile.policies || [];
    } catch (e) {
      logger.error(`failed to get selected policies, orgId: ${orgId}`, e);
    }
    return null;
  }
}
