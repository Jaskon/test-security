import loggerImport from "../../../../logger";
import { isDevelopment, isProd, isStaging } from "../../../envUtils";
import { ServiceBase } from "../../serviceBase";
import { CloneToSecondaryInput, CloneToSecondaryRes } from "../demo-types";
import cloneToSecondary from "../gql/clone-to-secondary";

const logger = loggerImport.getDebugLogger();
const DEMO_SERVICE_HOST_URL = process.env.DEMO_SERVICE_HOST_URL || "http://localhost:3020/graphql";

export class DemoService extends ServiceBase {
  private constructor() {
    super(DEMO_SERVICE_HOST_URL);
  }

  private static _instance: DemoService;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  async cloneToSecondary(scanId: string, orgId: string) {
    try {
      const isDevParentDemoOrg = isDevelopment() && orgId === "org_fEOzt4wtsHlpODLs";
      const isStgParentDemoOrg = isStaging() && orgId === "org_9nmsX94Wtjiex40n";
      const isProdParentDemoOrg = isProd() && orgId === "org_nEu9YXI2P5QVWmy4";
      if (isDevParentDemoOrg || isStgParentDemoOrg || isProdParentDemoOrg) {
        logger.info(`call demo service org ${orgId}`);
        await this.setAuthHeader();
        logger.info(`demo-service URL :${DEMO_SERVICE_HOST_URL}`);
        const input: CloneToSecondaryInput = {
          orgId,
          scanId,
        };
        const res = await this.gqlClient.request<CloneToSecondaryRes>(cloneToSecondary, input);
        logger.info(`cloneToSecondary res: ${JSON.stringify(res)}`);
        return res;
      }
      return null;
    } catch (e) {
      logger.error(`failed to cloneToSecondary, orgId: ${scanId}. error: ${e}`);
    }
    return null;
  }
}
