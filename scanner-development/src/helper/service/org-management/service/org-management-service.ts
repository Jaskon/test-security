import loggerImport from "../../../../logger";
import { ServiceBase } from "../../serviceBase";
import { updateDevelopersCount } from "../gql/update-developers-count";

const logger = loggerImport.getDebugLogger();
const ORG_MANAGEMENT_HOST_URL = process.env.ORG_MANAGEMENT_HOST_URL || "";

export class OrgManagementService extends ServiceBase {
  private constructor() {
    super(ORG_MANAGEMENT_HOST_URL);
  }

  private static _instance: OrgManagementService;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  async updateDevelopersCount(orgId: string, developersCount: number, developersByConnector: any, users: string[], resourceType: string) {
    try {
      await this.setAuthHeader();
      logger.info(`updating developers count orgId: ${orgId}`);
      const res = await this.gqlClient.request(updateDevelopersCount, {
        updateDevelopersCountInput: {
          developersCount,
          developersByConnector,
          users,
          resourceType,
        },
        orgId,
      });

      return true;
    } catch (e) {
      logger.error(`failed to update developers count, orgId: ${orgId}. error: ${e}`);
    }
    return false;
  }
}
