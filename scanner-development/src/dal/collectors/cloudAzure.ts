import axios from "axios";
import qs from "qs";
import { Token } from "../../entitis/collectorEntitisTypes";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import CloudBase from "../base/cloudBase";

const logger = loggerImport.getDebugLogger();
const concurrent_pool_call = 5;

class AzureContainerRegistry extends CloudBase {
  private_token: string;
  timeHelper: TimeHelper;
  isIdpToken: boolean = false;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    logger.info(
      `${this.token.name}, is using token, tenantId: ${this.token.tenantId}, clientId: ${this.token.clientId}, subscriptionId: ${this.token.subscriptionId}`,
    );
  }
  async initLib() {}

  /**
   * @description This method is to generate new access token for azure
   * @returns generated access token
   */
  private async generateAccessToken(): Promise<void> {
    try {
      const accessTokenUrl = `https://login.microsoftonline.com/${this.token.tenantId}/oauth2/v2.0/token`;
      const header = { headers: { "Content-Type": "application/x-www-form-urlencoded" } };
      const formData = {
        client_id: this.token.clientId,
        grant_type: "client_credentials",
        client_secret: this.token.clientSecret,
        scope: "https://management.azure.com/.default",
      };
      const { data } = await axios.post<{ access_token: string }>(accessTokenUrl, qs.stringify(formData), header);
      this.token.password = data.access_token;
      return;
    } catch (error) {
      logger.error(`${this.token.name}, failed to run generateAccessToken for: ${this.token.name} with type error : ${error}`);
      throw error;
    }
  }
}

export default AzureContainerRegistry;
