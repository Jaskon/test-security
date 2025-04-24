import loggerImport from "../../logger";

import { createAuthTokenProvider, ServiceType } from "@oxappsec/ox-unified-auth-token-provider";
const logger = loggerImport.getDebugLogger();
import { GraphQLClient, gql } from "graphql-request";

const debugLocal = process.env.DEBUG != undefined;

const auth0BaseUrl = process.env.AUTH0_BASE_URL;
let grantType = "client_credentials";
const clientId = process.env.AUTH0_BACK_2_BACK_API_CLIENT_ID;
const clientSecret = process.env.AUTH0_BACK_2_BACK_API_CLIENT_SECRET;
const audience = process.env.AUTH0_BACK_2_BACK_API_AUDIENCE;

class GraphQlHelper {
  uuid: string;
  orgName: string;
  authTokenProviderGetter: any = null;

  constructor(uuid: string, orgName: string) {
    this.uuid = uuid;
    this.orgName = orgName;
  }

  async init() {
    try {
      if (process.env.GRANT_TYPE_AUTH0 != undefined) {
        logger.info(`using GRANT_TYPE_AUTH0 env`);
        grantType = process.env.GRANT_TYPE_AUTH0;
      } else if (process.env.AUTH0_GRANT_TYPE != undefined) {
        logger.info(`using AUTH0_GRANT_TYPE env`);
        grantType = process.env.AUTH0_GRANT_TYPE;
      } else {
        logger.info(`using client_credentials env`);
      }

      if (debugLocal) {
        return;
      }

      logger.info(`try init graphQl helper`);

      const auth0Config = {
        client_id: clientId,
        client_secret: clientSecret,
        audience: audience,
        grant_type: grantType,
      };

      const authTokenProvider = createAuthTokenProvider({
        auth0BaseUrl: auth0BaseUrl,
        serviceTypeConfigs: {
          [ServiceType.Back2Back]: auth0Config,
        },
        cacheConfigs: {
          cacheClientProps: {
            host: process.env.REDIS_HOST,
            port: parseInt(process.env.REDIS_PORT),
          },
        },
      });

      this.authTokenProviderGetter = authTokenProvider(ServiceType.Back2Back);
    } catch (err) {
      logger.error(`failed init graphQl helper, err: ${err}`);
    }
  }

  async invokeDisablePoliciesForActiveProfileQueryRequest() {
    const url = process.env.POLICY_SERVICE_HOST_URL;

    try {
      const authorization = await this.authTokenProviderGetter.get();
      const graphQLClient = new GraphQLClient(url, {
        timeout: 30000,
        headers: {
          authorization: `Bearer ${authorization}`,
        },
      });

      const query = gql`
        query {
          getDisablePoliciesForActiveProfile {
            policies {
              id
              policyId
              ruleId
              name
              categoryId
              catId
              system
              description
              detailedDescription
              severity
              selected
              functionName
              exclusionCategory
              args {
                id
                name
                label
                tooltip
                type
                value
                range
                multiSelect
                visible
              }
              resources {
                id
                name
                type
              }
              exclusions
              appInclusions
            }
          }
        }
      `;

      const variables = {
        orgId: `${this.orgName}`,
      };

      const data = await graphQLClient.request(query, variables);
      return data.getDisablePoliciesForActiveProfile.policies;
    } catch (err) {
      const errInfo = "failed to get disable policies from policy service";
      logger.error(`exception for invoke graphQl for getting disable policies, url: ${url}, err: ${err}`);
    }
    return [];
  }

  async invokeConnectorsSetFullScan(setFullScanTo: boolean = false) {
    logger.info(`invokeConnectorsSetFullScan setting isFullScan to ${setFullScanTo}`);

    const url = process.env.CONNECTORS_HOST_URL;

    try {
      const authorization = await this.authTokenProviderGetter.get();

      const graphQLClient = new GraphQLClient(url, {
        timeout: 30000,
        headers: {
          authorization: `Bearer ${authorization}`,
        },
      });

      const query = gql`
        mutation SetFullScan($setFullScanTo: Boolean) {
          setFullScan(setFullScanTo: $setFullScanTo)
        }
      `;

      const variables = {
        orgId: `${this.orgName}`,
        setFullScanTo,
      };

      const result = await graphQLClient.request(query, variables);
    } catch (err) {
      logger.warn(`Failed in graphQl for setting isFullScan to ${setFullScanTo}, url: ${url}, err: ${err}`);
    }
  }
}

export default GraphQlHelper;
