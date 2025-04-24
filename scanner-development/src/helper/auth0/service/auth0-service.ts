import loggerImport from "../../../logger";
const logger = loggerImport.getDebugLogger();

import { createAuthTokenProvider, ServiceType } from "@oxappsec/ox-unified-auth-token-provider";

export class Auth0Service {
  authTokenProviderGetter: {
    get: () => Promise<string>;
  };

  private static _instance: Auth0Service;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  private constructor() {
    const debugLocal = process.env.DEBUG != undefined && !process.env.DOCKER_DEBUG;
    let grantType = "client_credentials";

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
        client_id: process.env.AUTH0_BACK_2_BACK_API_CLIENT_ID,
        client_secret: process.env.AUTH0_BACK_2_BACK_API_CLIENT_SECRET,
        audience: process.env.AUTH0_BACK_2_BACK_API_AUDIENCE,
        grant_type: grantType,
      };

      const authTokenProvider = createAuthTokenProvider({
        auth0BaseUrl: process.env.AUTH0_BASE_URL,
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
}
