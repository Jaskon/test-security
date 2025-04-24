import { GraphQLClient } from "graphql-request";
import { Auth0Service } from "../auth0/api";
import { retry } from "../commonUtils";

export abstract class ServiceBase {
  protected readonly gqlClient: GraphQLClient;
  constructor(serviceUrl: string) {
    this.gqlClient = new GraphQLClient(serviceUrl, {
      timeout: 60000,
    });
  }

  protected async runQueryWithRetry<T>(query: string, vars: any, api: string, rertyConfig: RertyConfig = { sleepInMS: 4000, times: 4 }) {
    const callback = async () => {
      return await this.gqlClient.request<T>(query, vars);
    };
    const res = await retry<T>(callback, rertyConfig, api);
    return res;
  }

  protected async setAuthHeader() {
    const authorization = await Auth0Service.Instance.authTokenProviderGetter.get();
    this.gqlClient.setHeader("authorization", `Bearer ${authorization}`);
    // this.gqlClient.setHeader(
    //   "authorization",
    //   "Bearer ",
    // );
  }
}

interface RertyConfig {
  times: number;
  sleepInMS: number;
}
