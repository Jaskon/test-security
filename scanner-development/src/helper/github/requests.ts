import memoryDB from "@oxappsec/ox-memory-db";
import axios from "axios";
import { GitHubRequest } from "../../entitis/codeRepoTypes";
import loggerImport from "../../logger";
import { isLocalDevelopment } from "../envUtils";
import { hash } from "../hash";
import StatesHelper from "../statesHelper";
import requestStats from "./requestStats";

const logger = loggerImport.getDebugLogger();
const minRedisKeyExpirationS = 60 * 60 * 24 * 10; // 10 days
const maxRedisKeyExpirationS = 60 * 60 * 24 * 20; // 20 days

const getAxiosConfig = (token: string, host: string) => ({
  baseURL: host === "" ? "https://api.github.com" : host,
  timeout: 30000,
  headers: {
    Authorization: "token " + token,
  },
});

const parseEndpoint = ({ url, parms: params }) => {
  const [method, endpoint] = url.includes(" ") ? url.split(" ") : ["GET", url];
  const parsedEndpoint = Object.keys(params).reduce((str, key) => str.replace(new RegExp(`{${key}}`, "g"), params[key]), endpoint);

  return [method, parsedEndpoint];
};

const handleNoCachedRequest = async (gitHubRequest: GitHubRequest, token: string, host: string) => {
  const axiosConfig = getAxiosConfig(token, host);
  const [method, endpoint] = parseEndpoint(gitHubRequest.query);
  const instance = axios.create({
    method,
    ...axiosConfig,
  });

  const requestObject = {
    url: endpoint,
    params: gitHubRequest.query.parms,
  };

  logger.debug(`handleNoCachedRequest to ${JSON.stringify(requestObject)}`);

  const { data } = await instance.request(requestObject);
  return data;
};

export const handleEtagRequest = async (
  token: string,
  host: string,
  gitHubRequest,
  cachedEtag: string,
  etagCacheKey: string,
  etagDataCacheKey: string,
) => {
  const stats = requestStats();
  const { query } = gitHubRequest;
  const [method, parsedEndpoint] = parseEndpoint(query);

  const axiosConfig = { ...getAxiosConfig(token, host), method };

  stats.addTotalEtagRequest();

  const requestObject = {
    url: parsedEndpoint,
    params: query.parms,
  };

  logger.debug(`Etag ${cachedEtag} found for request ${JSON.stringify(gitHubRequest)}, cacheKey: ${etagCacheKey}`);

  const instance = axios.create({
    ...axiosConfig,
    method,
    validateStatus: (status: number) => status >= 200 && (status < 300 || status == 304),
    headers: {
      ...axiosConfig.headers,
      "If-None-Match": cachedEtag,
    },
  });

  const { status, data, headers } = await instance.request(requestObject);

  // Return cached data if status is 304
  if (status === 304) {
    stats.addSuccessfulEtagRequest();
    logger.debug(`request status returned 304, returning cached data for cacheKey: ${etagCacheKey}`);
    const etagDataCached = (await memoryDB.get.execute(etagDataCacheKey)) as string;

    // reset the expiration key
    await memoryDB.set.execute(etagDataCacheKey, getRedisExpiration(minRedisKeyExpirationS, maxRedisKeyExpirationS), etagDataCached);
    await memoryDB.set.execute(etagCacheKey, getRedisExpiration(minRedisKeyExpirationS, maxRedisKeyExpirationS), cachedEtag);

    return JSON.parse(etagDataCached);
  }

  // If status is not 304, the data changed so i will updateCache
  stats.addExpiredEtagRequest();
  logger.debug(`etag ${cachedEtag} for cacheKey: ${etagCacheKey} is not relevant, returning response data and caching new`);

  await memoryDB.set.execute(etagDataCacheKey, getRedisExpiration(minRedisKeyExpirationS, maxRedisKeyExpirationS), JSON.stringify(data));
  await memoryDB.set.execute(etagCacheKey, getRedisExpiration(minRedisKeyExpirationS, maxRedisKeyExpirationS), headers.etag);

  return data;
};

const handleNoEtagRequest = async (
  token: string,
  host: string,
  gitHubRequest: GitHubRequest,
  etagCacheKey: string,
  etagDataCacheKey: string,
) => {
  const stats = requestStats();
  const { query } = gitHubRequest;
  const [method, parsedEndpoint] = parseEndpoint(query);

  const requestObject = {
    url: parsedEndpoint,
    params: query.parms,
  };

  const axiosConfig = {
    ...getAxiosConfig(token, host),
    method,
  };

  stats.addNoCachedEtagRequest();
  const instance = axios.create(axiosConfig);
  const { headers, data } = await instance.request(requestObject);
  logger.debug(`Storing ${etagCacheKey} with data: ${JSON.stringify(data)} for request ${JSON.stringify(gitHubRequest)}`);

  await memoryDB.set.execute(etagDataCacheKey, getRedisExpiration(minRedisKeyExpirationS, maxRedisKeyExpirationS), JSON.stringify(data));
  await memoryDB.set.execute(etagCacheKey, getRedisExpiration(minRedisKeyExpirationS, maxRedisKeyExpirationS), headers.etag);

  return data;
};

export const handleGithubRequest = async (gitHubRequest: GitHubRequest, token: string, host: string) => {
  const stats = requestStats();
  stats.addTotalRequest();

  if (!gitHubRequest.shouldBeCached || isLocalDevelopment()) {
    stats.addNoCachedRequests();
    return handleNoCachedRequest(gitHubRequest, token, host);
  }

  const orgName = StatesHelper.Instance.orgName;
  const requestHash = hash(JSON.stringify(gitHubRequest));
  const etagCacheKey = `etag:${orgName}:${requestHash}`;
  const etagDataCacheKey = `etag:data:${orgName}:${requestHash}`;

  const cachedEtag = await memoryDB.get.execute(etagCacheKey);

  // Check if etag is in cache
  if (cachedEtag) return handleEtagRequest(token, host, gitHubRequest, cachedEtag, etagCacheKey, etagDataCacheKey);
  else {
    // If no etag in cache, make request and store etag and data in cache
    return handleNoEtagRequest(token, host, gitHubRequest, etagCacheKey, etagDataCacheKey);
  }
};

function getRedisExpiration(minExpiration: number, maxExpiration: number): number {
  return Math.floor(Math.random() * (maxExpiration - minExpiration + 1)) + minExpiration;
}
