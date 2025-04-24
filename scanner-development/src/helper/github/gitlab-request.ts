import memoryDB from "@oxappsec/ox-memory-db";
import axios from "axios";
import { default_per_page_max_res } from "../../dal/collectors/gitlab";
import { GitlabRequest } from "../../entitis/codeRepoTypes";
import loggerImport from "../../logger";
import { hash } from "../hash";
import StatesHelper from "../statesHelper";
import requestStats from "./requestStats";

const logger = loggerImport.getDebugLogger();
const minRedisKeyExpirationS = 60 * 60 * 24 * 10; // 10 days
const maxRedisKeyExpirationS = 60 * 60 * 24 * 20; // 20 days

const handleNoCachedRequest = async (gitLabRequest: GitlabRequest) => {
  const instance = axios.get(
    gitLabRequest.query.url + `?per_page=${gitLabRequest.perPage || default_per_page_max_res}&page=${gitLabRequest.page}`,
    gitLabRequest.query.params,
  );
  const res: any = await instance;

  logger.debug(`handleNoCachedRequest to ${JSON.stringify(gitLabRequest)}`);

  return res.data;
};

export const handleEtagRequest = async (gitLabRequest, cachedEtag: string, etagCacheKey: string, etagDataCacheKey: string) => {
  const stats = requestStats();

  stats.addTotalEtagRequest();

  logger.debug(`Etag ${cachedEtag} found for request ${JSON.stringify(gitLabRequest)}, cacheKey: ${etagCacheKey}`);

  logger.debug(`Making request to ${gitLabRequest.query.url} with etag ${cachedEtag} and cacheKey: ${etagCacheKey}}`);

  gitLabRequest.query.params.headers["If-None-Match"] = cachedEtag;
  gitLabRequest.query.params["validateStatus"] = (status: number) => status >= 200 && (status < 300 || status == 304);

  const instance = axios.get(
    gitLabRequest.query.url + `?per_page=${gitLabRequest.perPage || default_per_page_max_res}&page=${gitLabRequest.page}`,
    gitLabRequest.query.params,
  );

  const res: any = await instance;

  // Return cached data if status is 304
  if (res.status === 304) {
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

  await memoryDB.set.execute(
    etagDataCacheKey,
    getRedisExpiration(minRedisKeyExpirationS, maxRedisKeyExpirationS),
    JSON.stringify(res.data),
  );
  await memoryDB.set.execute(etagCacheKey, getRedisExpiration(minRedisKeyExpirationS, maxRedisKeyExpirationS), res.headers.etag);

  return res.data;
};

function getRedisExpiration(minExpiration: number, maxExpiration: number): number {
  return Math.floor(Math.random() * (maxExpiration - minExpiration + 1)) + minExpiration;
}

const handleNoEtagRequest = async (gitLabRequest: GitlabRequest, etagCacheKey: string, etagDataCacheKey: string) => {
  const stats = requestStats();

  const url = gitLabRequest.query.url + `?per_page=${gitLabRequest.perPage || default_per_page_max_res}&page=${gitLabRequest.page}`;
  const instance = axios.get(url, gitLabRequest.query.params);
  const res: any = await instance;

  stats.addNoCachedEtagRequest();
  logger.debug(`Storing ${etagCacheKey} with data for request ${url}`);

  if (res.headers["etag"]) {
    await memoryDB.set.execute(
      etagDataCacheKey,
      getRedisExpiration(minRedisKeyExpirationS, maxRedisKeyExpirationS),
      JSON.stringify(res.data),
    );
    await memoryDB.set.execute(etagCacheKey, getRedisExpiration(minRedisKeyExpirationS, maxRedisKeyExpirationS), res.headers.etag);
  }

  return res.data;
};

export const handleGitlabRequest = async (gitLabRequest: GitlabRequest) => {
  const stats = requestStats();
  stats.addTotalRequest();

  if (!gitLabRequest.shouldBeCached) {
    stats.addNoCachedRequests();
    return handleNoCachedRequest(gitLabRequest);
  }

  const orgName = StatesHelper.Instance.orgName;
  const requestHash = hash(JSON.stringify(gitLabRequest));
  const etagCacheKey = `etag:${orgName}:${requestHash}`;
  const etagDataCacheKey = `etag:data:${orgName}:${requestHash}`;

  const cachedEtag = await memoryDB.get.execute(etagCacheKey);

  // Check if etag is in cache
  if (cachedEtag) return handleEtagRequest(gitLabRequest, cachedEtag, etagCacheKey, etagDataCacheKey);
  else {
    // If no etag in cache, make request and store etag and data in cache
    return handleNoEtagRequest(gitLabRequest, etagCacheKey, etagDataCacheKey);
  }
};
