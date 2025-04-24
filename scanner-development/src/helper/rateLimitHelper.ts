import { Repo } from "../entitis/codeRepoTypes";
import loggerImport from "../logger";
import StatesHelper from "./statesHelper";
import { millisToMinutesAndSeconds } from "./telemetry-utils";
import PromisePool from "@supercharge/promise-pool";
const logger = loggerImport.getDebugLogger();

const github = "github";
const githubci = "githubci";

export interface Parallel {
  pages: number;
  concurrency: number;
}

class APIRequest {
  constructor(request: any) {
    this.apiRequestData = request;
  }

  apiRequestData: any;
  rateLimitBasedOnMaxAllowedReq: boolean = false;
  retryCount: number = 1;

  fistCall: number = new Date().getTime();
  totalElapsedTime = new Date().getTime();
}

export class RateLimitHelperFactory {
  static allInstances = {};

  static getRateLimitHelperPerToken(tokenName: string, allowedNumberOfInflightRequests: number = 100) {
    let t = tokenName.toLowerCase();
    if (t.endsWith("ci")) {
      t = tokenName.toLowerCase().substring(0, t.length - "ci".length);
    } else if ((t = "gitlabArtifacts".toLowerCase())) {
      t = "gitlab";
    }

    if (RateLimitHelperFactory.allInstances[t]) {
      logger.info(`return rate limit instance for ${t}`);
      return RateLimitHelperFactory.allInstances[t];
    }
    RateLimitHelperFactory.allInstances[t] = new RateLimitHelper(tokenName, allowedNumberOfInflightRequests);
    logger.info(`return rate limit instance for ${t}`);
    return RateLimitHelperFactory.allInstances[t];
  }
}

class RateLimitHelper {
  //Configuration
  inRateLimitState: boolean = false;
  inflightRequests: number = 0;
  allowedNumberOfInflightRequests: number = 0;
  intervalToCheckInflightRequestsCount = 1000 * 10;

  //Stats
  invokerName: string;
  requestsBeforeRateLimitHappen: number = 0;
  dilatedDueToRateLimits: number = 0;
  totalRequest: number = 0;
  failedCollectedDueToRateLimit: number = 0;
  failedCollectedDueToErr: number = 0;

  //stats
  loggedOnce: boolean = false;
  lastReq: Date = new Date();

  //For Github
  totalRequestAllowed: number;

  constructor(invokerName: string, allowedNumberOfInflightRequests: number) {
    this.invokerName = invokerName.toLowerCase();
    this.allowedNumberOfInflightRequests = allowedNumberOfInflightRequests;
  }

  async sendApiRequest(
    functionName: string,
    apiRequestData: any,
    isRateLimitErrFunction: any,
    apiFunction: any,
    getQueryNextPageFunction: any,
    maxRetry: number,
    callerInstance: any,
    throwErr: boolean = false,
    repo?: Repo,
    parallel?: Parallel,
  ) {
    let res = [];

    try {
      //Do first request
      const singleRes = await this.sendSingleApiRequest(
        functionName,
        apiRequestData,
        isRateLimitErrFunction,
        apiFunction,
        maxRetry,
        callerInstance,
        throwErr,
        repo,
      );

      if (singleRes == null) {
        return [];
      }

      if (singleRes.length === 0) {
        return [];
      }
      res.push(singleRes);

      let safetyCheck = 50;

      //Do the rest if needed

      if (parallel) {
        safetyCheck = 120;
        let error = null;
        const pagesArray = Array.from(Array(parallel.pages - 1).keys()).map(i => i + 2);

        const { results } = await PromisePool.withConcurrency(parallel.concurrency)
          .for(pagesArray)
          .handleError(async (_error, pageNum, pool) => {
            pool.stop();
            error = _error;
          })
          .process(async pageNum => {
            const res = await this.sendSingleApiRequest(
              functionName,
              apiRequestData,
              isRateLimitErrFunction,
              apiFunction,
              maxRetry,
              callerInstance,
              throwErr,
              repo,
              pageNum,
            );
            safetyCheck--;
            if (safetyCheck <= 0) {
              logger.error(`safety check trigger for ${this.invokerName}, functionName: ${functionName}`);
            }
            return res;
          });

        res.push(...results);

        if (error !== null) {
          throw error;
        }
      }

      if (!parallel) {
        let lastPaginationRes = singleRes;
        if (getQueryNextPageFunction != null) {
          while (getQueryNextPageFunction(apiRequestData, lastPaginationRes) || safetyCheck == 0) {
            safetyCheck--;
            lastPaginationRes = await this.sendSingleApiRequest(
              functionName,
              apiRequestData,
              isRateLimitErrFunction,
              apiFunction,
              maxRetry,
              callerInstance,
              throwErr,
            );
            if (lastPaginationRes.length === 0) {
              break;
            }
            res.push(lastPaginationRes);
          }

          if (safetyCheck <= 0) {
            logger.error(`safety check trigger for ${this.invokerName}, functionName: ${functionName}`);
          }
        }
      }
    } catch (err) {
      if (throwErr) {
        throw err;
      }

      logger.error(`failed send api request, err: ${err}, functionName: ${functionName}`);
    }

    return res;
  }

  //return array always
  async sendSingleApiRequest(
    functionName: string,
    apiRequestData: any,
    isRateLimitErrFunction: any,
    apiFunction: any,
    maxRetryCount: number,
    callerInstance: any,
    throwErr: boolean,
    repo?: Repo,
    page?: number,
  ) {
    const r: APIRequest = new APIRequest(apiRequestData);

    while (r.retryCount < maxRetryCount) {
      try {
        //Enforce inflight bound
        if (this.inflightRequests >= this.allowedNumberOfInflightRequests) {
          //Start sleep in case too many request inflight
          const resOfWait = await this.waitForInflightRequestDropBellowLimit();
          if (!resOfWait) {
            logger.error(
              `rate limit, invoker name: ${this.invokerName}, last req: ${this.lastReq.toString()}, functionName: ${functionName}, retry: ${
                r.retryCount
              }, finish to wait for request to drop but inflight request: ${this.inflightRequests} still high this allowed: ${
                this.allowedNumberOfInflightRequests
              }`,
            );
            r.retryCount--;
            continue;
          }
        }

        //Check rate limit - this check should be fist, no need to check inflight request if we cannot do the request
        if (this.inRateLimitState) {
          //Start sleep in case rate limit happen
          await this.sleep(await callerInstance.getTimeToWait());
          this.inRateLimitState = false;
          this.requestsBeforeRateLimitHappen = 0;
        }

        if (this.invokerName === github || this.invokerName === githubci) {
          if (!isNaN(this.totalRequestAllowed)) {
            this.totalRequestAllowed--;
          }
        }

        if (this.inRateLimitState || this.inflightRequests >= this.allowedNumberOfInflightRequests) {
          r.retryCount--;
          continue;
        }

        this.loggedOnce = false;
        this.lastReq = new Date();
        this.totalRequest++;
        this.requestsBeforeRateLimitHappen++;
        this.inflightRequests++;

        //Do request
        const res = await apiFunction(r.apiRequestData, page);
        this.inflightRequests--;

        return res;
      } catch (err) {
        this.inflightRequests--;
        r.retryCount++;

        r.rateLimitBasedOnMaxAllowedReq = this.isRateLimitDueToMaxAllowedRequest();

        if (!r.rateLimitBasedOnMaxAllowedReq && !isRateLimitErrFunction(err)) {
          if (throwErr) {
            throw err;
          }

          if (this.httpWarning(err)) {
            return [];
          }

          logger.error(
            `failed call api for: ${this.invokerName}, function name: ${functionName} err: ${err}, ${err.response?.data?.message} number of inflight request: ${this.inflightRequests}, total request: ${this.totalRequest}`,
            err,
          );

          this.failedCollectedDueToErr++;
          return [];
        }

        //Rate limit hit
        if (!this.loggedOnce) {
          this.loggedOnce = true;
          logger.info(
            `rate limit detected for: ${this.invokerName}, last req: ${this.lastReq.toString()}, function name: ${functionName}, retry: ${
              r.retryCount
            }, after ${this.requestsBeforeRateLimitHappen}, total requests: ${this.totalRequest}, number of inflight request: ${
              this.inflightRequests
            }, err: ${err}`,
          );
        }

        //Print some stats for long time waiting
        try {
          let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - r.fistCall);
          if (elapsedTime / (1000 * 60) > 10) {
            r.fistCall = new Date().getTime();
            let totalElapsedTime = millisToMinutesAndSeconds(new Date().getTime() - r.totalElapsedTime);
            logger.warn(
              `rate limit detected on high amount of retry and wait time in minutes: ${(totalElapsedTime / (1000 * 60)).toFixed(1)} for: ${
                this.invokerName
              }, function name: ${functionName} after ${this.requestsBeforeRateLimitHappen}, total requests: ${
                this.totalRequest
              }, number of inflight request: ${this.inflightRequests}, total request: ${
                this.totalRequest
              }, last req: ${this.lastReq.toString()}, err: ${err}`,
            );
          }
        } catch (err) {
          logger.info(`rate limit print stats, err: ${err}`);
        }

        this.inRateLimitState = true;
        this.dilatedDueToRateLimits++;
      }
    }

    if (r.retryCount >= maxRetryCount) {
      logger.warn(
        `failed call api for: ${
          this.invokerName
        }, last req: ${this.lastReq.toString()}, function name: ${functionName} err: rate limit happen after max retry: ${maxRetryCount}, number of inflight request: ${
          this.inflightRequests
        }, total request: ${this.totalRequest}`,
      );

      if (functionName === "GET /repos/{owner}/{repo}/actions/permissions/workflow" && repo !== undefined && repo !== null) {
        StatesHelper.Instance.addFailedTool("min-permissions", repo.id);
      }
      this.failedCollectedDueToRateLimit++;
    }
    return [];
  }

  httpWarning(err) {
    if (err?.response?.status) {
      if (
        err.response.status == 401 ||
        err.response.status == 404 ||
        err.response.status == 403 ||
        // githubCI logs sometimes missing/old
        err.toString().includes("Failed to generate URL to download logs") ||
        err.toString().includes("Server Error")
      ) {
        return true;
      }
    }
    return false;
  }

  isRateLimitDueToMaxAllowedRequest() {
    if (isNaN(this.totalRequestAllowed)) {
      return false;
    }
    if (this.invokerName === github || this.invokerName === githubci) {
      if (this.totalRequestAllowed > 0) {
        return false;
      }
      return true;
    }
    return false;
  }

  async waitForInflightRequestDropBellowLimit() {
    let retry = 50;

    while (retry > 0) {
      await this.sleep(this.intervalToCheckInflightRequestsCount);
      if (this.inflightRequests < this.allowedNumberOfInflightRequests) {
        return true;
      }
      retry--;
    }
    if (retry == 0) {
      return false;
    }
    return true;
  }

  async sleep(timeout: number) {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(timeout);
  }

  printStats() {
    logger.info(
      `stats invoker name: ${this.invokerName}, failed collected due to err: ${this.failedCollectedDueToErr}, failed collected due to rate limit: ${this.failedCollectedDueToRateLimit} ,dilated due to rate limit: ${this.dilatedDueToRateLimits}`,
    );
  }
}

export default RateLimitHelper;
