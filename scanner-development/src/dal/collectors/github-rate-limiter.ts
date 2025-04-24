import Bottleneck from "bottleneck";
import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";

const logger = loggerImport.getDebugLogger();

export class GithubRateLimiter {
  private readonly RATE_REMAINING_HEADER = "X-RateLimit-Remaining";
  private readonly RATE_RESET_HEADER = "X-RateLimit-Reset";
  private readonly SECONDARY_LIMIT_HEADER = "Retry-After";

  private readonly bottleneck: Bottleneck;

  private primaryLimitWait: Promise<void> | null = null;
  private secondaryLimitWait: Promise<void> | null = null;

  constructor() {
    this.bottleneck = new Bottleneck({ maxConcurrent: 50 });
  }

  async runRateLimitedQuery<TResponse>(apiCall: ApiCall<TResponse>): Promise<ApiResponse<TResponse>> {
    try {
      // wait for rate limits
      await Promise.all([this.primaryLimitWait, this.secondaryLimitWait]);
      return await this.bottleneck.schedule(() => apiCall());
    } catch (err) {
      if (this.isPrimaryLimitErr(err)) {
        logger.info(`Hit primary rate limit`);
        const limitResetTime = err.response.headers.get(this.RATE_RESET_HEADER);
        this.createWaitPromise("primaryLimitWait", Number(limitResetTime) * 1000 - Date.now());
        return this.runRateLimitedQuery(apiCall);
      }
      if (this.isSecondaryLimitErr(err)) {
        logger.info(`Hit secondary rate limit`);
        const retryAfterSeconds = err.response.headers.get(this.SECONDARY_LIMIT_HEADER);
        this.createWaitPromise("secondaryLimitWait", Number(retryAfterSeconds) * 1000);
        return this.runRateLimitedQuery(apiCall);
      }
      throw err;
    }
  }

  private isSecondaryLimitErr(err: any): boolean {
    return err.response?.status === 403 && err.response?.headers?.get(this.SECONDARY_LIMIT_HEADER);
  }

  private isPrimaryLimitErr(err: any): boolean {
    return err.response?.status === 403 && err.response?.headers?.get(this.RATE_REMAINING_HEADER) === "0";
  }

  private createWaitPromise(limit: "primaryLimitWait" | "secondaryLimitWait", ms: number): void {
    if (this[limit]) {
      // Rate limit wait already set
      return;
    }
    const startWait = Date.now();
    logger.info(`Setting new rate limit ${limit}`);
    this[limit] = new Promise<void>(resolver => {
      setTimeout(() => resolver(), ms);
    }).then(() => {
      StatesHelper.Instance.scanInfoStats[
        limit === "primaryLimitWait" ? "githubGraphqlPrimaryRateLimitWait" : "githubGraphqlSecondaryRateLimitWait"
      ] += Date.now() - startWait;
      logger.info(`Rate limit ${limit} finished`);
      this[limit] = null;
    });
  }
}

interface Headers {
  get(name: string): string | null;
}

interface ApiResponse<TResponse> {
  headers: Headers;
  data: TResponse;
}

type ApiCall<TResponse> = () => Promise<ApiResponse<TResponse>>;
