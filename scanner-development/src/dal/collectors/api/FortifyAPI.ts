import axios, { AxiosResponse } from "axios";
import { Token } from "../../../entitis/collectorEntitisTypes";
import { MAX_RETRY_ATTEMPTS, TIME_OUTS, logger } from "../types/collectors-types";
import { shouldRetry, sleep } from "../../../helper/commonUtils";
import PQueue from "p-queue";

export default class FortifyAPI {
  api: string;
  token: Token;
  accessToken: string;
  isValidToken: boolean = false;
  constructor(token: Token) {
    this.token = token;
    this.isValidToken = false;
    this.api = token.host;
  }

  async auth() {
    const errMessage = `${this.token.name} - Authenticate Failed : token ${JSON.stringify(this.token)} `;

    try {
      logger.info(`${this.token.name} - Authentication  ** Begin **`);

      const requestBody = new URLSearchParams();
      requestBody.append("scope", "api-tenant");
      requestBody.append("grant_type", "client_credentials");
      requestBody.append("client_id", this.token.clientId);
      requestBody.append("client_secret", this.token.clientSecret);

      const result: AxiosResponse<any> = await axios.post(this.token.host + "/oauth/token", requestBody.toString(), {
        timeout: TIME_OUTS.MEDIUM,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });
      if (result.status === 200) {
        if (result?.data?.access_token) {
          this.isValidToken = true;
          this.accessToken = result?.data?.access_token;

          logger.info(`${this.token.name} - Authentication Success`);
        } else {
          this.isValidToken = false;
          logger.error(`${errMessage} Token not found!`);
        }
      } else {
        this.isValidToken = false;
        logger.error(`${errMessage} Not a valid Token!`);
      }
    } catch (error) {
      this.isValidToken = false;
      logger.error(` ${errMessage}, err: ${error}`);
    }
  }

  // For this api rate limit is 6 calls in 30 seconds
  async getAllVersions(): Promise<any[]> {
    const releaseList = [];
    let offset = 0;
    const totalWaitTime = 30 * 1000;
    const queue = new PQueue({ concurrency: 6 }); // change it to promise pool

    try {
      logger.info(`${this.token.name} - Scanning All Releases ** Begin **`);

      const startTime = Date.now();

      while (true) {
        const elapsedTime = Date.now() - startTime;
        const remainingTime = Math.max(0, totalWaitTime - elapsedTime);

        if (remainingTime === 0) {
          logger.info(`${this.token.name} - Maximum time reached. Exiting.`);
          break;
        }

        const waitTime = Math.min(remainingTime, totalWaitTime / 6);
        const result = await queue.add(() => this.fetchReleases(offset));

        if (!result?.data?.items) {
          break; // Break if no more items
        }

        for (const item of result.data.items) {
          releaseList.push(item);
        }

        offset += result.data.items.length;

        // Break loop if offset is greater than totalCount
        if (offset >= result.data.totalCount) {
          break;
        }

        // Introduce delay between requests
        await sleep(waitTime);
      }

      logger.info(`${this.token.name} - Scanning All Releases ** Completed **, Found ${releaseList.length} Releases`);
    } catch (error) {
      logger.error(`${this.token.name} - Failed to getAllVersions: ${error}`);
    }

    return releaseList;
  }

  private async fetchReleases(offset: number): Promise<AxiosResponse<any>> {
    try {
      const totalWaitTime = 30 * 1000;
      let retryAttempts = 0;
      while (retryAttempts < MAX_RETRY_ATTEMPTS) {
        try {
          const result: AxiosResponse<any> = await axios.get(
            `${this.api}/api/v3/releases?orderBy=applicationId&orderByDirection=ASC&offset=${offset}&limit=${50}`,
            {
              timeout: TIME_OUTS.LONG,
              headers: {
                Authorization: "Bearer " + this.accessToken,
                "Content-Type": "application/json",
              },
            },
          );

          return result;
        } catch (error) {
          logger.error(`${this.token.name} - Failed to fetch releases retryAttempts: ${retryAttempts}, Error: ${error}`);
          if (shouldRetry(error)) {
            await sleep(totalWaitTime);
            retryAttempts++;
          } else {
            break;
          }
        }
      }
    } catch (error) {
      logger.error(`${this.token.name} - Failed to fetch releases. Error: ${error}`);
    }
  }

  async getAllVulnerabilities(releaseId: string) {
    const vulList = [];
    try {
      //Allowed 10 in 1 second
      await this.fetchVulnerabilities(releaseId, "scantype%3AStatic%2BclosedStatus%3Afalse", vulList);
      logger.info(`${this.token.name}, Found vulList count: ${vulList.length} for releaseId: ${releaseId} and scantype: static`);

      //Allowed 1 in 1 second
      await this.extendVulnerabilitiesInfo(vulList);
    } catch (error) {
      logger.error(`${this.token.name} - Failed to get all vulnerabilities, releaseId: ${releaseId} , err: ${error}`);
    }
    return vulList;
  }

  async fetchVulnerabilities(releaseId: string, filters: string, vulList) {
    try {
      let offset = 0;
      const reqFields =
        "id,releaseId,severityString,severity,category,cwe,package,primaryLocation,vulnId,lineNumber,scantype,subtype,primaryLocationFull,isSuppressed,suppressedBy,scanId,instanceId,checkId,closedDate,closedStatus,introducedDate,scanStartedDate,scanCompletedDate,source,sink";
      const rowCount = 50;
      logger.info(`${this.token.name}, fetching Vulnerabilities for releaseId: ${releaseId} and filters: ${filters}`);

      while (true) {
        const result: AxiosResponse<any> = await axios.get(
          `${this.api}/api/v3/releases/${releaseId}/vulnerabilities?filters=${filters}&fields=${reqFields}&offset=${offset}&limit=${rowCount}&excludeFilters=true`,
          {
            timeout: TIME_OUTS.LONG,
            headers: {
              Authorization: "Bearer " + this.accessToken,
              "Content-Type": "application/json",
            },
          },
        );

        offset += rowCount;
        if (result?.data?.items) {
          vulList.push(...result.data.items);
        }

        // break loop if offset is greater than totalCount
        if (offset > result?.data?.totalCount) {
          break;
        }
      }
    } catch (error) {
      logger.error(
        `${this.token.name} - Failed to fetchVulnerabilities with filters: ${filters} and releaseId: ${releaseId} , err: ${error}`,
      );
    }
  }

  async extendVulnerabilitiesInfo(vulnerabilities: any[]) {
    try {
      for (const vulnerability of vulnerabilities) {
        await this.setVulnerabilityData(vulnerability);
      }
    } catch (error) {
      logger.error(`${this.token.name} - Failed to processVulnerabilities, err: ${error}`);
    }
  }

  private async setVulnerabilityData(vulnerability: any) {
    const totalWaitTime = 1 * 1000;
    let retryAttempts = 0;
    while (retryAttempts < MAX_RETRY_ATTEMPTS) {
      try {
        const res = await axios.get(
          `${this.api}/api/v3/releases/${vulnerability.releaseId}/vulnerabilities/${vulnerability.vulnId}/all-data`,
          {
            timeout: TIME_OUTS.LONG,
            headers: {
              Authorization: "Bearer " + this.accessToken,
              "Content-Type": "application/json",
            },
          },
        );
        vulnerability.VulData = res.data;
        break;
      } catch (error) {
        logger.error(
          `${this.token.name} - Failed to get vulnerabilities details for releaseId: ${vulnerability.releaseId}, vulnId: ${vulnerability.vulnId} retryAttempts: ${retryAttempts}, Error: ${error}`,
        );
        if (shouldRetry(error)) {
          await sleep(totalWaitTime);
          retryAttempts++;
        } else {
          break;
        }
      }
    }
  }
}
