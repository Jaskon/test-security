import { SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import axios, { AxiosResponse } from "axios";
import PromisePool from "@supercharge/promise-pool/dist";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import Constant from "../../entitis/constant";
import { MAX_RETRY_ATTEMPTS, TIME_OUTS, logger, urlRegex } from "./types/collectors-types";
import FortifyAPI from "./api/FortifyAPI";
import { findLineNumberAndText, removeSlashFromUrl } from "./utils/collectors-utils";
import PQueue from "p-queue";
import { shouldRetry, sleep } from "../../helper/commonUtils";

class Fortify extends ExternalSecurityProviderBase {
  private clientApi: FortifyAPI;
  host: string;
  token: Token;
  private_token: string;
  uniqueRepos = {};
  queue: PQueue;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.host = token.host;
    this.token = token;
  }

  async initLib() {
    try {
      this.host = removeSlashFromUrl(this.host);
      this.clientApi = new FortifyAPI(this.token);

      await this.clientApi.auth();
    } catch (err) {
      logger.error(`failed to initialize ${this.token.name}, Error : ${err}`);
    }
  }

  async getFilesInfo(vulnId, releaseId, traceIndex, traceEntryIndex) {
    try {
      const queue = new PQueue({ concurrency: 10 });
      const result = await queue.add(() => this.fetchFilesInfo(vulnId, releaseId, traceIndex, traceEntryIndex));
      return result;
    } catch (error) {
      logger.error(`failed getFilesInfo ${this.token.name}, Error : ${error}`);
    }
  }

  private async fetchFilesInfo(vulnId, releaseId, traceIndex, traceEntryIndex): Promise<AxiosResponse<any>> {
    const totalWaitTime = 30 * 1000;
    let retryAttempts = 0;
    while (retryAttempts < MAX_RETRY_ATTEMPTS) {
      try {
        const result: AxiosResponse<any> = await axios.get(
          `${this.clientApi.api}/api/v3/releases/${releaseId}/vulnerabilities/${vulnId}/traces/${traceIndex}/${traceEntryIndex}/code`,
          {
            timeout: TIME_OUTS.MEDIUM,
            headers: {
              Authorization: "Bearer " + this.clientApi.accessToken,
              "Content-Type": "application/json",
            },
          },
        );
        return result?.data;
      } catch (error) {
        logger.error(
          `${this.token.name} - Failed to get files info. ${this.clientApi.api}/api/v3/releases/${releaseId}/vulnerabilities/${vulnId}/traces/${traceIndex}/${traceEntryIndex}/code, retryAttempts: ${retryAttempts}, Error: ${error}`,
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

  async getApplicationIssues(release, securityEvents: SecurityEvent[]) {
    try {
      logger.info(
        `${this.token.name} - Generating release issues by releaseName: ${release.releaseName} - releaseId: ${release.releaseId}** Begins **`,
      );

      const vulnerabilities = await this.clientApi.getAllVulnerabilities(release.releaseId);

      await PromisePool.for(vulnerabilities)
        .withConcurrency(10)
        .process(async issue => {
          await this.setIssue(issue, release, securityEvents);
        });

      logger.info(
        `${this.token.name} - Generating Application issues by releaseName: ${release.releaseName} - releaseId: ${release.releaseId} ** Completed **, Found ${vulnerabilities?.length} Issues`,
      );
    } catch (error) {
      logger.error(
        `${this.token.name} - Failed generating application issues by releaseName: ${release.releaseName} - releaseId: ${release.releaseId}, Errors : ${error}`,
      );
    }
  }

  async setIssue(issueFromApi, release, securityEvents: SecurityEvent[]) {
    try {
      const issueFileName = issueFromApi.primaryLocation || issueFromApi?.VulData?.summary?.primaryLocation;
      const cwe: string[] = issueFromApi?.cwe?.includes(", ") ? issueFromApi?.cwe.split(", ") : [issueFromApi?.cwe] || [];
      const extractedUrls = [];
      const traces = issueFromApi?.VulData?.traces;
      let traceEntries = [];
      let traceIndex = 0;
      let traceEntryIndex = 0;
      let sourceFileInfo;
      let match = "";
      let lineNumber = 0;

      if (traces) {
        traceIndex = issueFromApi.VulData.traces[0]?.traceIndex;
        traceEntries = issueFromApi.VulData.traces[0]?.traceEntries;
        traceEntryIndex = traceEntries.find(trace => trace.lineNumber === issueFromApi.VulData?.summary?.lineNumber).index || 0;
        sourceFileInfo = await this.getFilesInfo(issueFromApi.vulnId, issueFromApi.releaseId, traceIndex, traceEntryIndex);
      }
      if (issueFromApi?.VulData?.summary?.lineNumber) {
        lineNumber = issueFromApi?.VulData?.summary?.lineNumber || 0;
      }
      if (sourceFileInfo) {
        if (sourceFileInfo.sourceFileContent) {
          match = findLineNumberAndText(sourceFileInfo.sourceFileContent, lineNumber); //sourceFileInfo.sourceFileContent; // change this to specific line
        } else if (issueFromApi.source !== "<None>") {
          match = issueFromApi.source;
        }
      }

      const lineContent = issueFromApi.sink !== "<None>" ? issueFromApi.sink : "";

      // Match URLs using the regular expression
      let matchUrl;
      while ((matchUrl = urlRegex.exec(issueFromApi?.VulData?.recommendations?.references)) !== null) {
        // Check and exclude undesired extensions
        if (
          matchUrl[2]?.endsWith(".html") &&
          !matchUrl[2]?.includes(".xml") &&
          !matchUrl[2]?.includes(".pdf") &&
          !matchUrl[2]?.includes(".json")
        ) {
          extractedUrls.push(matchUrl[2]);
        }
      }
      if (issueFromApi?.category?.toLowerCase()?.includes("password") || issueFromApi?.category?.toLowerCase()?.includes("secret")) {
        const securityEvent = new SecurityEvent(
          Constant.fortify,
          true,
          "",
          issueFromApi?.scanStartedDate,
          "",
          "",
          "",
          issueFromApi?.category || issueFromApi?.VulData?.details?.summary,
          issueFromApi?.VulData?.details?.summary,
          issueFileName,
          issueFromApi?.severityString === "Best Practice" ? "Info" : issueFromApi?.severityString,
          issueFromApi?.VulData?.details?.explanation,
          lineNumber,
          issueFromApi?.severityString === "Best Practice" ? "Info" : issueFromApi?.severityString,
          SecurityAlertType.secrets,
          issueFromApi?.VulData?.recommendations?.recommendations,
          lineContent,
          match,
          -1,
          false,
          false,
          "",
          "",
          "",
          "",
          issueFromApi.checkId,
          extractedUrls?.[0], // learn more link
          "",
          release?.applicationName,
          "",
          issueFromApi?.detail?.summary?.primaryLocationFull,
          "fortify",
        );

        securityEvent.blame.cwe = cwe;
        securityEvent.realMatch = issueFromApi.checkId;

        securityEvents.push(securityEvent);
      } else if (issueFromApi.scantype === "Static") {
        const securityEvent = new SecurityEvent(
          Constant.fortify,
          true,
          "",
          issueFromApi?.scanStartedDate,
          "",
          "",
          "",
          issueFromApi?.category || issueFromApi?.VulData?.details?.summary,
          issueFromApi?.VulData?.details?.summary,
          issueFileName,
          issueFromApi?.severityString === "Best Practice" ? "Info" : issueFromApi?.severityString,
          issueFromApi?.VulData?.details?.explanation,
          lineNumber,
          issueFromApi?.severityString === "Best Practice" ? "Info" : issueFromApi?.severityString,
          SecurityAlertType.sast,
          issueFromApi?.VulData?.recommendations?.recommendations,
          lineContent,
          match,
          -1,
          false,
          false,
          "",
          "",
          "",
          "",
          issueFromApi.checkId,
          extractedUrls?.[0], // learn more link
          "",
          release?.applicationName,
          "",
          issueFromApi?.VulData?.summary?.primaryLocationFull,
          "fortify",
        );

        securityEvent.blame.cwe = cwe;
        securityEvent.realMatch = issueFromApi.checkId;

        securityEvents.push(securityEvent);
      }
    } catch (e) {
      logger.error(`${this.token.name} : Failed to set security event, err: ${JSON.stringify(e)}, issue: ${JSON.stringify(issueFromApi)}`);
    }
  }

  async securityEvents() {
    const securityEvents: SecurityEvent[] = [];

    try {
      const releaseList = await this.clientApi.getAllVersions();

      await PromisePool.for(releaseList)
        .withConcurrency(8)
        .process(async release => {
          await this.getApplicationIssues(release, securityEvents);
        });
    } catch (error) {
      logger.error(`${this.token.name} Failed to set releases, Error: ${error}`);
    }

    logger.info(`${this.token.name} Getting All releases and Set securityEvents: ${securityEvents.length}`);
    return securityEvents;
  }
}

export default Fortify;
