import { SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import axios, { AxiosResponse } from "axios";
import PromisePool from "@supercharge/promise-pool/dist";

import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";

import xml2js from "xml2js";
import Constant from "../../entitis/constant";

const logger = loggerImport.getDebugLogger();
const concurrent_pool_call = 20;

class AppScanAPI {
  private api: string;
  private token: Token;
  private accessToken: string;
  public isValidToken: boolean = false;

  private TIME_UNITS = {
    SEC: 1000,
    MIN: 60 * 1000,
  };

  private TIME_OUTS = {
    SHORT: 10 * this.TIME_UNITS.SEC,
    MEDIUM: 50 * this.TIME_UNITS.SEC,
    LONG: 2 * this.TIME_UNITS.MIN,
  };

  constructor(token: Token) {
    this.token = token;
    this.isValidToken = false;

    this.api = token.host;
  }

  async sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  async auth() {
    const errMessage = `${this.token.name} - Authenticate Failed : token ${this.token} `;

    try {
      logger.info(`${this.token.name} - Authentication  ** Begin **`);

      const requestBody = {
        KeyId: this.token.userName,
        KeySecret: this.token.password,
      };
      const result: AxiosResponse<any> = await axios.post(this.token.host + "/api/V2/Account/ApiKeyLogin", requestBody, {
        timeout: this.TIME_OUTS.MEDIUM,
        headers: this.getHeaders(),
      });
      if (result.status === 200) {
        if (result?.data?.Token) {
          this.isValidToken = true;
          this.accessToken = result.data.Token;

          logger.info(`${this.token.name} - Authentication Success`);
        } else {
          this.isValidToken = false;
          logger.error(`${errMessage} Token not found!`);
        }
      } else {
        this.isValidToken = false;
        logger.error(`${errMessage} Not a valid Token!`);
      }
    } catch (error: any) {
      this.isValidToken = false;
      logger.error(` ${errMessage}, Error: ${error}`);
    }
  }

  getHeaders() {
    return {
      "Content-Type": "application/json",
    };
  }

  async getApplicationApi(applicationList: Array<any>[]) {
    try {
      const result: AxiosResponse<any> = await axios.get(this.api + "/api/v3/Apps", {
        timeout: this.TIME_OUTS.MEDIUM,
        headers: {
          Authorization: "Bearer " + this.accessToken,
          "Content-Type": "application/json",
        },
      });

      if (result?.data?.Items) {
        for (const item of result.data.Items) {
          applicationList.push(item);
        }
      }
    } catch (error) {
      logger.error(`${this.token.name} Failed to find Application : ${error}`);
    }
  }

  async getAllApps() {
    const applicationList = [];

    logger.info(`${this.token.name} - Getting All Apps ** Begin **`);

    await this.getApplicationApi(applicationList);

    logger.info(`${this.token.name} - Getting All Apps ** Completed ** , Found ${applicationList.length} Applications`);

    return applicationList;
  }

  async extractReportData(xml: string) {
    logger.info(` ${this.token.name} XML to JSON conversion  ** Begins **`);

    try {
      const parser = new xml2js.Parser();
      const result = await parser.parseStringPromise(xml);
      if (result) {
        const issueGroup = result["xml-report"]["issue-group"][0];
        const articleGroupData = result["xml-report"]["article-group"][0];
        const itemsData = [];
        if (issueGroup?.item && Array.isArray(issueGroup.item)) {
          const items = issueGroup.item;

          items.forEach(item => {
            try {
              const issueType = item["issue-type"]?.[0]?.ref?.[0] || "";
              const issueId = item["asoc-issue-id"]?.[0] || "";
              const issueTypeName = item["issue-type-name"]?.[0] || "";
              const severity = item["severity"]?.[0] || "";
              const technology = item["technology"]?.[0] || "";
              const cwe = item["cwe"]?.ref?.[0] || item["cwe"]?.[0] || "";
              const status = item["status"]?.[0] || "";
              const dateCreated = item["date-created"]?.[0] || "";
              const lastUpdated = item["last-updated"]?.[0] || "";
              const location = item["location"]?.[0] || "";
              const cvss = item["cvss"]?.[0] || "";
              const causeId = item["cause-id"]?.[0]?.ref?.[0] || "";
              const variantGroup = item["variant-group"]?.[0]?.item?.[0] || "";
              const fixGroupId = item["fix-group-id"]?.[0] || "";

              let issueGroupDetail = {};

              if (issueType) {
                const causes = [];
                const recommendations = [];
                const risks = [];
                const foundItem = articleGroupData?.item?.find(item => item["$"] && item["$"].id === issueType);

                if (foundItem && foundItem.cause && Array.isArray(foundItem.cause)) {
                  const causeItems = foundItem?.cause?.[0]?.["item"];
                  causeItems.forEach(causeItem => {
                    causes.push(causeItem["_"]);
                  });
                }

                if (foundItem?.recommendations && Array.isArray(foundItem.recommendations)) {
                  const recItems = foundItem?.recommendations?.[0]?.["item"];
                  recItems.forEach(recItem => {
                    recommendations.push(recItem["_"]);
                  });
                }

                if (foundItem?.risk && Array.isArray(foundItem.risk)) {
                  const risksItem = foundItem?.risk?.[0]?.["item"];
                  risksItem.forEach(riskItem => {
                    risks.push(riskItem["_"] || riskItem);
                  });
                }

                issueGroupDetail = {
                  api: foundItem["$"]?.api || "",
                  language: foundItem["$"]?.language || "",
                  cause: causes,
                  cwe: foundItem.cwe?.ref?.[0] || foundItem.cwe?.[0]?.["_"] || foundItem.cwe?.[0]?.["ref"]?.[0] || foundItem.cwe?.[0] || "",
                  recommendations: recommendations,
                  externalReferences: foundItem.externalReferences?.[0]?.["item"] || "",
                  risks: risks,
                };
              }

              const itemData = {
                issueId,
                issueType,
                issueTypeName,
                severity,
                technology,
                cwe,
                status,
                dateCreated,
                lastUpdated,
                location,
                cvss,
                causeId,
                variantGroup,
                issueGroupDetail,
                fixGroupId,
              };
              itemsData.push(itemData);
            } catch (error) {
              logger.error(`${this.token.name} Error found on reading data: ${JSON.stringify(item)}, err: ${error}`);
            }
          });
        } else {
          logger.warn(`${this.token.name} No issue found`);
        }
        logger.info(` ${this.token.name} XML to JSON conversion  ** Completed **, Total Count: ${itemsData.length}`);
        return itemsData;
      }
    } catch (err) {
      logger.error(`${this.token.name} Error found on reading data: ${err}`);
    }
  }

  async downloadReport(link: string) {
    logger.info(`${this.token.name}: Download Link : ${link} scanning begins`);

    try {
      const response = await axios.get(link);

      if (response.status === 200) {
        return response.data;
      } else {
        logger.error(`${this.token.name}: Failed to download XML: HTTP status ${response.status}`);
      }
    } catch (err) {
      logger.error(`${this.token.name}: Failed to download XML: HTTP status ${err}`);
    }
  }

  async checkReportStatusApi(reportId) {
    logger.info(`${this.token.name} - checkReportStatusApi , check report status for ${reportId}`);

    try {
      const result: AxiosResponse<any> = await axios.get(this.api + "/api/v2/Reports/" + reportId, {
        timeout: this.TIME_OUTS.MEDIUM,
        headers: {
          Authorization: "Bearer " + this.accessToken,
          "Content-Type": "application/json",
        },
      });

      if (result.status === 200) {
        logger.info(`${this.token.name} - checkReportStatusApi , Downloadble data: ${result.data.downloadLink}`);
        return result.data;
      } else {
        logger.warn(`${this.token.name} - checkReportStatusApi , No data found, data: ${JSON.stringify(result)}`);
      }
    } catch (error) {
      logger.error(`${this.token.name} - checkReportStatusApi , Failed to get reports for ${reportId} , err: ${error}`);
    }
  }

  ///// checkReportStatus is used to check status of download link is ready in every 5 mins
  ///// and get the link when ready

  async checkReportStatus(reportId, maxRetries = 2) {
    try {
      for (let retry = 0; retry < maxRetries; retry++) {
        const downloadReport = await this.checkReportStatusApi(reportId);
        if (downloadReport.Status === "Ready") {
          return downloadReport.DownloadLink;
        } else {
          await this.sleep(300000); // Sleep for 5 minutes (300,000 milliseconds)
        }
      }
    } catch (error) {
      logger.error(`${this.token.name} - checkReportStatusApi, Failed to get reports for ${reportId} , err: ${error}`);
    }
  }

  async generateSecurityReport(appId: string) {
    logger.info(`${this.token.name}: Generating Security reports for application: ${appId}`);

    try {
      const url = `${this.api}/api/v2/Reports/Security/Application/${appId}`;
      const requestBody = {
        Configuration: {
          Details: true,
          Advisories: true,
          FixRecommendation: true,
          Articles: true,
          ReportFileType: "Xml",
          Title: "string",
          Locale: "string",
        },
      };

      const result: AxiosResponse<any> = await axios.post(url, requestBody, {
        timeout: this.TIME_OUTS.MEDIUM,
        headers: {
          Authorization: "Bearer " + this.accessToken,
          "Content-Type": "application/json",
        },
      });

      if (result.status === 200) {
        return result.data;
      } else {
        logger.warn(`${this.token.name} - generateSecurityReport, No data found`);
      }
    } catch (error) {
      logger.error(`${this.token.name} - generateSecurityReport, Failed to Generate report for ${appId} , Errors : ${error}`);
    }
  }

  async getApplicationIssues(application, securityEvents: SecurityEvent[]) {
    try {
      logger.info(`${this.token.name} - Generating Application issues by ${application.id} ** Begins **`);

      const generateReportData = await this.generateSecurityReport(application.Id);

      const downloadLink = await this.checkReportStatus(generateReportData.Id);

      const reportDataXml = await this.downloadReport(downloadLink);

      const reportDataJson = await this.extractReportData(reportDataXml);

      if (reportDataJson?.length) {
        for (const issue of reportDataJson) {
          this.setIssue(issue, application, securityEvents);
        }
      }

      logger.info(
        `${this.token.name} - Generating Application issues by ${application.id} ** Completed **, Found ${reportDataJson?.length} Issues`,
      );
    } catch (error) {
      logger.error(`${this.token.name} - Generating Application issues by ${application.id} , Errors : ${error}`);
    }
  }

  setIssue(issue, application, securityEvents: SecurityEvent[]) {
    try {
      const issueFileName = issue?.location?.split(" ")[1] || issue?.location?.split("\\").pop() || issue?.location;
      const issueFileNameWithoutLine = issueFileName?.split(":")[0] || issueFileName;
      const lineNumber = issueFileName?.split(":")[1] || 0;

      if (issue.technology === "SAST") {
        const securityEvent = new SecurityEvent(
          Constant.hcl,
          true,
          `${this.api}/main/myapps/${application.Id}/issues/${issue.issueId}`,
          `${issue.dateCreated}`,
          "",
          "",
          "",
          issue.issueTypeName,
          issue?.issueGroupDetail?.cause.join("\n\n"),
          issueFileNameWithoutLine || "N/A",
          issue.severity,
          issue?.issueGroupDetail?.risks.join("\n\n"),
          lineNumber,
          issue.severity,
          SecurityAlertType.sast,
          issue?.issueGroupDetail?.recommendations.join("\n\n"),
          issueFileNameWithoutLine || "N/A",
          issue.location || "",
          lineNumber,
          false,
          false,
          "",
          "",
          "",
          "",
          issue.issueType || "N/A",
          issue?.issueGroupDetail?.externalReferences[0]?.url[0]._ || "", // more info link
          "",
          application.Name,
          "",
          "",
          "hcl",
        );

        securityEvent.realMatch = issue.issueId;
        securityEvent.linkToExternalProduct = `${this.api}/main/myapps/${application.Id}/issues/${issue.issueId}` || "";

        securityEvents.push(securityEvent);
      } else if (issue.technology === "DAST") {
        const securityEvent = new SecurityEvent(
          Constant.hcl,
          true,
          `${this.api}/main/myapps/${application.Id}/issues/${issue.issueId}`,
          `${issue.dateCreated}`,
          "",
          "",
          "",
          issue.issueTypeName,
          issue?.issueGroupDetail?.cause.join("\n\n"),
          issueFileNameWithoutLine || "N/A",
          issue.severity,
          issue?.issueGroupDetail?.risks.join("\n\n"),
          lineNumber,
          issue.severity,
          SecurityAlertType.sast, /// to change dast
          issue?.issueGroupDetail?.recommendations.join("\n\n"),
          issueFileNameWithoutLine || "N/A",
          issue.location || "",
          lineNumber,
          false,
          false,
          "",
          "",
          "",
          "",
          issue.issueType || "N/A",
          issue?.issueGroupDetail?.externalReferences[0]?.url[0]._ || "", // more info link
          "",
          application.Name,
          "",
          "",
          "hcl",
        );

        securityEvent.realMatch = issue.issueId;
        securityEvent.linkToExternalProduct = `${this.api}/main/myapps/${application.Id}/issues/${issue.issueId}` || "";

        securityEvents.push(securityEvent);
      }
    } catch (e) {
      logger.error(`${this.token.name} : Failed to set security event, err: ${e.message}, issue: ${JSON.stringify(issue)}`);
    }
  }
}

class AppScan extends ExternalSecurityProviderBase {
  host: string;
  token: Token;
  private_token: string;
  uniqueRepos = {};
  private clientApi: AppScanAPI;

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

  getClientAPI() {
    logger.info(`set ${this.token.name}, host: ${this.host}`);

    if (this.host.endsWith("/")) {
      const i = this.host.lastIndexOf("/");
      this.token.host = this.host.substring(0, i);
      logger.info(`${this.token.name} - removing slash from apiUrl: ${this.host}`);
    }
    this.clientApi = new AppScanAPI(this.token);
  }

  async initLib() {
    try {
      this.getClientAPI();

      await this.clientApi.auth();
    } catch (err) {
      logger.error(`failed to initialize ${this.token.name}, Error : ${err}`);
    }
  }

  async securityEvents() {
    const securityEvents: SecurityEvent[] = [];

    try {
      logger.info(`${this.token.name} Getting All applications List`);
      const applicationList = await this.clientApi.getAllApps();

      if (applicationList?.length) {
        await PromisePool.for(applicationList)
          .withConcurrency(concurrent_pool_call)
          .process(async application => {
            await this.clientApi.getApplicationIssues(application, securityEvents);
          });
      }
    } catch (error) {
      logger.error(`${this.token.name} Failed to set application issues, Error: ${error}`);
    }

    logger.info(`${this.token.name} Getting All applications issues and Set securityEvents: ${securityEvents.length}`);
    return securityEvents;
  }
}

export default AppScan;
