//https://snyk.docs.apiary.io/#reference/reporting-api/latest-issues/get-list-of-latest-issues
import { AlertSeverity, SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import axios, { AxiosResponse, AxiosRequestConfig, AxiosError } from "axios";
import PromisePool from "@supercharge/promise-pool/dist";

import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";

import path from "path";
import StatesHelper from "../../helper/statesHelper";

const logger = loggerImport.getDebugLogger();

const LOG_NAME = "Klocwork";

const recommendationURL = "{baseURL}/documentation/help/reference/{code}.htm?checker.help=true";

const TIME_UNITS = {
  SEC: 1000,
  MIN: 60 * 1000,
};

const TIME_OUTS = {
  SHORT: 10 * TIME_UNITS.SEC,
  MEDIUM: 50 * TIME_UNITS.SEC,
  LONG: 2 * TIME_UNITS.MIN,
};

interface KlocworkServerVersion {
  majorVersion: string;
  minorVersion: string;
}

interface KlocworkProject {
  id: string;
  name: string;
  creator: string;
  description?: string;
}

/**
 *  Issue statuses
 *
 *      Analyze                 | should be reviewed (default initial status). All newly detected issues display this status. It persists until you change it.
 *      Ignore	                | intended for issues found (whether valid or otherwise) in code you don't care about, for example test code
 *      Not a problem	        | false positive; the issue reported isn't valid. Relates to an analysis failure, and is often caused by build integration problems. Klocwork recommends opening a Customer Support Request (CSR) when you determine that a reported issue is a false positive, so that we can analyze the issue and make improvements to the engine, if necessary.
 *      Fix	                    | a valid issue that should be fixed as soon as possible
 *      Fix in Next Release     | a valid issue that is mostly harmless and can be left in the code base without too much risk, but should be addressed sooner rather than later
 *      Fix in Later Release    | a valid issue that is completely harmless and can be left in the code base indefinitely without risk
 *      Defer	                | a valid issue that needs discussion with others or escalation to (for example) a security team for final judgment
 *      Filter	                | provided for compatibility with older versions of Klocwork filter files
 */
const KlocworkIssueStatus = {
  Analyze: "Analyze",
  Ignore: "Ignore",
  Not_A_Problem: "Not a problem",
  Fix: "Fix",
  Fix_In_Next_Release: "Fix in Next Release",
  Fix_In_Later_Release: "Fix in Later Release",
  Defer: "Defer",
  Filter: "Filter",
};

/**
 *  Issue states
 *
 *      Issue states are read-only indicators that trace the history of an issue from the time it is first detected to the time when it is fixed.
 *
 *      New         | When issues are first detected in a build, they are labeled New.
 *      Fixed       | Issues that existed in the previous build but not in the current build are labeled Fixed.
 *      Existing    | Issues detected in both the current and the previous build are labeled Existing.
 */
const KlocworkIssueState = {
  New: "New",
  Fixed: "Fixed",
  Existing: "Existing",
};

interface KlocworkIssue {
  id: string; // the identifier of the issue in Static Code Analysis

  code: string; // the name of the checker that found that issue
  title: string;
  message: string; // the checker message for the issue in Static Code Analysis

  file: string; // the file in which the issue occurs
  method: string;

  status: string; // the status of the issue, such as Fix or Analyze
  state: string; // the state of the issue - Existing or Fixed

  severity: string; // the severity of the issue in textual form (not numeric)
  severityCode: number; // the severity of the issue in numeric form
  supportLevel: string;
  supportLevelCode: number;

  owner: string; // the owner of the issue
  taxonomyName: string;
  dateOriginated: number;
  url: string;
}

class KlocworkAPI {
  token: Token;
  orgName: string;

  baseUrl: string;
  apiUrl: string;

  isValidToken: boolean;
  serverVersion: KlocworkServerVersion;

  constructor(token: Token, orgName: string) {
    this.token = token;
    this.orgName = orgName;

    this.setBaseURL();
    this.setApiUrl();
  }

  private setBaseURL() {
    this.baseUrl = this.token.host;
    logger.info(`${LOG_NAME} - set , host: ${this.baseUrl}`);

    if (this.baseUrl.endsWith("/")) {
      const i = this.baseUrl.lastIndexOf("/");
      this.baseUrl = this.baseUrl.substring(0, i);

      logger.info(`${LOG_NAME} - removing slash from apiUrl: ${this.baseUrl}`);
    }
  }

  private setApiUrl() {
    this.apiUrl = `${this.baseUrl}/review/api`;
  }

  private getAuthParams() {
    return {
      user: this.token.userName,
      ltoken: this.token.password,
    };
  }

  /**
   * auth
   *
   * @description Authenticate User Credentials
   *
   * Notes : We do not have any auth API for the klocwork server , So we are using version check api to authenticate the user credentials
   */
  public async auth() {
    try {
      const params = Object.assign(this.getAuthParams(), { action: "version" });
      const result: AxiosResponse<any> = await axios.post(
        this.apiUrl,
        {},
        {
          timeout: TIME_OUTS.MEDIUM,
          params: params,
        },
      );

      if (result.data) {
        this.isValidToken = true;
        this.serverVersion = result.data;

        logger.info(`${LOG_NAME} - Server Version , Major: ${this.serverVersion.majorVersion} , Minor: ${this.serverVersion.minorVersion}`);
      }
    } catch (e) {
      this.isValidToken = false;
      logger.error(`${LOG_NAME} - Auth Failed , Not a valid Token!, token: ${JSON.stringify(this.token)} , Error : ${e}`);
      // StatesHelper.Instance.failedExternalTools.add("klocwork");
    }
  }

  private jsonLinesParser(str) {
    try {
      return str
        .split("\n")
        .filter(obj => obj != "") // removes the empty lines
        .map(JSON.parse); // parse the JSON
    } catch (e) {
      logger.error(`${LOG_NAME} - Error in jsonLinesParser , Error : ${e} , Data : ${str}`);
    }

    return [];
  }

  private async setProjects(projects: KlocworkProject[]) {
    let totalProjects: number = 0;

    try {
      const params = Object.assign(this.getAuthParams(), { action: "projects" });
      logger.info(`${LOG_NAME} - Getting Projects ** Begin **`);
      const result: AxiosResponse<any> = await axios.post(
        this.apiUrl,
        {},
        {
          timeout: TIME_OUTS.LONG,
          params: params,
        },
      );

      if (result.data) {
        const jsonProjects = this.jsonLinesParser(result.data);
        totalProjects = jsonProjects.length;

        if (totalProjects > 0) {
          projects.push(...jsonProjects);
        }
      }
    } catch (e) {
      logger.error(`${LOG_NAME} - Getting Projects , Error : ${e}`);
    }

    logger.info(`${LOG_NAME} - Getting Projects ** End **, found total ${totalProjects} projects`);
  }

  private async getIssues(project: KlocworkProject, securityEvents: SecurityEvent[]) {
    let totalIssues: number = 0;

    try {
      if ("All_Checkers".toLowerCase() === project.name.toLowerCase()) {
        logger.info(`${LOG_NAME} - Getting Issues ** Begin ** ignoring`);
        return;
      }

      const params = Object.assign(this.getAuthParams(), { action: "search", project: project.name });
      logger.info(`${LOG_NAME} - Getting Issues ** Begin ** for project ${project.name}`);
      const result: AxiosResponse<any> = await axios.post(
        this.apiUrl,
        {},
        {
          timeout: TIME_OUTS.LONG,
          params: params,
        },
      );

      logger.info(`${LOG_NAME} - Getting Issues ** got from API ** for project ${project.name}`);

      if (result.data) {
        const jsonIssues = this.jsonLinesParser(result.data);
        totalIssues = jsonIssues.length;
        logger.info(`${LOG_NAME} - Got total Issues: ${totalIssues} before process for project ${project.name}`);

        // @todo - Remove await in the future
        for (const issue of jsonIssues) {
          //await this.getIssueDetails(issue, project);
          this.setIssues(issue, project, securityEvents);
        }
      }
    } catch (e) {
      logger.error(`${LOG_NAME} - Getting Issues Error for project ${project.name} , Error : ${e}`);
    }

    logger.info(
      `${LOG_NAME} - Getting Issues ** End ** for project ${project.name}, found total ${totalIssues} issues for project ${project.name}`,
    );
  }

  /**
   *  Get Issue Details
   *
   *
   *  Notes : this function is only for the logging purpose
   *  @todo : Remove this in the future
   */
  private async getIssueDetails(issue: KlocworkIssue, project: KlocworkProject) {
    try {
      const params = Object.assign(this.getAuthParams(), { action: "issue_details", project: project.name, id: issue.id });

      //Debug
      logger.info(`${LOG_NAME} - List Row : ${JSON.stringify(issue)} `);

      const result: AxiosResponse<any> = await axios.post(
        this.apiUrl,
        {},
        {
          timeout: TIME_OUTS.LONG,
          params: params,
        },
      );

      if (result.data) {
        //Debug
        logger.info(`${LOG_NAME} - Details : ${JSON.stringify(result.data)}`);
      }
    } catch (e) {
      logger.error(`${LOG_NAME} - Getting Issue Details Error for project ${project.name} , Error : ${e}`);
    }
  }

  private setIssues(issue: KlocworkIssue, project: KlocworkProject, securityEventList: SecurityEvent[]) {
    try {
      // @see KlocworkIssueStatus and KlocworkIssueState
      if (
        [KlocworkIssueStatus.Analyze, KlocworkIssueStatus.Defer].includes(issue.status) === false ||
        issue.state === KlocworkIssueState.Fixed
      ) {
        return;
      }

      const securityEvent = new SecurityEvent(
        "Klocwork",
        true,
        issue.url,
        `${issue.dateOriginated}`,
        "",
        "",
        "",
        `${issue.message} - ${issue.taxonomyName}`,
        `${issue.title} - ${issue.message}`,
        issue.file,
        issue.severity.toLowerCase().includes("review") ? "Low" : issue.severity,
        "",
        0,
        AlertSeverity[AlertSeverity.High],
        SecurityAlertType.sast,
        recommendationURL.replace("{baseURL}", this.baseUrl).replace("{code}", issue.code.toLowerCase()),
        "N/A",
        "",
        -1,
        false,
        false,
        issue.owner,
        "",
        "",
        "",
        issue.code,
        "",
        "",
        project.name,
        "",
        issue.file,
        "klocwork",
      );

      securityEvent.linkToExternalProduct = issue.url;
      securityEvent.realMatch = issue.id;

      securityEventList.push(securityEvent);
    } catch (e) {
      logger.error(`${LOG_NAME} - setIssues Error , project : ${project.name} , issue : ${issue.id} , Error : ${e}`);
    }
  }

  async securityEvents(): Promise<SecurityEvent[]> {
    const securityEvents: SecurityEvent[] = [];
    try {
      if (this.isValidToken) {
        const projects: KlocworkProject[] = [];
        await this.setProjects(projects);

        logger.info(`${LOG_NAME} - ** projects **, projects Count: ${projects.length} `);

        for (const project of projects) {
          await this.getIssues(project, securityEvents);
        }
      }

      logger.info(`${LOG_NAME} - ** Completed **, Finish Collecting Security Events with Count: ${securityEvents.length} `);
    } catch (err) {
      logger.error(`${LOG_NAME} - securityEvents , Error : ${err}`);
    }
    return securityEvents;
  }
}

class Klocwork extends ExternalSecurityProviderBase {
  token: Token;
  orgName: string;
  clientApi: KlocworkAPI;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.token = token;
    this.orgName = orgName;
  }

  async initLib() {
    try {
      logger.info(`${LOG_NAME} - ** Started ** `);
      this.clientApi = new KlocworkAPI(this.token, this.orgName);

      await this.clientApi.auth();
    } catch (err) {
      logger.error(`failed to initialize ${this.token.name}, , host: ${this.token.host}, Error : ${err}`);
      StatesHelper.Instance.globalApisFails.add("klocwork");
    }
  }

  async securityEvents() {
    return await this.clientApi.securityEvents();
  }
}

export default Klocwork;
