//https://snyk.docs.apiary.io/#reference/reporting-api/latest-issues/get-list-of-latest-issues
import { Url } from "url";
import { AlertSeverity, SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import axios, { AxiosResponse, AxiosRequestConfig, AxiosError } from "axios";
import { PromisePool } from "@supercharge/promise-pool/dist/promise-pool";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import StatesHelper from "../../helper/statesHelper";
import { logsErrorWithExtraData } from "../../helper/commonUtils";

const logger = loggerImport.getDebugLogger();

const LOG_NAME = "SonaType";

const LOG_RECORDS = {
  CURR: 0,
  MAX: 10,
};

const LOG_COMPONENT_TYPES: string[] = [];

interface SonaTypeApplication {
  id: string;
  publicId: string;
  name: string;
  organizationId: string;
  contactUserName: string;
  applicationTags: string[];
}

interface SonaTypeReport {
  stage: string;
  applicationId: string;
  evaluationDate: string;
  latestReportHtmlUrl: string;
  reportHtmlUrl: string;
  embeddableReportHtmlUrl: string;
  reportPdfUrl: string;
  reportDataUrl: string;
}

interface SonaTypeIssues {
  source: string;
  reference: string;
  severity: number;
  status: string;
  url: string;

  threatCategory: string;
  cwe: string;
  cvssVector: string;
  cvssVectorSource: string;
}

interface SonaTypeSecurityData {
  securityIssues: SonaTypeIssues[];
}

interface SonaTypeComponentIdentifierCoordinatesMAVEN {
  artifactId: string;
  groupId: string;
  version: string;
  extension: string;
  classifier: string;
}

interface SonaTypeComponentIdentifierCoordinatesNPM {
  packageId: string;
  version: string;
}

interface SonaTypeComponentIdentifierCoordinates {
  extension: string;
  name: string;
  qualifier: string;
  version: string;
}

interface SonaTypeComponentIdentifier {
  format: string;
  coordinates:
    | SonaTypeComponentIdentifierCoordinates
    | SonaTypeComponentIdentifierCoordinatesNPM
    | SonaTypeComponentIdentifierCoordinatesMAVEN;
}

interface SonaTypeComponent {
  packageUrl: string;
  hash: string;
  componentIdentifier: SonaTypeComponentIdentifier;
  displayName: string;
  proprietary: boolean;
  matchState: string;
  pathnames: string[];
  identificationSource: string;
  licenseData: any;
  securityData: SonaTypeSecurityData;
}

interface SonaTypeComponentRemediationComponent {
  packageUrl: string;
  hash: string;
  componentIdentifier: SonaTypeComponentIdentifier;
  displayName: string;
}

interface SonaTypeComponentRemediationversionChangeComponent {
  component: SonaTypeComponentRemediationComponent;
}

interface SonaTypeComponentRemediationVersionChange {
  type: string;
  data: SonaTypeComponentRemediationversionChangeComponent;
}

interface SonaTypeComponentRemediation {
  versionChanges: SonaTypeComponentRemediationVersionChange[];
}

interface SonaTypeCVEWeaknessId {
  id: string;
  uri: string;
}

interface SonaTypeCVEWeakness {
  cweSource: string;
  cweIds: SonaTypeCVEWeaknessId[];
}

interface SonaTypeCVE {
  identifier: string;
  vulnIds: string[];
  vulnerabilityLink: string;

  source: any;
  mainSeverity: any;
  severityScores: any[];
  weakness: SonaTypeCVEWeakness;

  categories: string;
  description: string;
  explanationMarkdown: string;
  detectionMarkdown: string;
  recommendationMarkdown: string;
  advisories: any[];
  researchType: string;
  isAdvancedVulnerabilityDetection: boolean;
}

interface SonaTypeApplcationCompositeSourceControlValue {
  value: string;
  parentValue: string;
  parentName: string;
}

interface SonaTypeApplcationCompositeSourceControl {
  id: string;
  ownerId: string;
  repositoryUrl: string;
  provider: SonaTypeApplcationCompositeSourceControlValue;
  username: SonaTypeApplcationCompositeSourceControlValue;
  token: SonaTypeApplcationCompositeSourceControlValue;
  baseBranch: SonaTypeApplcationCompositeSourceControlValue;
  remediationPullRequestsEnabled: SonaTypeApplcationCompositeSourceControlValue;
  statusChecksEnabled: SonaTypeApplcationCompositeSourceControlValue;
  pullRequestCommentingEnabled: SonaTypeApplcationCompositeSourceControlValue;
  sourceControlEvaluationsEnabled: SonaTypeApplcationCompositeSourceControlValue;
  sourceControlScanTarget: SonaTypeApplcationCompositeSourceControlValue;
  sshEnabled: SonaTypeApplcationCompositeSourceControlValue;
  commitStatusEnabled: SonaTypeApplcationCompositeSourceControlValue;
}

const apiLogs = {
  auth: 1,
  applications: 3,
  applcationCompositeSourceControl: 3,
  componentRemediation: 3,
  cve: 3,
  report: 3,
  reportData: 3,
};

class SonaTypeAPI {
  private token: Token;
  public isValidToken: boolean = false;
  public infoAboutLogin: Set<string> = new Set<string>();

  private TIME_UNITS = {
    SEC: 1000,
    MIN: 60 * 1000,
  };

  private TIME_OUTS = {
    SHORT: 30 * this.TIME_UNITS.SEC,
    MEDIUM: 1 * this.TIME_UNITS.MIN,
    LONG: 3 * this.TIME_UNITS.MIN,
  };

  constructor(token: Token) {
    this.token = token;

    this.isValidToken = false;
  }

  /**
   * function logAPI
   *
   * This function will log the API Request and Response
   *
   * Example :
   *    // define the api log frequency
   *    const apiLogs = {
   *      applications : 3
   *    }
   *
   *    // this will log the applications request - response for the 3 times
   *    // Log will be -
   *    // `SonaType - apiLogs - Applications Request , { Request Object }`
   *    // `SonaType - apiLogs - Applications Response , { Response Object }`
   *
   *    this.logAPI( "applications" , "Applications" , { request : request } , response )
   *
   * Notes :
   *  Please use the apiLogs variable to define the frequency of the log
   *
   * @param key (str) : Log Key
   * @param message (str) : Log Message
   * @param request (obj) : API Request
   * @param response (obj) : API Response
   * @param force ( optional ) - use this to log the request without any condition check
   */
  logAPI(key: string, message: string, request: any, response: any, force?: boolean) {
    return;
    if ((apiLogs && apiLogs[key] && apiLogs[key] > 0) || force) {
      logger.info(`${LOG_NAME} - apiLogs - ${message} Request, ${request} `);
      logger.info(`${LOG_NAME} - apiLogs - ${message} Response, ${response} `);

      apiLogs[key] -= 1;
    }
  }

  async auth() {
    const errMessage = `${LOG_NAME} - Authenticate Failed : for token ${this.token}, host: ${this.token.host}, err: `;

    try {
      logger.info(`${LOG_NAME} - Authentication Begin`);

      const result: AxiosResponse<any> = await axios.get(`${this.token.host}/api/v2/users`, {
        withCredentials: true,
        timeout: this.TIME_OUTS.MEDIUM,
        headers: {
          "Content-Type": "application/json",
        },
        auth: {
          username: this.token.userName,
          password: this.token.password,
        },
      });

      if (result.data) {
        this.logAPI("auth", "Auth", { url: `${this.token.host}/api/v2/users` }, result.data);

        this.isValidToken = true;
        logger.info(`${LOG_NAME} - Authentication Success`);
      } else {
        this.isValidToken = false;
        logger.error(`${LOG_NAME} - Authentication Failed! - Not a valid Token!`);
        logger.error(`${LOG_NAME} - Authentication Data! - ${JSON.stringify(this.token)}`);
        StatesHelper.Instance.failedExternalTools.add("sona-type");
      }
      return result.data;
    } catch (error: any) {
      this.isValidToken = false;
      logger.error(`${LOG_NAME} - Authentication Failed! - Not a valid Token!`);
      logger.error(`${LOG_NAME} - Authentication Data! - ${JSON.stringify(this.token)}`);
      StatesHelper.Instance.failedExternalTools.add("sona-type");
    }
  }

  async getApplications() {
    try {
      logger.info(`${LOG_NAME} - Getting Applications List`);

      const url = `${this.token.host}/api/v2/applications`;
      const result: AxiosResponse<any> = await axios.get(url, {
        withCredentials: true,
        timeout: this.TIME_OUTS.MEDIUM,
        headers: {
          "Content-Type": "application/json",
        },
        auth: {
          username: this.token.userName,
          password: this.token.password,
        },
      });

      if (result.data) {
        this.logAPI("applications", "Application", { url: url }, result.data);
      }

      if (result.data && result.data.applications) {
        return result.data.applications;
      } else {
        logger.error(`${LOG_NAME} - Error in Getting Applications List, No Application Found!`);
      }
    } catch (error) {
      logger.error(`${LOG_NAME} - Error in Getting Applications List: ${error}`);
    }
    return [];
  }

  async getReport(application: SonaTypeApplication) {
    try {
      logger.info(`${LOG_NAME} - Getting Reports for Application : ${application.name}`);

      const url = `${this.token.host}/api/v2/reports/applications/${application.id}`;
      const result: AxiosResponse<any> = await axios.get(url, {
        withCredentials: true,
        timeout: this.TIME_OUTS.SHORT,
        headers: {
          "Content-Type": "application/json",
        },
        auth: {
          username: this.token.userName,
          password: this.token.password,
        },
      });

      if (result.data) {
        this.logAPI("report", "Report", { url: url }, result.data);

        return result.data;
      } else {
        logger.error(`${LOG_NAME} - Error in Getting Reports for Application : ${application.name}`);
      }
    } catch (error) {
      logger.error(`${LOG_NAME} - Error in Getting Reports for Application : ${application.name}, error: ${error}`);
    }
    return [];
  }

  async getReportData(report: SonaTypeReport, application: SonaTypeApplication) {
    try {
      logger.info(`${LOG_NAME} - Getting Report Data for Application : ${application.name}`);

      const url = `${this.token.host}/${report.reportDataUrl}`;
      const result: AxiosResponse<any> = await axios.get(url, {
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: {
          "Content-Type": "application/json",
        },
        auth: {
          username: this.token.userName,
          password: this.token.password,
        },
      });

      if (result.data) {
        this.logAPI("reportData", "ReportData", { url: url }, result.data);
      }

      if (result.data && result.data.components) {
        return result.data.components;
      } else {
        logger.error(`${LOG_NAME} - Error in Getting Report Data for Application : ${application.name}`);
      }
    } catch (error) {
      logger.error(`${LOG_NAME} - Error in Getting Report Data for Application : ${application.name}, error: ${error}`);
    }
    return [];
  }

  async getCVE(issue: SonaTypeIssues) {
    try {
      const url = `${this.token.host}/api/v2/vulnerabilities/${issue.reference}`;
      const result: AxiosResponse<any> = await axios.get(url, {
        withCredentials: true,
        timeout: this.TIME_OUTS.SHORT,
        headers: {
          "Content-Type": "application/json",
        },
        auth: {
          username: this.token.userName,
          password: this.token.password,
        },
      });

      if (result.data) {
        this.logAPI("cve", "CVE", { url: url }, result.data);

        return result.data;
      } else {
        logger.error(`${LOG_NAME} - Error in Getting CVE : ${issue.reference}`);
      }
    } catch (error) {
      logger.error(`${LOG_NAME} - Error in Getting CVE : ${issue.reference}, error: ${error}`);
    }
  }

  async getComponentRemediation(component: SonaTypeComponent, application: SonaTypeApplication, retryCount?: number) {
    try {
      const url = `${this.token.host}/api/v2/components/remediation/application/${application.id}`;
      const result: AxiosResponse<any> = await axios.post(
        url,
        { componentIdentifier: component.componentIdentifier },
        {
          withCredentials: true,
          timeout: this.TIME_OUTS.MEDIUM,
          headers: {
            "Content-Type": "application/json",
          },
          auth: {
            username: this.token.userName,
            password: this.token.password,
          },
        },
      );

      if (result.data) {
        this.logAPI(
          "componentRemediation",
          "Component Remediation",
          { url: url, data: { componentIdentifier: component.componentIdentifier } },
          result.data,
        );
      }

      if (result.data && result.data.remediation) {
        return result.data.remediation;
      } else {
        logger.error(`${LOG_NAME} - Error in Getting Component Remediation : ${component.displayName} , Application : ${application.id}`);
      }
    } catch (error) {
      logger.error(
        `${LOG_NAME} - Error in Getting Component Remediation : ${component.displayName}, Application : ${application.id} , error: ${error} , Retry Count : ${retryCount}`,
      );

      retryCount = !retryCount ? 1 : retryCount + 1;

      if (retryCount < 3) {
        return await this.getComponentRemediation(component, application, retryCount);
      }
    }
  }

  async getApplcationCompositeSourceControl(application: SonaTypeApplication) {
    try {
      const url = `${this.token.host}/api/v2/compositeSourceControl/application/${application.id}`;
      const result: AxiosResponse<any> = await axios.get(url, {
        withCredentials: true,
        timeout: this.TIME_OUTS.SHORT,
        headers: {
          "Content-Type": "application/json",
        },
        auth: {
          username: this.token.userName,
          password: this.token.password,
        },
      });

      if (result.data) {
        this.logAPI("applcationCompositeSourceControl", "Applcation Composite SourceControl", { url: url }, result.data);

        return result.data;
      } else {
        logger.error(`${LOG_NAME} - Error in Getting Applcation CompositeSourceControl : ${application.id}`);
      }
    } catch (error) {
      logger.error(`${LOG_NAME} - Error in Applcation CompositeSourceControl CVE : ${application.id}, error: ${error}`);
    }
  }

  getCvssVectorToComponent(str: string) {
    let obj = {};
    const cvssVersionRegEx = /[CVSS]+(:)+[0-9+.]+/g;
    const cvssComponentRegEx = /[A-Z]+(:)+[A-Z0-9]/g;

    try {
      const verStr = str.match(cvssVersionRegEx);
      if (verStr.length > 0) {
        const ver = verStr[0].match(/[0-9+.]+/g);
        if (ver.length > 0 && parseInt(ver[0]) === 3) {
          const cvssComponentArr = str.match(cvssComponentRegEx);
          if (cvssComponentArr.length > 0) {
            for (const cvssComponentStr of cvssComponentArr) {
              let arr = cvssComponentStr.split(":");
              obj[arr[0]] = arr[1];
            }
          }
        }
      }
    } catch (e) {
      // do nothing
    }

    return obj;
  }

  setSingleIssue(
    issue: SonaTypeIssues,
    component: SonaTypeComponent,
    remediation: SonaTypeComponentRemediation | undefined,
    cve: SonaTypeCVE,
    application: SonaTypeApplication,
    applicationCompositeSourceControl: SonaTypeApplcationCompositeSourceControl,
    report: SonaTypeReport,
  ) {
    try {
      // for debugging purpose only , remove in future
      if (LOG_RECORDS.CURR < LOG_RECORDS.MAX) {
        logger.info(`Issue : ` + JSON.stringify(issue));
        logger.info(`Component : ` + JSON.stringify(component));
        logger.info(`application : ` + JSON.stringify(application));
        logger.info(`applicationCompositeSourceControl : ` + JSON.stringify(applicationCompositeSourceControl));

        LOG_RECORDS.CURR += 1;
      }

      const createdAt = report.evaluationDate;

      let url: URL | undefined;
      try {
        url = new URL(applicationCompositeSourceControl.repositoryUrl);
      } catch (e) {
        url = undefined;
      }

      const repoFullName =
        (typeof url === "object" ? url.pathname.replace(/^\//g, "") : applicationCompositeSourceControl.repositoryUrl) || application.name;

      const fullPath = component.pathnames[0];

      let fileNameMatch = "";
      let fileNameArr = fullPath.split("/");

      const fileNameRegEx = /[a-zA-Z0-9_-]+[.]+[a-zA-Z]+[a-zA-Z]/g;
      for (const fileNameStr of fileNameArr) {
        if (!fileNameMatch && fileNameStr.match(fileNameRegEx)) {
          fileNameMatch = fileNameStr;
        }
      }

      let packageName = "";
      let packageVersion = "";

      if (component?.componentIdentifier?.coordinates) {
        // for debugging purpose only , remove in future
        if (LOG_COMPONENT_TYPES.includes(component.componentIdentifier.format) === false) {
          LOG_COMPONENT_TYPES.push(component.componentIdentifier.format);

          logger.info(`${LOG_NAME} - Logging COMPONENT_TYPES : ${component.componentIdentifier.format} , ` + JSON.stringify(component));
        }

        if ("packageId" in component.componentIdentifier.coordinates) {
          const packageCoordinates = component.componentIdentifier.coordinates as SonaTypeComponentIdentifierCoordinatesNPM;
          packageName = packageCoordinates.packageId;
          packageVersion = packageCoordinates.version;
        } else if ("artifactId" in component.componentIdentifier.coordinates) {
          const packageCoordinates = component.componentIdentifier.coordinates as SonaTypeComponentIdentifierCoordinatesMAVEN;
          packageName = packageCoordinates.artifactId;
          packageVersion = packageCoordinates.version;
        } else {
          const packageCoordinates = component.componentIdentifier.coordinates as SonaTypeComponentIdentifierCoordinates;
          packageName = packageCoordinates.name;
          packageVersion = packageCoordinates.version;
        }
      } else {
        logger.error(`${LOG_NAME} - Error : Component Data Missing , Component : ` + JSON.stringify(component));
        return;
      }

      const securityEvent = new SecurityEvent(
        "SonaType",
        true,
        "",
        createdAt,
        "",
        "",
        "",
        cve.explanationMarkdown,
        component.displayName,
        fullPath,
        issue.threatCategory,
        cve.description,
        0,
        AlertSeverity[AlertSeverity.High],
        SecurityAlertType.sca,
        cve.recommendationMarkdown,
        `${packageName}@${packageVersion}`,
        "",
        -1,
        false,
        false,
        "",
        "",
        "",
        "",
        issue.reference,
        packageVersion,
        "",
        repoFullName,
        "",
        fullPath,
        "sona-type",
      );

      securityEvent.blame.cve = issue.reference;
      if (securityEvent.blame.cve) {
        securityEvent.cves.push(securityEvent.blame.cve);
      }

      securityEvent.blame.cvssScore = issue.severity;
      securityEvent.blame.cvssVersion = issue.cvssVectorSource;

      if (cve.weakness && (cve.weakness.cweSource === "CVE" || cve.weakness.cweSource === "Sonatype")) {
        let cweId = cve.weakness.cweIds[0];
        securityEvent.blame.cweList = [
          {
            shortName: "N/A",
            name: "CWE-" + cweId.id,
            url: cweId.uri,
            description: "",
          },
        ];
      }

      let attackVector: any = this.getCvssVectorToComponent(issue.cvssVector);
      if (attackVector.AV) {
        if (attackVector.AV == "N") {
          securityEvent.blame.attackVector = "NETWORK";
        }

        if (attackVector.AV == "L") {
          securityEvent.blame.attackVector = "LOCAL";
        }
      }

      securityEvent.pkgManager = component.componentIdentifier.format;
      securityEvent.pkgName = `${packageName}`;
      securityEvent.installedVersion = packageVersion;

      if (remediation && remediation.versionChanges) {
        let version: SonaTypeComponentRemediationVersionChange = remediation.versionChanges
          .filter(v => v.type == "next-no-violations-with-dependencies")
          .pop();
        if (!version) {
          version = remediation.versionChanges.filter(v => v.type == "next-no-violations").pop();
        }

        if (version) {
          securityEvent.fixedVersion = version.data.component.componentIdentifier.coordinates.version;
        }
      }

      securityEvent.realMatch = `${packageName}@${packageVersion}`;

      return securityEvent;
    } catch (error) {
      logger.error(`${LOG_NAME} - Error in Setting Issue : ${issue.reference}, Component : ${component.displayName} , error: ${error}`);
      // StatesHelper.Instance.globalApisFails.add("sona-type")
    }
  }

  async setIssues(securityEventList: SecurityEvent[]) {
    let cveList: SonaTypeCVE[] = [];

    const applicationList: SonaTypeApplication[] = await this.getApplications();
    logger.info(`${LOG_NAME} - Found ${applicationList.length} Applications`);

    //Get all apps
    for (const application of applicationList) {
      try {
        const applicationCompositeSourceControl: SonaTypeApplcationCompositeSourceControl = await this.getApplcationCompositeSourceControl(
          application,
        );
        const reports: SonaTypeReport[] = await this.getReport(application);
        if (!reports) {
          continue;
        }

        logger.info(`${LOG_NAME} - Found ${reports.length} Reports for Application : ${application.name}`);
        if (reports.length > 1) {
          logger.info(`${LOG_NAME} - Found more ${reports.length} Reports for Application : ${application.name}`);
        }

        //Get all reports
        for (const report of reports) {
          try {
            const components: SonaTypeComponent[] = await this.getReportData(report, application);
            logger.info(`${LOG_NAME} - Found ${components.length} Component for Application : ${application.name}`);

            await PromisePool.for(components)
              .withConcurrency(100)
              .process(async (component: SonaTypeComponent) => {
                await this.setComponentData(component, application, cveList, applicationCompositeSourceControl, report, securityEventList);
              });
          } catch (err) {
            logger.error(`${LOG_NAME} - failed single report for app: ${application.name}, id: ${application.id}, err: ${err}`);
          }
        }
      } catch (err) {
        //nikunj@ox.security
        logsErrorWithExtraData(this.infoAboutLogin, "application", application, err, LOG_NAME);
      }
    }
  }

  async setComponentData(
    component: SonaTypeComponent,
    application: SonaTypeApplication,
    cveList: SonaTypeCVE[],
    applicationCompositeSourceControl: SonaTypeApplcationCompositeSourceControl,
    report: SonaTypeReport,
    securityEventList: SecurityEvent[],
  ) {
    //Get components
    try {
      if (!component.securityData) {
        return;
      }

      let remediation: SonaTypeComponentRemediation;

      //Set issues
      for (const issue of component.securityData.securityIssues) {
        try {
          if (issue.status.toLowerCase() !== "open") {
            continue;
          }

          if (!remediation) {
            remediation = await this.getComponentRemediation(component, application);
          }

          let cve: SonaTypeCVE = cveList.filter(cve => cve.identifier === issue.reference).pop();
          if (cve === undefined) {
            cve = await this.getCVE(issue);
            if (cve) {
              cveList.push(cve);
            }
          }

          const securityEvent: any = this.setSingleIssue(
            issue,
            component,
            remediation,
            cve,
            application,
            applicationCompositeSourceControl,
            report,
          );

          if (securityEvent) {
            securityEventList.push(securityEvent);
          }
        } catch (err) {
          logger.error(`${LOG_NAME} - failed single issue: ${issue.url} for app: ${application.name}, id: ${application.id}, err: ${err}`);
        }
      }
    } catch (err) {
      logger.error(
        `${LOG_NAME} - failed single component: ${component.displayName} for app: ${application.name}, id: ${application.id}, err: ${err}`,
      );
    }
  }
}

class SonaType extends ExternalSecurityProviderBase {
  token: Token;

  private clientApi: SonaTypeAPI;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.token = token;
  }

  async initLib() {
    try {
      logger.info(`set ${this.token.name}, host: ${this.token.host}`);
      this.clientApi = new SonaTypeAPI(this.token);

      await this.clientApi.auth();
    } catch (err) {
      logger.error(`failed to initialize ${this.token.name}, , host: ${this.token.host}, err: ${err}`);
    }
  }

  async securityEvents() {
    let securityEventList: SecurityEvent[] = [];

    try {
      if (this.clientApi.isValidToken) {
        await this.clientApi.setIssues(securityEventList);
      }

      logger.info(`${LOG_NAME} - Finish Collecting Security Events with Count: ${securityEventList.length}`);
    } catch (error) {
      logger.error(`${LOG_NAME} - Error in securityEvents , ${error} `);
    }

    return securityEventList;
  }
}

export default SonaType;
