//https://snyk.docs.apiary.io/#reference/reporting-api/latest-issues/get-list-of-latest-issues
import axios, { AxiosResponse, AxiosRequestConfig, AxiosError } from "axios";

import {
  AlertSeverity,
  SecurityAlertType,
  SecurityEvent,
  addSeverityChangedReason,
  addSeverityCloudChangedReason,
} from "../../entitis/codeRepoTypes";
import { CloudSecurityEvent } from "../../entitis/cloudTypes";

import { Token } from "../../entitis/collectorEntitisTypes";

import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import { capitalizeFirstLetter, cleanToolName, flatNestedJson } from "../../helper/commonUtils";
import { ArtifactorySecEventSystem, ArtifactorySecEventType, guessArtifactSystem } from "../../entitis/ArtifactTypes";
import { isLocalDevelopment } from "../../helper/envUtils";
import { severityReasons } from "../../entitis/service/blameTypes";
import Constant from "../../entitis/constant";
import { ContainerSecurityType } from "../../entitis/artifactoryTypes";
import { getHashType } from "../../helper/hash";
import { HahsType } from "../../entitis/applicationsFlowTypes";
import StatesHelper from "../../helper/statesHelper";
import { ExtraInfo } from "../../entitis/issuesTypes";
import { addRunningInCloudExtraInfo } from "../../helper/policy/severityHelper";
import { Tool } from "../../policy/rules/code/policyRulesBase";
import { SecurityTool } from "../../entitis/tool/securityVendorsTypes";

const logger = loggerImport.getDebugLogger();

const PER_PAGE_MAX_RES = 500;
const PER_PAGE_MAX_RES_SCA = 100;

const RETRY_COUNT = 4;
const LOG_NAME = Constant.wiz;

const linkToExternalProduct = `https://app.wiz.io/issues#~(issue~'{issueID})`;

interface WizSCAAlertExtraInfo {
  clientName: string;
  clientVersion: string;
}

interface WizSCAPolicy {
  id: string;
  name: string;
  type: string;
}

interface WizSCAResultJSONAnalyticsSecrets {
  cloudKeyCount: number;
  dbConnectionStringCount: number;
  gitCredentialCount: number;
  passwordCount: number;
  privateKeyCount: number;
}

interface WizSCAResultJSONAnalyticsVulnerabilities {
  criticalCount: number;
  highCount: number;
  infoCount: number;
  lowCount: number;
  mediumCount: number;
  unfixedCount: number;
}

interface WizSCAResultJSONAnalytics {
  secrets: WizSCAResultJSONAnalyticsSecrets;
  vulnerabilities: WizSCAResultJSONAnalyticsVulnerabilities;
}

interface WizSCAResultJSONOSPackageVulnerabilityCvssMetrics {
  attackVector: string;
}

interface WizSCAResultJSONOSPackageVulnerability {
  cvssV2Metrics: WizSCAResultJSONOSPackageVulnerabilityCvssMetrics;
  cvssV3Metrics: WizSCAResultJSONOSPackageVulnerabilityCvssMetrics;
  description: string;
  fixedVersion: any;
  name: string;
  score: number;
  severity: string;
}

interface WizSCAResultJSONOSPackage {
  detectionMethod: string;
  name: string;
  version: string;
  vulnerabilities: WizSCAResultJSONOSPackageVulnerability[];
}

interface WizSCAResultJSON {
  libraries: any;
  osPackages: WizSCAResultJSONOSPackage[];
  secrets: any;
}

interface WizSCAScanOriginResource {
  name: string;
}

interface WizSCAStatus {
  details: string;
  state: string;
  verdict: string;
}

interface WizSCAAlert {
  createdAt: string;
  extraInfo: WizSCAAlertExtraInfo;
  id: string;
  policies: WizSCAPolicy[];
  result: WizSCAResultJSON;
  scanOriginResource: WizSCAScanOriginResource;
  scanOriginResourceType: string;
  status: WizSCAStatus;
}

class WizAPI {
  private apiUrl: string;
  private authUrl: string;

  private token: Token;

  public isValidToken: boolean = false;
  private accessToken: string;
  accountIds = new Set();
  count = 0;

  private TIME_UNITS = {
    SEC: 1000,
    MIN: 60 * 1000,
  };

  private TIME_OUTS = {
    SHORT: 10 * this.TIME_UNITS.SEC,
    MEDIUM: 50 * this.TIME_UNITS.SEC,
    LONG: 3 * this.TIME_UNITS.MIN,
  };

  constructor(token: Token) {
    this.authUrl = token.authUrl;
    try {
      logger.info(`${LOG_NAME} - original authUrl: ${token.authUrl}, apiUrl: ${token.apiUrl}`);

      if (token.apiUrl.endsWith("/")) {
        const i = token.apiUrl.lastIndexOf("/");
        token.apiUrl = token.apiUrl.substring(0, i);
        logger.info(`${LOG_NAME} - removing slash from apiUrl: ${token.apiUrl}`);
      }
      if (!token.apiUrl.endsWith("graphql")) {
        token.apiUrl = `${token.apiUrl}/graphql`;
        logger.info(`${LOG_NAME} - adding graphql to apiUrl: ${token.apiUrl}`);
      }
      this.apiUrl = `${token.apiUrl}`;

      logger.info(`${LOG_NAME} - final authUrl: ${token.authUrl}, apiUrl: ${token.apiUrl}`);

      this.token = token;
      this.isValidToken = false;
    } catch (err) {
      logger.error(`${LOG_NAME} - constructor failed, err: ${err}`);
    }
  }

  /**
   * validateApiUrl - Validates user input , apiUrl.
   *
   * @notes : to validate the apiUrl , we call the issue api with limit 1
   * @returns {Boolean} isValid - Indicates if the apiUrl is valid
   */
  async validateApiUrl() {
    let isValid = false;

    const errMessage = `${LOG_NAME} - Error in validate apiUrl : err: `;

    try {
      const query = `
        query Query($first: Int) {
          issuesV2(first: $first) {
            nodes {
                ...IssueDetails,
            }
          }
        }
            
        fragment IssueDetails on Issue {
          id  
          createdAt
        }
      `;

      const variables = {
        first: 1,
      };

      const result: AxiosResponse<any> = await axios.post(
        this.apiUrl,
        { query: query, variables: variables },
        {
          timeout: this.TIME_OUTS.MEDIUM,
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            "Content-Type": "application/json",
          },
        },
      );

      if (result.status == 200) {
        isValid = true;
      } else {
        logger.error(`${errMessage} ${result.status}!`);
        StatesHelper.Instance.globalApisFails.add("wiz");
      }
    } catch (error: any) {
      logger.error(`${errMessage} ${error}`);
      StatesHelper.Instance.globalApisFails.add("wiz");
    }

    return isValid;
  }

  async auth() {
    const errMessage = `${LOG_NAME} - Authenticate Failed : for token ${this.token.name}, host: ${this.token.host}, err: `;

    try {
      logger.info(`${LOG_NAME} - Authentication ** Begin **`);
      logger.info(`${LOG_NAME} - authUrl: ${this.authUrl}, apiUrl:${this.apiUrl}`);

      const data = {
        grant_type: "client_credentials",
        client_id: this.token.clientId,
        client_secret: this.token.clientSecret,
        audience: "wiz-api",
      };

      const result: AxiosResponse<any> = await axios.post(this.authUrl, new URLSearchParams(data), {
        timeout: this.TIME_OUTS.MEDIUM,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });

      if (result.status == 200) {
        this.accessToken = result.data.access_token;

        const apiUrlValidation = await this.validateApiUrl();
        if (apiUrlValidation) {
          this.isValidToken = true;
          logger.info(`${LOG_NAME} - Authentication ** Success **`);
        } else {
          this.isValidToken = false;
        }
      } else {
        this.isValidToken = false;
        logger.error(`${errMessage} Not a valid Token!`);
      }
    } catch (error: any) {
      this.isValidToken = false;
      logger.error(`${errMessage} ${error}`);
    }
  }

  async alertHasNextPage(result) {
    return result.pageInfo && result.pageInfo.hasNextPage;
  }

  async getAllAlerts(cloudSecurityEvents: CloudSecurityEvent[], containerEvents: SecurityEvent[]) {
    await this.getAllAlertsSCA(containerEvents);
    await this.getAllAlertsCSPM(cloudSecurityEvents, containerEvents);
  }

  async getAllAlertsCSPM(cloudSecurityEvents: CloudSecurityEvent[], containerEvents: SecurityEvent[]) {
    let alertCount = 0;
    let failedAttempt = 0;
    let currPage = 0;
    let totalAlertCount = 0;
    let nextPageToken = "";
    let callApi = true;

    const uniqueContainer = new Set();

    logger.info(`${LOG_NAME} - Getting CSPM Alerts ** Begin **`);

    while (callApi) {
      try {
        if (totalAlertCount > 0 && currPage * PER_PAGE_MAX_RES >= totalAlertCount) {
          break;
        }

        this.logAlertsInfo(currPage, totalAlertCount, "CSPM");

        const result = await this.getAlertCSPM(nextPageToken);

        if (result) {
          if (result.pageInfo && result.pageInfo.hasNextPage) {
            nextPageToken = result.pageInfo.endCursor;
          }

          if (result.nodes.length == 0) {
            break;
          }

          for await (const alert of result.nodes) {
            await this.setAlertCSPM(alert, cloudSecurityEvents, containerEvents, uniqueContainer);
            alertCount++;
          }

          if (currPage == 0) {
            totalAlertCount = result.totalCount;
            logger.info(`${LOG_NAME} - Getting CSPM Alerts , Get Total : ${result.totalCount} Alerts`);
          }

          // for the logging purpose only
          currPage += 1;

          if (isLocalDevelopment()) {
            if (currPage > 3) {
              break;
            }
          }
        } else {
          failedAttempt += 1;
          if (failedAttempt > RETRY_COUNT) {
            logger.error(`${LOG_NAME} - Fetch Alerts failed safe limit reached!`);
            callApi = false;
          }
        }

        callApi = await this.alertHasNextPage(result);
      } catch (e) {
        logger.error(`${LOG_NAME} - Error in Fetching Alerts! : ${e}`);
        callApi = false;
      }
    }

    if (totalAlertCount != 0 && alertCount == totalAlertCount) {
      logger.info(`${LOG_NAME} - Getting CSPM Alerts , Successfully fetched All ${totalAlertCount} alerts!`);
    } else {
      logger.warn(
        `${LOG_NAME} - Getting CSPM Alerts , Missing ${
          totalAlertCount - alertCount
        } alerts , Fetched ${alertCount} out of ${totalAlertCount}!`,
      );
    }

    logger.info(`${LOG_NAME} - Getting CSPM Alerts ** Completed **`);
  }

  async setAlertCSPM(alert: any, cloudSecurityEvents: CloudSecurityEvent[], containerEvents: SecurityEvent[], uniqueContainer: any) {
    try {
      if (alert.status.toLowerCase() !== "open") {
        return;
      }

      let account_name = alert?.entity?.properties?.subscriptionExternalId;
      let accountId = account_name;
      let resource = alert?.entity?.providerData?.service;

      let owners = alert?.entitySnapshot?.subscriptionName ? [alert.entitySnapshot.subscriptionName] : [];
      if (alert.entitySnapshot.type === "USER_ACCOUNT") {
        resource = alert?.entity?.properties?.name;
        account_name = "Global";
        accountId = "Global";
        owners = [];
        owners.push(resource);
      } else if (alert.entitySnapshot.type === "SERVERLESS") {
        resource = alert?.entity?.name;
      } else if (alert.entitySnapshot.type === "COMPUTE_INSTANCE_GROUP") {
        resource = alert?.entity?.name;
      } else if (alert.entitySnapshot.type === "SERVICE_ACCOUNT") {
        resource = alert?.entity?.name;
      } else if (alert.entitySnapshot.type === "VIRTUAL_MACHINE") {
        resource = alert?.entity?.name;
      } else if (alert.entitySnapshot.type === "KUBERNETES_JOB") {
        resource = alert?.entitySnapshot?.kubernetesClusterName;
      } else {
        resource = alert?.entity?.name;
      }

      if (alert?.entitySnapshot?.cloudPlatform?.toLowerCase()?.includes("aws")) {
        if (!account_name && alert?.entity?.properties?.subscriptionExternalId)
          account_name = alert?.entity?.properties?.subscriptionExternalId;
      }

      let cloudPlatform = alert.entitySnapshot.cloudPlatform;
      if (!alert?.entitySnapshot?.cloudPlatform) {
        account_name = alert?.entity?.providerData?.projectId;
        accountId = alert?.entity?.providerData?.projectId;
        resource = alert?.entity?.providerData?.name;
        if (!cloudPlatform) {
          cloudPlatform = alert?.entity?.properties?.userDirectory;
        }
      }

      if (!account_name) {
        account_name = "Global";
      }
      if (!resource) {
        resource = "N/A";
      }

      const securityEvent = new CloudSecurityEvent(
        cloudPlatform,
        Constant.wiz,
        "",
        alert.createdAt,
        alert.description ? alert.description : "N/A",
        alert?.control?.name ? alert?.control?.name : alert.description,
        alert.severity,
        "",
        "",
        alert?.control?.resolutionRecommendation || "",
        false,
        alert?.control?.id || alert.entitySnapshot.type || "N/A",
        "",
        account_name,
        alert?.control?.securitySubCategories?.map(a => a.category && a.category.name)?.join(" , "),
        alert.entitySnapshot.region,
        alert.entitySnapshot.type.toLowerCase(),
        resource,
        "",
        "",
        false,
        true,
        "wiz-cspm" as Tool,
      );

      if (alert.id) {
        securityEvent.linkToExternalProduct = linkToExternalProduct.replace(`{issueID}`, alert.id);
      }

      securityEvent.accountId = accountId;
      securityEvent.cloudAccountOwners = owners;

      if (alert?.entity?.properties?.["accessibleFrom.internet"] || alert?.description?.includes("is exposed to the public internet")) {
        addSeverityCloudChangedReason(severityReasons.netExposed, securityEvent, undefined);
      }
      if (alert?.entity?.properties?.hasAdminPrivileges) {
        addSeverityCloudChangedReason(severityReasons.adminPrivilege, securityEvent, undefined);
      }
      if (alert?.entity?.properties?.hasHighPrivileges) {
        addSeverityCloudChangedReason(severityReasons.highPrivilege, securityEvent, undefined);
      }
      if (alert?.control?.impactSeverityExplanation === "High privileges") {
        addSeverityCloudChangedReason(severityReasons.highPrivilege, securityEvent, undefined);
      }
      if (alert?.entitySnapshot?.status === "Active") {
        const extraInfo: ExtraInfo[] = addRunningInCloudExtraInfo(securityEvent);
        addSeverityCloudChangedReason(severityReasons.runningInCloud, securityEvent, extraInfo);
      }

      if (alert.entitySnapshot.type === "USER_ACCOUNT") {
        addSeverityCloudChangedReason(severityReasons.userAccount, securityEvent, undefined);
      }
      if (alert.entitySnapshot.type === "SERVERLESS") {
        addSeverityCloudChangedReason(severityReasons.serverless, securityEvent, undefined);
      }
      if (alert.entitySnapshot.type === "COMPUTE_INSTANCE_GROUP") {
        addSeverityCloudChangedReason(severityReasons.computeInstanceGroup, securityEvent, undefined);
      }
      if (alert.entitySnapshot.type === "SERVICE_ACCOUNT") {
        addSeverityCloudChangedReason(severityReasons.serviceAccount, securityEvent, undefined);
      }
      if (alert.entitySnapshot.type === "VIRTUAL_MACHINE") {
        addSeverityCloudChangedReason(severityReasons.virtualMachine, securityEvent, undefined);
      }
      if (alert?.entitySnapshot?.cloudPlatform?.toLowerCase().includes("kubernetes") || alert?.entitySnapshot?.type === "KUBERNETES_JOB") {
        addSeverityCloudChangedReason(severityReasons.kubernetes, securityEvent, undefined);
      }

      //Debug
      if (isLocalDevelopment()) {
        if (alert?.description?.toLowerCase().includes("log4shell")) {
          const ads = "";
        }
        let pkgName;
        let fixVer;
        let cve;
        if (alert?.description?.toLowerCase().includes(" cve-")) {
          const cveI = alert?.description?.toLowerCase().indexOf("cve-");
          if (cveI !== -1) {
            const cveI2 = alert?.description.indexOf(cveI, " ");
            if (cveI2 !== -1) {
              cve = alert.substring(cveI, cveI2).trim();
            }
          }

          if (alert?.control?.resolutionRecommendation) {
            const recI = alert?.control?.resolutionRecommendation.toLowerCase().indexOf("versions to");
            if (recI !== -1) {
              const recI2 = alert?.control?.resolutionRecommendation.indexOf(recI, " ");
              if (recI2 !== -1) {
                fixVer = alert?.control?.resolutionRecommendation.substring(recI, recI2).trim();
              }
            }

            const pkgI = alert?.control?.resolutionRecommendation.toLowerCase().indexOf(" your ");
            if (pkgI !== -1) {
              const pkg2 = alert?.control?.resolutionRecommendation.indexOf(pkgI, "version");
              if (pkg2 !== -1) {
                pkgName = alert?.control?.resolutionRecommendation.substring(recI, pkg2).trim();
              }
            }
          }
        }
      }

      if (alert?.entity?.providerData?.containers) {
        const container = alert.entity.providerData.containers[0];

        let sha;
        let tag;
        let registry;

        uniqueContainer.add(container.name);

        let dockerFileInRunTime = container.name;
        if (dockerFileInRunTime.includes(":")) {
          const splitted = dockerFileInRunTime.split(":");
          dockerFileInRunTime = splitted[0];
          tag = splitted[1];
        }
        if (container.image.includes("@sha256:")) {
          const i = container.image.indexOf("@sha256:");
          sha = container.image.substring(i + "@sha256:".length, container.image.length);
        }
        if (container.image.includes("/")) {
          const i = container.image.indexOf("/");
          registry = container.image.substring(0, i);
        }

        const artifacts = {
          system: ArtifactorySecEventSystem.Generic,
          subType: ArtifactorySecEventType.Docker,
          repoFullName: "N/A",
          imageCreatedAt: alert.createdAt,
          dockerVer: "",
          hasPackageManager: false,
          os: "",
          sha: sha ? sha : "N/A",
          binariesCount: 0,
          pkgCount: 0,
          dockerFileInRunTime: dockerFileInRunTime,
          registry: registry,
          tag: tag,
          linkToRegistry: "N/A",
          linkToTask: "",
          baseImage: "",
          baseImageSha: "",
          baseImageOsVersion: "",
          registryName: registry,
          runningOnHost: "",
          region: alert.entitySnapshot.region,
          accountId: securityEvent.accountId,
        };

        securityEvent.artifacts = artifacts;
      }

      //securityEvent.additionalToolData = JSON.stringify(additionalInfoRes);
      cloudSecurityEvents.push(securityEvent);
    } catch (err) {
      logger.error(`${LOG_NAME} - failed for alert ${alert.id} , err : ${err}`);
    }
  }

  async getAlertCSPM(nextPageToken) {
    const errMessage = `${LOG_NAME} - Error in fetching all alerts : err: `;

    try {
      const query = `
        query Query($filterBy: IssueFilters, $first: Int, $after: String, $orderBy: IssueOrder) {
          issuesV2(filterBy: $filterBy, first: $first, after: $after, orderBy: $orderBy) {
            nodes {
                ...IssueDetails,
            }
        
            pageInfo {
                hasNextPage
                endCursor
            }
            totalCount
            informationalSeverityCount
            lowSeverityCount
            mediumSeverityCount
            highSeverityCount
            criticalSeverityCount
            uniqueEntityCount
          }
        }
            
        fragment IssueDetails on Issue {
            createdAt
            control{
                id
                impactSeverity
                impactSeverityExplanation
                likelihoodSeverity
                likelihoodSeverityExplanation
                name
                scopeQuery
                securitySubCategories{
                    id
                    category{
                        id
                        name
                    }
                }

                severity 
                type
                resolutionRecommendation
            }
            
            description
            
            entity{
                id
                name
                properties
                providerData
                providerUniqueId
                publicExposures(first:100){
                  totalCount
                  nodes{
                      id
                      exposedEntity{
                          id
                          name
                          type
                      }
                      accessibleFrom{
                          id
                          name
                          type
                      }
                      sourceIpRange
                      destinationIpRange
                      portRange
                      appProtocols
                      networkProtocols
                      path{
                          id
                          name
                          type
                      }
                      customIPRanges{
                          name
                          id
                          ipRanges
                      }
                      firstSeenAt
                      applicationEndpoints{
                          type
                          id
                          name
                      }
                      type
                  }
                }
            }
        
            entitySnapshot{
                cloudPlatform
                cloudProviderURL
                containerServiceId
                containerServiceName
                externalId
                id
                kubernetesClusterId
                kubernetesClusterName
                kubernetesNamespaceName
                name
                nativeType
                providerId
                region
                resourceGroupExternalId
                resourceGroupId
                status
                subscriptionExternalId
                subscriptionId
                subscriptionName
                subscriptionTags
                tags
                type
            }

            id
        
            openReason
            resolutionReason
            severity
        
            status
            suggestions
            type
          }
      `;

      const variables = {
        first: PER_PAGE_MAX_RES,
        filterBy: {
          status: ["OPEN", "IN_PROGRESS"],
        },
        orderBy: {
          field: "SEVERITY",
          direction: "DESC",
        },
      };

      if (nextPageToken) {
        variables["after"] = `${nextPageToken}`;
      }

      const result: AxiosResponse<any> = await axios.post(
        this.apiUrl,
        { query: query, variables: variables },
        {
          timeout: this.TIME_OUTS.MEDIUM,
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            "Content-Type": "application/json",
          },
        },
      );

      if (result.status == 200) {
        return result && result.data && result.data.data && result.data.data.issuesV2;
      } else {
        StatesHelper.Instance.globalApisFails.add("wiz-cspm");
        logger.error(`${errMessage} ${result.status}!`);
      }
    } catch (error: any) {
      logger.error(`${errMessage} ${error}`);
      StatesHelper.Instance.globalApisFails.add("wiz-cspm");
    }
  }

  async getAllAlertsSCA(containerEvents: SecurityEvent[]) {
    let alertCount = 0;
    let failedAttempt = 0;
    let currPage = 0;
    let totalAlertCount = 0;
    let nextPageToken = "";
    let callApi = true;

    logger.info(`${LOG_NAME} - Getting SCA Alerts ** Begin **`);

    while (callApi) {
      try {
        if (totalAlertCount > 0 && currPage * PER_PAGE_MAX_RES >= totalAlertCount) {
          break;
        }

        this.logAlertsInfo(currPage, totalAlertCount, "SCA");

        const result = await this.getAlertSCA(nextPageToken);

        if (result) {
          if (result.pageInfo && result.pageInfo.hasNextPage) {
            nextPageToken = result.pageInfo.endCursor;
          }

          const alerts: WizSCAAlert[] = result.nodes;
          if (alerts.length == 0) {
            break;
          }

          for (const alert of alerts) {
            alertCount++;

            //VIRTUAL_MACHINE, VIRTUAL_MACHINE_IMAGE, CONTAINER_IMAGE
            if (alert?.result?.osPackages) {
              for (const osPackage of alert.result?.osPackages) {
                for (const vulnerability of osPackage.vulnerabilities) {
                  const scaAlert = this.setAlertSCA(alert, osPackage, vulnerability, true);
                  if (scaAlert) {
                    containerEvents.push(scaAlert);
                  }
                }
              }
            }

            //nikunj
            //VIRTUAL_MACHINE, VIRTUAL_MACHINE_IMAGE, CONTAINER_IMAGE
            if (alert?.result?.libraries) {
              for (const lib of alert.result?.libraries) {
                for (const vulnerability of lib.vulnerabilities) {
                  const scaAlert = this.setAlertSCA(alert, lib, vulnerability, false);
                  if (scaAlert) {
                    containerEvents.push(scaAlert);
                  }
                }
              }
            }
            //nikunj
            //VIRTUAL_MACHINE, VIRTUAL_MACHINE_IMAGE, CONTAINER_IMAGE
            if (alert?.result?.secrets) {
              for (const secret of alert.result?.secrets) {
                const scaAlert = this.setAlertSecret(alert, secret);
                if (scaAlert) {
                  containerEvents.push(scaAlert);
                }
              }
            }

            if (alert.scanOriginResourceType === "IAC") {
              continue;
            }
            if (alert.scanOriginResourceType === "DIRECTORY") {
              continue;
            }
          }

          if (currPage == 0) {
            totalAlertCount = result.totalCount;
            logger.info(`${LOG_NAME} - Getting SCA Alerts , Get Total : ${result.totalCount} Alerts`);
          }

          // for the logging purpose only
          currPage += 1;

          if (isLocalDevelopment()) {
            if (currPage > 3) {
              break;
            }
          }
        } else {
          failedAttempt += 1;
          if (failedAttempt > RETRY_COUNT) {
            logger.error(`${LOG_NAME} - Fetch Alerts failed safe limit reached!`);
            callApi = false;
          }
        }

        callApi = await this.alertHasNextPage(result);
      } catch (e) {
        logger.error(`${LOG_NAME} - Error in Fetching Alerts! : ${e}`);
        callApi = false;
      }
    }

    if (totalAlertCount != 0 && alertCount == totalAlertCount) {
      logger.info(`${LOG_NAME} - Getting SCA Alerts , Successfully fetched All ${totalAlertCount} alerts!`);
    } else {
      logger.warn(
        `${LOG_NAME} - Getting SCA Alerts , Missing ${
          totalAlertCount - alertCount
        } alerts , Fetched ${alertCount} out of ${totalAlertCount}!`,
      );
      // StatesHelper.Instance.globalApisFails.add("wiz-cspm") // roman ?
    }

    logger.info(`${LOG_NAME} - Getting SCA Alerts ** Completed **`);
  }

  setAlertSCA(
    alert: WizSCAAlert,
    osPackage: WizSCAResultJSONOSPackage,
    vulnerability: WizSCAResultJSONOSPackageVulnerability,
    isOs: boolean,
  ) {
    try {
      const securityEvent = new SecurityEvent(
        Constant.wiz,
        true,
        "",
        alert.createdAt,
        "",
        "",
        "",
        vulnerability.description ? vulnerability.description : vulnerability.name,
        osPackage.name,
        `${osPackage.name}@${osPackage.version}`,
        vulnerability.severity,
        vulnerability.description,
        0,
        AlertSeverity[AlertSeverity.High],
        SecurityAlertType.container,
        "",
        `${osPackage.name}@${osPackage.version}`,
        "",
        -1,
        false,
        false,
        "",
        "",
        "",
        "",
        vulnerability.name,
        "",
        "",
        "",
        "",
        "",
        "wiz",
      );

      if (alert.id) {
        securityEvent.linkToExternalProduct = linkToExternalProduct.replace(`{issueID}`, alert.id);
      }

      if (vulnerability.fixedVersion) {
        securityEvent.fixedVersion = vulnerability.fixedVersion;
      }

      // if (securityEvent.severity === AlertSeverity.Critical) {
      //   const adsd = "";
      // }

      securityEvent.blame.cve = vulnerability.name;
      if (securityEvent.blame.cve) {
        securityEvent.cves.push(securityEvent.blame.cve);
      }
      securityEvent.blame.cvssScore = vulnerability.score;
      securityEvent.securitySubTypeAlertType = SecurityAlertType.cloudRunTime;
      securityEvent.skipEnrichment = true;

      addSeverityChangedReason(severityReasons.runningInCloud, securityEvent, undefined, []);

      //Public exploit --> mandatory --> nikunj
      // if (cve.exploits) {
      //   if (cve.exploits.length > 0) {
      //     securityEvent.blame.hasPublicExploit = true;
      //     if (securityEvent.blame.hasPublicExploit) {
      //       securityEvent.blame.publicExploitLink = cve.exploits[0].url;
      //       addSeverityChangedReason(severityReasons.hasPublicExpolit, securityEvent, undefined);
      //     } else {
      //       addSeverityChangedReason(severityReasons.noPublicExpolit, securityEvent, undefined);
      //     }
      //   }
      // }

      //Exposed outside --> NOT mandatory
      // const serviceExposed = item?.severity_contributing_factors?.find(i => i === "The resource is publicly exposed to the internet");
      // if (serviceExposed) {
      //   addSeverityChangedReason(severityReasons.netExposed, securityEvent, undefined);
      // }

      //Network exploitable vector
      if (vulnerability?.cvssV2Metrics?.attackVector === "NETWORK" || vulnerability?.cvssV3Metrics?.attackVector === "NETWORK") {
        securityEvent.blame.attackVector = "NETWORK";
      }
      if (vulnerability?.cvssV2Metrics?.attackVector === "LOCAL") {
        securityEvent.blame.attackVector = "LOCAL";
      }

      //Pkg name
      securityEvent.pkgName = `${osPackage.name}`;
      securityEvent.installedVersion = osPackage.version;

      //Pkg patch version
      if (vulnerability.fixedVersion) {
        securityEvent.fixedVersion = vulnerability.fixedVersion;
      }

      // if (isOs) {
      //   securityEvent.isOsLib = true;
      //   securityEvent.containerScanType = ContainerSecurityType.possibleOsOnly;
      // } else {
      //   securityEvent.isOsLib = false;
      //   securityEvent.containerScanType = ContainerSecurityType.appOnly;
      // }

      securityEvent.isOsLib = false;
      securityEvent.containerScanType = ContainerSecurityType.appOnly;
      securityEvent.cloudSubType = SecurityAlertType.sca;

      securityEvent.artifacts = this.getArtifactObj(alert);
      securityEvent.realMatch = `${osPackage.name}@${osPackage.version}`;

      return securityEvent;
    } catch (err) {
      logger.error(`${LOG_NAME} - failed for SCA alert ${alert.id} , err : ${err}`);
      StatesHelper.Instance.globalApisFails.add("wiz"); // roman ?
    }
  }

  getArtifactObj(alert: any) {
    const imageInfo = alert.scanOriginResource.name;

    let created_at = alert.createdAt;
    let accountId = "";
    let region = "";
    let hostname = "";
    let registryName = "";
    let tag = "";
    let sha = "";
    let os = "";
    let baseImageOsVersion = "";
    let baseImageSha = "";
    let baseImage = "";
    let imageName = "";

    if (imageInfo.includes(":")) {
      const sp = imageInfo.split(":");
      sha = sp[1];
      imageName = sp[0];
      const t = getHashType(sha);
      if (t === HahsType.Unknown) {
        tag = sha;
        sha = "";
      }
    } else {
      imageName = imageInfo;
    }

    registryName = guessArtifactSystem(imageName);
    if (registryName === ArtifactorySecEventSystem.ECR) {
      const i = imageName.indexOf(".");
      if (i != -1) {
        accountId = imageName.substring(0, i);
        this.accountIds.add(accountId);
      } else {
        this.accountIds.add("n/a");
      }
    }

    if (registryName === ArtifactorySecEventSystem.Generic && imageName.includes("/")) {
      const i = imageName.indexOf("/");
      registryName = imageName.substring(0, i);
      imageName = imageName.substring(i + 1, imageName.length);
    }

    const artifacts = {
      system: ArtifactorySecEventSystem.Generic,
      subType: ArtifactorySecEventType.Docker,
      repoFullName: "N/A",
      imageCreatedAt: created_at,
      dockerVer: "",
      hasPackageManager: false,
      os: os,
      sha: sha ? sha : "N/A",
      binariesCount: 0,
      pkgCount: 0,
      dockerFileInRunTime: imageName,
      registry: registryName,
      tag: tag,
      linkToRegistry: "N/A",
      linkToTask: "",
      baseImage: baseImage,
      baseImageSha: baseImageSha,
      baseImageOsVersion: baseImageOsVersion,
      registryName: registryName,
      runningOnHost: hostname,
      region: region,
      accountId: accountId,
    };

    return artifacts;
  }

  setAlertSecret(alert: WizSCAAlert, secret: any) {
    try {
      let s = secret.description;
      let match;
      const i = s.indexOf("(");
      if (i != -1) {
        s = secret.description.substring(0, i).trim();
      }
      const i2 = secret.description.indexOf(")");
      if (i != -1 && i2 != -1) {
        match = secret.description.substring(i + 1, i2).trim();
      }

      s = capitalizeFirstLetter(s);

      const securityEvent = new SecurityEvent(
        Constant.wiz,
        true,
        "",
        alert.createdAt,
        "",
        "",
        "",
        s,
        s,
        secret.path,
        "high",
        "",
        secret.lineNumber,
        AlertSeverity[AlertSeverity.High],
        SecurityAlertType.container,
        "Remove secret from container and move to environment variable",
        match,
        "",
        -1,
        false,
        false,
        "",
        "",
        "",
        "",
        secret.description,
        "",
        "",
        "",
        "",
        "",
        "wiz",
      );

      if (alert.id) {
        securityEvent.linkToExternalProduct = linkToExternalProduct.replace(`{issueID}`, alert.id);
      }

      securityEvent.realMatch = secret.snippet;
      securityEvent.artifactFilePath = secret.path;
      securityEvent.artifactFileLine = secret.lineNumber;
      securityEvent.fileName = secret.path;
      securityEvent.securitySubTypeAlertType = SecurityAlertType.cloudRunTime;
      securityEvent.cloudSubType = SecurityAlertType.secrets;
      securityEvent.skipEnrichment = true;

      securityEvent.artifacts = this.getArtifactObj(alert);

      addSeverityChangedReason(severityReasons.runningInCloud, securityEvent, undefined, []);
      addSeverityChangedReason(severityReasons.appContainerVull, securityEvent, undefined);

      return securityEvent;
    } catch (err) {
      logger.error(`${LOG_NAME} - failed for SCA alert ${alert.id} , err : ${err}`);
    }
  }

  async getAlertSCA(nextPageToken) {
    const errMessage = `${LOG_NAME} - Error in fetching SCA alerts : err: `;

    try {
      const query = `
      query Query($first: Int, $after: String) {
        cicdScans(first: $first, after: $after) {
          totalCount
          nodes {
            ...CICDScanDetails
          }
          pageInfo {
            hasNextPage
            endCursor
          }
        }
      }
      
      fragment CICDScanDetails on CICDScan {
        createdAt
      
        id
      
        result {
          ... on CICDDiskScanResult {
            libraries {
              detectionMethod
              name
              path
              version
              vulnerabilities {
                cvssV2Metrics {
                  attackVector
                }
                cvssV3Metrics {
                  attackVector
                }
                description
                fixedVersion
                score
                severity
                name
              }
            }
            osPackages {
              name
              version
              vulnerabilities {
                cvssV2Metrics {
                  attackVector
                }
                cvssV3Metrics {
                  attackVector
                }
                description
                fixedVersion
                score
                severity
                name
              }
            }
            secrets {
              description
              lineNumber
              path
              snippet
              type
            }
          }
      
          ... on CICDIACScanResult {
            secrets {
              description
              lineNumber
              path
              snippet
              type
            }
          }
        }
        scanOriginResource {
          name
        }
        scanOriginResourceType
      }      
      `;

      const variables = {
        first: PER_PAGE_MAX_RES_SCA,
      };

      if (nextPageToken) {
        variables["after"] = `${nextPageToken}`;
      }

      const result: AxiosResponse<any> = await axios.post(
        this.apiUrl,
        { query: query, variables: variables },
        {
          timeout: this.TIME_OUTS.LONG,
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            "Content-Type": "application/json",
          },
        },
      );

      if (result.status == 200) {
        return result && result.data && result.data.data && result.data.data.cicdScans;
      } else {
        StatesHelper.Instance.globalApisFails.add("wiz");

        logger.error(`${errMessage} ${result.status}!`);
      }
    } catch (error: any) {
      logger.error(`${errMessage} ${error}`);
      StatesHelper.Instance.globalApisFails.add("wiz");
    }
  }

  logAlertsInfo(currPage, totalAlertCount, type) {
    const start = type === "SCA" ? currPage * PER_PAGE_MAX_RES_SCA : currPage * PER_PAGE_MAX_RES;

    let end = type === "SCA" ? start + PER_PAGE_MAX_RES_SCA : start + PER_PAGE_MAX_RES;
    if (totalAlertCount != 0) {
      end = end > totalAlertCount ? totalAlertCount : end;
    }

    logger.info(`${LOG_NAME} - Getting ${type} Alerts from ${start} - ${end}`);
  }
}

class Wiz extends ExternalSecurityProviderBase {
  public token: Token;
  private clientApi: WizAPI;

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
      this.clientApi = new WizAPI(this.token);

      await this.clientApi.auth();
    } catch (err) {
      logger.error(`failed to initialize ${this.token.name}, host: ${this.token.host}, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add("wiz");
      StatesHelper.Instance.globalApisFails.add("wiz-cspm");
    }
  }

  async securityEvents() {
    const cloudSecurityEvents: CloudSecurityEvent[] = [];
    const containerEvents: SecurityEvent[] = [];

    try {
      if (this.clientApi.isValidToken) {
        try {
          logger.info(`${this.token.name} - try Collect Security Events`);

          await this.clientApi.getAllAlerts(cloudSecurityEvents, containerEvents);
        } catch (err) {
          logger.error(`${this.token.name} - failed to set all ${this.token.name} security events, err: ${err}`);
          StatesHelper.Instance.globalApisFails.add("wiz-cspm"); // roman ?
          StatesHelper.Instance.globalApisFails.add("wiz"); // roman ?
        }

        logger.info(
          `${this.token.name} - finish Collecting Security Events with, cloudSecurityEvents: ${
            cloudSecurityEvents.length
          }, containerEvents: ${containerEvents.length}, accountIds: ${Array.from(this.clientApi.accountIds)}`,
        );
      }
    } catch (err) {
      logger.error(`${this.token.name} - failed to set all ${this.token.name} security events, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add("wiz"); // roman ?
      StatesHelper.Instance.globalApisFails.add("wiz-cspm"); // roman ?
    }
    return { cloudSecurityEvents: cloudSecurityEvents, containerEvents: containerEvents };
  }
}

export default Wiz;
