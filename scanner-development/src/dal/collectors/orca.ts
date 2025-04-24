//https://snyk.docs.apiary.io/#reference/reporting-api/latest-issues/get-list-of-latest-issues
import axios, { AxiosResponse } from "axios";

import {
  SecurityAlertType,
  SecurityEvent,
  addSeverityChangedReason,
  addSeverityCloudChangedReason,
  AlertSeverity,
  setSeverity,
} from "../../entitis/codeRepoTypes";
import { CloudSecurityEvent } from "../../entitis/cloudTypes";
import { ArtifactorySecEventSystem, ArtifactorySecEventType } from "../../entitis/ArtifactTypes";
import { ContainerSecurityType } from "../../entitis/artifactoryTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { ChangeCategory, ChangeReason, SeverityFactorType, severityReasons } from "../../entitis/service/blameTypes";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import Constant from "../../entitis/constant";
import { replaceAll } from "../../helper/generalUtils";
import { cleanToolName, flatNestedJson, sleep } from "../../helper/commonUtils";
import StatesHelper from "../../helper/statesHelper";
import { isDevelopment, isLocalDevelopment } from "../../helper/envUtils";
import PromisePool from "@supercharge/promise-pool/dist";
import { ExtraInfo } from "../../entitis/issuesTypes";
import { addRunningInCloudExtraInfo } from "../../helper/policy/severityHelper";
import TimeHelper from "../../helper/timeHelper";

const logger = loggerImport.getDebugLogger();

const PER_PAGE_MAX_RES = 1000;
const RETRY_COUNT = 4;

const LOG_NAME = "Orca";
const shiftleftToIgnore = "shiftleft";

class OrcaAPI {
  private api: string;
  private token: string;
  private accountsStatusMap = new Map();

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

  constructor(api: any, token: any, private readonly connectorName: string) {
    this.token = token;

    const decodedToken = atob(this.token);
    const splitArray = decodedToken.split("||");
    this.api = `${splitArray[0]}/api`; // First element is the URL
    this.isValidToken = false;
    this.accountsStatusMap = new Map();
  }

  async auth() {
    const errMessage = `${LOG_NAME} - Authenticate Failed : for token ${this.token}, host: ${this.api}, err: `;

    try {
      logger.info(`${LOG_NAME} - Authentication Begin, for token ${this.token},`);
      const result: AxiosResponse<any> = await axios.get(this.api, {
        withCredentials: true,
        timeout: this.TIME_OUTS.MEDIUM,
        headers: {
          Authorization: "token " + this.token,
          "Content-Type": "application/json",
        },
      });
      if (result.status == 200) {
        this.isValidToken = true;
        logger.info(`${LOG_NAME} - Authentication Success`);
      } else {
        this.isValidToken = false;
        logger.error(`${errMessage} Not a valid Token!`);
      }
    } catch (error: any) {
      this.isValidToken = false;
      logger.error(`${errMessage} ${error}`);
      StatesHelper.Instance.globalApisFails.add("orca");
    }
  }

  async getAllAlerts(statsInfo, cloudSecurityEvents: CloudSecurityEvent[], containerEvents: SecurityEvent[]) {
    let alertCount = 0;
    let failedAttempt = 0;
    let currPage = 0;
    let totalAlertCount = 0;
    let nextPageToken = "";
    let callApi = true;
    let shouldExist = false;

    while (callApi && !shouldExist) {
      try {
        this.logAlertsInfo(currPage, totalAlertCount);

        const result = await this.getAlerts(nextPageToken);

        if (result.data) {
          if (result.has_next_page_token && result.next_page_token) {
            nextPageToken = result.next_page_token;
          }

          result.data.forEach(issue => {
            this.setIssue(issue, cloudSecurityEvents, containerEvents, statsInfo);
            alertCount++;
          });

          if (currPage == 0) {
            totalAlertCount = result.total_items;
            logger.info(`${LOG_NAME} - Get total : ${result.total_items} Alerts`);
          }

          // for the logging purpose only
          currPage += 1;
        } else {
          logger.info(`${LOG_NAME} - Get 0 Alerts, existing`);
          callApi = false;
          shouldExist = true;
        }

        //For local debug
        if (currPage > 10) {
          break;
        }

        callApi = this.alertHasNextPage(result);
        failedAttempt = 0;
      } catch (e) {
        logger.error(`${LOG_NAME} - Error in Fetching Alerts!, will wait for ${(1000 * 60) / 1000 / 60} m, err: ${e}`);
        await sleep(1000 * 60);
        failedAttempt += 1;
        if (failedAttempt > RETRY_COUNT) {
          logger.error(`${LOG_NAME} - Fetch Alerts failed safe limit reached!`);
          //callApi = false;
          shouldExist = true;
          StatesHelper.Instance.globalApisFails.add("orca");
        }
      }
    }

    logger.info(`${LOG_NAME} Fetched total alerts count : ${alertCount}, statsInfo: ${JSON.stringify(statsInfo)}`);

    if (totalAlertCount != 0 && alertCount == totalAlertCount) {
      logger.info(`${LOG_NAME} - Successfully fetched All ${totalAlertCount} alerts!`);
    } else {
      logger.warn(`${LOG_NAME} - Missing ${totalAlertCount - alertCount} alerts , Fetched ${alertCount} out of ${totalAlertCount}!`);
    }
  }

  logAlertsInfo(currPage, totalAlertCount) {
    const start = currPage * PER_PAGE_MAX_RES;

    let end = start + PER_PAGE_MAX_RES;
    if (totalAlertCount != 0) {
      end = end > totalAlertCount ? totalAlertCount : end;
    }

    logger.info(`${LOG_NAME} - Getting Alerts from ${start} - ${end}`);
  }

  alertHasNextPage(result) {
    return result.has_next_page_token == true;
  }

  async getAlertSchema() {
    let params = { limit: PER_PAGE_MAX_RES };

    try {
      const result: AxiosResponse<any> = await axios.get(this.api + "/alerts/scheme", {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: {
          Authorization: "token " + this.token,
          "Content-Type": "application/json",
        },
      });

      return result.data;
    } catch (e) {
      logger.error(`${LOG_NAME} - Error in getAlertSchema ${e}`);
    }
  }

  async getAlerts(nextPageToken = "") {
    try {
      let params = { limit: PER_PAGE_MAX_RES };

      if (nextPageToken != "") {
        params["next_page_token"] = nextPageToken;
      }

      const result: AxiosResponse<any> = await axios.get(this.api + "/query/alerts", {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: {
          Authorization: "token " + this.token,
          "Content-Type": "application/json",
        },
      });

      return result.data;
    } catch (e) {
      StatesHelper.Instance.globalApisFails.add("orca");
      throw `Error in getAlerts ${e}`;
    }
  }

  async setAccounts(nextPageToken = "") {
    try {
      let params = { limit: PER_PAGE_MAX_RES };

      if (nextPageToken != "") {
        params["next_page_token"] = nextPageToken;
      }

      const result: AxiosResponse<any> = await axios.get(this.api + "/cloudaccount", {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: {
          Authorization: "token " + this.token,
          "Content-Type": "application/json",
        },
      });

      result.data.data.forEach(account => this.accountsStatusMap.set(account.cloud_account_id, account.cloud_account_status));
    } catch (e) {
      logger.error(`${LOG_NAME} - Fetch get accounts, err: ${e}`);
    }
  }

  prepareIssueDataForCspm(item, cloudSecurityEvents: CloudSecurityEvent[], statsInfo) {
    try {
      let itemTitle = item.data?.title || item.type_string;
      let violationInfo = itemTitle;

      if (item.details) {
        violationInfo += ` : ${item.details}`;
      } else {
        if (item.data?.details) {
          violationInfo += ` : ${item.data?.details}`;
        }
      }

      let title = itemTitle;
      let confidence = item.state.orca_score;

      let recommendation = item.recommendation;
      let remediationConsonle = item.data?.remediation_console;
      if (remediationConsonle) {
        if (remediationConsonle.length > 0) {
          remediationConsonle = remediationConsonle.map(item => item.replace(/>/g, ""));
        }
        remediationConsonle = remediationConsonle.join("\n");
      }

      if ((!recommendation || recommendation === "") && remediationConsonle !== "") {
        recommendation = remediationConsonle;
      } else {
        recommendation = `${recommendation}`;

        if (remediationConsonle) {
          recommendation += `<br><br>
${remediationConsonle}`;
        }
      }

      const cloudEnv = item.cloud_provider;
      const accountName = item.account_name;
      const category = item.category;

      if (cloudEnv === shiftleftToIgnore) {
        statsInfo.shiftleft++;
        return;
      }

      let region = "";
      if (cloudEnv === "aws") {
        try {
          if (Array.isArray(item.model.data.Inventory.Region)) {
            region = item.model.data.Inventory.Region.join(",");
          } else {
            region = item.model.data.Inventory.Region;
          }
        } catch (e) {}

        if (!region) {
          if (Array.isArray(item.asset_regions)) {
            region = item.asset_regions.join(",");
          } else {
            region = JSON.stringify(item.asset_regions);
          }
        }
      } else if (cloudEnv === "azure") {
        if (Array.isArray(item.asset_regions)) {
          region = item.asset_regions.join(",");
        } else {
          region = JSON.stringify(item.asset_regions);
        }
      }

      let resource = item.asset_name;
      let cloudService = item.asset_type_string;

      const score = item?.state?.orca_score;
      let severity;
      if (score > 0 && score <= 2) {
        severity = "info";
      } else if (score > 2 && score <= 4) {
        severity = "low";
      } else if (score > 4 && score <= 6) {
        severity = "medium";
      } else if (score > 6 && score <= 8) {
        severity = "high";
      } else if (score > 8 && score <= 10) {
        severity = "critical";
      } else {
        statsInfo.noSeverity++;
        return;
      }

      const securityEvent = new CloudSecurityEvent(
        cloudEnv,
        Constant.orca,
        "",
        item.state.created_at,
        violationInfo,
        title,
        severity,
        "",
        confidence,
        recommendation,
        false,
        item.rule_id,
        "",
        accountName,
        category,
        region,
        cloudService,
        resource,
        "",
        "",
        false,
        true,
        "orca",
      );
      securityEvent.organization = item.organization_name;

      //State of asset
      if (item.asset_state) {
        const sf = replaceAll(`Asset ${item.asset_type_string} ${item.asset_state}`, "_", " ");
        const c = new ChangeReason(sf, sf, 0.01, ChangeCategory.Reachable, SeverityFactorType.Cloud);
        const extraInfo: ExtraInfo[] = addRunningInCloudExtraInfo(securityEvent);
        c.extraInfo = extraInfo;
        securityEvent.severityChangedReason.push(c);
      }

      if (this.accountsStatusMap.has(item.cloud_account_id)) {
        if (this.accountsStatusMap.get(item.cloud_account_id) === "offline") {
          addSeverityCloudChangedReason(severityReasons.cloudAccountOffline, securityEvent);
          securityEvent.setSeverity(AlertSeverity[AlertSeverity.Info]);
        }
      }

      //Category
      const sf1 = item.category;
      const c1 = new ChangeReason(sf1, sf1, 0, ChangeCategory.Exploitable, SeverityFactorType.Cloud);
      securityEvent.severityChangedReason.push(c1);

      //Content
      let index = 0;
      if (item?.model?.data?.Content?.HasPii) {
        try {
          item?.model?.data?.Content?.PiiTypes?.forEach(pii => {
            index++;
            if (index > 3) {
              return;
            }
            const sf = `${pii} PII`;
            const c = new ChangeReason(sf, sf, 0, ChangeCategory.Reachable, SeverityFactorType.Cloud);
            securityEvent.severityChangedReason.push(c);
          });
        } catch (err) {
          logger.error(`${LOG_NAME} - failed set pii data, err : ${err}`);
        }
      }

      //Mitre
      let index2 = 0;
      if (item.data) {
        try {
          item.data?.mitre_techniques?.forEach(technique => {
            if ("Generic technique" === technique) {
              return;
            }
            index2++;
            if (index2 > 3) {
              return;
            }
            const sf = technique;
            const c = new ChangeReason(sf, sf, 0, ChangeCategory.Reachable, SeverityFactorType.Cloud);
            securityEvent.severityChangedReason.push(c);
          });
        } catch (err) {
          logger.error(`${LOG_NAME} - failed set mitre data, err : ${err}`);
        }
      }

      cloudSecurityEvents.push(securityEvent);
    } catch (err) {
      logger.error(`${LOG_NAME} - failed, prepareIssueDataForCspm, err : ${err}`);
      StatesHelper.Instance.globalApisFails.add("orca");
    }
  }

  prepareIssueDataForCVE(item, cve, containerEvents: SecurityEvent[], statsInfo: any) {
    try {
      cve.packages.forEach(pkg => {
        try {
          const score = item?.state?.orca_score;
          let severity;
          if (score > 0 && score <= 2) {
            severity = "info";
          } else if (score > 2 && score <= 4) {
            severity = "low";
          } else if (score > 4 && score <= 6) {
            severity = "medium";
          } else if (score > 6 && score <= 8) {
            severity = "high";
          } else if (score > 8 && score <= 10) {
            severity = "critical";
          } else {
            statsInfo.noSeverity++;
            return;
          }

          if (item.cloud_provider === shiftleftToIgnore) {
            statsInfo.shiftleft++;
            return;
          }

          let securityEvent = new SecurityEvent(
            Constant.orca,
            true,
            "",
            cve.first_seen,
            "",
            "",
            "",
            cve.summary || pkg.summary || item.details,
            item.details,
            ``,
            severity,
            "",
            -1,
            cve.score,
            SecurityAlertType.container,
            item.recommendation,
            "",
            "",
            -1,
            false,
            false,
            "",
            "",
            "",
            "",
            item.rule_id,
            "",
            "",
            "",
            "",
            "",
            cleanToolName(this.connectorName),
          );
          securityEvent.organization = item.organization_name;
          securityEvent.cloudEnv = item.cloud_provider;
          securityEvent.skipEnrichment = true;

          //State of asset
          if (item.asset_state) {
            const sf = replaceAll(`Asset ${item.asset_type_string} ${item.asset_state}`, "_", " ");
            const c = new ChangeReason(sf, sf, 0.01, ChangeCategory.Reachable, SeverityFactorType.Cloud);
            securityEvent.severityChangedReason.push(c);
          }

          if (this.accountsStatusMap.has(item.cloud_account_id)) {
            if (this.accountsStatusMap.get(item.cloud_account_id) === "offline") {
              addSeverityChangedReason(severityReasons.cloudAccountOffline, securityEvent, undefined);
              setSeverity(AlertSeverity[AlertSeverity.Info], securityEvent);
            }
          }

          let index = 0;
          cve?.labels?.forEach(i => {
            index++;
            if (index > 5) {
              return;
            }
            const sf = replaceAll(i, "_", " ");
            const c2 = new ChangeReason(sf, sf, 0.01, ChangeCategory.Exploitable, SeverityFactorType.Cloud);
            securityEvent.severityChangedReason.push(c2);
          });

          securityEvent.blame.cve = cve.cve_id;
          if (securityEvent.blame.cve) {
            securityEvent.cves.push(securityEvent.blame.cve);
          }
          if (cve.cvss3_score) {
            securityEvent.blame.cvssScore = cve.cvss3_score;
          }
          securityEvent.blame.exploitDiversity = cve.published;

          //Public exploit
          if (cve.exploits) {
            if (cve.exploits.length > 0) {
              securityEvent.blame.hasPublicExploit = true;
              if (securityEvent.blame.hasPublicExploit) {
                securityEvent.blame.publicExploitLink = cve.exploits[0].url;
                addSeverityChangedReason(severityReasons.hasPublicExpolit, securityEvent, undefined);
              } else {
                addSeverityChangedReason(severityReasons.noPublicExpolit, securityEvent, undefined);
              }
            }
          }

          //Exposed outside
          const serviceExposed = item?.severity_contributing_factors?.find(i => i === "The resource is publicly exposed to the internet");
          if (serviceExposed) {
            addSeverityChangedReason(severityReasons.netExposed, securityEvent, undefined);
          }
          //Network exploitable vector
          if (cve?.labels?.find(i => i === "remote_code_execution")) {
            securityEvent.blame.attackVector = "NETWORK";
          }

          //Pkg name
          securityEvent.pkgName = pkg.package_name;
          if (securityEvent.pkgName.includes(":")) {
            const index = securityEvent.pkgName.lastIndexOf(":");
            securityEvent.pkgManager = securityEvent.pkgName.substring(index + 1, securityEvent.pkgName.length);
          }

          //Pkg patch version
          if (pkg.patched_version) {
            securityEvent.fixedVersion = pkg.patched_version;
          }
          //Pkg current version
          securityEvent.installedVersion = pkg.installed_version;
          //Exclusion info
          securityEvent.realMatch = `${securityEvent.pkgName}@${securityEvent.installedVersion}`;

          //IsOs
          if (pkg.non_os_package_paths) {
            securityEvent.isOsLib = false;
            securityEvent.containerScanType = ContainerSecurityType.appOnly;
          } else {
            securityEvent.isOsLib = true;
            securityEvent.containerScanType = ContainerSecurityType.possibleOsOnly;
            addSeverityChangedReason(severityReasons.osVull, securityEvent, undefined);
          }

          const region = item?.asset_regions_names?.join(", ");

          let dockerVer = "",
            baseImage = "",
            baseImageOsVersion = "",
            tag = "",
            dockerFileInRunTime = "";

          if (item.asset_type_string == "Container") {
            baseImage = item.asset_distribution_name;
            baseImageOsVersion = item.asset_distribution_version;
            dockerFileInRunTime = item.container_image_name;
            tag = item.container_image_version;
          } else if (item.asset_type_string == "Container Image") {
            baseImage = item.asset_distribution_name;
            baseImageOsVersion = item.asset_distribution_version;
            dockerFileInRunTime = item.image_repository_uri;
            tag = item.container_image_tags;
          } else if (item.asset_type_string == "VM") {
            baseImage = item.asset_distribution_name;
            baseImageOsVersion = item.asset_distribution_version;
            dockerFileInRunTime = item.asset_name;
          }

          //Split tags as for safty only, should hit this
          if (dockerFileInRunTime) {
            const sp = item.group_name.split(":");
            if (sp.length > 1) {
              dockerFileInRunTime = sp[0];
              tag = sp[1];
            }
          }

          securityEvent.securitySubTypeAlertType = SecurityAlertType.cloudRunTime;

          const artifacts = {
            system: ArtifactorySecEventSystem.Generic,
            subType: ArtifactorySecEventType.Docker,
            repoFullName: "N/A",
            imageCreatedAt: "",
            dockerVer: dockerVer,
            hasPackageManager: false,
            os: item.asset_distribution_name,
            sha: item.container_image_digest ? item.container_image_digest : "N/A",
            binariesCount: 0,
            pkgCount: 0,
            dockerFileInRunTime: dockerFileInRunTime,
            registry: "",
            tag: tag,
            linkToRegistry: "",
            linkToTask: "",
            baseImageSha: "",
            baseImage: baseImage,
            baseImageOsVersion: baseImageOsVersion,
            registryName: item.cloud_provider,
            runningOnHost: item.asset_hostname || "",
            region: region,
            accountId: item.account_name,
          };

          securityEvent.artifacts = artifacts;

          containerEvents.push(securityEvent);
        } catch (err) {
          logger.error(
            `${LOG_NAME} - Failed to Create SecurityEvent for alert_id : ${item?.state?.alert_id} , cve_id : ${cve?.cve_id} , err : ${err}`,
          );
        }
      });
    } catch (err) {
      logger.error(`failed to prepareIssueDataForCVE in orca, err: ${err}`);
    }
  }

  setIssue(item: any, cloudSecurityEvents: CloudSecurityEvent[], containerEvents: SecurityEvent[], statsInfo) {
    try {
      if (item.state.status === "closed" || item.state.closed_reason) {
        statsInfo.close++;
        return;
      }

      const timeHelper: TimeHelper = new TimeHelper("Commit");
      const timeDiff = timeHelper.getTimeIntervalFronNowInDays(item.state.created_at);
      if (timeDiff > 90 && (StatesHelper.Instance.isSofi || StatesHelper.Instance.aggCloudAlertsBaseOnOrg)) {
        statsInfo.ignored++;
        return;
      }

      if (item.state.orca_score < 3 && StatesHelper.Instance.isSofi) {
        statsInfo.low++;
      }

      if (item.cve_list) {
        for (const cve of item.findings.cve) {
          this.prepareIssueDataForCVE(item, cve, containerEvents, statsInfo);
        }
      } else {
        this.prepareIssueDataForCspm(item, cloudSecurityEvents, statsInfo);
      }
    } catch (err) {
      logger.error(`failed to setIssue in orca, err: ${err}`);
    }
  }
}

class Orca extends ExternalSecurityProviderBase {
  host: string;
  private_token: string;

  private clientApi: OrcaAPI;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.host = token.host;
    this.private_token = token.password;
  }

  async initLib() {
    try {
      logger.info(`set ${this.token.name}, host: ${this.host}`);
      this.clientApi = new OrcaAPI(this.host, this.private_token, this.token.name);

      await this.clientApi.auth();
    } catch (err) {
      StatesHelper.Instance.globalApisFails.add("orca");
      logger.error(`failed to initialize ${this.token.name}, host: ${this.host}, err: ${err}`);
    }
  }

  async securityEvents() {
    const cloudSecurityEvents: CloudSecurityEvent[] = [];
    const containerEvents: SecurityEvent[] = [];
    let stats = {
      closed: 0,
      low: 0,
      noSeverity: 0,
      ignored: 0,
      shiftleft: 0,
    };

    try {
      if (this.clientApi.isValidToken) {
        try {
          logger.info(`${this.token.name} - Try Collect Security Events`);

          //await this.clientApi.getAlertSchema();
          await this.clientApi.setAccounts();
          await this.clientApi.getAllAlerts(stats, cloudSecurityEvents, containerEvents);
        } catch (err) {
          logger.error(`${this.token.name} - failed to set all ${this.token.name} security events, err: ${err}`);
          StatesHelper.Instance.globalApisFails.add("orca");
        }

        logger.info(
          `${this.token.name} - Finish Collecting Security Events with, cloudSecurityEvents: ${
            cloudSecurityEvents.length
          }, containerEvents: ${containerEvents.length}, stats: ${JSON.stringify(stats)}`,
        );
      }
    } catch (err) {
      logger.error(`${this.token.name} - failed to set all ${this.token.name} security events, err: ${err}`);
    }
    if (cloudSecurityEvents.length === 0 || containerEvents.length === 0) {
      StatesHelper.Instance.globalApisFails.add("orca");
    }
    return { cloudSecurityEvents: cloudSecurityEvents, containerEvents: containerEvents };
  }
}

export default Orca;
