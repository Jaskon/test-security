import axios, { AxiosRequestConfig } from "axios";
import { ApplicationManager } from "../../appmgr/AppManager";
import { CloudSecurityEvent } from "../../entitis/cloudTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { cleanToolName, flatNestedJson } from "../../helper/commonUtils";
import { replaceAll } from "../../helper/generalUtils";
import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import { Tool } from "../../policy/rules/code/policyRulesBase";
import CloudBase from "../base/cloudBase";
import { ChangeCategory, ChangeReason, SeverityFactorType } from "../../entitis/service/blameTypes";
import { isLocalDevelopment } from "../../helper/envUtils";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
const fs = require("fs");
const Timeout = require("await-timeout");
const uuidGenerator = require("uuid");

const logger = loggerImport.getDebugLogger();

const FIVE_MONTH_DAYS = 150;

let olderThan5MonthAlertsCount = 0;

class Prisma extends ExternalSecurityProviderBase {
  host: string;
  private_token: string;
  appMgr: ApplicationManager;
  api: any;
  name: string;
  internalToken: any;
  f;

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
    this.appMgr = new ApplicationManager(this.uuid);
  }

  isOlderThan5Month(scanTime: string) {
    const nowDate = new Date();
    const scanTimeDate = new Date(scanTime);

    let dif = nowDate.getTime() - scanTimeDate.getTime();
    let daysDiff = Math.round(dif / (1000 * 3600 * 24));
    return daysDiff > FIVE_MONTH_DAYS;
  }

  async initLib() {
    this.internalToken = null;

    const urlInfo = this.token.host;
    const username = this.token.userName;
    const password = this.token.password;

    const request = {
      username: username,
      password: password,
    };

    const authUrl = `${urlInfo}/login`;

    try {
      const requestAxios = (await axios.post(authUrl, request, {
        headers: {
          ContentType: `application/json`,
        },
      })) as any;

      if (requestAxios.status != 200) {
        const err = `failed invoke post request to prisma to get token, response http err: ${requestAxios.status}`;
        logger.error(err);
        StatesHelper.Instance.globalApisFails.add("prisma-cspm");
      }

      this.internalToken = requestAxios.data.token;
    } catch (err) {
      logger.error(`failed to init prisma lib, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add("prisma-cspm");
    }
  }

  async securityEvents() {
    const urlInfo = this.token.host;
    const res = [];

    try {
      let offsetToSkip = 0;
      let limit = 4000;
      let token = "";

      while (true) {
        const dataInfo = JSON.stringify({
          detailed: true,
          limit: limit,
          offset: offsetToSkip,
          pageToken: token,
          filters: [
            {
              name: "alert.status",
              operator: "=",
              value: "open",
            },
          ],
          timeRange: {
            relativeTimeType: "BACKWARD",
            type: "relative",
            value: {
              amount: 12,
              unit: "month",
            },
          },
        });

        const config: AxiosRequestConfig = {
          method: "post",
          maxBodyLength: Infinity,
          url: `${urlInfo}/v2/alert`,
          headers: {
            "Content-Type": "application/json; charset=UTF-8",
            Accept: "*/*",
            "x-redlock-auth": `${this.internalToken}`,
          },
          data: dataInfo,
        };

        const response = (await axios(config)) as any;
        if (response.data == null) {
          StatesHelper.Instance.globalApisFails.add("prisma-cspm");
          break;
        }

        offsetToSkip += response.data.items.length;
        token = response.data.nextPageToken;

        res.push(response.data.items);

        if (isLocalDevelopment()) {
          break;
        }

        if (offsetToSkip >= response.data.totalRows || response.data.items.length == 0) {
          logger.info(`finish collect ${this.token.name} data, results count: ${offsetToSkip}`);
          break;
        }
      }
    } catch (err) {
      logger.error(`failed to get all security events from prisma api for ${this.token.name}, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add("prisma-cspm");
    }

    const oxRes = this.fromPrismaCSPMtoOxScanResults(res.flat());
    return { cloudSecurityEvents: oxRes, containerEvents: [] };
  }

  //https://pan.dev/prisma-cloud/api/cspm/post-alerts-v-2
  fromPrismaCSPMtoOxScanResults(prismaApiAlerts) {
    const securityEventList = [];

    try {
      logger.info(`${this.token.name}, sec events to process: ${prismaApiAlerts.length}`);

      let auditLogs = 0;

      for (const securityIssueEx of prismaApiAlerts) {
        try {
          if (securityIssueEx.policy.policyType === "audit_event") {
            auditLogs++;
            continue;
          }

          //Statuses - resolved,open,dismissed
          if (securityIssueEx.status != "open") {
            continue;
          }

          let cloudServiceName = securityIssueEx.resource.cloudServiceName;
          if (cloudServiceName == undefined) {
            cloudServiceName = securityIssueEx?.anomalyDetail?.features[0].sourceHost?.host;
            if (cloudServiceName == undefined) {
              if (
                securityIssueEx?.anomalyDetail?.description?.includes("_user_") ||
                securityIssueEx?.anomalyDetail?.description?.includes("time_travel")
              ) {
                cloudServiceName = "user";
              }
              if (cloudServiceName == undefined) {
                cloudServiceName = securityIssueEx.anomalyDetail.type.replace("_anomaly", "");
              }
            }
          }

          let rec = securityIssueEx.policy.recommendation;
          if (rec != undefined) {
            if (rec === '""' || rec === '"' || rec.length < 6) {
              rec = "";
            }
          }

          const alertTime = securityIssueEx.alertTime;

          if (this.isOlderThan5Month(alertTime)) {
            continue;
          }

          let securityEvent = new CloudSecurityEvent(
            securityIssueEx.resource.cloudType,
            "Prisma",
            securityIssueEx.resource.url,
            new Date(securityIssueEx.alertTime).toLocaleString(),
            securityIssueEx.policy.description,
            securityIssueEx.policy.name,
            securityIssueEx.policy.severity,
            securityIssueEx.policy.description,
            "low",
            rec,
            false,
            securityIssueEx.policy.name,
            "",
            `${securityIssueEx.resource.account}`,
            securityIssueEx.policy.policyType,
            `${securityIssueEx.resource.region} - (${securityIssueEx.resource.regionId})`,
            cloudServiceName,
            securityIssueEx.resource.name ? securityIssueEx.resource.name : securityIssueEx.resource.id,
            "",
            "",
            false,
            true,
            (cleanToolName("PAN: Prisma Cloud") + "-cspm") as Tool,
          );

          try {
            const sf = new Set();
            let index = 0;
            securityIssueEx?.policy?.complianceMetadata?.forEach(i => {
              if (index > 5) {
                return;
              }
              if (i.requirementName) {
                sf.add(i.requirementName);
                index++;
              }
            });
            Array.from(sf).forEach(i => {
              const name = i as any;
              const c = new ChangeReason(name, name, 0, ChangeCategory.Reachable, SeverityFactorType.Cloud);
              securityEvent.severityChangedReason.push(c);
            });
          } catch (err) {
            logger.error(`failed to add sf for prisma cloud, err: ${err}`);
          }

          securityEvent.accountId = securityIssueEx.resource.accountId;
          securityEvent.cloudAccountGroups = securityIssueEx?.resource?.cloudAccountGroups
            ? securityIssueEx?.resource?.cloudAccountGroups
            : [];
          securityEvent.cloudAccountOwners = securityIssueEx?.resource?.cloudAccountOwners
            ? securityIssueEx?.resource?.cloudAccountOwners
            : [];

          const additionalInfoRes = {};
          if (securityIssueEx.resource.url) {
            additionalInfoRes["linkToResource"] = securityIssueEx.resource.url;
          }
          if (securityIssueEx.resource.id) {
            additionalInfoRes["ResourceId"] = securityIssueEx.resource.id;
          }
          if (securityIssueEx.resource.rrn) {
            additionalInfoRes["ResourceRrn"] = securityIssueEx.resource.rrn;
          }
          if (securityIssueEx.resource.unifiedAssetId) {
            additionalInfoRes["UnifiedAssetId"] = securityIssueEx.resource.unifiedAssetId;
          }
          if (securityIssueEx.policy.lastModifiedBy) {
            additionalInfoRes["LastModifiedBy"] = securityIssueEx.policy.lastModifiedBy;
          }
          if (securityIssueEx.policy.lastModifiedOn) {
            additionalInfoRes["LastModifiedAt"] = new Date(securityIssueEx.policy.lastModifiedOn).toLocaleString();
          }

          securityEvent.additionalToolData = JSON.stringify(additionalInfoRes);

          securityEventList.push(securityEvent);
        } catch (err) {
          logger.error(`failed to single security event from vulnerabilities for ${this.token.name}, err: ${err}`);
        }
      }

      logger.info(
        `${this.token.name} security alerts count: ${securityEventList.length}, audit logs: ${auditLogs}, total alerts older than 5 month: ${olderThan5MonthAlertsCount}`,
      );
    } catch (err) {
      logger.error(`failed to get all security events for ${this.token.name}, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add("prisma-cspm");
    }

    return securityEventList;
  }
}

export default Prisma;
