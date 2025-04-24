import axios, { AxiosInstance, AxiosRequestConfig } from "axios";
import { SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import Constant from "../../entitis/constant";
const logger = loggerImport.getDebugLogger();

export enum AlertSeverity {
  unknown = 100,
  info = 0,
  low = 1,
  medium = 2,
  high = 3,
  critical = 4,
  appoxalypse = 5,
}

enum IssueTypes {
  secrets = "secrets",
  iac = "iac",
  oss = "oss",
}

class Spectral extends ExternalSecurityProviderBase {
  private axiosInstance: AxiosInstance;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);
  }

  async initLib() {
    try {
      logger.info(`set ${this.token.name}, host: ${this.token.host}`);
      const axiosConfig: AxiosRequestConfig<any> = {
        baseURL: this.token.host,
        timeout: 5000,
      };
      axiosConfig.headers = { Authorization: `Bearer ${this.token.password}` };
      this.axiosInstance = axios.create(axiosConfig);
    } catch (err) {
      logger.error(`failed to initialize ${this.token.name}, , host: ${this.token.host}, err: ${err}`);
    }
  }

  async getAllIssues() {
    try {
      const issues = [];
      while (true) {
        const getIssueUrl = `api/v1/issues/search`;
        const body: any = {
          metadata: { pageSize: 500 },
        };
        const { data } = await this.axiosInstance.post(getIssueUrl, body);
        if (data?.issues?.length) {
          issues.push(...data.issues);
        }

        // call api again if pageAfterCursor is present else break loop
        if (data?.pagination?.pageAfterCursor) {
          body.metadata.cursor = data.pagination.pageAfterCursor;
        } else {
          break;
        }
      }

      return this.formatIssues(issues);
    } catch (error) {
      logger.error(`${this.token.name}, Failed to getAllIssues, ${error}`);
    }
    return [];
  }

  formatIssues(issues) {
    const formattedIssues = [];
    try {
      let skipIssues = 0;
      for (const issue of issues) {
        try {
          // Skip issue if isIgnored or Inactive
          if (issue.isIgnored || issue.status != "Active") {
            ++skipIssues;
            continue;
          }

          const fileData = this.getFilePathAndLineNumber(issue);
          const filePathForBlameService = fileData.filePath.slice(fileData.filePath.indexOf("/") + 1);
          if (issue.kind === IssueTypes.oss) {
            const securityEvent = new SecurityEvent(
              Constant.spectral,
              true,
              issue.blameUrl || "",
              issue.firstSeen,
              "N/A",
              "N/A",
              "N/A",
              issue.detectorName,
              issue.detectorName,
              fileData.fileName,
              issue.severity,
              issue.detectorDescription || "",
              fileData.lineNumber,
              AlertSeverity[issue.severity],
              SecurityAlertType.sca,
              "N/A",
              "N/A",
              "",
              -1,
              false,
              false,
              "",
              "",
              "",
              "",
              issue.detectorId,
              "",
              issue.assetId,
              issue.assetName,
              "",
              fileData.filePath,
              "spectral",
            );

            securityEvent.pkgName = issue.detectorName.replace(`-${issue.detectorId}`, "");
            securityEvent.lineContent = issue.detectorName.replace(`-${issue.detectorId}`, "");
            // securityEvent.snippetContent = issue.detectorName.replace(`-${issue.detectorId}`, "");
            securityEvent.filePathForBlameService = filePathForBlameService;

            securityEvent.blame.cve = issue.detectorId;
            if (securityEvent.blame.cve) {
              securityEvent.cves.push(securityEvent.blame.cve);
            }

            securityEvent.realMatch = issue.fingerprint;
            securityEvent.linkToExternalProduct = `${this.token.host}/assets/${encodeURIComponent(
              issue.assetId,
            )}?expandedFile=${encodeURIComponent(fileData.filePath)}&status=Active&tab=open-source`;

            formattedIssues.push(securityEvent);
          } else if (issue.kind === IssueTypes.iac) {
            const securityEvent = new SecurityEvent(
              Constant.spectral,
              true,
              issue.blameUrl || "",
              issue.firstSeen,
              "N/A",
              "N/A",
              "N/A",
              issue.detectorName,
              issue.detectorName,
              fileData.fileName,
              issue.severity,
              issue.detectorDescription || issue.detectorName || "",
              fileData.lineNumber,
              AlertSeverity[issue.severity],
              SecurityAlertType.iac,
              issue.detectorDescription || issue.detectorName || "",
              "N/A",
              "",
              -1,
              false,
              false,
              "",
              "",
              "",
              "",
              issue.detectorId,
              "",
              issue.assetId,
              issue.assetName,
              "",
              fileData.filePath,
              "spectral",
            );

            securityEvent.realMatch = issue.fingerprint;
            securityEvent.filePathForBlameService = filePathForBlameService;

            securityEvent.linkToExternalProduct = `${this.token.host}/assets/${encodeURIComponent(
              issue.assetId,
            )}?expandedFile=${encodeURIComponent(fileData.filePath)}&status=Active&tab=iac`;
            formattedIssues.push(securityEvent);
          } else if (issue.kind === IssueTypes.secrets) {
            const securityEvent = new SecurityEvent(
              Constant.spectral,
              true,
              issue.uri || "",
              issue.firstSeen,
              "N/A",
              "N/A",
              "N/A",
              issue.detectorName,
              issue.detectorName,
              fileData.fileName,
              issue.severity,
              issue.detectorDescription || issue.detectorName || "",
              fileData.lineNumber,
              AlertSeverity[issue.severity],
              SecurityAlertType.secrets,
              "",
              "",
              "",
              -1,
              false,
              false,
              "",
              "",
              "",
              "",
              issue.detectorId,
              "",
              issue.assetId,
              issue.assetName,
              "",
              fileData.filePath,
              "spectral",
            );

            securityEvent.lineContent = issue.fingerprint;
            securityEvent.filePathForBlameService = filePathForBlameService;

            securityEvent.snippetContent = issue.fingerprint;
            securityEvent.realMatch = issue.fingerprint;
            securityEvent.linkToExternalProduct = `${this.token.host}/assets/${encodeURIComponent(
              issue.assetId,
            )}?status=Active&tab=secrets`;

            formattedIssues.push(securityEvent);
          } else {
            logger.info(`${this.token.name}, found different issue with type as: ${issue.kind}`);
          }
        } catch (error) {
          logger.error(
            `${this.token.name}, failed to format security object for: ${issue?.assetName}, code content: ${issue?.content}, assetCategory: ${issue?.assetCategory}, err: ${error}`,
          );
        }
      }

      logger.info(`finished creating issues for spectral, total issue: ${formattedIssues.length}`);
    } catch (error) {
      logger.error(`${this.token.name}, failed to formatIssues, err: ${error}`);
    }
    return formattedIssues;
  }

  getFilePathAndLineNumber(issue) {
    const data = {
      filePath: "",
      lineNumber: 0,
      fileName: "",
    };
    try {
      const filPathWithHash = issue.filePath.split("#").pop();
      const filePath = filPathWithHash.slice(filPathWithHash.indexOf("/"));
      const fileName = filePath.slice(filePath.lastIndexOf("/") + 1);

      data.filePath = filePath;
      data.fileName = fileName;

      if (issue.blameUrl) {
        const str = issue.blameUrl.split(`${filePath}#`).pop();
        let numberIndex = undefined;
        for (let i = 0; i < str.length; i++) {
          if (!isNaN(str[i])) {
            numberIndex = i;
            break;
          }
        }
        if (numberIndex != undefined) {
          data.lineNumber = str.slice(numberIndex);
        }
      }
    } catch (error) {
      logger.error(`${this.token.name}, failed to getFilePathAndLineNumber, err: ${error}`);
    }
    return data;
  }

  async securityEvents() {
    let securityEventList: SecurityEvent[] = [];
    try {
      logger.info(`try collect ${this.token.name} security events`);

      securityEventList = await this.getAllIssues();
      logger.info(`${this.token.name}, Found total issue count: ${securityEventList.length}`);
    } catch (err) {
      logger.error(`failed to set all ${this.token.name} security events, err: ${err}`);
    }
    return securityEventList;
  }
}

export default Spectral;
