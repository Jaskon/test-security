import axios, { AxiosInstance } from "axios";
import crypto from "crypto";
import PromisePool from "@supercharge/promise-pool";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import { AlertSeverity, CweObject, SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import loggerImport from "../../logger";
import { replaceAll } from "../../helper/generalUtils";
import { getPkgManagerPretty, shouldRetry, sleep } from "../../helper/commonUtils";
import StatesHelper from "../../helper/statesHelper";
const pathLib = require("path");

const logger = loggerImport.getDebugLogger();
const HMAC_PREFIX = "VERACODE-HMAC-SHA-256";
const HMAC_VERSION = "vcode_request_version_1";
const concurrent_pool_call = 5;

interface VeraCodeCWERef {
  name: string;
  url: string;
}

interface VeraCodeCWE {
  id: number;
  name: string;
  description: string;
  remediation_effort: number;
  recommendation: string;
  references: VeraCodeCWERef[];
}

class VeraCode extends ExternalSecurityProviderBase {
  token: Token;

  private axiosInstance: AxiosInstance;
  private hostWithoutHttps: string;
  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);
    const url = new URL(token.host);
    this.hostWithoutHttps = url.host;
    this.axiosInstance = axios.create({
      baseURL: this.token.host,
      timeout: 60 * 1000,
    });
  }

  async initLib() {}

  generateHMAC(url: string, method: string) {
    try {
      const data = `id=${this.token.userName}&host=${this.hostWithoutHttps}&url=${url}&method=${method}`;
      const timestamp = new Date().getTime().toString();
      const nonce = crypto.randomBytes(16).toString("hex");

      // calculate signature
      const hashedNonce = this.hmac256(this.getByteArray(nonce), this.getByteArray(this.token.password));
      const hashedTimestamp = this.hmac256(timestamp, hashedNonce);
      const hashedVerStr = this.hmac256(HMAC_VERSION, hashedTimestamp);
      const signature = this.hmac256(data, hashedVerStr, "hex");

      return `${HMAC_PREFIX} id=${this.token.userName},ts=${timestamp},nonce=${nonce},sig=${signature}`;
    } catch (err) {
      logger.error(`failed to generate hmac for ${this.token.name}, err: ${err}`);
    }
  }

  hmac256(data, key, format?: any) {
    const hash = crypto.createHmac("sha256", key).update(data);
    // no format = Buffer / byte array
    return hash.digest(format);
  }

  getByteArray(hex: string) {
    var bytes = [];

    for (var i = 0; i < hex.length - 1; i += 2) {
      bytes.push(parseInt(hex.substr(i, 2), 16));
    }

    // signed 8-bit integer array (byte array)
    return Int8Array.from(bytes);
  }

  async getAllApplications(retry: number = 0) {
    const allApplications = [];
    try {
      const getAllApplicationUrl = "/appsec/v1/applications";
      let currentPage = 0;
      let allPages = 0;

      do {
        let queryParams = `?size=100&page=${currentPage}`;
        const finalUrl = getAllApplicationUrl + queryParams;
        const headers = {
          Authorization: this.generateHMAC(finalUrl, "GET"),
        };

        const { data }: any = await this.axiosInstance.get(finalUrl, { headers });
        if (data?._embedded?.applications?.length) {
          allApplications.push(...data?._embedded?.applications);
        }

        if (data?.page?.total_pages) {
          allPages = data?.page?.total_pages;
        }
        currentPage++;
      } while (currentPage < allPages);
      logger.info(`${this.token.name}, Found total applications count ${allApplications.length}`);
    } catch (err) {
      ++retry;
      logger.error(`${this.token.name}, failed to get all application for  host: ${this.token.host}, retry: ${retry}, err: ${err}`);
      if (shouldRetry(err) && retry < 3) {
        await sleep(10 * 1000);
        return await this.getAllApplications(retry);
      }
    }
    return allApplications;
  }

  async getSCAIssues(application, securityEventList, retry: number = 0) {
    try {
      const allSCAIssues = [];
      const getSCAIssuesUrl = `/appsec/v2/applications/${application.guid}/findings`;
      let currentPage = 0;
      let allPages = 0;

      do {
        let queryParams = `?scan_type=SCA&size=100&page=${currentPage}`;
        const finalUrl = getSCAIssuesUrl + queryParams;
        const headers = {
          Authorization: this.generateHMAC(finalUrl, "GET"),
        };

        const { data }: any = await this.axiosInstance.get(finalUrl, { headers });
        if (data?._embedded?.findings?.length) {
          allSCAIssues.push(...data?._embedded?.findings);
        }

        if (data?.page?.total_pages) {
          allPages = data?.page?.total_pages;
        }
        currentPage++;
      } while (currentPage < allPages);

      this.formatData(application, securityEventList, allSCAIssues, []);

      logger.info(
        `${this.token.name}, found total SCA issues count ${securityEventList.length} after create ox objects, raw data size: ${
          allSCAIssues.length
        } for application: ${application?.profile?.name || application.guid}`,
      );
    } catch (err) {
      ++retry;
      logger.error(
        `${this.token.name}, failed to collect SCA issues for application: ${
          application?.profile?.name || application.guid
        }, retry: ${retry}, err: ${err}`,
      );
      if (shouldRetry(err) && retry < 3) {
        await sleep(10 * 1000);
        return await this.getSCAIssues(application, securityEventList, retry);
      }
    }
  }

  async getCWEs(retry: number = 0) {
    const cwes: VeraCodeCWE[] = [];
    try {
      const getCWEUrl = `/appsec/v1/cwes/`;
      let currentPage = 0;
      let allPages = 0;

      do {
        let queryParams = `?size=100&page=${currentPage}`;
        const finalUrl = getCWEUrl + queryParams;
        const headers = {
          Authorization: this.generateHMAC(finalUrl, "GET"),
        };

        const { data }: any = await this.axiosInstance.get(finalUrl, { headers });
        if (data?._embedded?.cwes?.length) {
          cwes.push(...data?._embedded?.cwes);
        }

        if (data?.page?.total_pages) {
          allPages = data?.page?.total_pages;
        }
        currentPage++;
      } while (currentPage < allPages);
      logger.info(`${this.token.name}, FOund total cwe count: ${cwes.length}`);
      return cwes;
    } catch (err) {
      ++retry;
      logger.error(`${this.token.name}, failed getCWEs for host: ${this.token.host}, retry: ${retry}, err: ${err}`);
      if (shouldRetry(err) && retry < 3) {
        await sleep(10 * 1000);
        return await this.getCWEs(retry);
      }
    }
    return cwes;
  }

  async getSastIssues(application, securityEventList, cwes, retry: number = 0) {
    try {
      const allSastIssues = [];
      const getSastIssuesUrl = `/appsec/v2/applications/${application.guid}/findings`;
      let currentPage = 0;
      let allPages = 0;

      do {
        let queryParams = `?scan_type=STATIC&size=100&page=${currentPage}`;
        const finalUrl = getSastIssuesUrl + queryParams;
        const headers = {
          Authorization: this.generateHMAC(finalUrl, "GET"),
        };

        const { data }: any = await this.axiosInstance.get(finalUrl, { headers });
        if (data?._embedded?.findings?.length) {
          allSastIssues.push(...data?._embedded?.findings);
        }

        if (data?.page?.total_pages) {
          allPages = data?.page?.total_pages;
        }
        currentPage++;
      } while (currentPage < allPages);

      this.formatData(application, securityEventList, allSastIssues, cwes);

      logger.info(
        `${this.token.name}, Found total SAST issues count ${securityEventList.length}, raw data size: ${
          allSastIssues.length
        }, for application: ${application?.profile?.name || application.guid}`,
      );
    } catch (err) {
      ++retry;
      logger.error(
        `${this.token.name}, failed to collect SAST issues for application: ${
          application?.profile?.name || application.guid
        }, retry: ${retry}, err: ${err}`,
      );
      if (shouldRetry(err) && retry < 3) {
        await sleep(10 * 1000);
        return await this.getSastIssues(application, securityEventList, cwes, retry);
      }
    }
  }

  formatData(application, securityEventList, issuesData, cwes: VeraCodeCWE[]) {
    try {
      for (const issue of issuesData) {
        try {
          if (issue.finding_status.status !== "OPEN") {
            continue;
          }

          const repoFullName = application.profile.name;

          if (issue.scan_type === "STATIC") {
            const fullPath = issue.finding_details.file_path;
            const fileName = issue.finding_details.file_name;
            const startLineNumber = issue.finding_details.file_line_number;
            const ruleId = issue.finding_details.finding_category.name;
            const endLineNumber = -1;
            const lineContent = "";

            const cwe = cwes.filter(c => c.id == issue.finding_details?.cwe?.id);

            let recommendationFix = "";
            let moreInfoLink = "";
            if (cwe.length) {
              recommendationFix = cwe[0].recommendation;
              if (cwe[0]?.references?.length) {
                const cweRef = cwe[0].references.find(ref => ref.name == "CWE");
                moreInfoLink = cweRef ? cweRef.url : "";
              }
            }
            const securityEvent = new SecurityEvent(
              "VeraCode",
              true,
              "",
              issue.finding_status.first_found_date,
              "",
              "",
              "",
              ruleId,
              issue.description,
              fileName,
              this.getSeverity(issue.finding_details.severity),
              issue.description,
              startLineNumber,
              AlertSeverity[AlertSeverity.High],
              SecurityAlertType.sast,
              recommendationFix,
              lineContent,
              "",
              endLineNumber,
              false,
              false,
              "",
              "",
              "",
              "",
              ruleId,
              moreInfoLink,
              "",
              repoFullName,
              "",
              fullPath,
              "vera-code",
            );

            const i = issue?.finding_details?.cwe;
            if (i) {
              securityEvent.blame.cwe.push(i.name);
              const c = new CweObject();
              c.name = i.name;
              c.shortName = `CWE-${i.id}`;
              c.url = i.href;
              securityEvent.blame.cweList.push(c);
            }

            if (repoFullName) {
              securityEvent.version = repoFullName;
            }

            securityEvent.realMatch = issue.issue_id;
            if (!securityEvent.realMatch) {
              logger.error(`failed add ${this.token.name}, no match, application: ${application?.profile?.name || application.guid}`);
              continue;
            }

            securityEventList.push(securityEvent);
          } else if (issue.scan_type === "SCA") {
            const paths = issue.finding_details.component_path;
            for (const pathInfo of paths) {
              try {
                const fullPath = pathInfo.path;
                const fileName = pathLib.basename(fullPath);
                const startLineNumber = 0;
                const endLineNumber = -1;
                const cve = issue.finding_details.cve.name;
                const moreInfoLink = issue.finding_details.cve.href;

                const pkgName = issue.finding_details.component_filename;
                const installedVersion = issue.finding_details.version;
                const recommendationFixVer = "";
                const lineContent = `${pkgName}@${installedVersion}`;

                const securityEvent = new SecurityEvent(
                  "VeraCode",
                  true,
                  "",
                  issue.finding_status.first_found_date,
                  "",
                  "",
                  "",
                  issue.description,
                  issue.description,
                  fileName,
                  issue?.finding_details?.cve?.severity,
                  issue.description,
                  startLineNumber,
                  AlertSeverity[AlertSeverity.High],
                  SecurityAlertType.sca,
                  recommendationFixVer,
                  lineContent,
                  "",
                  endLineNumber,
                  false,
                  false,
                  "",
                  "",
                  "",
                  "",
                  cve,
                  moreInfoLink,
                  "",
                  repoFullName,
                  "",
                  fullPath,
                  "vera-code",
                );
                securityEvent.lineContent = securityEvent.lineContent.trim().replace(/\s+/g, " ");

                const devLan = issue.finding_details.language ? replaceAll(issue.finding_details.language, "_", "") : "";
                if (devLan) {
                  securityEvent.pkgManager = getPkgManagerPretty(devLan);
                  securityEvent.language = devLan;
                }

                if (securityEvent.filePath.endsWith("go.mod")) {
                  securityEvent.lockfile = securityEvent.filePath.replace("go.mod", "go.sum");
                } else {
                  securityEvent.lockfile = securityEvent.filePath;
                }

                securityEvent.blame.cve = issue.finding_details.cve.name;
                if (securityEvent.blame.cve) {
                  securityEvent.cves.push(securityEvent.blame.cve);
                }

                securityEvent.blame.cvssScore = issue.finding_details.cve.cvss3.score;
                securityEvent.pkgName = pkgName;
                securityEvent.installedVersion = installedVersion;
                securityEvent.fixedVersion = recommendationFixVer;
                securityEvent.realMatch = `${pkgName}@${installedVersion}`;

                if (repoFullName) {
                  securityEvent.version = repoFullName;
                }

                if (!securityEvent.realMatch) {
                  logger.error(`failed add ${this.token.name}, no match, application: ${application?.profile?.name || application.guid}`);
                  continue;
                }

                securityEventList.push(securityEvent);
              } catch (err) {
                logger.error(
                  `failed to format single item data for ${this.token.name}, with application: ${
                    application?.profile?.name || application.guid
                  }, err: ${err}`,
                );
              }
              StatesHelper.Instance.globalApisFails.add("vera-code");
            }
          } else {
            logger.error(
              `failed to format single issue data for ${this.token.name}, with application: ${
                application?.profile?.name || application.guid
              }, type" ${issue.scan_type} is not know`,
            );
          }
        } catch (err) {
          logger.error(
            `failed to format single issue data for ${this.token.name}, with application: ${
              application?.profile?.name || application.guid
            }, err: ${err}`,
          );
          StatesHelper.Instance.globalApisFails.add("vera-code");
        }
      }
    } catch (err) {
      logger.error(
        `failed to format all data for ${this.token.name}, with application: ${
          application?.profile?.name || application.guid
        }, err: ${err}`,
      );
      StatesHelper.Instance.globalApisFails.add("vera-code");
    }
  }

  async securityEvents() {
    let securityEventList: SecurityEvent[] = [];
    try {
      const applications = await this.getAllApplications();
      const cwes: VeraCodeCWE[] = await this.getCWEs();
      for (const application of applications) {
        try {
          await this.getSCAIssues(application, securityEventList);
          await this.getSastIssues(application, securityEventList, cwes);
        } catch (err) {
          logger.error(`failed to collect security events for ${this.token.name}, in single application, err: ${err}`);
        }
      }
      logger.info(`${this.token.name}, Found overall total issues count: ${securityEventList.length}`);
    } catch (err) {
      logger.error(`failed to collect security events for ${this.token.name}, host: ${this.token.host}, err: ${err}`);
    }

    return securityEventList;
  }

  private getSeverity(sev: number) {
    if (sev === 0) return "info";
    if (sev === 1) return "info";
    if (sev === 2) return "low";
    if (sev === 3) return "medium";
    if (sev === 4) return "high";
    if (sev === 5) return "critical";
  }
}

export default VeraCode;
