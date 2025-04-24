import { PromisePool } from "@supercharge/promise-pool/dist/promise-pool";
import axios, { AxiosResponse } from "axios";
import { ContainerSecurityType } from "../../../entitis/artifactoryTypes";
import { ArtifactorySecEventType, guessArtifactSystem } from "../../../entitis/ArtifactTypes";
import { addSeverityChangedReason, AlertSeverity, CweObject, SecurityAlertType, SecurityEvent } from "../../../entitis/codeRepoTypes";
import { severityReasons } from "../../../entitis/service/blameTypes";
import { capitalizeFirstLetter, getLanFromPkgManager, shouldRetry, sleep } from "../../../helper/commonUtils";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { replaceAll } from "../../../helper/generalUtils";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "./../../../logger";

const logger = loggerImport.getDebugLogger();
const logName = "BlackDuck";

const TIME_UNITS = {
  SEC: 1000,
  MIN: 60 * 1000,
};

const TIME_OUTS = {
  SHORT: 10 * TIME_UNITS.SEC,
  MEDIUM: 50 * TIME_UNITS.SEC,
  LONG: 2 * TIME_UNITS.MIN,
};

enum BlackDuckApiRemediationStatus {
  Duplicate = "DUPLICATE",
  Ignored = "IGNORED",
  Mitigated = "MITIGATED",
  NeedsReview = "NEEDS_REVIEW",
  New = "NEW",
  Patched = "PATCHED",
  RemediationComplete = "REMEDIATION_COMPLETE",
  RemediationRequired = "REMEDIATION_REQUIRED",
}

const skip_statuses = [
  BlackDuckApiRemediationStatus.Ignored,
  BlackDuckApiRemediationStatus.Mitigated,
  BlackDuckApiRemediationStatus.Patched,
  BlackDuckApiRemediationStatus.RemediationComplete,
];

export default class BlackDuckAPI {
  private api: string;
  private token: string;
  private bearer: string;
  private statsCustomFiledsFound = {};
  private numOfRequestBeforeFirstIssue = 0;
  private skippedAlertsCount: number = 0;

  constructor(api: any, token: any) {
    this.api = api;
    this.token = token;
    this.bearer = "";
  }

  async auth() {
    try {
      const result: AxiosResponse<any> = await this.authApi(this.api, this.token);
      this.bearer = result.data.bearerToken;

      if (!result.data.expiresInMilliseconds) {
        logger.error(`${logName} no, refreshInterval: ${JSON.stringify(result.data)}`);
      } else {
        const refreshInterval = result.data.expiresInMilliseconds - 1000 * 60;
        setInterval(this.refreshTokenAndSetToken, refreshInterval, this);
        logger.info(`${logName} refreshInterval: ${refreshInterval}`);
      }
    } catch (error: any) {
      throw error;
    }
  }

  async authApi(api: string, token: string) {
    const result: AxiosResponse<any> = await axios.post(
      api + "/tokens/authenticate",
      {
        timeout: TIME_OUTS.MEDIUM,
      },
      {
        headers: {
          Authorization: "token " + token,
          Accept: "application/vnd.blackducksoftware.user-4+json",
          "Content-Type": "application/json",
        },
      },
    );
    return result;
  }

  async refreshTokenAndSetToken(bd: BlackDuckAPI) {
    try {
      if (!bd.bearer) {
        logger.error(`${logName} no bearer`);
        return;
      }

      logger.info(`${logName} token expired, trying to get refresh token`);

      const result: AxiosResponse<any> = await bd.authApi(bd.api, bd.token);
      bd.bearer = result.data.bearerToken;
    } catch (err) {
      logger.error(`${logName}failed to refresh token, err: ${err}`);
    }
  }

  async getAllSecEvents() {
    const secEvents = [];
    const statsInfo = {
      fromApi: 0,
      fromCash: 0,
      failedGetInfo: 0,
      recommendation: 0,
      noRecommendation: 0,
      files: 0,
      noFiles: 0,
      skippedAlertsCount: 0,
      container: 0,
      fromAfterCash: 0,
      license: 0,
    };

    try {
      const url = this.api + "/projects?limit=999";

      const projects = (await axios.get(url, {
        timeout: TIME_OUTS.LONG,
        headers: {
          Authorization: "Bearer " + this.bearer,
          Accept: "application/vnd.blackducksoftware.project-detail-4+json",
        },
      })) as any;

      logger.info(`${logName} found: ${projects.data.items.length}, projects`);

      const fixVerCash = {};

      await PromisePool.for(projects.data.items)
        .withConcurrency(5)
        .process(async (project: any) => {
          await this.processSingleProject(project, secEvents, fixVerCash, statsInfo);
        });

      secEvents.flat().forEach(i => {
        this.tryAdjustRemAfterPulling(i, statsInfo, fixVerCash);
      });
    } catch (err) {
      logger.error(`failed blackDuck getAllProjects, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}, err: ${err}`);
    }

    statsInfo.skippedAlertsCount = this.skippedAlertsCount;

    this.printStats(statsInfo);

    const resSecAlerts = secEvents.flat();
    return resSecAlerts;
  }

  printStats(stats: any) {
    try {
      logger.info(`blackDuck, stats: ${JSON.stringify(stats)} custom fields stats: ${JSON.stringify(this.statsCustomFiledsFound)}`);
    } catch (err) {
      logger.error(`failed blackDuck privateStats, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}, err: ${err}`);
    }
    //free
    this.statsCustomFiledsFound = {};
  }

  async getCustomFieldValues(item: any, info: string) {
    let codeRepoName = "",
      containerScanType = "";
    try {
      //Specific for digital assets
      if (!StatesHelper.Instance.enableDigitalAssetsLogicForContainers) {
        return { codeRepoName: codeRepoName, containerScanType: containerScanType };
      }

      const customFieldRes = await this.getProjectCustomFields(item, info);
      const codeRepoNameObj = customFieldRes.find(i => i.label === "codeRepoName");
      if (codeRepoNameObj) {
        if (codeRepoNameObj.values.length > 0) {
          codeRepoName = codeRepoNameObj.values[0];
          this.statsCustomFiledsFound[`${info}_codeRepoName`] = codeRepoName;
        }
      }

      const containerScanTypeObj = customFieldRes.find(i => i.label === "containerScanType");
      if (containerScanTypeObj) {
        if (containerScanTypeObj.values.length > 0) {
          containerScanType = containerScanTypeObj.values[0];
          this.statsCustomFiledsFound[`${info}_containerScanType`] = containerScanType;
        }
      }
    } catch (err) {
      logger.error(
        `failed ${logName} getCustomFieldValues, projectName: ${info}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}, err: ${err}`,
      );
    }

    return { codeRepoName: codeRepoName, containerScanType: containerScanType };
  }

  async processSingleProject(projectItem: any, allSecEvents: any, fixVerCash: any, stats: any) {
    const secEvents: SecurityEvent[] = [];

    try {
      let repoName = "",
        containerScanType = "";

      logger.info(`${logName} trying get versions for project name: ${projectItem.name}, project data: ${JSON.stringify(projectItem)}`);

      //Set default
      repoName = projectItem.name;

      // Get Project level custom fields
      const customFieldsRes = await this.getCustomFieldValues(projectItem, `Project: ${projectItem.name}`);
      const projectRepoNameCustomField = customFieldsRes.codeRepoName;
      const projectContainerScanTypeCustomField = customFieldsRes.containerScanType;
      if (projectRepoNameCustomField) {
        repoName = projectRepoNameCustomField;
      }
      if (projectContainerScanTypeCustomField) {
        containerScanType = projectContainerScanTypeCustomField;
      }

      const projectName = projectItem.name;
      if (isLocalDevelopment()) {
        if (!projectName.toLowerCase().includes("DA_IMAGE_SCAN".toLowerCase())) {
          return;
        }
      }

      let projectId = projectItem._meta.href;
      const index = projectId.lastIndexOf("/");
      projectId = projectId.substring(index + 1, projectId.length);

      let projectVersions = await this.getVersionsForSingleProject(projectItem, projectName);

      logger.info(`${logName} version count before: ${projectVersions.length}, projectName: ${projectItem.name}`);

      //Specific for digital assets
      this.setVersionsForDigitalAssetsOrg(projectVersions);

      if (isLocalDevelopment()) {
        projectVersions = projectVersions.slice(0, 3);
      }

      for (const projectVersion of projectVersions) {
        logger.info(`${logName} version name: ${projectVersion.versionName}, for projectName: ${projectItem.name}`);

        const verCustomFieldsRes = await this.getCustomFieldValues(
          projectVersion,
          `Project : ${projectItem.name} , Project Version : ${projectVersion.versionName}`,
        );
        const projectVersionRepoNameCustomField = verCustomFieldsRes.codeRepoName;
        const projectVersionContainerScanTypeCustomField = verCustomFieldsRes.containerScanType;

        try {
          if (projectVersionRepoNameCustomField) {
            repoName = projectVersionRepoNameCustomField;
          }
          if (projectVersionContainerScanTypeCustomField) {
            containerScanType = projectVersionContainerScanTypeCustomField;
          }
          if (projectVersion.withBase != undefined) {
            containerScanType = projectVersion.withBase ? "full" : ContainerSecurityType.appOnly;
          }

          await this.setVulBasedOnProjectVersion(
            projectId,
            projectVersion,
            projectName,
            secEvents,
            repoName,
            containerScanType,
            fixVerCash,
            stats,
          );
        } catch (err) {
          logger.error(
            `failed ${logName} get single projectName: ${projectName}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}, err: ${err}`,
          );
        }
      }

      logger.info(
        `finish ${logName} working project name: ${projectName}, projectId: ${projectId}, project version count: ${projectVersions.length}, repoName: ${repoName}`,
      );
    } catch (err) {
      logger.error(`failed ${logName} getAllProjects for: ${projectItem.name}, err: ${err}`);
    }

    allSecEvents.push(secEvents);
    this.removeDuplicatedEventsOnArtifactBaseAndApplicationCodeImage(secEvents);
  }

  setVersionsForDigitalAssetsOrg(resultProjectVersion: any) {
    try {
      if (!StatesHelper.Instance.enableDigitalAssetsLogicForContainers) {
        return resultProjectVersion;
      }

      let isContainer = false;
      (resultProjectVersion as any).forEach(i => {
        const withBase = i.versionName.includes("with-base") ? true : false;
        i.withBase = withBase ? true : false;
        if (withBase) {
          isContainer = true;
        }
      });

      //If at least one container type for project set the rest with the same type
      (resultProjectVersion as any).forEach(i => {
        if (isContainer) {
          i.isContainer = true;
        } else {
          i.isContainer = false;
        }
      });
    } catch (err) {
      logger.error(
        `failed ${logName} tryToGetUniqueVersions, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}, err: ${err}`,
      );
    }
  }

  tryAdjustRemAfterPulling(securityAlert: SecurityEvent, stats: any, fixVerCash: any) {
    try {
      if (!securityAlert.recommendation) {
        return;
      }

      const key = `${securityAlert.componentName}_${securityAlert.installedVersion}`;
      let recommendation;
      let fixFromCash = fixVerCash[key];
      if (fixFromCash != undefined) {
        if (fixFromCash) {
          recommendation = (fixFromCash?.data && fixFromCash?.data?.solution) || "";
          if (recommendation) {
            if (recommendation.includes("[**") && recommendation.includes("**]")) {
              const i = recommendation.indexOf("[**");
              const i2 = recommendation.indexOf("**]");
              recommendation = recommendation.substring(i + "[**".length, i2);
            }
          }
        }
      }

      if (recommendation) {
        stats.fromAfterCash++;
        securityAlert.recommendation = recommendation;
      }
    } catch (err) {
      logger.error(`failed ${logName} tryAdjustRemAfterPulling, err: ${err}`);
    }
  }

  async getVulRemediation(vul: any, matchFilesUrl: string, projectName: string, vulInfo: string, fixVerCash: any, stats: any) {
    let retry = 3;
    let FixFromApi;
    const key = `${vul.componentName}_${vul.componentVersionName}`;
    let url;
    let isOrigin = false;

    try {
      let fixFromCash = fixVerCash[key];
      if (fixFromCash != undefined) {
        stats.fromCash++;
        return fixFromCash;
      }

      if (vul.componentVersionOriginId == undefined) {
        this.numOfRequestBeforeFirstIssue++;
        url = vul._meta.href;
        FixFromApi = (await axios.get(url, {
          timeout: TIME_OUTS.MEDIUM,
          headers: {
            Authorization: "Bearer " + this.bearer,
            Accept: "application/vnd.blackducksoftware.bill-of-materials-6+json",
          },
        })) as any;

        const add = "";
      } else {
        isOrigin = true;
        const remediationUrl = vul._meta.href;
        const _arr = remediationUrl.split("/");
        const _len = _arr.length;

        let tempArr = matchFilesUrl.split("/");

        tempArr.pop();
        tempArr.push(_arr[_len - 3], _arr[_len - 2], _arr[_len - 1]);
        url = tempArr.join("/");

        this.numOfRequestBeforeFirstIssue++;
        FixFromApi = (await axios.get(url, {
          timeout: TIME_OUTS.MEDIUM,
          headers: {
            Authorization: "Bearer " + this.bearer,
            Accept: "application/vnd.blackducksoftware.bill-of-materials-6+json",
          },
        })) as any;

        const add = "";
      }

      //SetCash
      fixVerCash[key] = FixFromApi;
      stats.fromApi++;

      logger.info(
        `${logName} exist-getVulRemediation, projectName: ${projectName}, isOrigin: ${isOrigin}, url: ${url}, retry: ${retry}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}`,
      );

      return FixFromApi;
    } catch (err) {
      if (err?.response?.status) {
        if (err?.response?.status == 404) {
          stats.failedGetInfo++;
          fixVerCash[key] = {};
          return;
        }
      }

      retry--;

      if (shouldRetry(err)) {
        logger.info(
          `failed ${logName} getVulRemediation, projectName: ${projectName}, isOrigin: ${isOrigin}, url: ${url}, retry: ${retry}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}, vulInfo: ${vulInfo}, err: ${err}`,
        );
      } else {
        stats.failedGetInfo++;
        logger.error(
          `failed ${logName} getVulRemediation, projectName: ${projectName}, isOrigin: ${isOrigin}, url: ${url}, retry: ${retry}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}, vulInfo: ${vulInfo}, err: ${err}`,
        );
      }
    }
  }

  getArtifactInfoForDigitalAssetsOrg(projectVersion: any, repoName: string) {
    try {
      //Specific for digital assest
      if (!StatesHelper.Instance.enableDigitalAssetsLogicForContainers) {
        return;
      }
      if (!projectVersion.isContainer || !projectVersion.versionName) {
        return;
      }

      let dockerNameBaseImage;
      let baseImageOsVersion;
      let baseImageSha;
      if (projectVersion.releaseComments) {
        const releaseComments = projectVersion.releaseComments;
        dockerNameBaseImage = releaseComments;
        dockerNameBaseImage = dockerNameBaseImage.replace("base image: ", "");
        dockerNameBaseImage = replaceAll(dockerNameBaseImage, "''", "");
        if (dockerNameBaseImage.includes("@")) {
          const items = dockerNameBaseImage.split("@");
          dockerNameBaseImage = items[0];
          //Sha
          if (projectVersion.releaseComments.includes("sha256:")) {
            baseImageOsVersion = "";
            baseImageSha = projectVersion.releaseComments.substring(
              projectVersion.releaseComments.indexOf("sha256:") + "sha256:".length,
              projectVersion.releaseComments.length,
            );
          } else {
            baseImageOsVersion = items[1];
          }
        }
      }

      let tag = "NA";
      let dockerName = "NA";
      let registry = "NA";
      const index = projectVersion.versionName.indexOf("/");
      dockerName = projectVersion.versionName.substring(index + 1, projectVersion.versionName.length);
      registry = guessArtifactSystem(projectVersion.versionName);

      const artifacts = {
        system: registry,
        subType: ArtifactorySecEventType.Docker,
        repoFullName: repoName,
        imageCreatedAt: "",
        dockerVer: "",
        hasPackageManager: true,
        os: undefined,
        sha: "N/A",
        binariesCount: 0,
        pkgCount: 0,
        dockerFileInRunTime: dockerName,
        registry: registry,
        tag: tag,
        linkToRegistry: "",
        linkToTask: "",
        baseImage: dockerNameBaseImage,
        baseImageOsVersion: baseImageOsVersion,
        baseImageSha: "",
        baseImageRegistry: "",
        registryName: registry,
      };
      return artifacts;
    } catch (err) {
      logger.error(
        `failed ${logName} getArtifactInfoFromVersionInfo, repoName: ${repoName}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}, err: ${err}`,
      );
    }
  }

  removeDuplicatedEventsOnArtifactBaseAndApplicationCodeImage(secEvents: SecurityEvent[]) {
    try {
      if (!StatesHelper.Instance.enableDigitalAssetsLogicForContainers) {
        return;
      }

      const secEventPerProject = {};
      secEvents.forEach(i => {
        try {
          if (i.securityAlertType !== SecurityAlertType.container) {
            return;
          }
          if (!i?.artifacts?.dockerFileInRunTime) {
            return;
          }

          const key = i.artifacts.dockerFileInRunTime.replace("-with-base", "");
          if (secEventPerProject[key]) {
            secEventPerProject[key].push(i);
          } else {
            secEventPerProject[key] = [i];
          }
        } catch (err) {
          logger.error(
            `failed ${logName} single sec event add to secEventPerProject, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}, err: ${err}`,
            err,
          );
        }
      });

      logger.info(
        `${logName} run removeDuplicatedEventsOnArtifactBaseAndApplicationCodeImage for: ${Object.keys(secEventPerProject).length}`,
      );

      for (const [artifactName, secEventsEx] of Object.entries(secEventPerProject)) {
        try {
          const securityEvents: SecurityEvent[] = secEventsEx as any;
          const eventsFromAppOnly = securityEvents.filter(i => i.containerScanType === ContainerSecurityType.appOnly);
          const eventsFromAppOnlyMap = new Set();
          eventsFromAppOnly.forEach(i => {
            addSeverityChangedReason(severityReasons.appContainerVull, i, undefined);
            eventsFromAppOnlyMap.add(`${i.installedVersion}_${i.pkgName}`);
          });
          const eventsFromBaseOnly = securityEvents.filter(
            i => i.containerScanType === "full" && !eventsFromAppOnlyMap.has(`${i.installedVersion}_${i.pkgName}`),
          );

          eventsFromBaseOnly.forEach(i => {
            if (i.artifacts.baseImage) {
              i.containerScanType = ContainerSecurityType.baseOnly;
              addSeverityChangedReason(severityReasons.baseContainerVull, i, undefined);
            }
          });
        } catch (err) {
          logger.error(
            `failed ${logName} removeApplicationEvents, artifactName: ${artifactName}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}, err: ${err}`,
          );
        }
      }
    } catch (err) {
      logger.error(
        `failed ${logName} all removeApplicationEvents, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}, err: ${err}`,
      );
    }
  }

  async getVulBasedOnProjectVersion(projectId: string, versionId: string, projectName: string, versionName: string) {
    let resultProjectVerComponentItems = [];
    let resultProjectVerComponentItemsCount = 0;

    let offset = 0,
      limit = 999;

    let max_retry = 3;
    let failed_attempt = -1;
    let callResultProjectVerComponent = true;
    let safetyCheck = 0;

    logger.info(`${logName} try get vuls for versionName: ${versionName}, projectName: ${projectName}`);

    while (callResultProjectVerComponent) {
      safetyCheck++;
      if (safetyCheck > 30) {
        logger.warn(`${logName} safetyCheck trigger`);
        break;
      }

      if (resultProjectVerComponentItemsCount != 0) {
        if (offset + limit >= resultProjectVerComponentItemsCount) {
          callResultProjectVerComponent = false;
        }
      } else {
        // for exist the while loop in case of api mis behaviour
        failed_attempt += 1;
        if (failed_attempt > max_retry) {
          callResultProjectVerComponent = false;
        }
      }

      try {
        const url = `${this.api}/projects/${projectId}/versions/${versionId}/vulnerable-bom-components?offset=${offset}&limit=${limit}`;
        logger.info(`Getting vul ${offset} to ${offset + limit} for project name: ${projectName}, versionName: ${versionName}`);
        this.numOfRequestBeforeFirstIssue++;
        const resultProjectVerComponent = (await axios.get(url, {
          timeout: TIME_OUTS.LONG,
          headers: {
            Authorization: "Bearer " + this.bearer,
            Accept: "application/vnd.blackducksoftware.bill-of-materials-4+json",
          },
        })) as any;

        if (resultProjectVerComponent.data) {
          resultProjectVerComponentItems = [...resultProjectVerComponentItems, ...resultProjectVerComponent.data.items];

          if (offset == 0) {
            resultProjectVerComponentItemsCount = resultProjectVerComponent.data.totalCount;

            logger.info(
              `${logName} found: ${resultProjectVerComponentItemsCount} vul for project name: ${projectName}, versionName: ${versionName}`,
            );

            if (resultProjectVerComponentItemsCount <= offset + limit) {
              callResultProjectVerComponent = false;
            }
          }
        }
      } catch (e) {
        callResultProjectVerComponent = false;
        logger.warn(`${logName} vuln, project name: ${projectName}, versionName: ${versionName} error : ${e}`);
      }
      offset = offset + limit;
    }

    if (resultProjectVerComponentItemsCount != resultProjectVerComponentItems.length) {
      logger.error(
        `${logName} missing the ${resultProjectVerComponentItemsCount - resultProjectVerComponentItems.length} alerts , retrieved alerts ${
          resultProjectVerComponentItems.length
        } out of ${resultProjectVerComponentItemsCount}, projectName: ${projectName}, numOfRequestBeforeFirstIssue: ${
          this.numOfRequestBeforeFirstIssue
        }, versionName: ${versionName}`,
      );
    }

    logger.info(
      `${logName} finish get vuls for versionName: ${versionName}, projectName: ${projectName}, vuls: ${resultProjectVerComponentItems.length}`,
    );

    return resultProjectVerComponentItems;
  }

  async setVulBasedOnProjectVersion(
    projectId: string,
    projectVersion: any,
    projectName: string,
    secEvents: SecurityEvent[],
    repoName: string,
    containerScanType: string,
    fixVerCash: any,
    stats: any,
  ) {
    try {
      let versionId = projectVersion._meta.href;
      const index = versionId.lastIndexOf("/");
      versionId = versionId.substring(index + 1, versionId.length);

      const resultProjectVerComponentItems = await this.getVulBasedOnProjectVersion(
        projectId,
        versionId,
        projectName,
        projectVersion.versionName,
      );

      await PromisePool.for(resultProjectVerComponentItems)
        .withConcurrency(5)
        .process(async (vul: any) => {
          let retry = 3;
          while (retry > 0) {
            try {
              if (vul?.vulnerabilityWithRemediation?.remediationStatus) {
                if (skip_statuses.includes(vul?.vulnerabilityWithRemediation?.remediationStatus)) {
                  this.skippedAlertsCount++;
                  return;
                }
              }

              const vulInfo = `${vul.componentName}@${vul.componentVersionName}`;

              let matchFilesUrl = vul._meta.links.find(i => i.rel === "matched-files").href;
              if (!matchFilesUrl) {
                logger.error(
                  `failed ${logName} single vul event, err: cannot get matchFilesUrl, projectName: ${projectName}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}`,
                );
              }

              this.numOfRequestBeforeFirstIssue++;
              let matchFiles = [];
              //Get files only for repo vuls
              if (!projectVersion.isContainer) {
                const resultMatchFiles = (await axios.get(matchFilesUrl, {
                  timeout: TIME_OUTS.LONG,
                  headers: {
                    Authorization: "Bearer " + this.bearer,
                    Accept: "application/vnd.blackducksoftware.bill-of-materials-4+json",
                  },
                })) as any;

                if (resultMatchFiles.data.items.length > 100) {
                  resultMatchFiles.data.items = resultMatchFiles.data.items.slice(0, 100);
                }
                matchFiles = resultMatchFiles.data.items ? resultMatchFiles.data.items : [];
              }

              let recommendation = "";
              const FixFromApi = await this.getVulRemediation(vul, matchFilesUrl, projectName, vulInfo, fixVerCash, stats);

              if (FixFromApi) {
                recommendation = (FixFromApi?.data && FixFromApi?.data?.solution) || "";
                if (recommendation) {
                  if (recommendation.includes("[**") && recommendation.includes("**]")) {
                    const i = recommendation.indexOf("[**");
                    const i2 = recommendation.indexOf("**]");
                    recommendation = recommendation.substring(i + "[**".length, i2);
                  }
                }
              }

              if (projectVersion.isContainer) {
                if (recommendation) {
                  stats.recommendation++;
                } else {
                  stats.noRecommendation++;
                }
                if (matchFiles.length > 0) {
                  stats.files++;
                } else {
                  stats.noFiles++;
                }

                if (matchFiles.length === 0) {
                  this.setAlert(
                    stats,
                    vul,
                    FixFromApi,
                    "",
                    recommendation,
                    projectVersion,
                    repoName,
                    projectName,
                    containerScanType,
                    secEvents,
                  );
                }
              } else {
                for (const matchFile of matchFiles) {
                  if (recommendation) {
                    stats.recommendation++;
                  } else {
                    stats.noRecommendation++;
                  }
                  if (matchFiles.length > 0) {
                    stats.files++;
                  } else {
                    stats.noFiles++;
                  }

                  this.setAlert(
                    stats,
                    vul,
                    FixFromApi,
                    matchFile.filePath.path,
                    recommendation,
                    projectVersion,
                    repoName,
                    projectName,
                    containerScanType,
                    secEvents,
                  );
                }
                if (matchFiles.length === 0) {
                  if (recommendation) {
                    stats.recommendation++;
                  } else {
                    stats.noRecommendation++;
                  }
                  if (matchFiles.length > 0) {
                    stats.files++;
                  } else {
                    stats.noFiles++;
                  }

                  this.setAlert(
                    stats,
                    vul,
                    FixFromApi,
                    "N/A",
                    recommendation,
                    projectVersion,
                    repoName,
                    projectName,
                    containerScanType,
                    secEvents,
                  );
                }
              }

              break;
            } catch (err) {
              retry--;
              if (shouldRetry(err)) {
                logger.info(
                  `failed ${logName} single vul event, err: ${err}, projectName: ${projectName}, retry: ${retry}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}`,
                );
                continue;
              } else {
                logger.error(
                  `failed ${logName} single vul event, err: ${err}, projectName: ${projectName}, retry: ${retry}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}`,
                );
                break;
              }
            }
          }
        });

      logger.info(`${logName} created: ${resultProjectVerComponentItems.length}, vul for project name: ${projectName}`);
    } catch (err) {
      logger.error(
        `failed ${logName} all vuls, err: ${err}, projectName: ${projectName}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}`,
      );
    }
  }

  async setAlert(
    stats,
    vul,
    remediationFromApi,
    filePath,
    recommendation,
    projectVersion,
    repoName,
    projectName,
    containerScanType,
    secEvents,
  ) {
    try {
      const licenses = vul?.license?.licenses || [];
      let isLicense = false;

      if (licenses?.length > 0 && (isDevelopment() || isLocalDevelopment())) {
        for (const license of licenses) {
          const licenseUrl = license?.license;

          const licenseDetail = await this.getLicenseDetail(licenseUrl);

          if (licenseDetail && !licenseDetail.licenseStatus.includes("APPROVED")) {
            if (licenseUrl) {
              isLicense = true;
              await this.setSecurityEvent(
                stats,
                vul,
                remediationFromApi,
                filePath,
                recommendation,
                projectVersion,
                repoName,
                projectName,
                containerScanType,
                secEvents,
                isLicense,
              );
            }
          } else {
            await this.setSecurityEvent(
              stats,
              vul,
              remediationFromApi,
              filePath,
              recommendation,
              projectVersion,
              repoName,
              projectName,
              containerScanType,
              secEvents,
              isLicense,
            );
          }
        }
      } else {
        await this.setSecurityEvent(
          stats,
          vul,
          remediationFromApi,
          filePath,
          recommendation,
          projectVersion,
          repoName,
          projectName,
          containerScanType,
          secEvents,
          isLicense,
        );
      }
    } catch (err) {
      logger.error(
        `failed ${logName} single vul file info, err: ${err}, projectName: ${projectName}, numOfRequestBeforeFirstIssue: ${
          this.numOfRequestBeforeFirstIssue
        }, vulData: ${JSON.stringify(vul)}`,
      );
    }
  }

  getProjectName(versionName: string) {
    try {
      if (!versionName.includes(":")) {
        return;
      }
      const imageName = versionName.split(":")[0];
      const index = imageName.lastIndexOf("/");
      if (index === -1) {
        return;
      }
      const projectName = imageName.substring(index + 1, imageName.length);
      return projectName;
    } catch (err) {
      logger.error(
        `failed ${logName} getProjectName, err: ${err}, versionName: ${versionName}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}`,
      );
    }
  }

  async setSecurityEvent(
    stats,
    vul,
    remediationFromApi,
    filePath,
    recommendation,
    projectVersion,
    repoName,
    projectName,
    containerScanType,
    secEvents,
    isLicense,
  ) {
    try {
      if (isLicense) {
        const title =
          vul.vulnerabilityWithRemediation.vulnerabilityName &&
          `Library with unapproved license ${vul.vulnerabilityWithRemediation.vulnerabilityName}`;

        const securityEvent: SecurityEvent = new SecurityEvent(
          "Black Duck",
          true,
          "",
          vul?.vulnerabilityWithRemediation?.remediationCreatedAt,
          "",
          "",
          "",
          remediationFromApi?.data?.technicalDescription || vul.vulnerabilityWithRemediation.description,
          `${title} of the package ${vul.componentName}@${vul.componentVersionName}`,
          filePath || vul.packageUrl || "N/A",
          vul?.vulnerabilityWithRemediation?.severity,
          vul.vulnerabilityWithRemediation.relatedVulnerability,
          -1,
          AlertSeverity[AlertSeverity.Low],
          SecurityAlertType.license,
          remediationFromApi?.data?.solution || remediationFromApi?.data?.summary || "N/A",
          "",
          "",
          0,
          false,
          false,
          "",
          "",
          "",
          "",
          vul?.vulnerabilityWithRemediation?.cweId || vul?.vulnerabilityWithRemediation?.vulnerabilityName || "Generic",
          vul.componentVersion,
          "",
          repoName,
          "",
          filePath || vul.packageUrl || "N/A",
          "black-duck",
        );

        securityEvent.version = `${projectName} - ${projectVersion.versionName}`;
        securityEvent.containerScanType = containerScanType;
        if (vul.packageUrl) {
          const i = vul.packageUrl.indexOf("/");
          const i2 = vul.packageUrl.indexOf(":");
          if (i !== -1 && i2 !== -1) {
            securityEvent.pkgManager = vul.packageUrl.substring(i2 + 1, i);
            securityEvent.language = getLanFromPkgManager(securityEvent.pkgManager)?.toLowerCase();
            securityEvent.language = capitalizeFirstLetter(securityEvent.language);
          }
        }

        securityEvent.installedVersion = vul.componentVersionName;
        securityEvent.pkgName = vul.componentName;
        if (vul.componentVersionOriginId) {
          securityEvent.pkgName = vul.componentVersionOriginId.replace(`:${vul.componentVersionName}`, "");
          securityEvent.lineContent = securityEvent.pkgName;
        }
        securityEvent.componentName = vul.componentName;

        securityEvent.fixedVersion = recommendation;

        securityEvent.realMatch = `${vul.packageUrl}`;
        if (!securityEvent.realMatch) {
          securityEvent.realMatch = vul.componentVersionOriginId;
        }
        securityEvent.blame.cve = vul.vulnerabilityWithRemediation.cweId;
        if (vul.vulnerabilityWithRemediation.relatedVulnerability) {
          const index = vul.vulnerabilityWithRemediation.relatedVulnerability.lastIndexOf("/");
          if (index != -1) {
            securityEvent.blame.cve = vul.vulnerabilityWithRemediation.relatedVulnerability.substring(
              index + 1,
              vul.vulnerabilityWithRemediation.relatedVulnerability.length,
            );
          }
        }

        if (securityEvent.blame.cve) {
          securityEvent.cves.push(securityEvent.blame.cve);
        }

        if (remediationFromApi?.data?.exploitAvailable != undefined) {
          securityEvent.blame.hasPublicExploit = remediationFromApi?.data?.exploitAvailable;
          securityEvent.blame.publishedExploitDate = remediationFromApi?.data?.publishedDate;
          addSeverityChangedReason(severityReasons.hasPublicExpolit, securityEvent, undefined);
        }
        if (remediationFromApi?.data) {
          if (remediationFromApi?.data?.cvss3) {
            securityEvent.blame.cvssScore = remediationFromApi?.data?.cvss3?.overallScore;
            securityEvent.blame.cveDescription = remediationFromApi?.data?.summary;
            securityEvent.blame.attackVector = remediationFromApi?.data?.cvss3?.attackVector;
          } else if (remediationFromApi?.data?.cvss2) {
            securityEvent.blame.cvssScore = remediationFromApi?.data?.cvss2?.overallScore;
            securityEvent.blame.cveDescription = remediationFromApi?.data?.summary;
            securityEvent.blame.attackVector = remediationFromApi?.data?.cvss2?.accessVector;
          }
        }

        if (vul.vulnerabilityWithRemediation.cweId) {
          const cweObject: CweObject = new CweObject();
          cweObject.name = vul.vulnerabilityWithRemediation.cweId;
          cweObject.shortName = vul.vulnerabilityWithRemediation.cweId;
          cweObject.description = vul.vulnerabilityWithRemediation.description;
          securityEvent.blame.cwe.push(vul.vulnerabilityWithRemediation.cweId);
          securityEvent.blame.cweList.push(cweObject);
        }

        if (projectVersion.isContainer) {
          const artifact = this.getArtifactInfoForDigitalAssetsOrg(projectVersion, repoName);
          if (vul?.componentVersionOriginName) {
            securityEvent.setIsOsTypeLib(vul.componentVersionOriginName.toLowerCase());
          }
          securityEvent.artifacts = artifact as any;
          securityEvent.securitySubTypeAlertType = SecurityAlertType.sca;

          if (projectName === repoName) {
            const pName = this.getProjectName(projectVersion.versionName);
            if (pName) {
              artifact.repoFullName = pName;
              securityEvent.repoFullName = pName;
            }
          }
        }

        stats.license++;

        secEvents.push(securityEvent);
      } else {
        const securityEvent: SecurityEvent = new SecurityEvent(
          "Black Duck",
          true,
          "",
          vul.vulnerabilityWithRemediation.remediationCreatedAt,
          "",
          "",
          "",
          vul.vulnerabilityWithRemediation.description,
          remediationFromApi?.data?.technicalDescription
            ? remediationFromApi?.data?.technicalDescription
            : vul.vulnerabilityWithRemediation.description,
          filePath,
          vul.vulnerabilityWithRemediation.severity,
          "",
          -1,
          "LOW",
          projectVersion.isContainer ? SecurityAlertType.container : SecurityAlertType.sca,
          recommendation,
          `${vul.componentName}`,
          ``,
          -1,
          false,
          false,
          "",
          "",
          "",
          "",
          vul.vulnerabilityWithRemediation.cweId ? vul.vulnerabilityWithRemediation.cweId : "Generic",
          vul.componentVersion,
          "",
          repoName,
          "",
          filePath,
          "black-duck",
        );

        if (projectVersion.isContainer) {
          stats.container++;
        }

        securityEvent.version = `${projectName} - ${projectVersion.versionName}`;
        securityEvent.containerScanType = containerScanType;
        if (vul.packageUrl) {
          const i = vul.packageUrl.indexOf("/");
          const i2 = vul.packageUrl.indexOf(":");
          if (i !== -1 && i2 !== -1) {
            securityEvent.pkgManager = vul.packageUrl.substring(i2 + 1, i);
            securityEvent.language = getLanFromPkgManager(securityEvent.pkgManager)?.toLowerCase();
            securityEvent.language = capitalizeFirstLetter(securityEvent.language);
          }
        }

        securityEvent.installedVersion = vul.componentVersionName;
        securityEvent.pkgName = vul.componentName;
        if (vul.componentVersionOriginId) {
          securityEvent.pkgName = vul.componentVersionOriginId.replace(`:${vul.componentVersionName}`, "");
          securityEvent.lineContent = securityEvent.pkgName;
        }
        securityEvent.componentName = vul.componentName;

        securityEvent.fixedVersion = recommendation;

        securityEvent.realMatch = `${vul.packageUrl}`;
        if (!securityEvent.realMatch) {
          securityEvent.realMatch = vul.componentVersionOriginId;
        }
        securityEvent.blame.cve = vul.vulnerabilityWithRemediation.cweId;
        if (vul.vulnerabilityWithRemediation.relatedVulnerability) {
          const index = vul.vulnerabilityWithRemediation.relatedVulnerability.lastIndexOf("/");
          if (index != -1) {
            securityEvent.blame.cve = vul.vulnerabilityWithRemediation.relatedVulnerability.substring(
              index + 1,
              vul.vulnerabilityWithRemediation.relatedVulnerability.length,
            );
          }
        }

        if (securityEvent.blame.cve) {
          securityEvent.cves.push(securityEvent.blame.cve);
        }

        if (remediationFromApi?.data?.exploitAvailable != undefined) {
          securityEvent.blame.hasPublicExploit = remediationFromApi?.data?.exploitAvailable;
          securityEvent.blame.publishedExploitDate = remediationFromApi?.data?.publishedDate;
          addSeverityChangedReason(severityReasons.hasPublicExpolit, securityEvent, undefined);
        }
        if (remediationFromApi?.data) {
          if (remediationFromApi?.data?.cvss3) {
            securityEvent.blame.cvssScore = remediationFromApi?.data?.cvss3?.overallScore;
            securityEvent.blame.cveDescription = remediationFromApi?.data?.summary;
            securityEvent.blame.attackVector = remediationFromApi?.data?.cvss3?.attackVector;
          } else if (remediationFromApi?.data?.cvss2) {
            securityEvent.blame.cvssScore = remediationFromApi?.data?.cvss2?.overallScore;
            securityEvent.blame.cveDescription = remediationFromApi?.data?.summary;
            securityEvent.blame.attackVector = remediationFromApi?.data?.cvss2?.accessVector;
          }
        }

        if (vul.vulnerabilityWithRemediation.cweId) {
          const cweObject: CweObject = new CweObject();
          cweObject.name = vul.vulnerabilityWithRemediation.cweId;
          cweObject.shortName = vul.vulnerabilityWithRemediation.cweId;
          cweObject.description = vul.vulnerabilityWithRemediation.description;
          securityEvent.blame.cwe.push(vul.vulnerabilityWithRemediation.cweId);
          securityEvent.blame.cweList.push(cweObject);
        }

        if (projectVersion.isContainer) {
          const artifact = this.getArtifactInfoForDigitalAssetsOrg(projectVersion, repoName);
          if (vul?.componentVersionOriginName) {
            securityEvent.setIsOsTypeLib(vul.componentVersionOriginName.toLowerCase());
          }
          securityEvent.artifacts = artifact as any;
          securityEvent.securitySubTypeAlertType = SecurityAlertType.sca;

          if (projectName === repoName) {
            const pName = this.getProjectName(projectVersion.versionName);
            if (pName) {
              artifact.repoFullName = pName;
              securityEvent.repoFullName = pName;
            }
          }
        }

        secEvents.push(securityEvent);
      }
    } catch (err) {
      logger.error(
        `failed ${logName}, setSecurityEvent, err: ${err}, projectName: ${projectName}, numOfRequestBeforeFirstIssue: ${
          this.numOfRequestBeforeFirstIssue
        }, vulData: ${JSON.stringify(vul)}`,
      );
    }
  }

  async getVersionsForSingleProject(itemProject: any, projectName: string) {
    let projectId = itemProject?._meta?.href;
    let retry = 3;
    while (retry > 0) {
      retry--;

      try {
        const index = projectId.lastIndexOf("/");
        projectId = projectId.substring(index + 1, projectId.length);

        const url = this.api + `/projects/${projectId}/versions?limit=999`;
        this.numOfRequestBeforeFirstIssue++;
        const resultProjectVersion = (await axios.get(url, {
          timeout: TIME_OUTS.LONG,
          headers: {
            Authorization: "Bearer " + this.bearer,
            Accept: "application/vnd.blackducksoftware.project-detail-4+json",
          },
        })) as any;

        if (resultProjectVersion?.data?.items) {
          return resultProjectVersion?.data?.items ? resultProjectVersion?.data?.items : [];
        }
      } catch (err) {
        const errStr = JSON.stringify(err);

        if (!err.toString().includes("socket ") && !err.toString().includes("timeout of") && !errStr.includes("code 401")) {
          logger.error(
            `failed ${logName} getVersionsForSingleProject, projectName: ${projectName}, err: ${errStr}, projectId: ${projectId}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}`,
          );
          return [];
        } else {
          await sleep(1000 * 60);
        }
      }
    }
    return [];
  }

  async getProjectCustomFields(project: any, projectName: string) {
    try {
      const customFieldURL = project?._meta?.links.find(i => i.rel === "custom-fields")?.href;
      if (!customFieldURL) {
        return [];
      }

      this.numOfRequestBeforeFirstIssue++;
      const res = (await axios.get(customFieldURL, {
        timeout: TIME_OUTS.LONG,
        headers: {
          Authorization: "Bearer " + this.bearer,
          Accept: "*/*",
        },
      })) as any;

      if (res.data) {
        if (res.data.totalCount > 0) {
          return res.data.items;
        }
      }
    } catch (err) {
      logger.error(
        `failed ${logName} getProjectCustomFields, projectName: ${projectName}, numOfRequestBeforeFirstIssue: ${this.numOfRequestBeforeFirstIssue}, err: ${err}`,
      );
    }
    return [];
  }

  // Get License Detail to check License status, license Display etc.
  async getLicenseDetail(licenseUrl, retryCount = 3) {
    try {
      if (!licenseUrl) {
        return null;
      }
      const licenses = licenseUrl.split("/");
      const licenseId = licenses[licenses.length - 1];
      const url = this.api + `/licenses/${licenseId}`;
      const result = (await axios.get(url, {
        timeout: TIME_OUTS.LONG,
        headers: {
          Authorization: "Bearer " + this.bearer,
          Accept: "application/vnd.blackducksoftware.component-detail-5+json",
        },
      })) as any;

      if (result.status == 200) {
        // if (isDevelopment() || isLocalDevelopment()) {
        //   logger.info(`${logName} getLicenseDetail, data: ${JSON.stringify(result.data)}`);
        // }
        return result.data;
      }
      return null;
    } catch (err) {
      if (axios.isAxiosError(err) && err.code === "ECONNABORTED") {
        logger.error(`${logName} Request timed out: ${err.message}, licenseUrl: ${licenseUrl}`);
      } else {
        // Retry if the error is transient and retry count allows
        if (retryCount > 0) {
          logger.info(`${logName} Retrying getLicenseDetail, remaining retries: ${retryCount}`);
          return this.getLicenseDetail(licenseUrl, retryCount - 1);
        }
        logger.error(`failed ${logName} getLicenseDetail, err: ${err}, licenseUrl: ${licenseUrl}`);
      }
    }
    return null;
  }
}
