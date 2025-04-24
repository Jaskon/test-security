const util = require("util");
const exec = util.promisify(require("child_process").exec);
import { Dictionary } from "lodash";
import { setTimeout } from "node:timers/promises";
import { ContainerSecurityType } from "../../entitis/artifactoryTypes";
import { AlertSeverity, getUniqueInfoForAggregation, Repo, SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { OXtools } from "../../entitis/constant";
import { AlertRecommendationRequest, AlertRecommendationResponse } from "../../entitis/service/alertrRcommendationTypes";
import { getSharedFolder, replaceAll } from "../../helper/generalUtils";
import FileHelper from "../../helper/IO/fileHlper";
import loggerImport from "../../logger";
import { DependencyType } from "../../mongo/sbom/types";
import { escapeCharsFromPath } from "../commonUtils";
import { isK8Mode, isUploadToS3 } from "../envUtils";
import Iqueue from "../queue/Iqueue";
import { ShardFolderUtils } from "../sharedFolderUtils";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";

const onPrem = process.env.redisOnPrem != undefined;
const onSast = process.env.MONGO_CONN === "atlas";
const isk8 = isK8Mode();
const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();

class AlertRecommendationHelper {
  alertRecommendationHelperQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.alertRecommendationHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
  }

  async setAlertRecommendation(securityAlerts: SecurityEvent[], repo: Repo) {
    try {
      if (securityAlerts.length == 0) {
        return;
      }

      let alertsForRecommendation = [];
      if (StatesHelper.Instance.isContainerEnable) {
        alertsForRecommendation = securityAlerts.filter(
          i =>
            (i.securityAlertType === SecurityAlertType.sca ||
              (i.securityAlertType === SecurityAlertType.container && i.securitySubTypeAlertType === SecurityAlertType.sca) ||
              (i.securityAlertType === SecurityAlertType.container && i.securitySubTypeAlertType === SecurityAlertType.cloudRunTime)) &&
            !i.skipEnrichment,
        );
      } else {
        alertsForRecommendation = securityAlerts.filter(
          i =>
            i.securityAlertType === SecurityAlertType.sca ||
            (i.securityAlertType === SecurityAlertType.container && i.securitySubTypeAlertType === SecurityAlertType.sca && !i.isOsLib) ||
            (i.securityAlertType === SecurityAlertType.container &&
              i.securitySubTypeAlertType === SecurityAlertType.cloudRunTime &&
              !i.isOsLib &&
              !i.skipEnrichment),
        );
      }
      const alerts = this.getUniqueAlertsForRecommendation(alertsForRecommendation, repo);

      logger.info(
        `[AlertRecommendation] try generate requests for repo: ${repo.fullName}, alerts: ${securityAlerts.length}, unique alerts: ${
          Object.keys(alerts).length
        }`,
      );

      let requests: AlertRecommendationRequest[] = [];
      this.generateAlertRecommendationRequests(alerts, requests, repo);
      requests = requests.filter(i => i != undefined);

      if (requests.length > 0) {
        const scanSharedFolderPath = ShardFolderUtils.getScanSharedFolderPath(this.orgName, this.uuid);
        if (!repo.alertRecommendation) {
          const alertRecommendation = `${scanSharedFolderPath}/${replaceAll(uuid.v4(), "-", "_")}/alertRecommendation`;
          repo.alertRecommendation = alertRecommendation;
        }

        let i = 0;
        const chunks = this.splitToChunks(requests, repo);
        const proms = chunks.map(c => {
          i++;
          return this.sendAndWaitForRes(c as AlertRecommendationRequest[], repo, i);
        });
        const resProms = await Promise.all(proms);

        let input = resProms.filter(i => i != null);
        input = input.flat();

        this.updateSecurityAlertsWithAlertRecInfo(input, alertsForRecommendation, repo);
      }
      logger.info(
        `[AlertRecommendation] finish set for repo: ${repo.fullName}, security alerts: ${securityAlerts.length}, requests: ${requests.length}`,
      );
    } catch (err) {
      logger.error(`[AlertRecommendation] failed set for all security alerts for repo: ${repo.fullName}`, err);
    }
  }

  private generateAlertRecommendationRequests(alerts: Dictionary<any>, requests: AlertRecommendationRequest[], repo: Repo) {
    for (const [name, entry] of Object.entries(alerts)) {
      try {
        const entryInfo = entry as any;
        const securityAlert: SecurityEvent = entryInfo.singleAlert;

        //Dont ask again on the same sec alert for, safety check.
        if (securityAlert.askedOnceForAlertRecommendation) {
          return;
        }

        securityAlert.askedOnceForAlertRecommendation = true;
        const alertRecommendationRequest: AlertRecommendationRequest = new AlertRecommendationRequest();
        alertRecommendationRequest.uid = name;
        alertRecommendationRequest.category = securityAlert.securityAlertTypeStr;
        alertRecommendationRequest.ruleId = securityAlert.ruleId;
        alertRecommendationRequest.match = securityAlert.lineContent;
        alertRecommendationRequest.fileName = securityAlert.artifacts ? "" : securityAlert.fileName;
        alertRecommendationRequest.type =
          securityAlert.artifacts && securityAlert.securitySubTypeAlertType !== SecurityAlertType.secrets ? "artifact" : "repo";
        alertRecommendationRequest.pkgManager = securityAlert.pkgManager;
        alertRecommendationRequest.pkgName = securityAlert.pkgName;
        alertRecommendationRequest.fixedVersion = securityAlert.fixedVersion;
        alertRecommendationRequest.directCount = entryInfo.directCount;
        alertRecommendationRequest.indirectCount = entryInfo.indirectCount;
        alertRecommendationRequest.devCount = entryInfo.devCount;
        alertRecommendationRequest.installedVersion = securityAlert.installedVersion;
        alertRecommendationRequest.lockfile = securityAlert.lockfile;
        if (securityAlert.blame.triggerPackage) {
          alertRecommendationRequest.triggerPkgName = securityAlert.blame.triggerPackage.name;
          alertRecommendationRequest.triggerPkgVersion = securityAlert.blame.triggerPackage.version;
          if (Array.isArray(securityAlert.blame.triggerPackage.importName) && securityAlert.blame.triggerPackage.importName.length > 0) {
            alertRecommendationRequest.groupId = securityAlert.blame.triggerPackage.importName[0];
          }
        } else {
          alertRecommendationRequest.triggerPkgName = securityAlert.pkgName;
          alertRecommendationRequest.triggerPkgVersion = securityAlert.installedVersion;
          alertRecommendationRequest.groupId = securityAlert.groupId;
        }
        alertRecommendationRequest.toolsName.add(securityAlert.tool);

        //Docker file
        this.generateSingleDockerRequest(securityAlert, entryInfo, alertRecommendationRequest, repo);

        //Possible os only
        let shouldCountinue: boolean = this.generateSinglePossibleOsRequest(securityAlert, entryInfo, alertRecommendationRequest, repo);
        if (shouldCountinue) continue;

        //Base only
        shouldCountinue = this.generateSingleBaseOnlyRequest(securityAlert, entryInfo, alertRecommendationRequest, repo);
        if (shouldCountinue) continue;

        if (securityAlert.blame.runtime) {
          alertRecommendationRequest.languageName = securityAlert.blame?.runtime?.languageInfo?.name;
          alertRecommendationRequest.languageVersion = securityAlert.blame?.runtime?.languageInfo?.version;
        }

        if (securityAlert?.scaValidatorTypesResponse?.pkgImported !== undefined) {
          alertRecommendationRequest.pkgImported = securityAlert?.scaValidatorTypesResponse?.pkgImported ? true : false;
        } else {
          alertRecommendationRequest.pkgImported = true;
        }

        requests.push(alertRecommendationRequest);
      } catch (err) {
        logger.error(`[AlertRecommendation] failed to generate single request for repo: ${repo.fullName}`, err);
      }
    }
  }

  private generateSingleDockerRequest(
    securityAlert: SecurityEvent,
    entryInfo: any,
    alertRecommendationRequest: AlertRecommendationRequest,
    repo: Repo,
  ) {
    try {
      if (securityAlert.securitySubTypeAlertType === SecurityAlertType.dockerFileVul) {
        const severityCounts = {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          unknown: 0,
        };

        (entryInfo.allAlertsInfo as SecurityEvent[]).forEach(i => {
          if (i.originalSeverity === AlertSeverity.Critical) {
            severityCounts.critical++;
          } else if (i.originalSeverity === AlertSeverity.Appoxalypse) {
            severityCounts.critical++;
          } else if (i.originalSeverity === AlertSeverity.High) {
            severityCounts.high++;
          } else if (i.originalSeverity === AlertSeverity.Medium) {
            severityCounts.medium++;
          } else if (i.originalSeverity === AlertSeverity.Low) {
            severityCounts.low++;
          } else {
            severityCounts.unknown++;
          }
        });
        alertRecommendationRequest.severityCounts = severityCounts;
        alertRecommendationRequest.directCount = (entryInfo.allAlertsInfo as SecurityEvent[]).length;
        alertRecommendationRequest.indirectCount = 0;
      }
    } catch (err) {
      logger.error(`[AlertRecommendation] failed to generate single request in docker files for repo: ${repo.fullName}`, err);
    }
  }

  private generateSinglePossibleOsRequest(
    securityAlert: SecurityEvent,
    entryInfo: any,
    alertRecommendationRequest: AlertRecommendationRequest,
    repo: Repo,
  ) {
    try {
      if (securityAlert.containerScanType === ContainerSecurityType.possibleOsOnly && StatesHelper.Instance.isContainerEnable) {
        alertRecommendationRequest.triggerPkgName = securityAlert.artifacts.os;
        alertRecommendationRequest.triggerPkgVersion = securityAlert.artifacts.osVersion;
        if (!alertRecommendationRequest.triggerPkgName || !alertRecommendationRequest.triggerPkgVersion) {
          logger.error(
            `[AlertRecommendation] failed to generate single for possibleOsOnly request for repo: ${
              repo.fullName
            }, triggerPkgName, triggerPkgVersion are empty, securityAlert: ${JSON.stringify(securityAlert)}`,
          );
          return true;
        }

        //Set hard coded in the meantime
        alertRecommendationRequest.pkgManager = "apk";
        alertRecommendationRequest.type = "artifact_os";
        //Number for rec service
        alertRecommendationRequest.indirectCount = entryInfo.allAlertsInfo.length;
        alertRecommendationRequest.directCount = 0;
        alertRecommendationRequest.devCount = 0;

        const severityCounts = {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          unknown: 0,
        };

        let layerOneCount = 0;
        //Layer 1
        (entryInfo.allAlertsInfo as SecurityEvent[])
          .filter(i => i.LayerOrder === 1)
          .forEach(i => {
            layerOneCount++;
            alertRecommendationRequest.layer = i.LayerId;
            if (i.originalSeverity === AlertSeverity.Critical) {
              severityCounts.critical++;
            } else if (i.originalSeverity === AlertSeverity.Appoxalypse) {
              severityCounts.critical++;
            } else if (i.originalSeverity === AlertSeverity.High) {
              severityCounts.high++;
            } else if (i.originalSeverity === AlertSeverity.Medium) {
              severityCounts.medium++;
            } else if (i.originalSeverity === AlertSeverity.Low) {
              severityCounts.low++;
            } else {
              severityCounts.unknown++;
            }
          });
        alertRecommendationRequest.severityCounts = severityCounts;

        logger.info(
          `[AlertRecommendation] created single request for repo: ${repo.fullName}, artifact: ${securityAlert?.artifacts?.dockerFileInRunTime}, type: osType, triggerPkgNameVersion: ${alertRecommendationRequest.triggerPkgName}@${alertRecommendationRequest.triggerPkgVersion}, total count: ${alertRecommendationRequest.indirectCount}, layerOneCount: ${layerOneCount}`,
        );
      }
    } catch (err) {
      logger.error(`[AlertRecommendation] failed to generate single request in possibleOs for repo: ${repo.fullName}`, err);
    }
  }

  private generateSingleBaseOnlyRequest(
    securityAlert: SecurityEvent,
    entryInfo: any,
    alertRecommendationRequest: AlertRecommendationRequest,
    repo: Repo,
  ) {
    try {
      if (securityAlert.containerScanType === ContainerSecurityType.baseOnly && StatesHelper.Instance.isContainerEnable) {
        alertRecommendationRequest.triggerPkgName = securityAlert.artifacts.baseImage;
        alertRecommendationRequest.triggerPkgVersion = securityAlert.artifacts.baseImageOsVersion;
        if (!alertRecommendationRequest.triggerPkgName || !alertRecommendationRequest.triggerPkgVersion) {
          logger.error(
            `[AlertRecommendation] failed to generate single for baseOnly request for repo: ${
              repo.fullName
            }, triggerPkgName, triggerPkgVersion are empty, image name: ${
              securityAlert.artifacts.dockerFileInRunTime
            }, securityAlert: ${JSON.stringify(securityAlert)}`,
          );
          return true;
        }

        //Set hard coded in the meantime
        alertRecommendationRequest.pkgManager = "apk";
        alertRecommendationRequest.type = "artifact_base_img";
        //Number for rec service
        alertRecommendationRequest.indirectCount = entryInfo.allAlertsInfo.length;
        alertRecommendationRequest.directCount = 0;
        alertRecommendationRequest.devCount = 0;
        alertRecommendationRequest.baseDigest = securityAlert.artifacts.baseImageSha;
        alertRecommendationRequest.baseRepoName = securityAlert.artifacts.baseImage;
        alertRecommendationRequest.baseTags = securityAlert.artifacts.baseImageTags;

        alertRecommendationRequest.baseOsName = securityAlert.artifacts.os;
        alertRecommendationRequest.baseOsVersion = securityAlert.artifacts.osVersion;

        const severityCounts = {
          critical: 0,
          high: 0,
          medium: 0,
          low: 0,
          unknown: 0,
        };

        //Layer 1
        (entryInfo.allAlertsInfo as SecurityEvent[]).forEach(i => {
          if (i.originalSeverity === AlertSeverity.Critical) {
            severityCounts.critical++;
          } else if (i.originalSeverity === AlertSeverity.Appoxalypse) {
            severityCounts.critical++;
          } else if (i.originalSeverity === AlertSeverity.High) {
            severityCounts.high++;
          } else if (i.originalSeverity === AlertSeverity.Medium) {
            severityCounts.medium++;
          } else if (i.originalSeverity === AlertSeverity.Low) {
            severityCounts.low++;
          } else {
            severityCounts.unknown++;
          }
        });
        alertRecommendationRequest.severityCounts = severityCounts;

        logger.info(
          `[AlertRecommendation] created single request for repo: ${repo.fullName}, artifact: ${securityAlert?.artifacts?.dockerFileInRunTime}, type: baseType, triggerPkgNameVersion: ${alertRecommendationRequest.triggerPkgName}@${alertRecommendationRequest.triggerPkgVersion}, total count: ${alertRecommendationRequest.indirectCount}`,
        );
      }
    } catch (err) {
      logger.error(`[AlertRecommendation] failed to generate single request in possible baseOnly for repo: ${repo.fullName}`, err);
    }
  }

  private getUniqueAlertsForRecommendation(allAlerts: SecurityEvent[], repo: Repo) {
    const unique = {};
    for (const alert of allAlerts) {
      try {
        const key = this.getKey(alert);
        if (unique[key]) {
          if (alert.blame.dependencyType == DependencyType.Direct || alert.artifacts) {
            unique[key].directCount = unique[key].directCount + 1;
          } else if (alert.blame.dependencyType == DependencyType.Indirect) {
            unique[key].indirectCount = unique[key].indirectCount + 1;
          } else {
            unique[key].indirectCount = unique[key].devCount + 1;
          }
          unique[key].allAlertsInfo.push(alert);
        } else {
          if (alert.blame.dependencyType == DependencyType.Direct) {
            unique[key] = {
              singleAlert: alert,
              directCount: 1,
              indirectCount: 0,
              devCount: 0,
              allAlertsInfo: [alert],
            };
          } else if (alert.blame.dependencyType == DependencyType.Indirect) {
            unique[key] = {
              singleAlert: alert,
              directCount: 0,
              indirectCount: 1,
              devCount: 0,
              allAlertsInfo: [alert],
            };
          } else {
            unique[key] = {
              singleAlert: alert,
              directCount: 0,
              indirectCount: 0,
              devCount: 1,
              allAlertsInfo: [alert],
            };
          }
        }
      } catch (err) {
        logger.error(`[AlertRecommendation] failed set unique alert for repo: ${repo.fullName}`, err);
      }
    }
    return unique;
  }

  private getKey(alert: SecurityEvent) {
    let key = getUniqueInfoForAggregation(alert);
    return key;
  }

  private updateSecurityAlertsWithAlertRecInfo(resOfAllAlertRec: AlertRecommendationResponse[], allAlerts: SecurityEvent[], repo: Repo) {
    let attached = 0;
    let notFoundById = 0;

    try {
      logger.info(`[AlertRecommendation] number of results before digest for repo: ${repo.fullName} count: ${resOfAllAlertRec.length}`);

      for (const resAlertRecommendation of resOfAllAlertRec) {
        try {
          let key = resAlertRecommendation.uid;
          const secEvents: SecurityEvent[] = allAlerts.filter(alert => this.getKey(alert) === key) as any;

          if (secEvents.length == 0) {
            logger.error(`[AlertRecommendation] fail to find security alert for key: ${key}, repo: ${repo.fullName}`);
            notFoundById++;
            continue;
          }

          attached += secEvents.length;
          secEvents.forEach(secEvent => {
            secEvent.alertRecommendationResponse = resAlertRecommendation;
            secEvent.alertRecommendationResponse.success = true;
            secEvent.recommendation = resAlertRecommendation.recommendation;
          });
        } catch (err) {
          logger.error(`[AlertRecommendation] fail single alert uid: ${resAlertRecommendation.uid}, repo: ${repo.fullName}`, err);
        }
      }
    } catch (err) {
      logger.error(`[AlertRecommendation] fail alerts for repo: ${repo.fullName}`, err);
    }
    logger.info(
      `[AlertRecommendation] finish alerts for repo: ${repo.fullName}, attached: ${attached}, notFoundById: ${notFoundById}, total response: ${resOfAllAlertRec.length} for single chunk`,
    );
  }

  private async sendAndWaitForRes(requests: AlertRecommendationRequest[], repo: Repo, index: number) {
    let data;
    const requestId = uuid.v4();

    try {
      if (requests.length == 0) {
        return null;
      }

      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;
      let repoForUpload = repo.name;
      if (!repo.realRepo) {
        repoForUpload = `${repo.fullName}_${uuid.v4()}`;
      }
      logger.info(`[AlertRecommendation] sending request for repo: ${repo.fullName}, count: ${requests.length}`);

      let url = onSast ? process.env.RECOMMENDATION_SERVICE_SQS_URL : process.env.RECOMMENDATION_SERVICE_QUEUE_KEY;
      if (isk8) {
        url = process.env.RECOMMENDATION_SERVICE_QUEUE_KEY;
      }

      const dirToPutRes = `${repo.alertRecommendation}/${requestId}`;
      fs.mkdirSync(dirToPutRes, { recursive: true });

      const filePathRequest = `${dirToPutRes}/recommendationRequest.json`;
      fs.writeFileSync(filePathRequest, JSON.stringify(requests));

      const filePathRes = `${dirToPutRes}/recommendation.json`;

      //If this is onPrem the zip folder is the actual code folder without a zip
      //If we are on SAST then we need the parent folder in case its mono repo and if not the regular repo
      let cloneDir = "";
      let toolCopyDestination = "";
      let monoRepoChildSubfolder = "";
      if (repo.realRepo) {
        cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;

        toolCopyDestination = repo.getRepoForToolsBasedOnEnv();
        if (!onPrem || isk8) {
          toolCopyDestination = `${toolCopyDestination}/${index.toString()}`;
        }

        monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;
      }

      let command = this.getCommand(filePathRequest, dirToPutRes, toolCopyDestination);
      command = escapeCharsFromPath(command);

      const msg = {
        MessageId: requestId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "alert-recommendation-service",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 900000,
        orgDisplayName: process.env["companyName"],
        cloneDir: cloneDir,
        toolCopyDestination: toolCopyDestination,
        isMonoRepoChild: repo.monoRepoChild,
        monoRepoChildSubfolder: monoRepoChildSubfolder,
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: repo.ignoredMonoRepoChildrenSubfolders,
        putInQueueTime: new Date().getTime(),
        shouldSkipLocalCopy: true,
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(
        `[AlertRecommendation] about to send msg to queue for repo: ${repo.fullName}, num of requests: ${
          requests.length
        }, msg: ${JSON.stringify(msg)}`,
      );

      //From Debug(shell)
      if (process.env.DEBUG != undefined && !process.env.DOCKER_DEBUG) {
        const reqRes = await this.runShell(repo.name, msg.localCommand);
        const data = fs.readFileSync(filePathRes, "utf8");
        const alertRecomendationfixRes = JSON.parse(data);
        return alertRecomendationfixRes;
      }

      //From SAST(sqs)
      const reqRes = await this.alertRecommendationHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        this.setFailedEnrichmentTools(repo, requests);
        ToolsExecutionStats.addExecutionStateOnFail(
          requestId,
          OXtools.recommendation,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          -1,
          ToolError.SendToQueue,
        );
        return null;
      }

      logger.info(
        `[AlertRecommendation] about to start waiting for repo: ${repo.fullName}, repoForUpload: ${repoForUpload}, num of requests: ${
          requests.length
        }, msg: ${JSON.stringify(msg)}`,
      );

      this.copyToolResults({ repoName: repoForUpload, dir: filePathRequest });

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromAlertRec = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 15; // 60 seconds * 15 = 15 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.recommendation,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );

          StatesHelper.Instance.scanInfoStats.failedAlertRecommendationTimeout++;
          StatesHelper.Instance.scanInfoStats.failedAlertRecommendationTimeoutRepoNames.push(repo.name);
          this.setFailedEnrichmentTools(repo, requests);
          return null;
        }

        //Failed from recommendation
        if (fs.existsSync(failedFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.recommendation,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.ResFileNotFound,
          );

          this.setFailedEnrichmentTools(repo, requests);
          StatesHelper.Instance.scanInfoStats.failedAlertRecommendationBatches++;
          StatesHelper.Instance.scanInfoStats.failedAlertRecommendationRepoNames.push(repo.name);
          return null;
        }

        //Done from recommendation
        if (fs.existsSync(doneFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `[AlertRecommendation] done file discovered from repo: ${repo.fullName}, num of requests: ${requests.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromAlertRec = true;
          break;
        }

        //10 seconds
        await setTimeout(10 * 1000);
        counter--;
      }

      if (!fs.existsSync(filePathRes)) {
        let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

        ToolsExecutionStats.addExecutionStateOnFail(
          requestId,
          OXtools.recommendation,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );

        this.setFailedEnrichmentTools(repo, requests);
        StatesHelper.Instance.scanInfoStats.failedAlertRecommendationBatches++;
        StatesHelper.Instance.scanInfoStats.failedAlertRecommendationRepoNames.push(repo.name);
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      data = fs.readFileSync(filePathRes, "utf8");
      const alertRecommendationFixRes = JSON.parse(data);

      //Delete after reading
      this.copyToolResults({ repoName: repoForUpload, dir: filePathRes });
      this.fileHelper.deleteFile(filePathRes);
      this.fileHelper.deleteFile(filePathRequest);

      const failed = new Set<string>();
      ToolsExecutionStats.addToExecutionStatsFromFile(
        doneFilePath,
        requestId,
        OXtools.recommendation,
        repo.fullName,
        repo.id,
        "repo",
        repo.cloneDir,
        failed,
      );
      if (failed.size > 0) {
        this.setFailedEnrichmentTools(repo, requests);
        return null;
      }
      logger.info(
        `[AlertRecommendation] finish waiting for repo: ${repo.fullName}, num of requests: ${requests.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, recommendation res number: ${alertRecommendationFixRes.length}, counter: ${counter}`,
      );

      return alertRecommendationFixRes;
    } catch (err) {
      ToolsExecutionStats.addExecutionStateOnFail(
        requestId,
        OXtools.recommendation,
        repo.fullName,
        repo.id,
        "repo",
        "",
        -1,
        ToolError.Generic,
      );

      this.setFailedEnrichmentTools(repo, requests);
      StatesHelper.Instance.scanInfoStats.failedAlertRecommendationBatches++;
      StatesHelper.Instance.scanInfoStats.failedAlertRecommendationRepoNames.push(repo.name);

      logger.error(`[AlertRecommendation] failed to send batch of security alerts for repo: ${repo.fullName}, data: ${data}`, err);
    }

    return null;
  }

  private setFailedEnrichmentTools(repo: Repo, requests: AlertRecommendationRequest[]) {
    requests.forEach(r => {
      r.toolsName.forEach(toolName => {
        repo.addFailedSecurityTools(toolName);
      });
    });
  }

  splitToChunks(array, repo: Repo) {
    const chunkSize = process.env.DEBUG && !process.env.DOCKER_DEBUG ? 20000 : 50;
    const chunks: any[] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      const c = array.slice(i, i + chunkSize);
      chunks.push(c);
    }

    return chunks;
  }

  async runShell(requesterName: string, command: string) {
    try {
      await this.shell(requesterName, command);
      return true;
    } catch (err) {
      logger.error(`[AlertRecommendation] failed run shell command: ${command} to run`, err);
    }
    return false;
  }

  async shell(requesterName, command: string) {
    try {
      logger.info(`[AlertRecommendation] try run from shell, repo: ${requesterName}: cmd: ${command}`);

      const { stdout, stderr } = await exec(command, {
        maxBuffer: 1024 * 1024 * 10,
        env: { ...process.env, FOO: "ah" },
      });
      logger.debug(`stdout:, ${JSON.stringify(stdout, null, 4)}`);
      logger.debug(`stderr:, ${JSON.stringify(stderr, null, 4)}`);
    } catch (err) {
      logger.error(
        `[AlertRecommendation] shell command: ${command} failed to run error: ${err} stdout: ${err.stdout + "\n"} stderr: ${
          err.stderr + "\n"
        }`,
        err,
      );

      logger.info(`[AlertRecommendation] finish run from shell, requester name: ${requesterName} cmd: ${command}`);
    }
  }

  copyToolResults({ repoName, dir }: { repoName: string; dir: string }): void {
    if (isUploadToS3()) {
      const oxDir = getSharedFolder(this.uuid) + "/ox-security";
      const telemetryDir = oxDir + "/telemetry-" + this.uuid;
      const repoDir = telemetryDir + "/security-report/" + repoName;
      const toolDir = repoDir + "/alertRecommendation";

      try {
        if (!fs.existsSync(toolDir)) {
          fs.mkdirSync(toolDir, { recursive: true });
        }

        this.fileHelper.copyFileSync(dir, toolDir);
      } catch (err) {
        logger.error(`[AlertRecommendation] failed to copy tool result file for repo name ${repoName}`, err);
      }
    }
  }

  getCommand(requestPath: string, outputDir: string, repoDir: string) {
    if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
      return `python ${process.env.RECOMMENDATION_PATH} --events-path ${requestPath} --output-dir ${outputDir}`;
    }
    return `python /src/recommendation_cli.py --events-path ${requestPath} --output-dir ${outputDir}`;
  }
}

export default AlertRecommendationHelper;
