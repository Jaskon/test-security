const util = require("util");
const uuidGenerator = require("uuid");
const exec = util.promisify(require("child_process").exec);
import { setTimeout } from "node:timers/promises";
import { Application } from "../../appmgr/application";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { Sbom, SbomComponent, SbomComponentType, SbomEvent } from "../../entitis/artifactoryTypes";
import { CloudSecurityEvent } from "../../entitis/cloudTypes";
import {
  addSeverityChangedReason,
  CweObject,
  Dependency,
  getBlameDir,
  Repo,
  repoType,
  SecurityAlertType,
  SecurityEvent,
  setSecEventFromDelta,
  setSeverity,
  VCSType,
} from "../../entitis/codeRepoTypes";
import { OXtools } from "../../entitis/constant";
import { BlameRequest, BlameResponse, ChangeReason, severityReasons } from "../../entitis/service/blameTypes";
import { getSharedFolder } from "../../helper/generalUtils";
import FileHelper from "../../helper/IO/fileHlper";
import loggerImport from "../../logger";
import { escapeCharsFromPath } from "../commonUtils";
import { ZipType } from "../compression/unzipHelper";
import { isK8Mode, isLocalDevelopment, isUploadToS3 } from "../envUtils";
import GraphHelper from "../graphHelper";
import { PipeLineHelper } from "../pipelineHelper";
import Iqueue from "../queue/Iqueue";
import { ExtendedSbomComponent } from "../sbom/sbomHelper";
import StatesHelper, { PerformanceType } from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";
const crypto = require("crypto");

const privateIpAddressRegex = /(10\.\d{1,3}\.|192\.168\.)\d{1,3}\.\d{1,3}|172\.(1[6-9]|2[0-9]|3[0-1])(\.\d{1,3}){2}/;
const productionRegex = /(^|[a-z\W\s_\.])([Pp]ro?d|[Pp]roduction|PRO?D|PRODUCTION)([A-Z\W\s_]|$)/;
const nonProductionRegex = /(^|[\W\s_])(qa|development|dev|stg|staging|stage|tests?|test(ing|er)|stub|mock)([\W\s_]|$)/i;
const onPrem = process.env.redisOnPrem != undefined;
const onSast = process.env.MONGO_CONN === "atlas";
const isk8 = isK8Mode();
const uuid = require("uuid");
const fs = require("fs");
const pathInfo = require("path");

const logger = loggerImport.getDebugLogger();

class BlameHelper {
  blameQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.blameQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
  }

  runDuringPipeline(repo: Repo) {
    if (
      StatesHelper.Instance.isPipelineScan &&
      StatesHelper.Instance.canRunFastestPipelineScan &&
      PipeLineHelper.Instance.performance === PerformanceType.fastest
    ) {
      logger.info(`skipping blame check during fastest mode on pipeline scan over repo - ${repo.fullName}`);
      return false;
    }

    return true;
  }

  async extendBlameSBOMForSingleApp(libs: ExtendedSbomComponent[], sbomInfo: SbomEvent, app: Application, resourceName: string) {
    const repoTempCast: any = app.appInfo.repo == null ? null : (app.appInfo.repo as any);
    if (repoTempCast == null) {
      return;
    }

    const repo: Repo = repoTempCast.code_repo as Repo;

    if (!this.runDuringPipeline(repo)) {
      return;
    }

    if (repo.vcsType === VCSType.tfvc) return;

    logger.info(`try handle sbom blame info for resource name: ${resourceName}, events: ${libs.length}`);

    const requests: BlameRequest[] = this.getBlameRequestFromSbom(libs, sbomInfo, repo, resourceName);

    if (requests.length > 0) {
      let i = 0;
      const chunks = this.splitToChunks(requests, resourceName, "sbom", StatesHelper.Instance.isPipelineScan);
      const proms = chunks.map(c => {
        i++;
        return this.sendAndWaitForRes(c as BlameRequest[], repo, "sbom", i, resourceName);
      });
      const resProms = await Promise.all(proms);

      let input = resProms.filter(i => i != null);
      input = input.flat();

      const startTime = Date.now();
      const graphHelper = new GraphHelper();
      await graphHelper.setGraphBasedOnSboms(libs, input, resourceName);
      logger.info(`Add dependency graph to every lib in resource name: ${resourceName} (${Date.now() - startTime}ms)`);

      this.updateSecurityResultWithBlameServiceResults(
        input,
        libs.map(i => i.blame),
        repo,
        "sbom",
        resourceName,
      );
    }

    const additionalLibsBasedOnTriggerPkgs: ExtendedSbomComponent[] = [];
    // this.overwriteSbomEvents(libs, additionalLibsBasedOnTriggerPkgs, resourceName);

    // if (additionalLibsBasedOnTriggerPkgs.length > 0) {
    //   additionalLibsBasedOnTriggerPkgs.forEach(i => {
    //     libs.push(i);
    //   });
    // }

    logger.info(
      `finish handle sbom blame info for repo: ${resourceName}, additional libs based on trigger pkg: ${additionalLibsBasedOnTriggerPkgs.length}, events: ${libs.length}`,
    );
  }

  async extendBlameSecurityEventsForSingleApp(securityAlerts: SecurityEvent[], repo: Repo, requesterType: string, resourceName: string) {
    try {
      if (!this.runDuringPipeline(repo)) {
        return;
      }

      const requests: BlameRequest[] = this.getReqForSecEvents(securityAlerts, resourceName);

      if (requests.length > 0) {
        const stats = {
          reposThatOvertimeTitle: new Set(),
        };

        logger.info(`try set blame for request type: ${requesterType}, repo: ${resourceName} alerts: ${securityAlerts.length}`);

        if (process.env.BLAME_LOG_REQUEST) {
          logger.info(`Blame request: ${JSON.stringify(requests)}`);
        }

        let i = 0;
        const chunks = this.splitToChunks(requests, resourceName, "blame", StatesHelper.Instance.isPipelineScan);
        const proms = chunks.map(c => {
          i++;
          return this.sendAndWaitForRes(c as BlameRequest[], repo, "blame", i, resourceName);
        });
        const resProms = await Promise.all(proms);

        let input = resProms.filter(i => i != null);
        input = input.flat();
        // TODO: Refactor
        input.forEach(i => delete i?.triggerPackage?.dependencyGraph);

        this.updateSecurityResultWithBlameServiceResults(
          input,
          securityAlerts.map(i => i.blame),
          repo,
          requesterType,
          resourceName,
        );

        const additionalSecurityEventsBasedOnTriggerPkgs: SecurityEvent[] = [];
        securityAlerts.forEach(i => this.overwriteSecEvents(i, repo, stats, resourceName, additionalSecurityEventsBasedOnTriggerPkgs));

        if (additionalSecurityEventsBasedOnTriggerPkgs.length > 0) {
          additionalSecurityEventsBasedOnTriggerPkgs.forEach(i => {
            securityAlerts.push(i);
          });
        }

        securityAlerts.forEach((securityAlert: SecurityEvent) => {
          const hasSaas = securityAlert.severityChangedReason.find(
            (cr: ChangeReason) => cr.shortName === severityReasons.saasSecret.shortName,
          );
          if (securityAlert.blame.severityChangedReason) {
            securityAlert.blame.severityChangedReason.forEach(i => {
              if (!hasSaas || i.shortName !== severityReasons.onPremSecret.shortName) {
                addSeverityChangedReason(i, securityAlert, repo, i.extraInfo);
              }
            });
          }
        });

        logger.info(
          `finish set blame for repo: ${resourceName}, alerts: ${securityAlerts.length}, stats: reposThatOvertimeTitle --> length: ${
            stats.reposThatOvertimeTitle.size
          }, added from trigger pkg: ${additionalSecurityEventsBasedOnTriggerPkgs.length}, data ${Array.from(
            stats.reposThatOvertimeTitle,
          ).join(", ")}, beforeSplice`,
        );
      }
    } catch (err) {
      logger.error(`failed extend all security alerts for repo: ${resourceName}, err: ${err}`);
    }
  }

  overwriteSbomEvents(libs: ExtendedSbomComponent[], additionalLibsBasedOnTriggerPkgs: ExtendedSbomComponent[], resourceName: string) {
    try {
      let index = 0;

      libs.forEach(lib => {
        try {
          const shouldRun = lib?.blame?.triggerPackagesList?.length > 1;
          if (!shouldRun) {
            return;
          }

          lib.blame.triggerPackagesList.forEach(i => {
            try {
              //Overwrite exist
              if (i.name !== lib.blame.triggerPackage.name) {
                const securityAlertObj: ExtendedSbomComponent = JSON.parse(JSON.stringify(lib));
                securityAlertObj.blame.triggerPackage = i;
                const t = securityAlertObj.blame.dependencyChainList[index];
                if (!t) {
                  logger.error(`not have dependencyChainList for ${resourceName}`);
                  return;
                }
                securityAlertObj.blame.dependencyChain = t;
                if (i?.match) {
                  if (i.startLineNumber >= 0) {
                    securityAlertObj.blame.startLineNumber = i.startLineNumber;
                  }
                  if (i.snippetLineNumber >= 0) {
                    securityAlertObj.blame.snippetLineNumber = i.snippetLineNumber;
                  }
                }
                if (i?.commit_info) {
                  securityAlertObj.blame.commitSha = i.commit_info.commit_id;
                  securityAlertObj.blame.commitDate = i.commit_info.author_date;
                  securityAlertObj.blame.commiterName = i.commit_info.author_name;
                  securityAlertObj.blame.commiterEmail = i.commit_info.author_email;
                  securityAlertObj.blame.commitDescription = i.commit_info.message;
                }

                additionalLibsBasedOnTriggerPkgs.push(securityAlertObj);
              }
              index++;
            } catch (err) {
              logger.error(
                `failed to extend single sbom for trigger pkg list in repo: ${resourceName}, lib: ${lib.name}, for sec events, err: ${err}`,
              );
            }
          });
        } catch (err) {
          logger.error(`failed to extend single sbom for trigger pkg list in repo: ${resourceName}, for all libs, err: ${err}`);
        }
      });
    } catch (err) {
      logger.error(`failed to extend single sbom for trigger pkg list in repo: ${resourceName}, for all libs in total, err: ${err}`);
    }
  }

  overwriteSecEvents(
    securityEvent: SecurityEvent,
    repo: Repo,
    stats: any,
    requesterName: string,
    additionalSecurityEventsBasedOnTriggerPkgs: SecurityEvent[],
  ) {
    //Debug
    // logger.info(
    //   `try set blame for sec event: ${securityAlert?.pkgName} ${securityAlert.installedVersion}, ${securityAlert.severity}, ${securityAlert.severityStr}, ${securityAlert.originalSeverityStr}, ${securityAlert.severityChangeNumber}`,
    // );

    try {
      if (securityEvent.securityAlertType === SecurityAlertType.secrets) {
        if (!securityEvent.realMatch) {
          if (securityEvent.blame.lineContent) {
            securityEvent.realMatch = crypto.createHash("md5").update(securityEvent.blame.lineContent).digest("hex");
          } else {
            logger.error(`failed to set realMatch for sec event: ${securityEvent.ruleId}`);
            return;
          }
        }
        if (securityEvent.blame?.fromCommitHistory) {
          securityEvent.fromCommitHistory = securityEvent.blame.fromCommitHistory;
        }

        if (securityEvent.fromCommitHistory) {
          if (securityEvent.isPII) {
            addSeverityChangedReason(severityReasons.piiInCodeHistory, securityEvent, repo);
          } else {
            addSeverityChangedReason(severityReasons.secretInCodeHistory, securityEvent, repo);
          }
        } else {
          if (securityEvent.isPII) {
            addSeverityChangedReason(severityReasons.piiInCode, securityEvent, repo);
          } else {
            addSeverityChangedReason(severityReasons.secretInCode, securityEvent, repo);
          }
        }
      }

      if (securityEvent?.blame?.snippetContent) {
        securityEvent.blame.severityChangedReason.forEach((changeReason: ChangeReason) => {
          if (
            changeReason.shortName === severityReasons.prodSecret.shortName ||
            changeReason.shortName === severityReasons.nonProdSecret.shortName
          ) {
            try {
              let reducted = "";
              let prodIndex = -1;
              let lineBreaksBeforeStart = 0;
              if (changeReason.shortName === severityReasons.prodSecret.shortName) {
                prodIndex = securityEvent.blame.snippetContent.search(productionRegex);
              } else {
                prodIndex = securityEvent.blame.snippetContent.search(nonProductionRegex);
              }
              if (prodIndex >= 0) {
                // const startIndex = Math.max(prodIndex - 5, 0);
                let startIndex = prodIndex;
                const endIndex = Math.min(prodIndex + 15, securityEvent.blame.snippetContent.length - 1);
                lineBreaksBeforeStart = Math.max(securityEvent.blame.snippetContent.substring(0, startIndex).split("\n").length - 1, 0);
                const lines = securityEvent.blame.snippetContent.split("\n");
                const line = lines[lineBreaksBeforeStart];
                const totalStringLength = lines.slice(0, lineBreaksBeforeStart).reduce((total, str) => {
                  if (typeof str === "string") {
                    return total + str.length + 1;
                  } else {
                    return total;
                  }
                }, 0);

                startIndex = Math.max(startIndex - 5, totalStringLength, 0);
                const prodStr = securityEvent.blame.snippetContent.substring(startIndex, endIndex);
                const starPrefixLength = Math.max(Math.min(startIndex - totalStringLength, 25), 0);
                const starSuffixLength = Math.max(Math.min(line.length - starPrefixLength - prodStr.length, 25), 0);
                reducted = "*".repeat(starPrefixLength) + prodStr + "*".repeat(starSuffixLength);
              }
              if (reducted) {
                const lineNumber = securityEvent.blame.snippetLineNumber + lineBreaksBeforeStart;
                changeReason.extraInfo.push({
                  key: "Snippet",
                  link: securityEvent.link.replace(/\d+$/, lineNumber.toString()),
                  snippet: {
                    fileName: securityEvent.blame.fileName,
                    text: reducted,
                    language: securityEvent.blame.language,
                    snippetLineNumber: lineNumber,
                  },
                });
              }
            } catch (err) {
              logger.error(`failed snippetContent search, err: ${err}, stack: ${err.stack}`);
            }
          }
        });
      }
      if (repo.severityChangedReason) {
        repo.severityChangedReason.forEach((changeReason: ChangeReason) => {
          if (changeReason.extraInfo.length >= changeReason.requiredHits && changeReason.shouldBeSeverityFactor) {
            // demend at least two hits per tag
            addSeverityChangedReason(changeReason, securityEvent, repo, changeReason.extraInfo);
          }
        });
      }
      if (securityEvent.securityAlertType === SecurityAlertType.iac || securityEvent.securityAlertType === SecurityAlertType.sast) {
        securityEvent.blame.cweList.forEach((cwe: CweObject) => {
          if (cwe?.shortName === "CWE-94" || cwe?.shortName === "CWE-502") {
            addSeverityChangedReason(severityReasons.potentialRCE, securityEvent, repo);
            addSeverityChangedReason(severityReasons.lateralMovement, securityEvent, repo);
          } else if (cwe?.shortName === "CWE-89") {
            addSeverityChangedReason(severityReasons.sqlInjection, securityEvent, repo);
          } else if (cwe?.shortName === "CWE-400") {
            addSeverityChangedReason(severityReasons.dos, securityEvent, repo);
          } else if (
            cwe?.shortName === "CWE-295" ||
            cwe?.shortName === "CWE-310" ||
            cwe?.shortName === "CWE-326" ||
            cwe?.shortName === "CWE-327" ||
            cwe?.shortName === "CWE-328" ||
            cwe?.shortName === "CWE-329" ||
            cwe?.shortName === "CWE-330" ||
            cwe?.shortName === "CWE-331" ||
            cwe?.shortName === "CWE-332" ||
            cwe?.shortName === "CWE-333" ||
            cwe?.shortName === "CWE-334" ||
            cwe?.shortName === "CWE-335" ||
            cwe?.shortName === "CWE-336" ||
            cwe?.shortName === "CWE-337" ||
            cwe?.shortName === "CWE-338" ||
            cwe?.shortName === "CWE-339" ||
            cwe?.shortName === "CWE-340"
          ) {
            addSeverityChangedReason(severityReasons.weakCryptography, securityEvent, repo);
          } else if (cwe?.shortName === "CWE-284") {
            addSeverityChangedReason(severityReasons.improperAccessControl, securityEvent, repo);
          } else if (cwe?.shortName === "CWE-250" || cwe?.shortName === "CWE-269" || cwe?.shortName === "CWE-732") {
            addSeverityChangedReason(severityReasons.overPrivilegedAccess, securityEvent, repo);
          } else if (cwe?.shortName === "CWE-778" || cwe?.shortName === "CWE-1210") {
            addSeverityChangedReason(severityReasons.insufficientLogging, securityEvent, repo);
          } else if (cwe?.shortName === "CWE-312" || cwe?.shortName === "CWE-922") {
            addSeverityChangedReason(severityReasons.dataAtRest, securityEvent, repo);
          } else if (cwe?.shortName === "CWE-319") {
            addSeverityChangedReason(severityReasons.dataInTransit, securityEvent, repo);
          } else if (cwe?.shortName === "CWE-79" || cwe?.shortName === "CWE-80") {
            addSeverityChangedReason(severityReasons.crossSiteScripting, securityEvent, repo);
          } else if (cwe?.shortName === "CWE-693") {
            addSeverityChangedReason(severityReasons.lackOfSecurityContorl, securityEvent, repo);
          }
        });
      }
      if (securityEvent.blame.registry) securityEvent.registry = securityEvent.blame.registry;
      if (securityEvent.blame.pkgManager) securityEvent.betterPkgManager = securityEvent.blame.pkgManager;
      if (securityEvent.blame.language) securityEvent.language = securityEvent.blame.language;
      if (securityEvent.blame.link) securityEvent.link = securityEvent.blame.link;
      if (securityEvent.blame.lineContent) securityEvent.lineContent = securityEvent.blame.lineContent;
      if (securityEvent.blame.snippetContent && securityEvent.securityAlertType !== SecurityAlertType.iac)
        securityEvent.snippetContent = securityEvent.blame.snippetContent;
      if (
        securityEvent.blame.recommendation &&
        (securityEvent.securityAlertType === SecurityAlertType.iac || securityEvent.securityAlertType === SecurityAlertType.sast)
      ) {
        securityEvent.recommendation = securityEvent.blame.recommendation;
      }
      if (securityEvent.blame.fixes && securityEvent.fixes.length === 0) securityEvent.fixes = securityEvent.blame.fixes;
      if (securityEvent.blame.title) {
        securityEvent.title = securityEvent.blame.title;
        stats.reposThatOvertimeTitle.add(requesterName);
      }
      if (securityEvent.blame.fixedVersion) {
        securityEvent.fixedVersion = securityEvent.blame.fixedVersion;
      }

      if (securityEvent.blame.fileName && securityEvent.fileName) {
        securityEvent.filePath = securityEvent.blame.fileName; //securityEvent.filePath.replace(fileNameOnly, securityEvent.blame.fileName);
        securityEvent.fileName = securityEvent.blame.fileName;
      }

      if (securityEvent.blame.startLineNumber >= 0) {
        if (securityEvent.blame.startLineNumber && securityEvent.link) {
          if (
            securityEvent.fileName.endsWith(".rst") ||
            securityEvent.fileName.endsWith(".md") ||
            securityEvent.fileName.endsWith(".ipynb")
          ) {
            securityEvent.link = securityEvent.link.replace(securityEvent.fileName, securityEvent.fileName + "?plain=1");
          }
          securityEvent.link = securityEvent.link.replace(/(#L|#lines-|&lines=)\d*$/, `$1${securityEvent.blame.startLineNumber}`);
          //handle case for AWSCodeCommit
          if (securityEvent.link.includes(`&lines=`)) {
            securityEvent.link = securityEvent.link + `-` + `${securityEvent.blame.startLineNumber}`;
          }
        }
      }

      //Overwrite severity
      if (securityEvent.blame.severityStr) {
        if (securityEvent.severityStr !== securityEvent.blame.severityStr) {
          setSeverity(securityEvent.blame.severityStr, securityEvent);
        }
      }

      if (securityEvent.blame.startLineNumber >= 0) {
        securityEvent.startLineNumber = securityEvent.blame.startLineNumber;
      }

      //
      if (!securityEvent.installedVersion) {
        securityEvent.installedVersion = securityEvent.blame.installedVersion;
      }

      //Debug
      // logger.info(
      //   `finish set blame for sec event: ${securityAlert?.pkgName} ${securityAlert.installedVersion}, ${securityAlert.severity}, ${securityAlert.severityStr}, ${
      //     securityAlert.originalSeverityStr
      //   }, ${securityAlert.severityChangeNumber}, ${JSON.stringify(securityAlert.blame.severityChangedReason)}`,
      // );
    } catch (err) {
      logger.error(`failed to overwrite in repo: ${requesterName}, for sec events, err: ${err}`);
    }

    try {
      let index = 0;
      if (securityEvent?.blame?.triggerPackagesList && securityEvent.oxTool) {
        const securityAlertCopy = JSON.parse(JSON.stringify(securityEvent));
        securityEvent.blame.triggerPackagesList.forEach(i => {
          try {
            //Overwrite exist
            let securityAlertObj: SecurityEvent = securityEvent;
            let differentTrigger: boolean = i.name !== securityEvent.blame.triggerPackage.name;
            if (differentTrigger) {
              securityAlertObj = JSON.parse(JSON.stringify(securityAlertCopy));
              securityAlertObj.blame.triggerPackage = i;
              securityAlertObj.blame.dependencyChain = securityEvent.blame.dependencyChainList[index];
              securityAlertObj.uid = uuidGenerator.v4();
              securityAlertObj.blame.dependencyType = i.dependencyType;

              if (i?.match) {
                securityAlertObj.lineContent = i.match;
                securityAlertObj.snippetContent = i.snippet;
                securityAlertObj.blame.lineContent = i.match;
                securityAlertObj.blame.snippetContent = i.snippet;
                if (i.startLineNumber >= 0) {
                  securityAlertObj.startLineNumber = i.startLineNumber;
                  securityAlertObj.blame.startLineNumber = i.startLineNumber;
                  securityAlertObj.link = securityEvent.link.replace(/\d*$/, `${securityAlertObj.blame.startLineNumber}`);
                }
                if (i.snippetLineNumber >= 0) {
                  securityAlertObj.blame.snippetLineNumber = i.snippetLineNumber;
                }
              }
              if (i?.commit_info) {
                securityAlertObj.blame.commitSha = i.commit_info.commit_id;
                securityAlertObj.blame.commitDate = i.commit_info.author_date;
                securityAlertObj.blame.commiterName = i.commit_info.author_name;
                securityAlertObj.blame.commiterEmail = i.commit_info.author_email;
                securityAlertObj.blame.commitDescription = i.commit_info.message;
              }

              setSecEventFromDelta(repo, securityAlertObj);
              additionalSecurityEventsBasedOnTriggerPkgs.push(securityAlertObj);
            }

            const ignoreDep =
              securityAlertObj.blame.securityAlertType === SecurityAlertType.container ||
              securityAlertObj.blame.securityAlertSubType === SecurityAlertType.dockerFileVul;
            if (securityAlertObj.blame.dependencyType && !ignoreDep) {
              if (securityAlertObj.blame.dependencyType === "direct") {
                securityAlertObj.blame.checkedForDirectIndirect = true;
                securityAlertObj.blame.severityChangedReason.push(severityReasons.directDependency);
              } else if (securityAlertObj.blame.dependencyType === "dev") {
                securityAlertObj.blame.checkedForDirectIndirect = true;
                securityAlertObj.blame.severityChangedReason.push(severityReasons.devDependency);
              } else if (securityAlertObj.blame.dependencyType === "indirect") {
                if (!securityAlertObj.blame.dependencyChain || securityAlertObj.blame.dependencyChain.length < 3) {
                  securityAlertObj.blame.checkedForDirectIndirect = true;
                  securityAlertObj.blame.severityChangedReason.push(severityReasons.firstLevelIndirectDependency);
                } else if (securityAlertObj.blame.dependencyChain) {
                  securityAlertObj.blame.checkedForDirectIndirect = true;
                  securityAlertObj.blame.severityChangedReason.push(severityReasons.deepLevelIndirectDependency);
                } else {
                  securityAlertObj.blame.severityChangedReason.push(severityReasons.firstLevelIndirectDependency);
                }
              }
            }

            index++;
          } catch (err) {
            logger.error(
              `failed to extend single alerts for trigger pkg list in repo: ${requesterName}, for sec events, err: ${err}, stack: ${err.stack}`,
            );
          }
        });
      }
    } catch (err) {
      logger.error(`failed to extend alerts for trigger pkg list in repo: ${requesterName}, for sec events, err: ${err}`);
    }
  }

  private setFailedEnrichmentTools(repo: Repo, requests: BlameRequest[]) {
    requests.forEach(r => {
      repo.addFailedSecurityTools(r.toolName);
    });
  }

  private updateSecurityResultWithBlameServiceResults(
    resOfAllBlameResults: any,
    blameDataToFillIn: BlameResponse[],
    repo: Repo,
    type: string,
    resourceName: string,
  ) {
    let attached = 0;
    let commitInfoNotFoundByBlameService = 0;
    let notFoundById = 0;
    try {
      logger.info(
        `number of blame results before digest for resource name: ${resourceName} count: ${resOfAllBlameResults.length}, type: ${type}`,
      );

      if (process.env.LOG_BLAME_RESPONSE) {
        logger.info(
          `Blame resource name: ${resourceName}, Data: ${JSON.stringify(resOfAllBlameResults)}, and blame data: ${JSON.stringify(
            blameDataToFillIn,
          )}`,
        );
      }

      for (const blameInfo of resOfAllBlameResults) {
        try {
          const singleBlameResponse = blameDataToFillIn.find(i => i.uid === blameInfo.uid);
          if (singleBlameResponse == undefined) {
            logger.error(`fail to find securityAlert for blameInfo uid: ${blameInfo.uid}, resource name: ${resourceName}`);
            notFoundById++;
            continue;
          }

          //Debug
          //logger.info(`lib blame res for resource name: ${resourceName} blameInfo: ${JSON.stringify(blameInfo)}`);

          if (!singleBlameResponse.commitSha) {
            if (!blameInfo?.found || !blameInfo?.commit_info) {
              //Only for logging do nothing hear
              commitInfoNotFoundByBlameService++;
              logger.debug(
                `fail to find commit info: ${JSON.stringify(blameInfo)}, securityAlert: ${JSON.stringify(
                  singleBlameResponse,
                )}, type: ${type}, resource name: ${resourceName}`,
              );
            } else {
              singleBlameResponse.commitSha = blameInfo.commit_info.commit_id;
              singleBlameResponse.commitDate = blameInfo.commit_info.author_date;
              singleBlameResponse.commiterName = blameInfo.commit_info.author_name;
              singleBlameResponse.commiterEmail = blameInfo.commit_info.author_email;
              singleBlameResponse.commitDescription = blameInfo.commit_info.message;
            }
          }

          singleBlameResponse.eduVideoLink = blameInfo?.eduVideoLink;
          singleBlameResponse.summaryTitle = blameInfo?.summaryTitle;
          singleBlameResponse.detailedTitle = blameInfo?.detailedTitle;
          singleBlameResponse.fromCommitHistory = blameInfo?.fromCommitHistory;

          if (!singleBlameResponse.installedVersion) {
            singleBlameResponse.installedVersion = blameInfo?.installedVersion;
          }

          try {
            let tName;
            let tVer;
            if (singleBlameResponse?.triggerPackage?.name && singleBlameResponse?.triggerPackage?.version) {
              tName = singleBlameResponse?.triggerPackage?.name;
              tVer = singleBlameResponse?.triggerPackage?.version;
            }
            if (blameInfo?.triggerPackage) {
              singleBlameResponse.triggerPackage = blameInfo?.triggerPackage;
            }
            if (tVer && tName) {
              if (singleBlameResponse.triggerPackage) {
                singleBlameResponse.triggerPackage.name = tName;
                singleBlameResponse.triggerPackage.version = tVer;
              } else {
                singleBlameResponse.triggerPackage = new Dependency();
                singleBlameResponse.triggerPackage.name = tName;
                singleBlameResponse.triggerPackage.version = tVer;
              }
            }
          } catch (err) {
            logger.error(`failed set trigger pkg data, err: ${err}`);
          }

          if (blameInfo?.publishedDate) {
            singleBlameResponse.publishedExploitDate = blameInfo?.publishedDate;
          }
          if (blameInfo?.pkgManager) {
            singleBlameResponse.pkgManager = blameInfo?.pkgManager;
          }

          singleBlameResponse.runtime = blameInfo?.runtime;
          singleBlameResponse.epss = blameInfo?.epss;
          singleBlameResponse.percentile = blameInfo?.percentile;
          singleBlameResponse.githubCode = blameInfo?.githubCode;
          singleBlameResponse.githubIssues = blameInfo?.githubIssues;
          singleBlameResponse.githubRepos = blameInfo?.githubRepos;
          singleBlameResponse.githubCode = blameInfo?.githubCode;
          singleBlameResponse.fixAdoption = blameInfo?.fixAdoption;
          singleBlameResponse.exploitDiversity = blameInfo?.exploitDiversity;
          singleBlameResponse.communityAwareness = blameInfo?.communityAwareness;
          singleBlameResponse.registry = blameInfo?.registry;

          if (blameInfo?.verifiedFp !== undefined) {
            singleBlameResponse.verifiedFp = blameInfo?.verifiedFp;
          }
          if (blameInfo?.dependencyChain !== undefined) {
            singleBlameResponse.dependencyChain = blameInfo?.dependencyChain;
          }
          if (blameInfo?.dependencyChainList !== undefined) {
            singleBlameResponse.dependencyChainList = blameInfo?.dependencyChainList;
          }
          singleBlameResponse.triggerPackagesList = blameInfo?.triggerPackagesList;
          singleBlameResponse.hasPublicExploit = blameInfo?.hasPublicExploit || singleBlameResponse.hasPublicExploit;
          singleBlameResponse.publicExploitLink = blameInfo?.publicExploitLink || singleBlameResponse.publicExploitLink;
          singleBlameResponse.vulnerableFunction = blameInfo?.vulnerableFunction;
          singleBlameResponse.dependencyType = blameInfo?.dependencyType;

          singleBlameResponse.cvssScore = blameInfo?.cvssScore;
          singleBlameResponse.cvssVersion = blameInfo?.cvssVersion;
          singleBlameResponse.attackVector = blameInfo?.attackVector;
          singleBlameResponse.language = blameInfo?.language;

          if (blameInfo?.cweList) {
            if (blameInfo.cweList.length) {
              singleBlameResponse.cweList = blameInfo?.cweList;
            }
          }

          if (blameInfo?.cveDescription) {
            singleBlameResponse.cveDescription = blameInfo?.cveDescription;
          }

          if (blameInfo?.severity) {
            singleBlameResponse.severityStr = blameInfo?.severity;
          }

          if (blameInfo?.versionsPageUrl) {
            singleBlameResponse.versionsPageUrl = blameInfo.versionsPageUrl;
          }
          if (singleBlameResponse.detailedTitle) {
            singleBlameResponse.title = singleBlameResponse.detailedTitle;
          }
          if (blameInfo?.cve) {
            singleBlameResponse.cve = blameInfo.cve;
          }
          if (blameInfo?.fileName) {
            let originalFileName = singleBlameResponse?.fileName;
            if (!repo.monoRepoChild) {
              singleBlameResponse.link = singleBlameResponse.link.replace(singleBlameResponse.fileName, blameInfo.fileName);
              singleBlameResponse.fileName = blameInfo.fileName;
            } else if (!blameInfo.fileName.endsWith(singleBlameResponse.fileName)) {
              const correctFileName = blameInfo.fileName.replace(`${repo.insideFolder.substring(1)}/`, "");
              singleBlameResponse.link = singleBlameResponse.link.replace(singleBlameResponse.fileName, correctFileName);
              singleBlameResponse.fileName = correctFileName;
            }

            if (blameInfo?.snippetLineNumber) {
              if (blameInfo?.snippetLineNumber >= 0) {
                singleBlameResponse.snippetLineNumber = blameInfo.snippetLineNumber;
              }
            }

            if (blameInfo?.startLineNumber && blameInfo?.fileName) {
              if (blameInfo.fromCommitHistory && singleBlameResponse.securityAlertType === SecurityAlertType.secrets) {
                if (repo.type === "GitLab" || repo.type === "GitHub") {
                  if (singleBlameResponse.link.includes("/commit/")) {
                    if (blameInfo?.startLineNumber >= 0) {
                      singleBlameResponse.link = `${singleBlameResponse.link.replace("/commit/", "/blob/")}/${
                        singleBlameResponse.fileName
                      }#L${blameInfo.startLineNumber}`;
                    } else {
                      singleBlameResponse.link = `${singleBlameResponse.link.replace("/commit/", "/blob/")}/${
                        singleBlameResponse.fileName
                      }`;
                    }
                  } else {
                    const indexOfBlob = singleBlameResponse.link.indexOf("/blob/");
                    let endOfBlob = indexOfBlob + 6;
                    const baseUrlWithBlob = singleBlameResponse.link.substring(0, endOfBlob);
                    let branchName = singleBlameResponse.commitSha;
                    if (singleBlameResponse.commitSha === "") {
                      // in case we dont have commitSha
                      let relevantSubLink = singleBlameResponse.link.substring(endOfBlob);
                      let branchIndex = relevantSubLink.indexOf("/");
                      while (branchIndex == 0) {
                        endOfBlob += 1;
                        relevantSubLink = singleBlameResponse.link.substring(endOfBlob - 1);
                        branchIndex = relevantSubLink.indexOf("/");
                      }

                      branchName = relevantSubLink.substring(0, branchIndex);
                    }
                    let baseUrlWithBlobWithCommitSha = "";
                    if (repo.monoRepoChild) {
                      const relevantIndex = repo.fullName.lastIndexOf("/");
                      const currRepo = repo.fullName.substring(relevantIndex + 1);
                      baseUrlWithBlobWithCommitSha = baseUrlWithBlob + branchName + "/" + currRepo + "/" + singleBlameResponse.fileName;
                    } else {
                      baseUrlWithBlobWithCommitSha = baseUrlWithBlob + branchName + "/" + singleBlameResponse.fileName; //here is the issue
                    }
                    if (blameInfo?.startLineNumber >= 0) {
                      baseUrlWithBlobWithCommitSha += `#L${blameInfo.startLineNumber}`;
                    }
                    singleBlameResponse.link = baseUrlWithBlobWithCommitSha;
                  }
                }
                if (repo.type.toLowerCase() === repoType.azureGit.toLowerCase()) {
                  singleBlameResponse.link = `${singleBlameResponse.link}?path=/${singleBlameResponse.fileName}`;
                }
              } else {
                if (blameInfo?.startLineNumber) {
                  if (blameInfo?.startLineNumber >= 0) {
                    const tempRegex: RegExp = RegExp(`${singleBlameResponse.startLineNumber}\$`);
                    singleBlameResponse.link = singleBlameResponse.link.replace(tempRegex, blameInfo.startLineNumber);
                    singleBlameResponse.startLineNumber = blameInfo?.startLineNumber;
                  }
                }
              }

              if (blameInfo?.startLineNumber) {
                if (blameInfo?.startLineNumber >= 0) {
                  singleBlameResponse.startLineNumber = blameInfo.startLineNumber;
                }
              }

              if (blameInfo?.endLineNumber) {
                singleBlameResponse.endLineNumber = blameInfo.endLineNumber;
              } else {
                singleBlameResponse.endLineNumber = blameInfo.startLineNumber;
              }

              if (StatesHelper.Instance.isHilan) {
                if (
                  repo.type.toLowerCase() === repoType.azureTFS.toLowerCase() ||
                  repo.type.toLowerCase() === repoType.azure.toLowerCase() ||
                  repo.type.toLowerCase() === repoType.azureGit.toLowerCase()
                ) {
                  singleBlameResponse.link = `${singleBlameResponse.link}?path=/${singleBlameResponse.fileName}`;
                  logger.info(`Link debug: ${singleBlameResponse.link}`);
                }
              }
            }
          }
          if (blameInfo?.exploitType) {
            singleBlameResponse.exploitType = blameInfo.exploitType;
          }
          if (blameInfo?.cwe) {
            if (Array.isArray(blameInfo.cwe) && blameInfo.cwe.every(i => typeof i === "string")) {
              blameInfo.cwe.forEach(cwe => {
                if (!singleBlameResponse.cwe.includes(cwe)) {
                  singleBlameResponse.cwe.push(cwe);
                }
              });
            } else {
              logger.error(`cwe is not array of string, type: ${type}, resource name: ${resourceName}`);
            }
          }
          if (blameInfo?.match) {
            singleBlameResponse.lineContent = blameInfo.match;
          }
          if (blameInfo?.snippet) {
            singleBlameResponse.snippetContent = blameInfo.snippet;
          }
          if (blameInfo?.recommendation) {
            singleBlameResponse.recommendation = blameInfo.recommendation;
          }
          if (blameInfo?.graphExists) {
            singleBlameResponse.graphExists = blameInfo.graphExists;
          }
          if (blameInfo?.fixedVersion) {
            singleBlameResponse.fixedVersion = blameInfo.fixedVersion;
          }
          if (singleBlameResponse.fixes.length == 0 && blameInfo?.fixes) {
            singleBlameResponse.fixes = blameInfo.fixes;
          }
          attached++;

          // // tuning SCA severity
          if (
            singleBlameResponse.securityAlertType === SecurityAlertType.sca ||
            singleBlameResponse.securityAlertType === SecurityAlertType.container
          ) {
            if (singleBlameResponse?.epss) {
              let epssReason: ChangeReason = null;
              let likelihood = "";
              if (singleBlameResponse.epss > 0.9) {
                singleBlameResponse.frequentPublicExploit = true;
                likelihood = "high";
                epssReason = ChangeReason.copy(severityReasons.extremelyFrequentlyExpolitITW);
              } else if (singleBlameResponse.epss > 0.1) {
                likelihood = "reasonable";
                singleBlameResponse.someSeenExploit = true;
                epssReason = ChangeReason.copy(severityReasons.frequentlyExpolitITW);
              } else if (singleBlameResponse.epss < 0.01) {
                likelihood = "slight";
                singleBlameResponse.rarelySeenExploit = true;
                epssReason = ChangeReason.copy(severityReasons.rarelyExpolitITW);
              }
              if (epssReason) {
                // epssReason.reason = `According the the Exploit Prediction Scoring System (EPSS) model ${singleBlameResponse.cve} has a ${likelihood} chance to be attempted to exploit. Because ${epssReason.reason}`;
                singleBlameResponse.severityChangedReason.push(epssReason);
              }
            }

            if (singleBlameResponse.exploitDiversity > 0) {
              const exploitDiversityReason = ChangeReason.copy(severityReasons.exploitDiversity);
              if (singleBlameResponse.githubRepos && singleBlameResponse.githubCode) {
                exploitDiversityReason.reason = `${exploitDiversityReason.reason.replace("CVE", singleBlameResponse.cve)} ${
                  singleBlameResponse.cve
                } has been mentioned on at least ${singleBlameResponse.githubRepos} public repositories and ${
                  singleBlameResponse.githubCode
                } PoC code references on GitHub, which is among the top 10% of all CVEs.`;
                singleBlameResponse.severityChangedReason.push(exploitDiversityReason);
              }
            }
            if (singleBlameResponse.communityAwareness > 0) {
              const communityAwarenessReason = ChangeReason.copy(severityReasons.communityAwareness);
              if (singleBlameResponse.githubIssues) {
                communityAwarenessReason.reason = `${communityAwarenessReason.reason.replace("CVE", singleBlameResponse.cve)} ${
                  singleBlameResponse.cve
                } has been mentioned on at least ${
                  singleBlameResponse.githubIssues
                } of issues and comments, which is among the top 10% of all CVEs.`;
                singleBlameResponse.severityChangedReason.push(communityAwarenessReason);
              }
            }
            if (singleBlameResponse.fixAdoption > 0) {
              const fixAdoptionReason = ChangeReason.copy(severityReasons.fixAdoption);
              if (singleBlameResponse.githubCommits) {
                fixAdoptionReason.reason = `${fixAdoptionReason.reason.replace("CVE", singleBlameResponse.cve)} ${
                  singleBlameResponse.cve
                } has been mentioned on at least ${
                  singleBlameResponse.githubCommits
                } commits references on GitHub, which is among the top 10% of all CVEs.`;
                singleBlameResponse.severityChangedReason.push(fixAdoptionReason);
              }
            }

            if (singleBlameResponse.hasPublicExploit === true) {
              const hasPublicExpolitChangedReason = ChangeReason.copy(severityReasons.hasPublicExpolit);
              hasPublicExpolitChangedReason.reason = `${singleBlameResponse.cve} has ${hasPublicExpolitChangedReason.reason}`;
              singleBlameResponse.severityChangedReason.push(hasPublicExpolitChangedReason);
            } else if (
              singleBlameResponse.hasPublicExploit === false ||
              (singleBlameResponse.hasPublicExploit === undefined && singleBlameResponse?.cvssScore)
            ) {
              singleBlameResponse.severityChangedReason.push(severityReasons.noPublicExpolit);
            }
          }
          //Debug
          // logger.info(
          //   `post blame res for resource name: ${resourceName} uid: ${singleBlameResponse.uid}, blameInfo: ${JSON.stringify(
          //     singleBlameResponse,
          //   )}`,
          // );
          if (singleBlameResponse.securityAlertType === SecurityAlertType.secrets) {
            if (singleBlameResponse?.snippetContent) {
              const lowercaseSnippet = singleBlameResponse.snippetContent;
              if (
                lowercaseSnippet.includes("localhost") ||
                lowercaseSnippet.includes(".local") ||
                lowercaseSnippet.includes(".internal") ||
                lowercaseSnippet.includes("127.0.0.1") ||
                lowercaseSnippet.search(privateIpAddressRegex) >= 0
              ) {
                let onPremSecretReason = ChangeReason.copy(severityReasons.onPremSecret);
                // onPremSecretReason.reason = ``; put something useful here
                singleBlameResponse.severityChangedReason.push(onPremSecretReason);
              }
              // if (isDevelopment() || isLocalDevelopment()) {
              const snippetProdIndex = singleBlameResponse.snippetContent.search(productionRegex);
              const snippetNonProdIndex = singleBlameResponse.snippetContent.search(nonProductionRegex);
              const fileNameProdIndex = singleBlameResponse.fileName.search(productionRegex);
              const fileNameNonProdIndex = singleBlameResponse.fileName.search(nonProductionRegex);
              if ((snippetProdIndex >= 0 && snippetNonProdIndex < 0) || (fileNameProdIndex >= 0 && fileNameNonProdIndex < 0)) {
                singleBlameResponse.productionSecret = true;
                let prodSecretReason = ChangeReason.copy(severityReasons.prodSecret);
                if (fileNameProdIndex >= 0) {
                  prodSecretReason.reason = `From analyzing the filepath ${singleBlameResponse.fileName} we determine that this secret is in use of a production system`;
                } else {
                  prodSecretReason.reason = `From analyzing the surrounding code of the secret at ${singleBlameResponse.fileName} we determine that this secret is in use of a production system`;
                }
                singleBlameResponse.severityChangedReason.push(prodSecretReason);
              } else if (
                (!singleBlameResponse.snippetContent.includes(".dev/") && snippetProdIndex < 0 && snippetNonProdIndex >= 0) ||
                (fileNameProdIndex < 0 && fileNameNonProdIndex >= 0)
              ) {
                let nonProdSecretReason = ChangeReason.copy(severityReasons.nonProdSecret);
                if (fileNameNonProdIndex >= 0) {
                  nonProdSecretReason.reason = `From analyzing the filepath ${singleBlameResponse.fileName} we determine that this secret is in use of a non-production system`;
                } else {
                  nonProdSecretReason.reason = `From analyzing the surrounding code of the secret at ${singleBlameResponse.fileName} we determine that this secret is in use of a non-production system`;
                }
                // nonProdSecretReason.reason = ``; put something useful here
                if (singleBlameResponse.securityAlertSubType !== SecurityAlertType.PII) {
                  singleBlameResponse.severityChangedReason.push(nonProdSecretReason);
                }
              }
              // }
            }
          }

          singleBlameResponse.success = true;
        } catch (err) {
          logger.error(`failed to set batch of single events to blame service for repo: ${resourceName}, type: ${type}, err: ${err}`);
        }
      }
    } catch (err) {
      logger.error(`failed to set batch of events to blame service for resource name: ${resourceName}, type: ${type}, err: ${err}`);
    }

    logger.info(
      `finish set blame for resource name: ${resourceName}, type: ${type}, blame return ${resOfAllBlameResults.length} results, from them attached: ${attached}, not found by id: ${notFoundById}, commit info not found from blame service: ${commitInfoNotFoundByBlameService}`,
    );
  }

  /**
   * Create a map of all the dependencies, and add the dependencies to the components. Also extract the application components.
   */
  private buildDependenciesMap(
    sbom: Sbom,
    libs: ExtendedSbomComponent[],
  ): [SbomComponentWithDependencies[], Map<string, ExtendedSbomComponentWithDependencies>] {
    const applications: SbomComponentWithDependencies[] = [];

    for (let component of sbom.components) {
      if (component["type"] === "application") {
        applications.push(component);
      }
    }

    const m = libs.reduce((map, lib) => map.set(lib["bom-ref"], lib), new Map<string, ExtendedSbomComponentWithDependencies>());

    for (let dependency of sbom.dependencies) {
      const ref = m.get(dependency.ref);
      if (ref) {
        ref.dependsOn = dependency.dependsOn;
      }
      const app = applications.find(app => app["bom-ref"] === dependency.ref);
      if (app) {
        app.dependsOn = dependency.dependsOn;
      }
    }
    return [applications, m];
  }

  /**
   * Recursively create a blame request for a component and for each of its dependencies.
   */
  private createlameRequestRecursive(
    ref: string,
    map: Map<string, ExtendedSbomComponentWithDependencies>,
    fileName: string,
    repo: Repo,
  ): BlameRequest[] {
    const lib = map.get(ref);
    if (!lib) {
      logger.warn(`Could not find component for dependency: ${ref}`);
      return [];
    }
    if (lib.blame.askedOnce) {
      return [];
    }
    lib.fileName = fileName;
    lib.blame.fileName = lib.fileName;
    lib.blame.askedOnce = true;

    let filePathForBlameService = lib.fileName;
    if (repo.insideFolder != "") {
      filePathForBlameService = `${repo.insideFolder}/${lib.fileName}`;
      if (filePathForBlameService.startsWith("/")) {
        filePathForBlameService = filePathForBlameService.substring(1, filePathForBlameService.length);
      }
    }

    const js: BlameRequest = new BlameRequest();
    js.cloneDir = repo.cloneDir;
    js.fileName = filePathForBlameService;
    js.pkgManager = lib.pkgManager;
    js.match = lib.name;
    js.pkgName = lib.name;
    try {
      if (["maven"].includes(lib.pkgManager)) {
        const splits = lib.name.split(":");
        js.match = splits[splits.length - 1];
        js.pkgName = splits[splits.length - 1];
      }
    } catch (err) {
      logger.error(`failed maven, err: ${err}`);
    }
    js.category = SecurityAlertType[SecurityAlertType.sca];
    js.fixedVersion = "";
    js.installedVersion = lib.version;
    js.uid = lib.uid;
    js.ruleId = "SBOM";
    js.snippet = lib.name;
    js.cve = "";
    js.cwe = [];
    js.title = "";

    //Set uid for connection
    lib.blame.uid = lib.uid;
    const childrenRequests = lib.dependsOn?.map(ref => this.createlameRequestRecursive(ref, map, fileName, repo)).flat() ?? [];
    return [js, ...childrenRequests];
  }

  private getBlameRequestFromSbom(libs: ExtendedSbomComponent[], sbomInfo: SbomEvent, repo: Repo, resourceName: string): BlameRequest[] {
    try {
      const [applications, dependencyMap] = this.buildDependenciesMap(sbomInfo.sbom, libs);

      // Create blame requests for each application, starting from the root of each application tree
      const newRequests = applications
        .map(app => app.dependsOn?.map(ref => this.createlameRequestRecursive(ref, dependencyMap, app.name, repo)).flat() ?? [])
        .flat();

      // Fix for dependencies that are not in any application tree (known issue with pnpm, maybe others)
      for (const lib of libs) {
        if (!lib.blame.askedOnce && lib.type === SbomComponentType.Library) {
          newRequests.push(...this.createlameRequestRecursive(lib["bom-ref"], dependencyMap, newRequests[0]?.fileName, repo));
        }
      }

      logger.info(`blame for sbom for resource name: ${resourceName}, count: ${newRequests.length}`);
      return newRequests;
    } catch (err) {
      logger.error(`failed to set all blame request of sbom events to blame service for resource name: ${resourceName}, err: ${err}`);
    }
    return [];
  }

  private getReqForSecEvents(securityAlerts: SecurityEvent[], resourceName: string): BlameRequest[] {
    const requests: BlameRequest[] = [];

    try {
      for (const securityAlert of securityAlerts) {
        try {
          let securityAlertType: SecurityAlertType = securityAlert.securityAlertType;

          //kyz: test if blame really need security alert type sca instead of ox
          if (securityAlert.securityAlertType == SecurityAlertType.ox) {
            securityAlertType = SecurityAlertType.sast;
          }

          if (securityAlert.skipEnrichment) {
            continue;
          }
          if (securityAlert.blame.askedOnce) {
            logger.info(`not sending for blame: ${securityAlert.securityAlertTypeStr} due askedOnce`);
            continue;
          }
          // if (securityAlert.startLineNumber === -1 && !securityAlert.lineContent && securityAlertType !== SecurityAlertType.sca) {
          //   //logger.info(`not sending for blame: ${securityAlert.securityAlertTypeStr} startLineNumber is -1`);
          //   continue;
          // }
          if ((securityAlert.fileName === "" || securityAlert.fileName === "NA") && securityAlertType !== SecurityAlertType.sca) {
            logger.info(`not sending for blame: ${securityAlert.securityAlertTypeStr} fileName is empty`);
            continue;
          }
          if (securityAlertType === SecurityAlertType.container && securityAlert.securitySubTypeAlertType !== SecurityAlertType.sca) {
            logger.info(`not sending for blame: ${securityAlert.securityAlertTypeStr} not sca container`);
            continue;
          }

          securityAlert.blame.askedOnce = true;

          const js: BlameRequest = new BlameRequest();
          js.cloneDir = securityAlert.cloneForBlameService;
          js.fileName = securityAlert.filePathForBlameService;

          js.isOS = securityAlert.isOsLib;
          js.match = securityAlert.lineContent;
          js.category = SecurityAlertType[securityAlertType];
          js.pkgName = securityAlert.pkgName;
          try {
            if (["maven"].includes(securityAlert.pkgManager)) {
              const splits = securityAlert.pkgName.split(":");
              js.match = splits[splits.length - 1];
              js.pkgName = splits[splits.length - 1];
            }
          } catch (err) {
            logger.error(`failed maven, err: ${err}`);
          }
          js.pkgManager = securityAlert.pkgManager;
          js.fixedVersion = securityAlert.fixedVersion;
          js.installedVersion = securityAlert.installedVersion;
          js.uid = securityAlert.uid;
          js.ruleId = securityAlert.ruleId;
          js.snippet = securityAlert.snippetContent;
          js.cve = securityAlert.blame.cve;
          js.cwe = securityAlert.blame.cwe;
          js.title = securityAlert.title;
          js.commitSha = securityAlert.blame.commitSha;
          js.fromCommitHistory = securityAlert.fromCommitHistory;
          js.startLineNumber = securityAlert.startLineNumber;
          js.repoFullName = securityAlert.repoFullName;
          js.toolName = securityAlert.tool;
          if (securityAlert?.blame?.triggerPackage?.name) {
            js.triggerPackageName = securityAlert.blame.triggerPackage.name;
          }
          if (securityAlert?.blame?.triggerPackage?.version) {
            js.triggerPackageVersion = securityAlert.blame.triggerPackage.version;
          }

          //Set uid and additional info needed for connection
          securityAlert.blame.uid = securityAlert.uid;
          securityAlert.blame.securityAlertType = securityAlert.securityAlertType;
          securityAlert.blame.startLineNumber = securityAlert.startLineNumber;
          securityAlert.blame.endLineNumber = securityAlert.endLineNumber;
          securityAlert.blame.securityAlertSubType = securityAlert.securitySubTypeAlertType;
          securityAlert.blame.fileName = securityAlert.fileName;
          securityAlert.blame.link = securityAlert.link;
          securityAlert.blame.severity = securityAlert.severity;
          securityAlert.blame.severityStr = securityAlert.severityStr;
          securityAlert.blame.ruleId = securityAlert.ruleId;

          requests.push(js);
        } catch (err) {
          logger.error(`failed send blame request for single security alerts in repo: ${resourceName}, err: ${err}`);
        }
      }

      logger.info(`finish set request for blame sec events repo: ${resourceName}, count: ${requests.length}`);

      return requests;
    } catch (err) {
      logger.error(`failed to set batch of requests security alerts to blame service for repo: ${resourceName}, err: ${err}`);
    }
    return [];
  }

  private async sendAndWaitForRes(requests: BlameRequest[], repo: Repo, type: string, index: number, resourceName: string) {
    let data;
    const requestId = uuid.v4();

    try {
      if (requests.length == 0) {
        return null;
      }

      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;

      let url = onSast ? process.env.BLAME_SQS_URL : process.env.BLAME_QUEUE_KEY;
      if (isk8) {
        url = process.env.BLAME_QUEUE_KEY;
      }

      //If this is onPrem the zip folder is the actual code folder without a zip
      //If we are on SAST then we need the parent folder in case its mono repo and if not the regular repo
      let cloneDir = "";
      let toolCopyDestination = "";
      let monoRepoChildSubfolder = "";
      let dirToPutRes = "";

      if (repo.realRepo) {
        cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;

        if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
          if (repo.monoRepoChild) {
            toolCopyDestination = repo.parentRepoOfMonoRepo.cloneDir;
          } else {
            toolCopyDestination = repo.cloneDir;
          }
        } else {
          toolCopyDestination = repo.getRepoForToolsBasedOnEnv();
          if (!onPrem || isk8) {
            toolCopyDestination = `${toolCopyDestination}_${type}/${index.toString()}`;
          }
        }

        monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;

        dirToPutRes = `${repo.blameResDir}/${requestId}`;
      } else {
        dirToPutRes = `${getBlameDir(this.orgName, this.uuid)}/${requestId}`;
      }

      fs.mkdirSync(dirToPutRes, { recursive: true });

      let dep = [];
      try {
        if (repo.realRepo) {
          if (repo.dependencyGraphInfoPath && repo.dependencyGraphInfoPath != null) {
            if (fs.existsSync(repo.dependencyGraphInfoPath)) {
              const data = fs.readFileSync(repo.dependencyGraphInfoPath, "utf8");
              dep = JSON.parse(data);
            } else {
              logger.info(`dep graph doesn't exist for repo: ${repo.fullName}`);
            }
          } else {
            logger.warn(`dep graph not set for repo:${repo.fullName}`);
          }
        }
      } catch (err) {
        let errInfo = `failed read dependencyGraphInfoPath, resource name: ${resourceName}, err: ${err}`;
        logger.error(`${errInfo}`);
      }

      const filePathRequest = `${dirToPutRes}/blameServiceRequest.json`;
      fs.writeFileSync(
        filePathRequest,
        JSON.stringify({
          dependencyGraphInfo: dep,
          requests: requests,
        }),
      );

      const filePathRes = `${dirToPutRes}/blameService.json`;

      let noGit = false;
      let copyType = CopyType.All;
      if (repo.realRepo) {
        const path = `${cloneDir}/${ZipType.Dotgit}`;
        if (repo.largeGitHistory) {
          noGit = true;
          logger.info(`largeGitHistory: ${repo.repositoryHistorySize} for resource name: ${resourceName}, running no git`);
        } else if (!fs.existsSync(path) && !isLocalDevelopment()) {
          noGit = true;
          logger.info(`no .git file for resource name: ${resourceName}, running no git`);
        }
      }

      if (noGit) {
        copyType = type === "sbom" ? CopyType.LeanCodeOnly : CopyType.CodeOnly;
      } else {
        copyType = type === "sbom" ? CopyType.LeanCodeWithDotGit : CopyType.All;
      }

      //Always keep no git for tfs
      if (repo.vcsType === VCSType.tfvc) {
        noGit = true;
      }

      let command = this.getCommand(filePathRequest, dirToPutRes, toolCopyDestination, noGit);
      command = escapeCharsFromPath(command);

      const isFastScan = StatesHelper.Instance.pipelineScanInfo.performance === PerformanceType.fast;
      const isFastestScan = StatesHelper.Instance.pipelineScanInfo.performance === PerformanceType.fastest;
      const canRunFastScan = StatesHelper.Instance.canRunFastPipelineScan;
      const canRunFastestScan = StatesHelper.Instance.canRunFastestPipelineScan;
      if (
        StatesHelper.Instance.isPipelineScan &&
        ((isFastScan && canRunFastScan) || (isFastestScan && canRunFastestScan) || !repo.useDotGit)
      ) {
        copyType = CopyType.CodeOnly;
        noGit = true;
        logger.info(
          `sending request to blame for fast mode in service for resource, name: ${resourceName}, type: ${type}, noGit: ${noGit}, useDotGit: ${repo.useDotGit}, copyType: ${copyType}, count: ${requests.length}`,
        );
      } else {
        logger.info(
          `sending request to blame service for resource, name: ${resourceName}, type: ${type}, noGit: ${noGit}, useDotGit: ${repo.useDotGit}, copyType: ${copyType}, count: ${requests.length}`,
        );
      }

      const msg = {
        MessageId: requestId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "blame-service",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 1800000,
        orgDisplayName: process.env["companyName"],
        cloneDir: cloneDir,
        copyType: copyType,
        toolCopyDestination: toolCopyDestination,
        isMonoRepoChild: repo.monoRepoChild,
        monoRepoChildSubfolder: monoRepoChildSubfolder,
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: repo.ignoredMonoRepoChildrenSubfolders,
        putInQueueTime: new Date().getTime(),
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = { url: url, msg: msg };

      logger.info(
        `about to send msg to queue for blame, resource name: ${resourceName}, num of requests: ${requests.length}, msg: ${JSON.stringify(
          msg,
        )}`,
      );

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromBlame = false;

      //From Debug(shell)
      if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
        const reqRes = await this.runShell(repo.name, msg.localCommand);
        const data = fs.readFileSync(filePathRes, "utf8");
        const blameRes = JSON.parse(data);
        return blameRes;
      }

      //From SAST(sqs)
      const reqRes = await this.blameQ.sendQueueMessage(info);
      if (!reqRes) {
        ToolsExecutionStats.addExecutionStateOnFail(
          requestId,
          OXtools.blame,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          -1,
          ToolError.SendToQueue,
        );
        this.setFailedEnrichmentTools(repo, requests);
        return null;
      }

      if (this.orgName === "org_Az2qqFFrocg1e7SA") {
        logger.info(`setting blame forced fail for repo: ${repo.fullName}, num of requests: ${requests.length}, org: ${this.orgName}`);
        this.setFailedEnrichmentTools(repo, requests);
      }

      logger.info(`about to start waiting for blame, resource name: ${resourceName}, num of requests: ${requests.length}`);
      this.copyToolResults({ repoName: repo.name, dir: filePathRequest, type: type, index: index });
      const startProcessTime = new Date().getTime();

      let counter = 6 * 20; // 60 seconds * 20 = 20 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.blame,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );

          this.setFailedEnrichmentTools(repo, requests);
          StatesHelper.Instance.scanInfoStats.failedBlameTimeout++;
          StatesHelper.Instance.scanInfoStats.failedBlameTimeoutRepoNames.push(repo.name);
          return null;
        }

        //Failed from blame
        if (fs.existsSync(failedFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.blame,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.ResFileNotFound,
          );

          this.setFailedEnrichmentTools(repo, requests);
          StatesHelper.Instance.scanInfoStats.failedBlameBatches++;
          StatesHelper.Instance.scanInfoStats.failedBlameRepoNames.push(repo.name);

          return null;
        }

        //Done from blame
        if (fs.existsSync(doneFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `done file discovered from blame response, resource name: ${resourceName}, num of requests: ${requests.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromBlame = true;
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
          OXtools.blame,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );

        StatesHelper.Instance.scanInfoStats.failedBlameBatches++;
        StatesHelper.Instance.scanInfoStats.failedBlameRepoNames.push(repo.name);

        this.setFailedEnrichmentTools(repo, requests);
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      data = fs.readFileSync(filePathRes, "utf8");

      const blameRes = JSON.parse(data);

      const failed = new Set<string>();
      ToolsExecutionStats.addToExecutionStatsFromFile(
        doneFilePath,
        requestId,
        OXtools.blame,
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
        `finish waiting for blame, resource name: ${resourceName}, num of requests: ${requests.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, blame res number: ${blameRes.length}, counter: ${counter}`,
      );

      //Delete after reading
      this.copyToolResults({ repoName: repo.name, dir: filePathRes, type: type, index: index });
      this.fileHelper.deleteFile(filePathRes);
      this.fileHelper.deleteFile(filePathRequest);

      return blameRes;
    } catch (err) {
      logger.error(
        `failed to send and wait for res of batch of security alerts to blame service for resource name: ${resourceName}, data: ${data}, err: ${err}`,
      );

      this.setFailedEnrichmentTools(repo, requests);
      ToolsExecutionStats.addExecutionStateOnFail(requestId, OXtools.blame, repo.fullName, repo.id, "repo", "", -1, ToolError.Generic);

      StatesHelper.Instance.scanInfoStats.failedBlameBatches++;
      StatesHelper.Instance.scanInfoStats.failedBlameRepoNames.push(repo.name);
    }
    return null;
  }

  splitToChunks(array, resourceName: string, blameType: string, isPipelineScan: boolean) {
    // const chunkSize = process.env.DEBUG ? 20000 : 500;
    let chunkSize: number = 200;
    if (isPipelineScan) {
      chunkSize = blameType == "blame" ? 200 : 50;
    } else {
      chunkSize = blameType == "blame" ? 500 : 200;
    }
    if (isLocalDevelopment() && !process.env.DOCKER_DEBUG) {
      chunkSize = 20000;
    }
    const chunks = [];
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
      logger.error(`failed run shell command: ${command} to run err: ${err}`);
    }
    return false;
  }

  async shell(requesterName, command: string) {
    try {
      logger.info(`try run from shell, repo: ${requesterName}: cmd: ${command}`);

      const { stdout, stderr } = await exec(command, {
        maxBuffer: 1024 * 1024 * 10,
        env: { ...process.env, FOO: "ah" },
      });
      logger.debug(`stdout:, ${JSON.stringify(stdout, null, 4)}`);
      logger.debug(`stderr:, ${JSON.stringify(stderr, null, 4)}`);
    } catch (err) {
      logger.error(
        `uuid: ${this.uuid} shell command: ${command} failed to run error: ${err} stdout: ${err.stdout + "\n"} stderr: ${
          err.stderr + "\n"
        }`,
        err,
      );

      logger.info(`finish run from shell, requester name: ${requesterName} cmd: ${command}`);
    }
  }

  copyToolResults({ repoName, dir, type, index }: { repoName: string; dir: string; type: string; index: number }): void {
    if (isUploadToS3()) {
      const oxDir = getSharedFolder(this.uuid) + "/ox-security";
      const telemetryDir = oxDir + "/telemetry-" + this.uuid;
      const repoDir = telemetryDir + "/security-report/" + repoName;
      const toolDir = repoDir + "/blameDir/" + type + "/" + index;

      try {
        if (!fs.existsSync(toolDir)) {
          fs.mkdirSync(toolDir, { recursive: true });
        }
        this.fileHelper.copyFileSync(dir, toolDir);
      } catch (err) {
        logger.error(`failed to copy tool blameDir result file for repo name ${repoName}`, err);
      }
    }
  }

  getCommand(requestPath: string, outputDir: string, repoDir: string, no_git: boolean) {
    const noGitFlag = no_git ? "--no-git" : "";
    if (repoDir) {
      if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
        return `python ${process.env.BLAME_PATH} --source ${repoDir} --events-path ${requestPath} --output-dir ${outputDir} ${noGitFlag}`;
      }
      return `python /src/blame_cli.py --source ${repoDir} --events-path ${requestPath} --output-dir ${outputDir} ${noGitFlag}`;
    } else {
      if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
        return `python ${process.env.BLAME_PATH} --events-path ${requestPath} --output-dir ${outputDir} ${noGitFlag}`;
      }
      return `python /src/blame_cli.py --events-path ${requestPath} --output-dir ${outputDir} ${noGitFlag}`;
    }
  }
}

export function getUniqueCloudSeverityChanges(securityEvent: CloudSecurityEvent, allSecurityEvent: CloudSecurityEvent[]) {
  try {
    const newChangeReasons: ChangeReason[] = [];

    const allChangeReasons: ChangeReason[] = allSecurityEvent.map(i => i.severityChangedReason).flat();
    const u = new Set();

    allChangeReasons.forEach(i => {
      if (u.has(i.shortName)) {
        return;
      }
      u.add(i.shortName);
      newChangeReasons.push(i);
    });
    return newChangeReasons;
  } catch (err) {
    logger.error(`failed get cloud severity changes unique, err: ${err}`);
  }
  return securityEvent.severityChangedReason;
}

export default BlameHelper;

export interface SbomComponentWithDependencies extends SbomComponent {
  dependsOn?: string[];
}
export interface ExtendedSbomComponentWithDependencies extends ExtendedSbomComponent {
  dependsOn?: string[];
}
