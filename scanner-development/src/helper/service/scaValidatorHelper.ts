const util = require("util");
const exec = util.promisify(require("child_process").exec);
import { setTimeout } from "node:timers/promises";
import { Application } from "../../appmgr/application";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { addSeverityChangedReason, Repo, SecurityAlertType, SecurityEvent, VCSType } from "../../entitis/codeRepoTypes";
import { OXtools } from "../../entitis/constant";
import { ExtraInfo } from "../../entitis/issuesTypes";
import { ChangeReason, getDependencyType, severityReasons } from "../../entitis/service/blameTypes";
import { CveApplicability, Match, ScaValidatorTypesRequest, ScaValidatorTypesResponse } from "../../entitis/service/scaValidatorTypes";
import { getSharedFolder } from "../../helper/generalUtils";
import FileHelper from "../../helper/IO/fileHlper";
import loggerImport from "../../logger";
import { DependencyType } from "../../mongo/sbom/types";
import { escapeCharsFromPath } from "../commonUtils";
import { isDevelopment, isK8Mode, isLocalDevelopment, isUploadToS3 } from "../envUtils";
import Iqueue from "../queue/Iqueue";
import { ExtendedSbomComponent } from "../sbom/sbomHelper";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";

const onPrem = process.env.redisOnPrem != undefined;
const onSast = process.env.MONGO_CONN === "atlas";
const isk8 = isK8Mode();
const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();

class ScaVerificationHelper {
  scaHelperQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;
  supportedLanguages: string[] = ["JavaScript", "Python", "Java", "Go"];

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.scaHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
  }

  async setScaValidator(securityAlerts: SecurityEvent[], app: Application) {
    if (StatesHelper.Instance.isPipelineScan) {
      return;
    }

    const repoTempCast: any = app.appInfo.repo == null ? null : (app.appInfo.repo as any);
    if (repoTempCast == null) {
      return;
    }
    const repo = repoTempCast.code_repo as Repo;

    if (repo.vcsType === VCSType.tfvc) return;

    try {
      const scaAlerts = securityAlerts.filter(
        i => i.securityAlertType == SecurityAlertType.sca && i.securitySubTypeAlertType === SecurityAlertType.Unknown && !i.skipEnrichment,
      );

      const items = {};
      scaAlerts.forEach(i => {
        const key = i.blame?.triggerPackage?.name
          ? `${i.blame.triggerPackage.name}_${i.blame.triggerPackage.version}`
          : `${i.pkgName}_${i.installedVersion}`;
        if (items[key]) {
          items[key].push(i);
        } else {
          items[key] = [i];
        }
      });

      const itemLength = Object.keys(items).length;
      if (itemLength == 0) {
        return;
      }

      logger.info(
        `[ScaValidator] try generate requests for repo: ${repo.fullName}, alerts by key: ${itemLength}, total sca alerts: ${scaAlerts.length}`,
      );

      const isDev = isDevelopment() || isLocalDevelopment();
      let requests: ScaValidatorTypesRequest[] = [];
      let libsWeDidntSend = 0;
      for (const [key, val] of Object.entries(items)) {
        try {
          const alerts: SecurityEvent[] = val as SecurityEvent[];
          if (alerts.length == 0) {
            continue;
          }

          const scaValidatorRequest: ScaValidatorTypesRequest = new ScaValidatorTypesRequest();
          let add = false;
          const uniqueCve = new Set<string>();

          alerts.forEach(securityAlert => {
            try {
              //Dont ask again on the same sec alert for, safety check.
              if (securityAlert.askedOnceForScaValidator) {
                return;
              }

              if (!this.supportedLanguages.includes(securityAlert.blame.language) && !isDev) {
                return;
              }

              if (getDependencyType(securityAlert.blame.dependencyType) === DependencyType.Development) {
                return;
              }

              add = true;
              securityAlert.askedOnceForScaValidator = true;

              scaValidatorRequest.uid = key;
              scaValidatorRequest.pkgName = securityAlert.pkgName;
              scaValidatorRequest.fileName = securityAlert.fileName;
              scaValidatorRequest.language = securityAlert.blame.language;
              scaValidatorRequest.toolsName.add(securityAlert.tool);

              if (securityAlert?.blame?.cve) {
                if (!uniqueCve.has(securityAlert?.blame?.cve)) {
                  uniqueCve.add(securityAlert?.blame?.cve);
                  scaValidatorRequest.cve.push(securityAlert.blame.cve);
                } else {
                  // ?? dor
                  uniqueCve.add(securityAlert?.blame?.cve);
                }
              }

              if (securityAlert?.blame?.dependencyChain) {
                scaValidatorRequest.dependencyChain = securityAlert.blame.dependencyChain;
              }
            } catch (err) {
              logger.error(`[ScaValidator] failed to generate single request for repo: ${repo.fullName}`, err);
            }
          });

          if (add) {
            requests.push(scaValidatorRequest);
          } else {
            libsWeDidntSend++;
          }
        } catch (err) {
          logger.error(`[ScaValidator] failed to generate all request for repo: ${repo.fullName}`, err);
        }
      }

      requests = requests.filter(i => i != undefined);

      if (requests.length > 0) {
        const resProms = await Promise.all(
          this.splitToChunks(requests, repo).map((chunk, i) => this.sendAndWaitForRes(chunk as ScaValidatorTypesRequest[], repo, i, false)),
        );

        let input = resProms.filter(i => i != null);
        input = input.flat();

        this.updateSecurityAlertsWithScaValidator(input, scaAlerts, repo);
      }

      logger.info(
        `[ScaValidator] finish set for repo: ${repo.fullName}, security alerts: ${scaAlerts.length}, requests: ${requests.length}, libs we didnt send: ${libsWeDidntSend}`,
      );
    } catch (err) {
      logger.error(`[ScaValidator] failed set for all security alerts for repo: ${repo.fullName}`, err);
    }
  }

  private updateSecurityAlertsWithScaValidator(resOfAllScaValidators: ScaValidatorTypesResponse[], alerts: SecurityEvent[], repo: Repo) {
    let attached = 0;
    let notFoundById = 0;

    try {
      logger.info(`[ScaValidator] number of results before digest for repo: ${repo.fullName} count: ${resOfAllScaValidators.length}`);

      for (const scaValidatorSingleRes of resOfAllScaValidators) {
        try {
          const scaValidatorResponse: SecurityEvent[] = alerts.filter(
            i =>
              `${i.blame.triggerPackage.name}_${i.blame.triggerPackage.version}` === scaValidatorSingleRes.uid ||
              `${i.pkgName}_${i.installedVersion}` === scaValidatorSingleRes.uid,
          ) as any;

          if (scaValidatorResponse == undefined || scaValidatorResponse.length === 0) {
            logger.error(`[ScaValidator] fail to find security alert for uid: ${scaValidatorSingleRes.uid}, repo: ${repo.fullName}`);
            notFoundById++;
            continue;
          }

          attached++;
          scaValidatorResponse.forEach((singleScaValidatorResponse: SecurityEvent) => {
            singleScaValidatorResponse.scaValidatorTypesResponse = scaValidatorSingleRes;
            let pkgUsed = true;
            let pkgImported = true;
            if (
              scaValidatorSingleRes.success &&
              (singleScaValidatorResponse.blame.triggerPackage?.name ||
                singleScaValidatorResponse.blame.dependencyType === DependencyType.Direct)
            ) {
              if (
                scaValidatorSingleRes.pkgImported === false &&
                !singleScaValidatorResponse.fileName.endsWith("requirements.txt") && //sometimes requirements contains indirect packages
                !singleScaValidatorResponse.fileName.endsWith("Pipfile") && //sometimes requirements contains indirect packages
                !["Go", "Java"].includes(singleScaValidatorResponse.blame.language) //still need to verify Go and Java
              ) {
                pkgImported = false;
                addSeverityChangedReason(severityReasons.packageNotImported, singleScaValidatorResponse, repo);
              } else if (scaValidatorSingleRes.pkgImported === true) {
                const extraInfo: ExtraInfo[] = [];
                if (scaValidatorSingleRes.dependencyChain) {
                  scaValidatorSingleRes.dependencyChain.forEach(link => {
                    let imports = link.imports;
                    const lineNumbers = [];
                    if (imports) {
                      if (imports.length > 10) {
                        imports = imports.slice(0, 10);
                      }
                    }
                    imports?.forEach((match: Match) => {
                      if (!lineNumbers.includes(match.line)) {
                        const link = repo.fileLink + match.fileName + repo.linkFilePreffix + match.line;
                        extraInfo.push({
                          key: "Snippet",
                          link: link,
                          snippet: {
                            fileName: match.fileName,
                            text: match.snippet.substring(0, 200),
                            language: singleScaValidatorResponse.blame.language,
                            snippetLineNumber: match.line,
                          },
                        });
                      }
                      lineNumbers.push(match.line);
                    });
                  });
                }

                const packageImportedSeverityReason = ChangeReason.copy(severityReasons.packageImported);
                addSeverityChangedReason(packageImportedSeverityReason, singleScaValidatorResponse, repo, extraInfo);
              } else {
                scaValidatorSingleRes.pkgImported = undefined;
              }
            } else {
              scaValidatorSingleRes.pkgImported = undefined;
            }

            if (scaValidatorSingleRes.pkgUsed) {
              const extraInfo: ExtraInfo[] = [];
              scaValidatorSingleRes.dependencyChain.forEach(link => {
                link?.pkgUsage?.map((match: Match) => {
                  const link = repo.fileLink + match.fileName + repo.linkFilePreffix + match.line;
                  extraInfo.push({
                    key: "Snippet",
                    link: link,
                    snippet: {
                      fileName: match.fileName,
                      text: match.snippet.substring(0, 200),
                      language: singleScaValidatorResponse.blame.language,
                      snippetLineNumber: match.line,
                    },
                  });
                });
              });

              const packageUsedSeverityReason = ChangeReason.copy(severityReasons.packageUsed);
              addSeverityChangedReason(packageUsedSeverityReason, singleScaValidatorResponse, repo, extraInfo);
            } else if (
              scaValidatorSingleRes?.wasPkgChecked &&
              !scaValidatorSingleRes?.specialCase &&
              singleScaValidatorResponse.blame.language !== "Python"
            ) {
              pkgUsed = false;
              const packageUsedSeverityReason = ChangeReason.copy(severityReasons.packageNotUsed);
              addSeverityChangedReason(packageUsedSeverityReason, singleScaValidatorResponse, repo);
            }

            let exploitNotApplicable = false;
            let totalCVEs = scaValidatorSingleRes?.cveApplicability.length ? scaValidatorSingleRes?.cveApplicability.length : -1;
            if (pkgImported === false || pkgUsed === false) {
              const exploitNotApplicableSeverityReason = ChangeReason.copy(severityReasons.exploitNotApplicable);
              let vulnerabilityStr = "";
              let isAreStr = "";
              if (totalCVEs === 1) {
                vulnerabilityStr = "vulnerability";
                isAreStr = "is";
              } else {
                vulnerabilityStr = "vulnerabilities";
                isAreStr = "are";
              }
              exploitNotApplicableSeverityReason.reason = `The ${vulnerabilityStr} of this issue ${isAreStr} non-exploitable, because the vulnerable package in not in use.`;
              addSeverityChangedReason(exploitNotApplicableSeverityReason, singleScaValidatorResponse, repo);
              exploitNotApplicable = true;
            }

            const notApplicableExploitCVEs = {};
            const applicableExploitCVEs = {};

            if (exploitNotApplicable === false) {
              if (scaValidatorSingleRes.vulnerableComponentAnalyzed) {
                const extraInfo: ExtraInfo[] = [];
                scaValidatorSingleRes?.cveApplicability?.forEach((cveApp: CveApplicability) => {
                  if (cveApp.vulnerableComponentAnalyzed && !cveApp.vulnerableComponentUsed) {
                    notApplicableExploitCVEs[cveApp.cve] = cveApp.explanation;
                  } else if (cveApp.vulnerableComponentAnalyzed && cveApp.vulnerableComponentUsed) {
                    applicableExploitCVEs[cveApp.cve] = cveApp.explanation;
                    cveApp?.usage?.map((match: Match) => {
                      const link = repo.fileLink + match.fileName + repo.linkFilePreffix + match.line;
                      extraInfo.push({
                        key: "Snippet",
                        link: link,
                        snippet: {
                          fileName: match.fileName,
                          text: match.snippet.substring(0, 200),
                          language: singleScaValidatorResponse.blame.language,
                          snippetLineNumber: match.line,
                        },
                      });
                    });
                  }
                });
                const applicableExploitsCount = Object.entries(applicableExploitCVEs).length;
                const notApplicableExploitsCount = Object.entries(notApplicableExploitCVEs).length;
                if (applicableExploitsCount > 0) {
                  const exploitApplicableSeverityReason = ChangeReason.copy(severityReasons.exploitApplicable);
                  const cveNamesArray = Object.keys(applicableExploitCVEs);
                  const cves = cveNamesArray.join(", ");
                  const vulnerabilityStr = applicableExploitsCount == 1 ? "vulnerability" : "vulnerabilities";
                  let explanationsArray = Object.entries(applicableExploitCVEs).map(([key, value]) => (value ? `${key} - ${value}` : ""));
                  explanationsArray = explanationsArray.filter(element => element !== "");
                  const explanationsStr = explanationsArray.join("\n");
                  exploitApplicableSeverityReason.reason = `For the direct ${vulnerabilityStr}: ${cves}. OX was able to simulate a concrete exploit against your application.\n\n${explanationsStr}`;
                  addSeverityChangedReason(exploitApplicableSeverityReason, singleScaValidatorResponse, repo, extraInfo);
                } else if (notApplicableExploitsCount > 0 && totalCVEs == notApplicableExploitsCount) {
                  if (singleScaValidatorResponse.blame.dependencyType === DependencyType.Direct) {
                    exploitNotApplicable = true;
                    const exploitNotApplicableSeverityReason = ChangeReason.copy(severityReasons.exploitNotApplicable);
                    const cveNamesArray = Object.keys(notApplicableExploitCVEs);
                    const cves = cveNamesArray.join(", ");
                    const vulnerabilityStr = notApplicableExploitsCount == 1 ? "vulnerability" : "vulnerabilities";
                    let explanationsArray = Object.entries(notApplicableExploitCVEs).map(([key, value]) =>
                      value ? `${key} - ${value}` : "",
                    );
                    explanationsArray = explanationsArray.filter(element => element !== "");
                    const explanationsStr = explanationsArray.join("\n");
                    exploitNotApplicableSeverityReason.reason = `For the direct ${vulnerabilityStr}: ${cves}. OX was able to determine there is no active risk of an exploit.\n\n${explanationsStr}`;
                    addSeverityChangedReason(exploitNotApplicableSeverityReason, singleScaValidatorResponse, repo);
                  } else if (singleScaValidatorResponse.blame.dependencyType === DependencyType.Indirect) {
                    // logger.info("TODO: indirect exploitNotApplicable"); // eyalp
                  }
                }
              }

              if (scaValidatorSingleRes.vulnerableFunctionUsed) {
                const extraInfo: ExtraInfo[] = [];
                scaValidatorSingleRes?.cveApplicability?.forEach((cveApp: CveApplicability) => {
                  cveApp?.usage?.map((match: Match) => {
                    const link = repo.fileLink + match.fileName + repo.linkFilePreffix + match.line;
                    extraInfo.push({
                      key: "Snippet",
                      link: link,
                      snippet: {
                        fileName: match.fileName,
                        text: match.snippet.substring(0, 200),
                        language: singleScaValidatorResponse.blame.language,
                        snippetLineNumber: match.line,
                      },
                    });
                  });
                });

                const packageUsedSeverityReason = ChangeReason.copy(severityReasons.vulnerableFnUsed);
                addSeverityChangedReason(packageUsedSeverityReason, singleScaValidatorResponse, repo, extraInfo);
              } // else {
              //   const packageUsedSeverityReason = ChangeReason.copy(severityReasons.vulnerableFnNotUsed);
              //   addSeverityChangedReason(packageUsedSeverityReason, singleScaValidatorResponse, repo);
              // }
            }

            scaValidatorSingleRes.success = true;
          });
        } catch (err) {
          logger.error(`[ScaValidator] fail sca single alert, repo: ${repo.fullName}`, err);
        }
      }
    } catch (err) {
      logger.error(`[ScaValidator] fail alerts for repo: ${repo.fullName}`, err);
    }
    logger.info(
      `[ScaValidator] finish alerts for repo: ${repo.fullName}, attached: ${attached}, notFoundById: ${notFoundById}, total response: ${resOfAllScaValidators.length} for single chunk`,
    );
  }

  async setScaValidatorSBOM(sbomLibs: ExtendedSbomComponent[], app: Application) {
    if (StatesHelper.Instance.isPipelineScan) {
      return;
    }
    //Eyal remove when fixed
    if (StatesHelper.Instance.isWalmart) {
      return;
    }
    if (!sbomLibs) {
      return;
    }

    const repoTempCast: any = app.appInfo.repo == null ? null : (app.appInfo.repo as any);
    if (repoTempCast == null) {
      return;
    }
    const repo = repoTempCast.code_repo as Repo;

    if (repo.vcsType === VCSType.tfvc) return;

    try {
      if (sbomLibs.length == 0) {
        return;
      }

      logger.info(`[ScaValidator] try generate requests for sbom repo: ${repo.fullName}, total sbom libs: ${sbomLibs.length}`);

      let requests: ScaValidatorTypesRequest[] = [];
      for (const lib of sbomLibs) {
        try {
          const scaValidatorRequest: ScaValidatorTypesRequest = new ScaValidatorTypesRequest();
          const uniqueCve = new Set<string>();

          if (!this.supportedLanguages.includes(lib.blame.language)) {
            continue;
          }

          if (getDependencyType(lib.blame.dependencyType) === DependencyType.Development) {
            continue;
          }

          const key = `${lib.name}@${lib.version}`;
          scaValidatorRequest.uid = key;
          scaValidatorRequest.pkgName = lib.name;
          scaValidatorRequest.fileName = lib.fileName;
          scaValidatorRequest.language = lib.blame.language;

          if (lib?.blame?.cve) {
            if (!uniqueCve.has(lib?.blame?.cve)) {
              uniqueCve.add(lib?.blame?.cve);
              scaValidatorRequest.cve.push(lib.blame.cve);
            } else {
              // ?? dor
              uniqueCve.add(lib?.blame?.cve);
            }
          }
          if (lib?.blame?.dependencyChain) {
            scaValidatorRequest.dependencyChain = lib.blame.dependencyChain;
          }

          requests.push(scaValidatorRequest);
        } catch (err) {
          logger.error(`[ScaValidator] failed to generate all request for repo: ${repo.fullName}`, err);
        }
      }

      requests = requests.filter(
        i => i != undefined && i.dependencyChain && i.dependencyChain.length === 1 && i.dependencyChain[0].name === i.pkgName,
      );

      if (requests.length > 0) {
        const resProms = await Promise.all(
          this.splitToChunks(requests, repo).map((chunk, i) => this.sendAndWaitForRes(chunk as ScaValidatorTypesRequest[], repo, i, true)),
        );

        let input = resProms.filter(i => i != null);
        input = input.flat();

        this.updateSBOMWithScaValidator(input, sbomLibs, repo);
      }
      logger.info(`[ScaValidator] finish generate requests for sbom repo: ${repo.fullName}, total sbom libs: ${sbomLibs.length}`);
    } catch (err) {
      logger.error(`[ScaValidator] failed set for all sbom libs for repo: ${repo.fullName}`, err);
    }
  }

  private updateSBOMWithScaValidator(resOfAllScaValidators: ScaValidatorTypesResponse[], sbomLibs: ExtendedSbomComponent[], repo: Repo) {
    let attached = 0;
    let notFoundById = 0;

    try {
      logger.info(
        `[ScaValidator] number of sbom libs results before digest for repo: ${repo.fullName} count: ${resOfAllScaValidators.length}`,
      );

      for (const scaValidatorSingleRes of resOfAllScaValidators) {
        try {
          const libForRes: ExtendedSbomComponent[] = sbomLibs.filter(i => `${i.name}@${i.version}` === scaValidatorSingleRes.uid) as any;

          if (libForRes == undefined || libForRes.length === 0) {
            logger.error(`[ScaValidator] fail to find sbom lib for uid: ${scaValidatorSingleRes.uid}, repo: ${repo.fullName}`);
            notFoundById++;
            continue;
          }

          attached++;
          libForRes.forEach((lib: ExtendedSbomComponent) => {
            lib.scaValidator = scaValidatorSingleRes;

            if (scaValidatorSingleRes.success && (lib.blame.triggerPackage?.name || lib.blame.dependencyType === DependencyType.Direct)) {
              //Do nothing
            } else {
              scaValidatorSingleRes.pkgImported = undefined;
            }
          });
        } catch (err) {
          logger.error(`[ScaValidator] fail sca single sbom lib: ${JSON.stringify(scaValidatorSingleRes)}, repo: ${repo.fullName}`, err);
        }
      }
    } catch (err) {
      logger.error(`[ScaValidator] fail sbom lib for repo: ${repo.fullName}`, err);
    }
    logger.info(
      `[ScaValidator] finish sbom lib for repo: ${repo.fullName}, attached: ${attached}, notFoundById: ${notFoundById}, total response: ${resOfAllScaValidators.length} for single chunk`,
    );
  }

  private async sendAndWaitForRes(requests: ScaValidatorTypesRequest[], repo: Repo, index: number, isSbom: boolean) {
    let data;
    const requestId = uuid.v4();

    try {
      if (requests.length == 0) {
        return null;
      }
      const runType: string = isSbom ? "SBOM" : "SCA";
      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;

      logger.info(`[ScaValidator] sending request for repo: ${repo.fullName}, count: ${requests.length}`);

      let url = onSast ? process.env.SCA_VALIDATION_SERVICE_SQS_URL : process.env.SCA_VALIDATION_SERVICE_QUEUE_KEY;
      if (isk8) {
        url = process.env.SCA_VALIDATION_SERVICE_QUEUE_KEY;
      }

      const dirToPutRes = `${repo.scaValidatorDir}/${requestId}`;

      fs.mkdirSync(dirToPutRes, { recursive: true });

      const filePathRequest = `${dirToPutRes}/scaValidatorRequest.json`;
      fs.writeFileSync(filePathRequest, JSON.stringify(requests));

      let filePathRes = `${dirToPutRes}/scaValidator.json`;

      //If this is onPrem the zip folder is the actual code folder without a zip
      //If we are on SAST then we need the parent folder in case its mono repo and if not the regular repo
      let cloneDir = "";
      let toolCopyDestination = "";
      let monoRepoChildSubfolder = "";
      if (repo.realRepo) {
        cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;

        toolCopyDestination = repo.getRepoForToolsBasedOnEnv();
        if ((!process.env.DEBUG || process.env.DOCKER_DEBUG) && (!onPrem || isk8)) {
          toolCopyDestination = `${toolCopyDestination}_${runType}/${index.toString()}`;
        }

        monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;
      }

      let command = this.getCommand(filePathRequest, toolCopyDestination, dirToPutRes, runType);
      command = escapeCharsFromPath(command);

      const msg = {
        MesssageId: requestId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "sca-validator-service",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 900000,
        orgDisplayName: process.env["companyName"],
        cloneDir: cloneDir,
        copyType: CopyType.CodeOnly,
        toolCopyDestination: toolCopyDestination,
        isMonoRepoChild: repo.monoRepoChild,
        monoRepoChildSubfolder: monoRepoChildSubfolder,
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: repo.ignoredMonoRepoChildrenSubfolders,
        putInQueueTime: new Date().getTime(),
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = { url, msg };

      logger.info(
        `[ScaValidator] about to send msg to queue for repo: ${repo.fullName}, num of requests: ${requests.length}, msg: ${JSON.stringify(
          msg,
        )}`,
      );
      this.copyToolResults({ repoName: repo.name, dir: filePathRequest, type: runType, index });

      //From Debug(shell)
      if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
        const reqRes = await this.runShell(repo.name, msg.localCommand);
        const data = fs.readFileSync(filePathRes, "utf8");
        const scaVerificationRes = JSON.parse(data);
        return scaVerificationRes;
      }

      //From SAST(sqs)
      const reqRes = await this.scaHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        ToolsExecutionStats.addExecutionStateOnFail(
          requestId,
          OXtools.scaValidator,
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

      logger.info(
        `[ScaValidator] about to start waiting for requests repo: ${repo.fullName}, num of requests: ${
          requests.length
        }, msg: ${JSON.stringify(msg)}`,
      );

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromScaVerification = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 15; // 60 seconds * 15 = 15 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.scaValidator,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );

          StatesHelper.Instance.scanInfoStats.failedScaValidatorTimeout++;
          StatesHelper.Instance.scanInfoStats.failedScaValidatorTimeoutRepoNames.push(repo.name);

          this.setFailedEnrichmentTools(repo, requests);
          return null;
        }

        //Failed from sca
        if (fs.existsSync(failedFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.scaValidator,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.ResFileNotFound,
          );

          StatesHelper.Instance.scanInfoStats.failedScaValidatorBatches++;
          StatesHelper.Instance.scanInfoStats.failedScaValidatorRepoNames.push(repo.name);

          this.setFailedEnrichmentTools(repo, requests);
          return null;
        }

        //Done from sca
        if (fs.existsSync(doneFilePath)) {
          //setToolInfoFromDoneFile(doneFilePath, this.orgName, this.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `[ScaValidator] done file discovered from response, repo: ${repo.fullName}, num of requests: ${requests.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromScaVerification = true;
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
          OXtools.scaValidator,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );

        StatesHelper.Instance.scanInfoStats.failedScaValidatorBatches++;
        StatesHelper.Instance.scanInfoStats.failedScaValidatorRepoNames.push(repo.name);

        this.setFailedEnrichmentTools(repo, requests);
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      data = fs.readFileSync(filePathRes, "utf8");
      const scaValidatorRes = JSON.parse(data);
      this.copyToolResults({ repoName: repo.name, dir: filePathRes, index, type: runType });

      //Delete after reading
      this.fileHelper.deleteFile(filePathRes);
      this.fileHelper.deleteFile(filePathRequest);

      const failed = new Set<string>();
      ToolsExecutionStats.addToExecutionStatsFromFile(
        doneFilePath,
        requestId,
        OXtools.scaValidator,
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
        `[ScaValidator] finish waiting for sca, repo: ${repo.fullName}, num of requests: ${requests.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, sca validator res number: ${scaValidatorRes.length}, counter: ${counter}`,
      );

      return scaValidatorRes;
    } catch (err) {
      ToolsExecutionStats.addExecutionStateOnFail(
        requestId,
        OXtools.scaValidator,
        repo.fullName,
        repo.id,
        "repo",
        "",
        -1,
        ToolError.Generic,
      );
      logger.error(`[ScaValidator] failed to send batch of security alerts for repo: ${repo.fullName}, data: ${data}`, err);

      StatesHelper.Instance.scanInfoStats.failedScaValidatorBatches++;
      StatesHelper.Instance.scanInfoStats.failedScaValidatorRepoNames.push(repo.name);

      this.setFailedEnrichmentTools(repo, requests);
      return null;
    }
  }

  private setFailedEnrichmentTools(repo: Repo, requests: ScaValidatorTypesRequest[]) {
    requests.forEach(r => {
      r.toolsName.forEach(toolName => {
        repo.addFailedSecurityTools(toolName);
      });
    });
  }

  splitToChunks(array, repo: Repo) {
    const chunkSize = process.env.DEBUG && !process.env.DOCKER_DEBUG ? 20000 : 500;
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
      logger.error(`[ScaValidator] failed run shell command: ${command} to run`, err);
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
        `[ScaValidator] shell command: ${command} failed to run error: ${err} stdout: ${err.stdout + "\n"} stderr: ${err.stderr + "\n"}`,
        err,
      );

      logger.info(`[ScaValidator] finish run from shell, requester name: ${requesterName} cmd: ${command}`);
    }
  }

  copyToolResults({ repoName, dir, type, index }: { repoName: string; dir: string; type: string; index: number }): void {
    if (isUploadToS3()) {
      const oxDir = getSharedFolder(this.uuid) + "/ox-security";
      const telemetryDir = oxDir + "/telemetry-" + this.uuid;
      const repoDir = telemetryDir + "/security-report/" + repoName;
      const toolDir = repoDir + "/scaValidator/" + type.toLowerCase() + "/" + index;

      try {
        if (!fs.existsSync(toolDir)) {
          fs.mkdirSync(toolDir, { recursive: true });
        }
        this.fileHelper.copyFileSync(dir, toolDir);
      } catch (err) {
        logger.error(`[ScaValidator] failed to copy tool result file for repo name ${repoName}`, err);
      }
    }
  }

  getCommand(requestPath: string, repoDir: string, outputDir: string, runType: string) {
    if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
      return `SERVER_ENVIRONMENT=${process.env.SERVER_ENVIRONMENT} python ${process.env.SCA_VALDITOR_PATH} --source ${repoDir} --events-path ${requestPath} --output-dir ${outputDir} --run-type ${runType}`;
    }
    return `SERVER_ENVIRONMENT=${process.env.SERVER_ENVIRONMENT} python /src/sca-validator.py --source ${repoDir} --events-path ${requestPath} --output-dir ${outputDir} --run-type ${runType}`;
  }
}

export default ScaVerificationHelper;
