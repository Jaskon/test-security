import { exec } from "child_process";
import { uniq } from "lodash";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { addSeverityChangedReason, Dependency, Repo, SecurityAlertType, SecurityEvent, VCSType } from "../../entitis/codeRepoTypes";
import Constant, { OXtools } from "../../entitis/constant";
import { severityReasons } from "../../entitis/service/blameTypes";
import FileHelper from "../../helper/IO/fileHlper";
import loggerImport from "../../logger";
import { CveToolsService } from "../../mongo/cve-tools.service";
import { enableByPolicy, escapeCharsFromPath } from "../commonUtils";
import { isK8Mode, isUploadToS3 } from "../envUtils";
import { getSharedFolder, replaceAll } from "../generalUtils";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";
import { SourceToolType } from "@oxappsec/ox-consolidated-categories";

const onPrem = process.env.redisOnPrem != undefined;
const onSast = process.env.MONGO_CONN === "atlas";
const isk8 = isK8Mode();
const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();
const sharedDir = process.env.OX_SHARED_DATA === "undefined" ? "/var/shared-data" : process.env.OX_SHARED_DATA;

interface Vulnerability {
  pkgName: string;
  installedVersion: string;
  cve: string;
  severity: string;
  severityFactors: string[];
}

interface ImageScan {
  imageName: string;
  imageTag: string;
  vulnerabilities: Vulnerability[];
}

interface DockerfileScanResult {
  fileName: string;
  images: ImageScan[];
}

class dockerfileScannerHelper {
  dockerfileScannerHelperQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.dockerfileScannerHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
  }

  async setRepoDockerfileScannerInfo(repo: Repo) {
    try {
      const secEvents: SecurityEvent[] = [];

      if (repo.vcsType === VCSType.tfvc) {
        return [];
      }

      if (repo.ignoredTools.find(i => i === "docker-file-scanning")) {
        logger.info(`skipping Dockerfile Scanner, repo:${repo.fullName} due to ignoredTools`);
        return [];
      }

      //This data needed for blame and we dont need blame in delta
      if (repo.isDelta) {
        logger.info(`skipping Dockerfile Scanner, repo:${repo.fullName} due to delta`);
        return [];
      }

      if (!process.env.TOOLS_TRIVY) {
        logger.info(`skipping Dockerfile Scanner, repo:${repo.fullName} due trivy disable`);
        return;
      }

      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;

      logger.info(`try get Dockerfile Scanner, repo:${repo.fullName}`);
      repo.dockerfileScannerInfoPath = await this.sendAndWaitForRes(repo, secEvents);
      logger.info(`finish get Dockerfile Scanner, repo:${repo.fullName}, create secEvents ${secEvents.length}`);

      secEvents.forEach(secEvent => CveToolsService.instance.addToCveTools(secEvent.repoFullName, secEvent));

      return secEvents;
    } catch (err) {
      logger.error(`failed set all Dockerfile Scanner, repo:${repo.fullName}, err: ${err}`);
    }
    return [];
  }

  private async sendAndWaitForRes(repo: Repo, secEvents: SecurityEvent[]) {
    const dockerfileScannerDir = `${sharedDir}/${this.orgName}/scan_${replaceAll(this.uuid, "-", "_")}/dockerfileScanner`;
    const uniqueId = uuid.v4();
    try {
      const url = process.env.DOCKERFILE_SCANNER_QUEUE_KEY;

      if (!url && !process.env.DEBUG) {
        return null;
      }

      const dirToPutRes = `${dockerfileScannerDir}/${uniqueId}`;
      fs.mkdirSync(dirToPutRes, { recursive: true });

      const filePathRes = `${dirToPutRes}/dockerfileScanner.json`;

      let cloneDir = "";
      let toolCopyDestination = "";
      let monoRepoChildSubfolder = "";
      if (repo.realRepo) {
        cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;

        toolCopyDestination = repo.getRepoForToolsBasedOnEnv();

        monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;
      }

      let command = this.getCommand(dirToPutRes, toolCopyDestination, monoRepoChildSubfolder);
      command = escapeCharsFromPath(command);

      const msg = {
        MessageId: uniqueId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "dockerfile-scanner",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 1800000,
        orgDisplayName: process.env["companyName"],
        cloneDir: cloneDir,
        copyType: CopyType.LeanCodeOnly,
        toolCopyDestination: toolCopyDestination,
        isMonoRepoChild: repo.monoRepoChild,
        monoRepoChildSubfolder: monoRepoChildSubfolder,
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: repo.ignoredMonoRepoChildrenSubfolders,
        putInQueueTime: new Date().getTime(),
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(
        `about to send msg to queue for Dockerfile Scanner, repo:${repo.fullName}, uniqueId: ${uniqueId}, msg: ${JSON.stringify(msg)}`,
      );

      if (process.env.DEBUG) {
        const reqRes = await this.runShell(repo.name, msg.localCommand);
        await this.sleep();
        await this.sleep();
        return filePathRes;
      }

      const reqRes = await this.dockerfileScannerHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        logger.error(
          `failed enter item to Dockerfile Scanner Q, uniqueId: ${uniqueId}, repo:${repo.fullName}, msg: ${JSON.stringify(msg)}`,
        );
        repo.addFailedSecurityTools(OXtools.dockerScanner);
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.dockerScanner,
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
        `about to start waiting for Dockerfile Scanner requests, uniqueId: ${uniqueId} repo:${repo.fullName}, msg: ${JSON.stringify(msg)}`,
      );

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromDockerfileScanner = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 30; // 60 seconds * 30 = 30 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          StatesHelper.Instance.scanInfoStats.failedDockerfileScannerTimeout++;
          StatesHelper.Instance.scanInfoStats.failedDockerfileScannerTimeoutRepoNames.push(repo.name);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          repo.addFailedSecurityTools(OXtools.dockerScanner);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.dockerScanner,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );
          return null;
        }

        //Failed from Dockerfile Scanner
        if (fs.existsSync(failedFilePath)) {
          StatesHelper.Instance.scanInfoStats.failedDockerfileScannerBatches++;
          StatesHelper.Instance.scanInfoStats.failedDockerfileScannerBatchesNames.push(repo.name);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          repo.addFailedSecurityTools(OXtools.dockerScanner);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.dockerScanner,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.FailedFileFound,
          );
          return null;
        }

        //Done from Dockerfile Scanner
        if (fs.existsSync(doneFilePath)) {
          const failed = new Set<string>();
          ToolsExecutionStats.addToExecutionStatsFromFile(
            doneFilePath,
            uniqueId,
            OXtools.dockerScanner,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            failed,
          );
          if (failed.size > 0) {
            repo.addFailedSecurityTools(OXtools.dockerScanner);
            return null;
          }
          doneFromDockerfileScanner = true;
          break;
        }

        //10 seconds
        await this.sleep();
        counter--;
      }

      await this.sleep();
      if (!fs.existsSync(filePathRes)) {
        StatesHelper.Instance.scanInfoStats.failedDockerfileScannerBatches++;
        const elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

        repo.addFailedSecurityTools(OXtools.dockerScanner);
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.dockerScanner,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);

      this.copyToolResults({ repoName: repo.name, dir: filePathRes });

      logger.info(
        `finish waiting for Dockerfile Scanner, repo: ${repo.fullName}, uniqueId: ${uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, counter: ${counter}`,
      );

      // adding security events to secEvents
      const data = fs.readFileSync(filePathRes, "utf8");

      //Delete after reading
      this.fileHelper.deleteFile(filePathRes);

      //Debug
      //logger.info(`Dockerfile Scanner data: ${data}`);
      const uniqueFiles = {};

      let totalVulsFromTool = 0;
      const alerts = JSON.parse(data);
      alerts?.dockerfilesResults?.forEach((dockerfileScanResult: DockerfileScanResult) => {
        try {
          if (!dockerfileScanResult?.images) {
            return;
          }
          dockerfileScanResult?.images?.forEach((imageScan: ImageScan) => {
            try {
              if (imageScan?.vulnerabilities && imageScan.vulnerabilities.length > 0) {
                imageScan.vulnerabilities.forEach((vuln: Vulnerability) => {
                  try {
                    totalVulsFromTool++;
                    const key = dockerfileScanResult.fileName;
                    if (uniqueFiles[key]) {
                      uniqueFiles[key] = uniqueFiles[key] + 1;
                    } else {
                      uniqueFiles[key] = 1;
                    }

                    const event = new SecurityEvent(
                      SourceToolType["Open Source Security"],
                      true,
                      repo.fileLink + dockerfileScanResult.fileName + repo.linkFilePreffix,
                      new Date().toString(),
                      "",
                      "",
                      "",
                      `${imageScan.vulnerabilities.length} vulnerabilities were found on image '${imageScan.imageName}':${imageScan.imageTag}`,
                      `Liad put description here: ${imageScan.vulnerabilities.length} vulnerabilities were found on image '${imageScan.imageName}':${imageScan.imageTag}`,
                      dockerfileScanResult.fileName,
                      vuln.severity,
                      "",
                      0,
                      "",
                      SecurityAlertType.sca,
                      "",
                      "",
                      "",
                      -1,
                      true,
                      false,
                      "",
                      "",
                      "",
                      "",
                      vuln.cve,
                      `https://nvd.nist.gov/vuln/detail/${vuln.cve}`,
                      repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
                      repo.fullName,
                      repo.insideFolder,
                      repo.monoRepoChild ? repo.name.substring(1) + "/" + dockerfileScanResult.fileName : dockerfileScanResult.fileName,
                      OXtools.dockerScanner,
                    );

                    event.version = repo.defaultBranch;
                    event.blame.triggerPackage = new Dependency();
                    event.blame.triggerPackage.name = imageScan.imageName;
                    event.blame.triggerPackage.version = imageScan.imageTag;
                    event.realMatch = `${dockerfileScanResult.fileName}:${vuln.pkgName}'@${vuln.installedVersion}`;
                    event.blame.cve = vuln.cve;
                    event.pkgName = vuln.pkgName;
                    event.originalFilName = dockerfileScanResult.fileName;
                    event.installedVersion = vuln.installedVersion;
                    event.securitySubTypeAlertType = SecurityAlertType.dockerFileVul;

                    addSeverityChangedReason(severityReasons.baseContainerVull, event, undefined);
                    try {
                      if (vuln?.severityFactors) {
                        vuln.severityFactors.forEach((sfKey: string) => {
                          if (severityReasons.hasOwnProperty(sfKey)) {
                            addSeverityChangedReason(severityReasons[sfKey], event, undefined);
                          }
                        });
                      }
                    } catch (err) {
                      logger.error(`failed severityFactors, repo: ${repo.fullName}, err: ${err}`);
                    }
                    secEvents.push(event);
                  } catch (err) {
                    logger.error(`failed image vulnerabilities, repo: ${repo.fullName}, err: ${err}`);
                  }
                });
              }
            } catch (err) {
              logger.error(`failed images, repo: ${repo.fullName}, err: ${err}`);
            }
          });
        } catch (err) {
          logger.error(`failed dockerfilesResults, repo: ${repo.fullName}, err: ${err}`);
          repo.addFailedSecurityTools(OXtools.dockerScanner);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.dockerScanner,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            -1,
            ToolError.Generic,
          );
        }
      });

      ToolsExecutionStats.addExecutionStateOfAlertsNumber(
        uniqueId,
        repo.fullName,
        repo.id,
        "artifact",
        OXtools.dockerScanner,
        dirToPutRes,
        totalVulsFromTool,
        secEvents.length,
      );

      logger.info(
        `docker scanning res for repo: ${repo.fullName}, secEvents: ${secEvents.length}, uniqueFiles: ${JSON.stringify(uniqueFiles)}`,
      );

      return filePathRes; // change to return of security events
    } catch (err) {
      repo.addFailedSecurityTools(OXtools.dockerScanner);
      ToolsExecutionStats.addExecutionStateOnFail(
        uniqueId,
        OXtools.dockerScanner,
        repo.fullName,
        repo.id,
        "repo",
        "",
        -1,
        ToolError.Generic,
      );
      StatesHelper.Instance.scanInfoStats.failedDockerfileScannerBatches++;
      logger.error(`failed to send batch of Dockerfile Scanner request, repo: ${repo.fullName}, uniqueId: ${uniqueId}, err: ${err}`);
    }
  }

  getCommand(outputDir: string, repoDir: string, monoRepoChildSubfolder) {
    let exec_path: string | undefined = "/src/dockerfile-scanner.py";
    if (process.env.DEBUG) {
      exec_path = process.env.DOCKERFILE_SCANNER_PATH;
      if (monoRepoChildSubfolder) {
        return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir} --monorepo ${monoRepoChildSubfolder}`;
      } else {
        return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir}`;
      }
    }

    if (monoRepoChildSubfolder) {
      return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir} --monorepo ${monoRepoChildSubfolder}`;
    } else {
      return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir}`;
    }
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
      );

      logger.info(`finish run from shell, requester name: ${requesterName} cmd: ${command}`);
    }
  }

  copyToolResults({ repoName, dir }: { repoName: string; dir: string }): void {
    if (isUploadToS3()) {
      const oxDir = getSharedFolder(this.uuid) + "/ox-security";
      const telemetryDir = oxDir + "/telemetry-" + this.uuid;
      const repoDir = telemetryDir + "/security-report/" + repoName;
      const toolDir = repoDir + "/dockerfileScanner";

      try {
        if (!fs.existsSync(toolDir)) {
          fs.mkdirSync(toolDir, { recursive: true });
        }
        this.fileHelper.copyFileSync(dir, toolDir);
      } catch (err) {
        logger.error(`failed to copy tool dockerScan result file for repo name ${repoName}`);
      }
    }
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 10);
  }
}

export default dockerfileScannerHelper;
