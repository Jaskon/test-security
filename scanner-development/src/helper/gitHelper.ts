import { Repo, RepositoryInfoJSON, repoType, VCSType } from "../entitis/codeRepoTypes";
import loggerImport from "../logger";
import { RepoZipHelper, ZipType } from "./compression/unzipHelper";
import FileHelper from "./IO/fileHlper";
import { millisToMinutesAndSeconds } from "./telemetry-utils";

import Timeout from "await-timeout";
import * as child_process from "child_process";
import fsExtra from "fs-extra";
import PQueue from "p-queue";
import util from "util";
import afPubSub from "../appmgr/AFPubSub";
import CodeRepoBase from "../dal/base/codeRepoBase";
import { OXtools } from "../entitis/constant";
import { downloadTfsZipViaCurl } from "../helper/localTFScloner";
import { copyToolInfo } from "./commonUtils";
import { isK8Mode, isLocalDevelopment } from "./envUtils";
import { PipeLineHelper } from "./pipelineHelper";
import StatesHelper, { PerformanceType } from "./statesHelper";
import { ToolError, ToolsExecutionStats } from "./toolExecutionStats";
const logger = loggerImport.getDebugLogger();
const clone = require("git-clone/promise");
const fs = require("fs");
const Timeout = require("await-timeout");
const exec = util.promisify(child_process.exec);
const uuid = require("uuid");

const onSaas = process.env.MONGO_CONN === "atlas";
const isk8 = isK8Mode();

const pathToLeanZip = (dir: string) => `${dir}/${ZipType.LeanCode}`;
const pathToRepoInfoJSON = (dir: string) => `${dir}-repo-info.json`;
const pathToGitInfoJSON = (dir: string) => `${dir}-git-info.json`;

class GitHelper {
  uuid: string;
  orgName: string;
  repoZipHelper: RepoZipHelper;
  unzipQ: PQueue;
  fileHelper: FileHelper;

  constructor(uuid: string, orgName: string) {
    this.uuid = uuid;
    this.orgName = orgName;
    this.repoZipHelper = new RepoZipHelper(uuid);
    this.fileHelper = new FileHelper(uuid);
  }

  async cloneRepo(repo: Repo, collector: CodeRepoBase) {
    let success = false;
    try {
      success = await this.cloneInternalRepo(repo, collector);
      logger.info(`clone internal repo: ${repo.fullName} stage 1 result: ${success}`);

      if (!success && !repo.isDelta && !StatesHelper.Instance.isPipelineScan) {
        repo.isDelta = true;
        success = await this.cloneInternalRepo(repo, collector);
        logger.info(`clone internal after failed first try, repo: ${repo.fullName}, second try res: ${success}`, {
          "ox-tool-name": "cloner",
          "retrieve-from-cache": success,
          "ox-tool-items-sent": 1,
          "ox-tool-items-retrieve": success ? 1 : 0,
        });
      }

      if (success && !repo.isDelta) {
        const repoInfoJSONPath = `${repo.codeZipDir}-repo-info.json`;
        copyToolInfo(repo.name, repoInfoJSONPath, "cloner", this.uuid);
      }
    } catch (error) {
      logger.error(`could not clone internal repo: ${repo.fullName}, error: ${error}`);
    } finally {
      return success;
    }
  }

  async cloneInternalRepo(repo: Repo, collector: CodeRepoBase) {
    let requestId = uuid.v4();
    try {
      //Debug
      if (process.env.DEBUG != undefined && !process.env.DOCKER_DEBUG) {
        if (repo.vcsType === VCSType.tfvc) {
          //For local
          // const tfsUrl = repo.tfsUrl;
          // const tfsRepoClonePath = repo.tfsRepoClonePath;
          // const tfsToken = repo.tfsToken;
          //await cloneTfsRepoLocaly(repo, tfsRepoClonePath, tfsToken, tfsUrl);

          this.fileHelper.createDir(repo.codeZipDir);
          await downloadTfsZipViaCurl(repo.tfsToken, `${repo.codeZipDir}/code.zip`, repo.name);
          return true;
        } else {
          const resFromGit = await this.cloneRepoFromGit(repo);
          StatesHelper.Instance.clonedRepos[repo.fullName] = repo.cloneDir;
          return resFromGit;
        }
      }

      let retry = 400;
      if (repo.vcsType === VCSType.tfvc || repo.type === repoType.gerrit) {
        retry = 850;
      }

      logger.info(
        `try clone by external service, retry: ${retry}, vcsType: ${repo.vcsType === VCSType.tfvc}, repo: ${repo.fullName} to ${
          repo.codeZipDir
        }`,
      );

      const doneFilePath = `${repo.codeZipDir}.done`;
      const failedFilePath = `${repo.codeZipDir}.fail`;

      const startTimeBeforWait = new Date().getTime();
      const sendRes = await this.cloneRepoViaSqs(repo, collector, requestId);
      if (sendRes == true) {
        await this.repoZipHelper.unzipRepo(repo.codeZipDir, repo.cloneDir, repo.fullName);
        const elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTimeBeforWait);
        StatesHelper.Instance.clonedRepos[repo.fullName] = repo.cloneDir;
        await this.sendAFPubSub(repo);
        logger.info(`finish clone from local disk cash, time in minutes: ${elapsedTime}, repo: ${repo.fullName} to ${repo.codeZipDir}`);
        return true;
      }

      let cloneRequestRetryHappen = false;

      if (sendRes != null) {
        //Wait for clone to finish by long pulling
        const startTime = new Date().getTime();

        while (retry > 0) {
          if (fs.existsSync(doneFilePath)) {
            break;
          }

          if (fs.existsSync(failedFilePath)) {
            logger.info(`failedFilePath in clone detected for repo: ${repo.fullName} to ${repo.codeZipDir}`);

            //Git
            if (repo.vcsType === VCSType.git) {
              let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
              ToolsExecutionStats.addExecutionStateOnFail(
                requestId,
                OXtools.cloner,
                repo.fullName,
                repo.id,
                "repo",
                repo.cloneDir,
                elapsedTimeProcessTime,
                ToolError.FailedFileFound,
              );

              StatesHelper.Instance.scanInfoStats.failedClones++;
              StatesHelper.Instance.scanInfoStats.failedClonesRepoNames.push(repo.name);
              return false;
            }

            //Not Git
            if (cloneRequestRetryHappen) {
              let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
              ToolsExecutionStats.addExecutionStateOnFail(
                requestId,
                OXtools.cloner,
                repo.fullName,
                repo.id,
                "repo",
                repo.cloneDir,
                elapsedTimeProcessTime,
                ToolError.FailedFileFound,
              );

              StatesHelper.Instance.scanInfoStats.failedClones++;
              StatesHelper.Instance.scanInfoStats.failedClonesRepoNames.push(repo.name);
              return false;
            } else {
              logger.info(`retry clone repo: ${repo.fullName} to ${repo.codeZipDir}`);

              //Makr to do it once only
              cloneRequestRetryHappen = true;

              //Delete any leftovers as clone failed
              this.fileHelper.deleteFile(failedFilePath);
              this.fileHelper.deleteFile(doneFilePath);

              //Try to resend again
              const sendRes = await this.cloneRepoViaSqs(repo, collector, requestId);
              if (sendRes == null) {
                logger.info(`will not retry clone repo: ${repo.fullName} to ${repo.codeZipDir}`);
                return false;
              }
            }
          }

          retry--;
          await sleep();
        }

        //Failed due timeout
        if (retry <= 0) {
          StatesHelper.Instance.scanInfoStats.timeoutClones++;
          StatesHelper.Instance.scanInfoStats.timeoutClonesRepoNames.push(repo.name);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            requestId,
            OXtools.cloner,
            repo.fullName,
            repo.id,
            "repo",
            repo.cloneDir,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );
          return false;
        }

        //Finished
        let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);

        logger.info(
          `finish clone by external service, time in minutes: ${elapsedTime}, repo: ${repo.fullName} retry: ${retry}, to ${repo.codeZipDir}`,
        );

        if (onSaas || isk8) {
          await this.repoZipHelper.unzipRepo(repo.codeZipDir, repo.cloneDir, repo.fullName);
        }

        const failed = new Set<string>();
        ToolsExecutionStats.addToExecutionStatsFromFile(
          doneFilePath,
          requestId,
          OXtools.cloner,
          repo.fullName,
          repo.id,
          "repo",
          repo.cloneDir,
          failed,
        );
        if (failed.size > 0) {
          return false;
        }

        StatesHelper.Instance.clonedRepos[repo.fullName] = repo.cloneDir;
        await this.sendAFPubSub(repo);

        return true;
      }
    } catch (err) {
      logger.error(`failed clone by external service repo: ${repo.name} err ${err}`);

      StatesHelper.Instance.scanInfoStats.failedClones++;
      StatesHelper.Instance.scanInfoStats.failedClonesRepoNames.push(repo.name);
      ToolsExecutionStats.addExecutionStateOnFail(requestId, OXtools.cloner, repo.fullName, repo.id, "repo", "", -1, ToolError.Generic);
    }

    return false;
  }

  async getHeadSha(repo: Repo) {
    const command = `git -C ${repo.cloneDir} rev-parse HEAD`;

    try {
      logger.info(`try retrieving HEAD sha, repo: ${repo.name}, cmd: ${command}`);

      const { stdout, stderr } = await exec(command);

      const maybeSha = stdout.trim();
      const shaRegex = /\b([a-f0-9]{40})\b/;
      if (shaRegex.test(maybeSha)) {
        logger.info(`retrieved HEAD sha, repo: ${repo.name}, sha: ${maybeSha}`);
        return maybeSha;
      }

      logger.warn(
        `${command} output is unexpected, not a sha, repo: ${repo.name}, stdout: ${JSON.stringify(stdout)}, stderr:, ${JSON.stringify(
          stderr,
        )}`,
      );
      return null;
    } catch (err) {
      const msg = `failed to retrieve HEAD sha, error: ${err} stdout: ${err.stdout} stderr: ${err.stderr}`.replace("\n", "; ").trim();
      logger.error(msg);
      return null;
    }
  }

  async getHistorySizeWithTimeout(repo: Repo): Promise<number> {
    const longHistoryCutoffConstant = 1000000000;

    const getHistorySize = async () => {
      try {
        const { stdout, stderr } = await exec(`git -C ${repo.cloneDir} log -p -U0 --full-history --all | wc -c`, {
          maxBuffer: 1024 * 1024 * 10,
        });

        logger.info(`getHistorySize stdout: ${stdout}, stderr: ${stderr}`);

        return parseInt(stdout.trim().replace("\r|\n", ""));
      } catch (e) {
        logger.error(`Error getting history size for ${repo.name}} in ${repo.cloneDir}: `, e);
      }
      return 0;
    };

    try {
      logger.info(`Trying to determine the history size of ${repo.name}`);

      const result = await Timeout.wrap(
        getHistorySize(),
        30 * 1000,
        `Reached a timeout trying to figure out the history size of ${repo.name}`,
      );

      return result;
    } catch (err) {
      logger.error(`failed getHistorySizeWithTimeout, repo: ${repo.name} err ${err}`);
      return longHistoryCutoffConstant;
    }
  }

  async sendAFPubSub(repo: Repo) {
    try {
      await afPubSub.instance.publish(this.uuid, repo.fullName, {
        id: repo.fullName,
        cloneDir: repo.cloneDir,
      });
    } catch (err) {
      logger.error(`failed send AFPubSub repo: ${repo.name} err ${err}`);
    }
  }

  async cloneRepoFromGit(repo: Repo) {
    try {
      const fileHelper: FileHelper = new FileHelper(this.uuid);

      fileHelper.createDir(repo.codeZipDir);

      logger.info(`try clone by git repo: ${repo.fullName} to ${repo.codeZipDir}`);

      const startTime = new Date().getTime();

      if (repo.cloneURL.includes("GIT_SSH_COMMAND ")) {
        await this.shell(repo.fullName, repo.cloneURL);
      } else if (process.env.DISABLE_GIT_CLONE !== "true") {
        const config = repo.cloneArgs ? { args: repo.cloneArgs } : [];
        await Timeout.wrap(clone(repo.cloneURL, repo.codeZipDir, config), 1000 * 60 * 20, "Timeout clone");
      }

      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);

      logger.info(`finish clone clone by git time in minutes: ${elapsedTime}, repo: ${repo.fullName} to ${repo.codeZipDir}`);

      return true;
    } catch (err) {
      if (process.env.DEBUG) {
        return true;
      }
      logger.error(`failed clone by git repo: ${repo.name} to ${repo.codeZipDir}, err: ${err}`);
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

  getFilePathInRepo = (pathInfo: string, repoName: string) => {
    if (pathInfo.includes(`clone`)) {
      const clonePos = pathInfo.indexOf(`clone`);
      pathInfo = pathInfo.substring(clonePos + `clone`.length);

      const projectPos = pathInfo.indexOf(repoName);
      pathInfo = pathInfo.substring(projectPos + repoName.length);
    }

    if (pathInfo.startsWith("\\")) {
      pathInfo = pathInfo.substring("\\".length);
    } else if (pathInfo.startsWith("/")) {
      pathInfo = pathInfo.substring("/".length);
    }
    return pathInfo;
  };

  private async getFullScanMonoRepoInfoForPipelineScan(repo: Repo): Promise<{ isMonoRepo: boolean; monoRepoChildren: string[] } | null> {
    if (!StatesHelper.Instance.isPipelineScan) return null;

    try {
      const persistedRepoInfoFileExists = await fsExtra.pathExists(pathToRepoInfoJSON(repo.persistentCloneDir));
      if (!persistedRepoInfoFileExists) return null;

      await fsExtra.copy(pathToRepoInfoJSON(repo.persistentCloneDir), pathToRepoInfoJSON(repo.codeZipDir));
      const rawRepoInfoJSON = await fsExtra.readFile(pathToRepoInfoJSON(repo.codeZipDir), { encoding: "utf8" });
      const repoInfoJSON: RepositoryInfoJSON = JSON.parse(rawRepoInfoJSON);

      return {
        isMonoRepo: repoInfoJSON.isMonoRepo,
        monoRepoChildren: repoInfoJSON.repoInfoPerMonorepoChild.map(child => child.monoRepoChild),
      };
    } catch (e) {
      logger.error(`[getFullScanMonoRepoInfoForPipelineScan] unable to retrieve, e: ${e}`);
      return null;
    }
  }

  private async cloneRepoViaSqs(repo: Repo, collector: CodeRepoBase, requestId: string) {
    let url = onSaas ? process.env.CLONER_SERVICE_SQS_URL : process.env.CLONER_QUEUE_KEY;
    if (isk8 || process.env.DOCKER_DEBUG) {
      url = process.env.CLONER_QUEUE_KEY;
    }

    try {
      //Checking if we can skip clone in case its delta repo and no filed operation was done by the tools
      const shouldSkipClone = repo.isDelta;
      if (shouldSkipClone) {
        let [leanZipFileExist, repoInfoFileExist, gitInfoFileExist] = await Promise.all([
          fsExtra.pathExists(pathToLeanZip(repo.persistentCloneDir)),
          fsExtra.pathExists(pathToRepoInfoJSON(repo.persistentCloneDir)),
          fsExtra.pathExists(pathToGitInfoJSON(repo.persistentCloneDir)),
        ]);

        if (repo.vcsType === VCSType.tfvc) {
          gitInfoFileExist = true;
        }

        if (leanZipFileExist && repoInfoFileExist && gitInfoFileExist) {
          logger.info(
            `no need for clone for repo: ${repo.fullName}, due to delta, leanZipFileExist: ${leanZipFileExist}, repoInfoFileExist: ${repoInfoFileExist}, gitInfoFileExist: ${gitInfoFileExist} in: ${repo.persistentCloneDir}`,
          );

          await fsExtra.copy(pathToLeanZip(repo.persistentCloneDir), pathToLeanZip(repo.codeZipDir));
          await fsExtra.copy(pathToRepoInfoJSON(repo.persistentCloneDir), pathToRepoInfoJSON(repo.codeZipDir));

          if (repo.vcsType !== VCSType.tfvc) {
            await fsExtra.copy(pathToGitInfoJSON(repo.persistentCloneDir), pathToGitInfoJSON(repo.codeZipDir));
          }

          repo.failedClone = false;
          repo.successfulClone = true;

          StatesHelper.Instance.scanInfoStats.skippedClonesDueToCash++;
          return true;
        }

        logger.warn(
          `repo: ${repo.fullName} is delta but missing a file, leanZipFileExist: ${leanZipFileExist}, repoInfoFileExist: ${repoInfoFileExist}, gitInfoFileExist: ${gitInfoFileExist}, persistentCloneDir: ${repo.persistentCloneDir} going to try to clone`,
        );
      }
    } catch (err) {
      logger.error(`failed to retrieve clone from cache for delta for ${repo.name}, err: ${err}`);
    }

    // for pipeline scans when pulling files from API we need to do our best to retain the monorepo split at least based on the previous full scan
    const fullScanMonoRepoInfo = await this.getFullScanMonoRepoInfoForPipelineScan(repo);

    const tools: string[] = collector.toolsCreator.securityTools.map(i => i.toolConfig.nameForExternalService);
    const extraFilesToRead = [...StatesHelper.Instance.filesToRead.values()].flat().map(f => f.replace(".", "\\.").toLowerCase());

    if (StatesHelper.Instance.isPipelineScan) {
      if (
        PipeLineHelper.Instance.performance === PerformanceType.fast ||
        PipeLineHelper.Instance.performance === PerformanceType.fastest ||
        PipeLineHelper.Instance.performance === PerformanceType.regular
      ) {
        repo.useDotGit = false;
      }
    }

    let sourceBranch = StatesHelper.Instance.isPipelineScan ? repo.pipelineScanInfo.sourceBranch : undefined;
    if (repo.sourceBranch) {
      sourceBranch = repo.sourceBranch;
    }

    const msg = {
      MessageId: requestId,
      orgId: collector.orgName,
      orgDisplayName: process.env["companyName"],
      scanId: this.uuid,
      type: repo.type,
      repoName: repo.fullName,
      repoURL: repo.cloneURL,
      cloneDir: repo.codeZipDir,
      securityResDir: repo.securityResDir,
      enabledTools: tools,
      sourceBranch: sourceBranch,
      targetBranch: repo.pipelineScanInfo.targetBranch,
      monoRepoSplit: StatesHelper.Instance.monoRepoSplit,
      monoRepoSplitByList: StatesHelper.Instance.monoRepoSplitByList,
      sha: repo.pipelineScanInfo.sha,
      baseSha: repo.pipelineScanInfo.baseSha,
      putInQueueTime: new Date().getTime(),
      tfsUrl: repo.tfsUrl,
      tfsRepoClonePath: repo.tfsRepoClonePath,
      tfsToken: repo.tfsToken,
      SSHKey: StatesHelper.Instance.pathToSSHKeyGerrit,
      isPipelineScan: StatesHelper.Instance.isPipelineScan,
      provideDotGit: repo.useDotGit, // eventually `true` if PerformanceType === detailed, `false` on other types. only applied for pipeline scans
      fullScanMonoRepoInfo,
      filesModifiedInPullRequest: repo.filesModifiedInPullRequest,
      apiCredentials: StatesHelper.Instance.isPipelineScan ? await collector.getAPICredentials(repo) : null,
      apiRepoInfo: StatesHelper.Instance.isPipelineScan ? collector.getAPIRepoInfo(repo) : null,
      cloneType: repo.vcsType === VCSType.tfvc ? "tfs" : "git",
      regexes: [
        "\\.bandit",
        "\\.semgrepignore",
        "\\.gitignore", // https://gitlab.com/oxsecurity/app/scanner/-/blob/aff933d368ae1b34ab3c81ce46068bdd9149c7f3/src/dal/base/codeRepoBase.ts#L2422
        "dockerfile", // https://gitlab.com/oxsecurity/app/scanner/-/blob/58785a174cb72dc9e1327a5ec30e20e5ad7896d5/src/helper/tools/dockerScanner.ts#L566
        "Jenkinsfile",
        "\\.teamcity|teamcity\\.|/rest/vcs-root",
        "\\.buildkite",
        "\\.CircleCI",
        "makefile",
        "publish",
        "deploy",
        "ignore$",
        "lock$",
        "settings",
        "\\.sh$",
        "\\.txt$",
        "properties$",
        "\\.ya?ml$",
        "\\.xml$",
        "\\.ini$",
        "\\.toml$",
        "\\.npmrc$",
        "\\.gradle$",
        "\\.gradle.kts$",
        "\\.build$",
        "\\.lockfile$",
        "\\.config$",
        "\\.mod$",
        "\\.json$",
        "\\.sum$",
        "\\.sbt$",
        "\\.tf$",
        "\\.bzl$",
        "\\.bazel$",
        "\\.cmake$",
        "\\.config$",
        "\\.csproj$",
        "gemfile$",
        "Dependencies\\.kt",
        "Dependencies\\.scala",
        "CMakeLists\\.txt$",
        "conanfile\\.txt$",
        "conanfile\\.py",
        "\\.yarnrc\\.yml$",
        "\\.yarnrc$",
        "WORKSPACE",
        "Pipfile",
        "setup\\.py",
        "Podfile",
        "manifest.json",
        ...extraFilesToRead,
      ], // list from Eyal
      // hashRegexes: ["\\.py$", "package\\.json$"], // list from Gady, decided against this solution for now
      lastCodeChangeAt: repo.lastPushTime,
      args: repo.cloneArgs,
      persistentCloneDir: repo.persistentCloneDir,
      timeout: repo.vcsType === VCSType.tfvc || repo.type === repoType.gerrit ? 65 : 35,
    };

    const info = { url: url, msg: msg };

    StatesHelper.Instance.scanInfoStats.sendToClone++;

    const msgSendRes = await collector.clonerQueue.sendQueueMessage(info);
    if (msgSendRes == false) {
      logger.error(`failed to send clone message for ${repo.name}, url: ${url}, codeZipDir: ${repo.codeZipDir}`);
      return null;
    } else {
      logger.info(
        `SEND clone message for ${repo.name}, url: ${url}, persistentCloneDir: ${repo.persistentCloneDir}, codeZipDir: ${repo.codeZipDir} (msgId: ${msg.MessageId}), useDotGit: ${repo.useDotGit}, sourceBranch: ${sourceBranch}, pipeLine performance: ${PipeLineHelper.Instance.performance}`,
      );
    }
    return msg;
  }
}

export async function waitForClonedRepoAndGetDirPath(repoFullName: string, defaultRetry: number = isLocalDevelopment() ? 1 : 60) {
  // kyz: On super slow repos it takes up-to 25 minutes, see:
  // https://oxsecurity.atlassian.net/browse/OXDEV-9625?focusedCommentId=10890
  let retry = defaultRetry;
  try {
    let clonePath = "";
    while (retry) {
      clonePath = StatesHelper.Instance.clonedRepos[repoFullName];
      if (clonePath === "not-important") {
        logger.info(`skipping wait for cloned repo: ${repoFullName}, not important repo`);
        return "";
      }
      if (clonePath) {
        break;
      }
      retry--;
      await sleep();
    }
    if (retry > 0) {
      return clonePath;
    }
    logger.error(`failed to wait for cloned repo: ${repoFullName}, retry are 0`);
    return "";
  } catch (err) {
    logger.error(`failed to wait for cloned repo: ${repoFullName}, err: ${err}`);
    return "";
  }
}

async function sleep() {
  const delay = ms => new Promise(res => setTimeout(res, ms));
  await delay(1000 * 5);
}

export default GitHelper;
