import { spawn } from "child_process";
import extract from "extract-zip";
import path from "path";
import loggerImport from "../../logger";
import FileHelper from "../IO/fileHlper";
const logger = loggerImport.getDebugLogger();

export enum ZipType {
  // produced by cloner
  Code = "code.zip",
  Dotgit = "dotgit.zip",
  LeanCode = "leanCode.zip",
  // produced by pre-toolrunner service
  LeanCodeDependencyTools = "leanCodeDependencyTools.zip",
}

export class RepoZipHelper {
  fileHelper: FileHelper;

  constructor(public uuid: string) {
    this.fileHelper = new FileHelper(uuid);
  }

  private pathToZip = (dir: string, zipType: ZipType) => path.join(dir, zipType);
  private pathToLeanCodeZip = (dir: string) => this.pathToZip(dir, ZipType.LeanCode);

  private async unzipNative(pathToZip: string, destinationFolder: string) {
    const start = new Date().getTime();
    const took = () => (new Date().getTime() - start) / 1000;

    const zipSizeB = await this.fileHelper.getFileSize(pathToZip);
    const zipSizeMB = zipSizeB / 1024 / 1024;

    const cmd = "unzip";
    // -q: quiet mode
    // -o: overwrite existing files without prompting (unattended operation)
    const args = ["-q", "-o", pathToZip, "-d", destinationFolder];

    const errorMessage = (tail: string) =>
      `error while unzipping (native) via '${cmd} ${args.join(" ")}', zip size: ${zipSizeMB} MB, after ${took()} seconds. ` + tail;

    const bufferedStdout: string[] = [];
    const bufferizeStdout = (data: string) => {
      bufferedStdout.push(data);
      bufferedStdout.slice(-20);
    };

    let spawned = false;

    const healthcheckIntervalId = setInterval(() => {
      logger.info(
        `unzip process via '${cmd} ${args.join(" ")}' is taking ${took()} seconds, spawned: ${spawned}, ` +
          `last stdout: ${bufferedStdout.join("; ")}`,
      );
    }, 10 * 1000);
    const clearHealthcheckInterval = () => clearInterval(healthcheckIntervalId);

    return new Promise<void>((resolve, reject) => {
      const ps = spawn(cmd, args);

      ps.on("spawn", () => {
        spawned = true;
      });

      ps.on("error", e => {
        logger.error(errorMessage(`failed to start subprocess, e: ${e}`));
        clearHealthcheckInterval();
        reject();
      });

      // debug
      // ps.stdout?.on("data", data => bufferizeStdout(data.toString("utf-8").trim()));

      ps.stderr?.on("data", data => {
        logger.error(errorMessage(`stderr: ${data}`));
        clearHealthcheckInterval();
        reject();
      });

      // since we don't really care about stdio streams being closed, we listen to exit event
      // https://nodejs.org/api/child_process.html#event-close
      // https://nodejs.org/api/child_process.html#event-exit
      ps.on("exit", (code, signal) => {
        clearHealthcheckInterval();
        if (code === 0) {
          logger.info(
            `successfully unzipped (native) via '${cmd} ${args.join(" ")}', ` +
              `zip size: ${zipSizeMB} MB, ` +
              `unzip took ${took()} seconds`,
          );
          return resolve();
        }

        logger.error(errorMessage(`non-zero exit code ${code} or signal ${signal}`));
        reject();
      });
    });
  }

  // left just in case we need to go back to JS unzipping
  private async unzipJS(pathToZip: string, destinationFolder: string) {
    try {
      logger.debug(`unzipping ${pathToZip} to ${destinationFolder}`);
      const start = new Date().getTime();
      const zipSize = await this.fileHelper.getFileSize(pathToZip);
      let fileCount = 0;
      await extract(pathToZip, {
        dir: destinationFolder,
        onEntry: entry => {
          if (entry?.fileName?.endsWith("/")) return;
          fileCount++;
        },
      });
      const end = new Date().getTime();
      logger.info(
        `successfully unzipped ${pathToZip} to ${destinationFolder}, ` +
          `zip size: ${zipSize / 1024 / 1024} MB, file count: ${fileCount}, ` +
          `unzip took ${(end - start) / 1000} seconds`,
      );
    } catch (err) {
      logger.error(`error while unzipping from ${pathToZip} to ${destinationFolder}, err: ${err}`);
      throw err;
    }
  }

  private async unzip(pathToZip: string, destinationFolder: string) {
    return this.unzipNative(pathToZip, destinationFolder);
  }

  public async unzipRepo(codeZipDir: string, cloneDir: string, repoFullName: string) {
    try {
      logger.info(`try unzipping ${repoFullName}`);

      // create temp dir for the zips
      const tempZipsDir = `${cloneDir}-zips`;
      this.fileHelper.createDir(tempZipsDir);
      this.fileHelper.createDir(cloneDir);

      // lean zip
      await this.fileHelper.copyFile(this.pathToLeanCodeZip(codeZipDir), this.pathToLeanCodeZip(tempZipsDir));
      await this.unzip(this.pathToLeanCodeZip(tempZipsDir), cloneDir);

      // delete temp dir with zips
      this.fileHelper.deleteDir(tempZipsDir);

      logger.info(`finish unzip clone by external service, repo: ${repoFullName}`);
    } catch (err) {
      logger.error(`unable to unzip repo from ${codeZipDir} to ${cloneDir}, err: ${err}`);
      throw err;
    }
  }

  public async unzipTfvcRepo(pathToZip: string, cloneDir: string) {
    try {
      // unzip from to clone dir
      await this.unzip(pathToZip, cloneDir);
      // delete zip
      //this.fileHelper.deleteFile(pathToZip);
    } catch (err) {
      logger.error(`unable to unzip tvfc repo from ${pathToZip} to ${cloneDir}, err: ${err}`);
      throw err;
    }
  }
}
