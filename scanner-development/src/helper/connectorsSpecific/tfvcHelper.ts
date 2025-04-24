import { Repo } from "../../entitis/codeRepoTypes";
import FileHelper from "../IO/fileHlper";
import { RepoZipHelper } from "../compression/unzipHelper";
import loggerImport from "../../logger";
import StatesHelper from "../statesHelper";
import { ITfvcApi } from "azure-devops-node-api/TfvcApi";
import { VersionControlRecursionType } from "azure-devops-node-api/interfaces/TfvcInterfaces";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
const Timeout = require("await-timeout");
const uuidEx = require("uuid");
const logger = loggerImport.getDebugLogger();
const fs = require("fs");

export class TfvcHelper {
  uuid: string;
  orgName: string;
  tfsApi: ITfvcApi;
  repoZipHelper: RepoZipHelper;

  constructor(uuid: string, orgName: string, tfsApi: ITfvcApi) {
    this.uuid = uuid;
    this.orgName = orgName;
    this.tfsApi = tfsApi;
    this.repoZipHelper = new RepoZipHelper(uuid);
  }

  async downloadRepo(repo: Repo, tfsApiPath: string) {
    try {
      const res = await Timeout.wrap(this.downloadRepoEx(repo, tfsApiPath), 1000 * 60 * 10, "Timeout clone");

      return res;
    } catch (err) {
      logger.error(`failed downloading tfvc repo: ${repo.name}, e: ${err}`);
    }
    return false;
  }

  async downloadRepoEx(repo: Repo, tfsApiPath: string) {
    try {
      const fileHelper: FileHelper = new FileHelper(this.uuid);
      fileHelper.createDir(repo.cloneDir);

      const folderToDownload = repo.cloneDir + "/" + `${uuidEx.v4()}`;
      const pathToZip = folderToDownload + "/" + `${uuidEx.v4()}_repo.zip`;

      fileHelper.createDir(folderToDownload);

      const startTimeDownload = new Date().getTime();
      logger.info(`try download zip for repo: ${repo.name}, path: ${tfsApiPath}`);
      await this.downloadTfsZip(tfsApiPath, pathToZip);
      let elapsedTimeDownload = millisToMinutesAndSeconds(new Date().getTime() - startTimeDownload);
      logger.info(`finish download zip for repo: ${repo.name}, path: ${tfsApiPath} in elapsedTime: ${elapsedTimeDownload}`);

      const startTimeUnzip = new Date().getTime();
      logger.info(`try download zip for repo: ${repo.name}, path: ${tfsApiPath}`);
      logger.info(`try unzip for repo: ${repo.name}, path: ${tfsApiPath}`);
      let elapsedTimeUnzip = millisToMinutesAndSeconds(new Date().getTime() - startTimeUnzip);
      await this.repoZipHelper.unzipTfvcRepo(pathToZip, repo.cloneDir);
      logger.info(`finish unzip for repo: ${repo.name}, path: ${tfsApiPath} in elapsedTime: ${elapsedTimeUnzip}`);

      return true;
    } catch (e) {
      logger.error(`Error downloading tfvc repo for: ${repo.name}: err: ${e}`);
      return false;
    }
  }

  async downloadTfsZip(tfsApiPath: string, pathToZip: string) {
    return new Promise<void>(async (resolve, reject) => {
      try {
        const zipReadableStream = await this.tfsApi.getItemZip(tfsApiPath);

        const fsWritableStream = fs.createWriteStream(pathToZip);

        fsWritableStream.on("pipe", () => logger.info(`started piping from readable stream into file ${pathToZip} ${tfsApiPath}`));

        fsWritableStream.on("error", e => {
          logger.error(`error on writable stream while piping from readable stream into file ${pathToZip} for ${tfsApiPath}`, e);
          reject(e);
        });

        zipReadableStream.on("error", e => {
          logger.error(`error on readable stream while piping from readable stream into file ${pathToZip} for ${tfsApiPath}`, e);
          reject(e);
        });

        zipReadableStream.on("end", () => {
          fsWritableStream.close();
          logger.info(`finished piping from readable stream into file ${pathToZip} for ${tfsApiPath}`);
          resolve();
        });

        zipReadableStream.pipe(fsWritableStream);
      } catch (e) {
        reject(`unable to get zip readable stream for path: ${tfsApiPath}, err: ${e}`);
      }
    });
  }
}
