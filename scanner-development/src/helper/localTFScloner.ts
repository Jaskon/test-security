import * as azdev from "azure-devops-node-api";
import * as fs from "fs";
import loggerImport from "../logger";
import { Repo } from "../entitis/codeRepoTypes";
import { TfvcHelper } from "./connectorsSpecific/tfvcHelper";
import FileHelper from "./IO/fileHlper";
import { RepoZipHelper, ZipType } from "./compression/unzipHelper";
const util = require("util");
const path = require("path");
const exec = util.promisify(require("child_process").exec);

const logger = loggerImport.getDebugLogger();

export async function cloneTfsRepoLocaly(repo: Repo, path: string, token: string, orgUrl: string) {
  const fileHelper: FileHelper = new FileHelper("");
  fileHelper.createDir(repo.codeZipDir);
  fileHelper.createDir(repo.cloneDir);
  const pathToZip = `${repo.codeZipDir}/${ZipType.Code}`;

  let lastErr;

  const authHandler = azdev.getPersonalAccessTokenHandler(token);
  const connection = new azdev.WebApi(orgUrl, authHandler, {
    socketTimeout: 50 * 60 * 1000,
  });
  const tfvcApi = await connection.getTfvcApi();

  let retry = 4;
  while (retry > 0) {
    try {
      if (path) {
        //Try to delete old one
        fileHelper.deleteFile(pathToZip);

        logger.info(`try clone on tfs repo: ${repo.fullName} to: ${pathToZip}, retry: ${retry}`);
        await downloadTfsZip(path, pathToZip, tfvcApi);
        logger.info(`finish clone on tfs repo: ${repo.fullName} to: ${pathToZip}, retry: ${retry}`);
        repo.successfulClone = true;

        const repoZipHelper: RepoZipHelper = new RepoZipHelper("");
        await repoZipHelper.unzipTfvcRepo(pathToZip, repo.cloneDir);
        logger.info(`finish unzip on tfs repo: ${repo.fullName} to: ${repo.cloneDir}, retry: ${retry}`);
      } else {
        logger.error(`failed cloneTfsRepoLocaly, repoName: ${repo.fullName} path are empty, retry: ${retry}`);
        repo.failedClone = true;
        return;
      }
    } catch (error) {
      lastErr = error;
    }
    if (repo.successfulClone) {
      return;
    }
    retry--;
    //sleep 3 m
    await sleep();
  }
  if (lastErr) {
    logger.error(`failed cloneTfsRepoLocaly, repoName: ${repo.fullName}, err: ${lastErr}, retry: ${retry}`);
    lastErr;
  }
  repo.failedClone = true;
}

export async function downloadTfsZipViaCurl(token: string, pathToZip: string, repoName: string) {
  return new Promise<void>(async (resolve, reject) => {
    try {
      //curl --retry 100 -u ":6jtd2kbbddumnlcur47xikztydiuvytyi2bsxw6w7p7qry5tqhpq" -H "Accept: application/zip" "https://dev.azure.com/MamanGroup/_apis/tfvc/items?path=%24%2FLauferGHI-Elis" -o Z:\Development\Maman\Elis.zip
      //curl --retry 100 -u ":6jtd2kbbddumnlcur47xikztydiuvytyi2bsxw6w7p7qry5tqhpq" -H "Accept: application/zip" "https://dev.azure.com/MamanGroup/_apis/tfvc/items?path=%24%2fLauferGHI-Elis" -o C:/CLONE/org_k3J32UDhElDcg9bc/scan_6913c325_347e_4cca_9849_4114866a071d/clone/AzureReposTFVC/LauferGHI-Elis_64f42e32-9792-443b-acd0-5a8dcd7482e1/code.zip

      const command = `curl --retry 100 -u ":${token}" -H "Accept: application/zip" "https://dev.azure.com/MamanGroup/_apis/tfvc/items?path=%24%2F${repoName}" -o ${pathToZip}`;

      await runShell(pathToZip, command);
      resolve();
    } catch (e) {
      reject(`unable to get zip readable stream for path: ${pathToZip}, repo: ${repoName}, err: ${e}`);
    }
  });
}

export async function downloadTfsZip(tfsApiPath: string, pathToZip: string, tfsApi: any) {
  return new Promise<void>(async (resolve, reject) => {
    try {
      const zipReadableStream = await tfsApi.getItemZip(tfsApiPath);

      const fsWritableStream = fs.createWriteStream(pathToZip);

      fsWritableStream.on("pipe", () => logger.info(`started piping from readable stream into file ${pathToZip} ${tfsApiPath}`));

      fsWritableStream.on("error", e => {
        logger.error(`error on writable stream while piping from readable stream into file ${pathToZip} for ${tfsApiPath}, err: ${e}`);
        reject(e);
      });

      zipReadableStream.on("error", e => {
        logger.error(`error on readable stream while piping from readable stream into file ${pathToZip} for ${tfsApiPath}, err: ${e}`);
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

async function runShell(requesterName: string, command: string) {
  try {
    logger.info(`try run from shell, repo: ${requesterName}: cmd: ${command}`);

    const { stdout, stderr } = await exec(command, {
      maxBuffer: 1024 * 1024 * 10,
      env: { ...process.env, FOO: "ah" },
    });

    logger.info(`stdout:, ${JSON.stringify(stdout, null, 4)}`);
    logger.error(`stderr:, ${JSON.stringify(stderr, null, 4)}`);
  } catch (err) {
    logger.error(`shell command: ${command} failed to run error: ${err} stdout: ${err.stdout + "\n"} stderr: ${err.stderr + "\n"}`);

    logger.info(`finish run from shell, requester name: ${requesterName} cmd: ${command}`);
  }
}

async function sleep() {
  const delay = ms => new Promise(res => setTimeout(res, ms));
  await delay(1000 * 60 * 3);
}
