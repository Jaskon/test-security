import { exec } from "child_process";
import dns from "dns";
import fs from "fs";
import sizeof from "object-sizeof";
import { deflateSync } from "zlib";
import { Repo, RepoTypeName } from "../entitis/codeRepoTypes";
import { ScannerMessage } from "../entitis/service/connector-message-types";
import FileHelper from "../helper/IO/fileHlper";
import loggerImport from "../logger";
import { Tool } from "../policy/rules/code/policyRulesBase";
import { isUploadToS3 } from "./envUtils";
import { getSharedFolder } from "./generalUtils";
import StatesHelper from "./statesHelper";

const logger = loggerImport.getDebugLogger();

const sleep = (ms: number) => {
  return new Promise(resolve => setTimeout(resolve, ms));
};

export default async function resolveDomainNameToIp(domainName) {
  try {
    const addresses = await dns.promises.resolve4(domainName);
    return addresses;
  } catch (err) {
    return "";
  }
}

export function getMonoRepoFilePath(repo: Repo, fileName: string) {
  let filePathForBlameService = fileName;
  if (repo.insideFolder != "") {
    filePathForBlameService = `${repo.insideFolder}/${fileName}`;
    if (filePathForBlameService.startsWith("/")) {
      filePathForBlameService = filePathForBlameService.substring(1, filePathForBlameService.length);
    }
  }
  return filePathForBlameService;
}

export function getLinkToFile(
  repo: Repo,
  filePath: string | undefined,
  line: string | number | undefined,
  includesChildRepoPath: boolean = true,
) {
  if (!filePath) {
    return "";
  }

  let repoLnk = repo?.fileLink;
  //if mono repo child remove the child repo path directory from the repo link as we get it from the file link
  if (repo.monoRepoChild && includesChildRepoPath) {
    const monoRepoChildSubfolder = repo?.insideFolder.startsWith("/") ? repo?.insideFolder.slice(1) : repo?.insideFolder;
    repoLnk = repo?.fileLink.replace(monoRepoChildSubfolder, "");
    repoLnk = repoLnk.endsWith("//") ? repoLnk.slice(0, -1) : repoLnk;
    //logger.info(`getLinkToFile: monoRepoChildSubfolder: ${monoRepoChildSubfolder}, repo?.fileLink: ${repo?.fileLink}, repoLnk: ${repoLnk}, filePath: ${filePath}`);
  }

  let lnk = repoLnk + filePath;
  if (line) {
    lnk =
      repo?.type.toLowerCase() == RepoTypeName.awsCodeCommit.toLowerCase()
        ? lnk + repo?.linkFilePreffix + line + "-" + line
        : lnk + repo?.linkFilePreffix + line;
  }
  return lnk;
}

export function fullyDecodeURI(uri: string) {
  let decodedURI = uri;
  let previousDecodedURI = "";

  while (decodedURI !== previousDecodedURI) {
    previousDecodedURI = decodedURI;
    decodedURI = decodeURIComponent(decodedURI);
  }

  return decodedURI;
}

export function copyToolInfo(repoName: string, file: string, toolName: string, uuid: string): void {
  try {
    if (!isUploadToS3()) return;

    if (typeof process.env.AWS_LAMBDA_RUNTIME_API === "undefined" || process.env.AWS_LAMBDA_RUNTIME_API === null) {
      const oxDir = getSharedFolder(uuid) + "/ox-security";
      const telemetryDir = oxDir + "/telemetry-" + uuid;
      const repoDir = telemetryDir + "/security-report/" + repoName;
      const toolDir = `${repoDir}/${toolName}`;

      try {
        if (!fs.existsSync(toolDir)) {
          fs.mkdirSync(toolDir, { recursive: true });
        }
        let fileHelper = new FileHelper(uuid);
        fileHelper.copyFileSync(file, toolDir);
      } catch (err) {
        logger.error(`failed to copy tool ${toolName} result file for repo name ${repoName}, err: ${err}`);
      }
    }
  } catch (err) {
    logger.error(`failed to copy tool ${toolName}, repo name ${repoName}, err: ${err}`);
  }
}

export async function runShell(requesterName: string, command: string, toolName: string) {
  try {
    await shell(requesterName, command, toolName);
    return true;
  } catch (err) {
    logger.error(`[${toolName}] failed run shell command: ${command} to run err: ${err}`);
  }
  return false;
}

async function shell(requesterName: string, command: string, toolName: string) {
  try {
    logger.info(`[${toolName}] try run from shell, repo: ${requesterName}: cmd: ${command}`);

    const { stdout, stderr } = await exec(command, {
      maxBuffer: 1024 * 1024 * 10,
      env: { ...process.env, FOO: "ah" },
    });
    logger.debug(`[${toolName}] stdout:, ${JSON.stringify(stdout, null, 4)}`);
    logger.debug(`[${toolName}] stderr:, ${JSON.stringify(stderr, null, 4)}`);
  } catch (err) {
    logger.error(
      `[${toolName}]shell command: ${command} failed to run error: ${err} stdout: ${err.stdout + "\n"} stderr: ${err.stderr + "\n"}`,
    );

    logger.info(`[${toolName}] finish run from shell, requester name: ${requesterName} cmd: ${command}`);
  }
}

export function splitToChunks(array: any, chunkSize: number) {
  const chunks: any[] = [];
  for (let i = 0; i < array.length; i += chunkSize) {
    const c = array.slice(i, i + chunkSize);
    chunks.push(c);
  }
  return chunks;
}

export function enableByPolicy(toolName: string) {
  const toolNameEnv = `TOOLS_${toolName.toUpperCase()}`;
  if (toolNameEnv in process.env && process.env[toolNameEnv] === "enabled") {
    return true;
  }
  return false;
}

export function isInt(n) {
  return n % 1 === 0;
}

export function removeUrlAndKeepOnlyIp(host: string) {
  try {
    let ipInfoClean = host;
    if (ipInfoClean.includes("://")) {
      const i = ipInfoClean.indexOf("://");
      ipInfoClean = ipInfoClean.substring(i + "://".length, ipInfoClean.length);
    }
    if (ipInfoClean.includes("/")) {
      const i = ipInfoClean.indexOf("/");
      ipInfoClean = ipInfoClean.substring(0, i);
    }
    logger.info(`removeUrlAndKeepOnlyIp, ipInfoClean ${ipInfoClean}`);
    return ipInfoClean;
  } catch (err) {
    logger.error(`failed removeUrlAndKeepOnlyIp, host: ${host}, err: ${err}`);
  }
  return host;
}

export function isIpAddress(host: string) {
  try {
    const regexExp = /^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$/gi;
    const isIp = regexExp.test(host);
    return isIp;
  } catch (err) {
    logger.error(`failed isIpAddress, host: ${host}, err: ${err}`);
  }
  return false;
}

export function replaceUrlWithHostForOnPremGit(urlInfo: string, host: string) {
  try {
    let ipInfoClean = host.replace("https://", "");
    const preffix = urlInfo.indexOf("@");
    let suffix = -1;
    if (preffix !== -1) {
      suffix = urlInfo.indexOf("/", preffix + 1);
    }
    if (suffix !== -1 && preffix !== -1) {
      const str1 = urlInfo.substring(0, preffix + 1);
      const str2 = urlInfo.substring(suffix, urlInfo.length);
      const urlRes = `${str1}${ipInfoClean}${str2}`;
      logger.info(`changing clone url with host: ${urlRes}`);
      return urlRes;
    }
  } catch (err) {
    logger.error(`failed replaceUrlWithHostForOnPremGit, host: ${host}, url: ${urlInfo}, err: ${err}`);
  }
  return urlInfo;
}

export function replaceUrlWithIpForOnPremGit(urlInfo: string, ip: string) {
  try {
    let ipInfoClean = removeUrlAndKeepOnlyIp(ip);

    const isIp = isIpAddress(ipInfoClean);
    if (isIp) {
      const preffix = urlInfo.indexOf("@");
      let suffix = -1;
      if (preffix !== -1) {
        suffix = urlInfo.indexOf("/", preffix + 1);
      }
      if (suffix !== -1 && preffix !== -1) {
        const str1 = urlInfo.substring(0, preffix + 1);
        const str2 = urlInfo.substring(suffix, urlInfo.length);
        const urlRes = `${str1}${ipInfoClean}${str2}`;
        logger.info(`changing clone url with ip: ${urlRes}`);
        return urlRes;
      }
    } else {
      logger.info(`replaceUrlWithIpForOnPremGit not an ip: ${ip}, url: ${urlInfo}`);
    }
  } catch (err) {
    logger.error(`failed replaceUrlWithIpForOnPremGit, ip: ${ip}, url: ${urlInfo}, err: ${err}`);
  }
  return urlInfo;
}

export function adaptLibName(libName: string) {
  if (libName.includes(":")) {
    const index = libName.lastIndexOf(":");
    return libName.substring(index + 1, libName.length);
  }
  return libName;
}

export function getGitlabRepoName(fullName: string) {
  try {
    const index = fullName.indexOf("/");
    if (index) fullName = fullName.substr(index + "/".length, fullName.length);
    return fullName.trimStart();
  } catch (err) {
    logger.error(`failed to get gitlab repo name for: ${this.token.type}, err: ${err}`);
  }
  return fullName;
}

const capitalizeFirstLetter = string => {
  if (!string) {
    return "";
  }
  string = string.toLowerCase();
  return string.charAt(0).toUpperCase() + string.slice(1);
};

const timeoutPromise = (t: number, errMsg: string = "timeout") => {
  const e = new Error(errMsg);
  return new Promise((_, reject) => {
    setTimeout(reject, t, e);
  });
};

export function runOnce(fun: Function | undefined): Promise<void> {
  let n = 2;
  let result: void;

  return new Promise(async (resolve, reject) => {
    if (--n > 0) {
      if (fun) {
        result = await fun.apply(null);
        resolve(result);
      }
    }

    if (n <= 1) {
      fun = undefined;
    }
  });
}

const execWithTimeout = (p: Promise<any>, t: number, errMsg = "timeout") => {
  return Promise.race([p, timeoutPromise(t, errMsg)]);
};

export function deleteFolderAfterDoneWorkingForOnPrem(fullName: string, path: string) {
  try {
    const shouldRun = process.env.DELETE_DURING_SCAN || StatesHelper.Instance.orgName === "" || StatesHelper.Instance.isWalmart;
    if (!shouldRun) {
      return;
    }

    logger.info(`try deleteFolderAfterDoneWorking, repo: ${fullName}, dir: ${path}`);

    const tmpFileHelper = new FileHelper(path);
    tmpFileHelper.deleteDir(path);

    logger.info(`finish deleteFolderAfterDoneWorking, repo: ${fullName}, dir: ${path}`);
  } catch (err) {
    logger.error(`failed deleteFolderAfterDoneWorking, repo: ${fullName}, err: ${err}`);
  }
}

export function escapeCharsFromPath(pathToRepo: string) {
  if (pathToRepo.includes("(")) pathToRepo = pathToRepo.replaceAll("\\(", "\\(");
  if (pathToRepo.includes(")")) pathToRepo = pathToRepo.replaceAll("\\)", "\\)");
  return pathToRepo;
}

export function getSelectedRepos(name: string, body: ScannerMessage) {
  if (name === "gkrartifacts") {
    name = "googleartifactregistry";
  } else if (name === "jfrogartifacts") {
    name = "jfrog";
  } else if (name.toLowerCase() === "gitlabartifacts") {
    name = "gitlabcontainerregistry";
  } else if (name.toLowerCase() === "cloudaws") {
    name = "aws";
  } else if (name.toLowerCase() === "dockerhubregistry") {
    name = "dockerhub";
  }

  const userSelectedRepos = body?.configuredConnectors?.find(connector => connector.name.replace(/\s/g, "").toLowerCase() === name);

  if (name === "googleartifactregistry") {
    name = "gkrartifacts";
  } else if (name === "jfrog") {
    name = "jfrogartifacts";
  } else if (name === "gitlabcontainerregistry") {
    name = "gitlabartifacts";
  } else if (name.toLowerCase() === "aws") {
    name = "cloudaws";
  } else if (name.toLowerCase() === "dockerhub") {
    name = "dockerhubregistry";
  }

  if (userSelectedRepos != undefined) {
    logger.info(`found selected apps by user for: ${name}`);
    return userSelectedRepos;
  } else {
    logger.info(`didn't found selected apps by user for: ${name}`);
  }
}

export const getConnector = (body: ScannerMessage) => {
  const connector = body.configuredConnectors.find(con => {
    return con.monitoredResources !== undefined;
  });
  return connector;
};

export function getPkgManagerPretty(pkgManager: string) {
  const pkgManagerLower = pkgManager.toLowerCase();
  if ("Bitnami".toLowerCase() === pkgManagerLower) {
    return "Bitnami";
  }
  if ("Ivy".toLowerCase() === pkgManagerLower) {
    return "Ivy";
  }
  if ("CocoaPods".toLowerCase() === pkgManagerLower) {
    return "CocoaPods";
  }
  if ("Conda".toLowerCase() === pkgManagerLower) {
    return "Conda";
  }
  if ("Groovy".toLowerCase() === pkgManagerLower) {
    return "Groovy";
  }
  if ("Gradle".toLowerCase() === pkgManagerLower) {
    return "Gradle";
  }
  if ("Enthought Canopy".toLowerCase() === pkgManagerLower) {
    return "Enthought Canopy";
  }
  if ("Docker".toLowerCase() === pkgManagerLower) {
    return "Docker";
  }
  if ("NET".toLowerCase() === pkgManagerLower) {
    return ".NET";
  }
  if ("CTAN".toLowerCase() === pkgManagerLower) {
    return "CTAN";
  }
  if ("CRAN".toLowerCase() === pkgManagerLower) {
    return "CRAN";
  }
  if ("CPAN".toLowerCase() === pkgManagerLower) {
    return "CPAN";
  }
  if ("Leiningen".toLowerCase() === pkgManagerLower) {
    return "Leiningen";
  }
  if ("LuaRocks".toLowerCase() === pkgManagerLower) {
    return "LuaRocks";
  }
  if ("Maven".toLowerCase() === pkgManagerLower || pkgManagerLower === "java" || pkgManagerLower === "jar") {
    return "Maven";
  }
  if ("NuGet".toLowerCase() === pkgManagerLower) {
    return "NuGet";
  }
  if ("golang".toLowerCase() === pkgManagerLower || "go" === pkgManagerLower) {
    return "Golang";
  }
  if ("npm".toLowerCase() === pkgManagerLower || "node.js" === pkgManagerLower || "node" === pkgManagerLower) {
    return "npm";
  }
  if ("PAR".toLowerCase() === pkgManagerLower) {
    return "PAR";
  }
  if ("PEAR".toLowerCase() === pkgManagerLower) {
    return "PEAR";
  }
  if ("pip".toLowerCase() === pkgManagerLower) {
    return "pip";
  }
  if ("PyPI".toLowerCase() === pkgManagerLower) {
    return "PyPI";
  }
  if ("RubyGems".toLowerCase() === pkgManagerLower) {
    return "RubyGems";
  }
  if ("sbt".toLowerCase() === pkgManagerLower) {
    return "sbt";
  }
  if ("pom".toLowerCase() === pkgManagerLower) {
    return "POM";
  }
  return capitalizeFirstLetter(pkgManager);
}

export function flatNestedJson(yourObject) {
  try {
    if (!yourObject || yourObject == null) {
      return;
    }
    const res = flattenObject(yourObject);
    return res;
  } catch (err) {
    logger.error(`failed flat nested json: ${JSON.stringify(yourObject)}, err: ${err}`);
  }
}

const flattenObject = (obj, prefix = "") =>
  Object.keys(obj).reduce((acc, k) => {
    const pre = prefix.length ? `${prefix} ` : "";
    if (typeof obj[k] === "object" && obj[k] !== null && Object.keys(obj[k]).length > 0) Object.assign(acc, flattenObject(obj[k], pre + k));
    else acc[pre + k] = obj[k];
    return acc;
  }, {});

export { sleep, execWithTimeout, capitalizeFirstLetter };
export const compress = (string: string) => {
  const buffer = deflateSync(string);
  return buffer.toString("base64");
};

export function getLanFromPkgManager(pkgManager: string) {
  try {
    if (!pkgManager) {
      return "";
    }

    const str = pkgManager.toLowerCase();
    if ("CocoaPods".toLowerCase() === str) return "Swift";
    if ("Composer".toLowerCase() === str) return "PHP";
    if ("CPAN".toLowerCase() === str) return "Perl";
    if ("CRAN".toLowerCase() === str) return "R";
    if ("CTAN".toLowerCase() === str) return "TeX";
    if ("Gradle".toLowerCase() === str) return "Java";
    if ("Ivy".toLowerCase() === str) return "Java";
    if ("Leiningen".toLowerCase() === str) return "Lua";
    if ("Maven".toLowerCase() === str) return "Java";
    if ("npm".toLowerCase() === str) return "JavaScript";
    if ("NuGet".toLowerCase() === str) return ".NET";
    if ("PAR".toLowerCase() === str) return "Perl";
    if ("pip".toLowerCase() === str) return "Python";
    if ("RubyGems".toLowerCase() === str) return "Ruby";
    if ("sbt".toLowerCase() === str) return "Scala";
    if ("yarn".toLowerCase() === str) return "JavaScript";
    return "";
  } catch (err) {
    return "";
  }
}

export function logsErrorWithExtraData(infoAboutLogin: Set<string>, apiInfo: string, itemToLog: any, err: any, logName: string) {
  try {
    if (!infoAboutLogin.has(apiInfo)) {
      infoAboutLogin.add(apiInfo);
      let item = itemToLog;
      if (Array.isArray(itemToLog)) {
        item = itemToLog[0];
      }
      logger.error(`${logName} failed in: ${apiInfo}, err: ${err}, itemToLog: ${JSON.stringify(itemToLog)}`);
    } else {
      logger.error(`${logName} failed in: ${apiInfo}, err: ${err}`);
    }
  } catch (err) {
    //Ignore
  }
}

export function shouldRetry(err): boolean {
  if (err.toString().includes("socket")) {
    return true;
  }
  if (err.toString().includes("rate limit")) {
    return true;
  }
  if (err.toString().includes("ECONNRESET".toLowerCase())) {
    return true;
  }
  if (err.toString().includes("timeout of")) {
    return true;
  }
  if (err.response?.status) {
    if (err.response.status == 429) {
      return true;
    }
  }
  return false;
}

export function handleFileNameReplace(fileName, path) {
  try {
    if (path.startsWith("/") && !fileName.startsWith("/")) {
      path = path.replace("/", "");
    }
    fileName = fileName.replace(`${path}/`, "");

    if (fileName.includes(path)) {
      logger.error(`handleFileNameReplace failed for ${fileName}, path: ${path}`);
    }

    return fileName;
  } catch (e) {
    logger.error(`handleFileNameReplace failed for ${fileName}, path: ${path}`);
  }
  return fileName;
}

export const retry = async <T>(
  callback: () => Promise<T>,
  { times, sleepInMS }: { times: number; sleepInMS: number },
  operationName: string,
) => {
  let numberOfTries = 0;
  try {
    const res = await callback();
    numberOfTries++;
    logger.info(`Operation ${operationName} successful, retried ${numberOfTries} times.`);
    return res;
  } catch (err) {
    numberOfTries++;
    logger.error(`Unsuccessful ${operationName}, retried ${numberOfTries} times... ${err}`);
  }
  return new Promise<T>((resolve, reject) => {
    const interval = setInterval(async () => {
      numberOfTries++;
      if (numberOfTries === times) {
        logger.info(`Trying ${operationName} for the last time... (${times})`);
        clearInterval(interval);
      }
      try {
        const res = await callback();
        clearInterval(interval);
        logger.info(`Operation ${operationName} successful, retried ${numberOfTries} times.`);
        resolve(res);
      } catch (err) {
        logger.error(`Unsuccessful ${operationName}, retried ${numberOfTries} times... ${err}`);
        if (times === numberOfTries) {
          reject(err);
        }
      }
    }, sleepInMS);
  });
};

export const checkObjectSize = object => {
  return sizeof(object) / (1024 * 1024); // Convert size into MB
};

export const cleanToolName = (tool: string) => {
  try {
    const res = tool.toLowerCase().replaceAll(" ", "-");
    return res as Tool;
  } catch (e) {
    logger.error(`failed cleanToolName. error: ${e}`);
  }
  return tool as Tool;
};

export const getAllObjectsS3 = async (bucketName: string, s3) => {
  try {
    return new Promise((resolve, reject) => {
      const params = {
        Bucket: bucketName,
      };
      s3.listObjectsV2(params, function (s3Err, data) {
        if (s3Err) {
          console.log(`Could not get files from bucket: ${bucketName}, err: ${s3Err}`);
          resolve(undefined);
        } else {
          console.log(`Successfully got the s3 keys`);
          resolve(data);
        }
      });
    });
  } catch (e) {
    logger.error(`Could not get all files of ${bucketName} bucketName, err: ${e}`);
  }
};

export const downloadFileInternalS3 = async (bucketName: string, key: string, s3) => {
  try {
    return new Promise((resolve, reject) => {
      const params = {
        Bucket: bucketName,
        Key: key,
      };
      s3.getObject(params, function (s3Err, data) {
        if (s3Err) {
          logger.error(`Error downloading ${key} from S3, with error:` + s3Err);
          resolve([]);
        } else {
          const convertedData = data?.Body?.toString("utf-8");
          let jsonObj = [];
          try {
            jsonObj = JSON.parse(convertedData);
          } catch (err) {
            logger.error(`Could not parse the string to json, err: ${err}`);
          }
          resolve(jsonObj);
        }
      });
    });
  } catch (e) {
    logger.error(`Could not download the file: ${key} from s3, err: ${e} `);
  }
};
