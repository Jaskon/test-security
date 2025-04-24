import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import {
  ApiSecurityItem,
  ApiSecurityItemDef,
  ApiSecurityItemFunction,
  ApiSecurityItemResponse,
  ApiSecurityItemSource,
  httpMethods,
  Parameter,
} from "../../entitis/apiTypes";
import { FileWithLanguage, Repo, VCSType } from "../../entitis/codeRepoTypes";
import { OXtools } from "../../entitis/constant";
import loggerImport from "../../logger";
import { copyToolInfo, escapeCharsFromPath, getLinkToFile, sleep } from "../commonUtils";
import { replaceAll } from "../generalUtils";
import FileHelper from "../IO/fileHlper";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";

const uuid = require("uuid");
const fs = require("fs");
const yaml = require("js-yaml");

const logger = loggerImport.getDebugLogger();
const sharedDir = process.env.OX_SHARED_DATA === "undefined" ? "/var/shared-data" : process.env.OX_SHARED_DATA;

class APIDiscoveryHelper {
  serviceHelperQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;
  appName: string;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.serviceHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
  }

  async setRepoAPIDiscoveryInfo(repo: Repo, apisSecurity: ApiSecurityItem[]) {
    try {
      if (StatesHelper.Instance.isWalmart) {
        return;
      }

      if (repo.vcsType === VCSType.tfvc) {
        return;
      }

      if (repo.isDelta) {
        logger.info(`[${APIDiscoveryHelper.name}] skipping isDelta, repo:${repo.fullName}`);
        return;
      }

      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;

      const codeApiDiscovery: ApiSecurityItem[] = [];
      logger.info(`[${APIDiscoveryHelper.name}] Start, repo:${repo?.fullName}`);
      repo.apiDiscoveryInfoPath = await this.sendAndWaitForRes(repo, codeApiDiscovery);
      const frameworks: string = Array.from(repo.frameworks).join(", ");
      logger.info(
        `[${APIDiscoveryHelper.name}] End, repo:${repo?.fullName}, apisSecurity: ${codeApiDiscovery.length}, frameworks: ${frameworks}`,
        {
          "ox-api-discovery-repo": repo?.fullName,
          "ox-api-discovery-length": codeApiDiscovery.length,
          "ox-api-discovery-frameworks": frameworks,
        },
      );

      codeApiDiscovery.forEach(i => {
        apisSecurity.push(i);
      });
    } catch (err) {
      logger.error(`[${APIDiscoveryHelper.name}] Failed, repo:${repo.fullName}, err: ${err}`);
    }
  }

  private async sendAndWaitForRes(repo: Repo, apisSecurity: ApiSecurityItem[]) {
    const uniqueId = uuid.v4();
    try {
      if (!StatesHelper.Instance.isApiSecEnable) {
        return;
      }
    } catch (err) {
      logger.error(`[${APIDiscoveryHelper.name}] failed to check if service should run ,err: ${err}`);
    }

    logger.info(`[${APIDiscoveryHelper.name}] calling service for: repo:${repo.fullName}`);
    const apiDiscoveryhDir = `${sharedDir}/${this.orgName}/scan_${replaceAll(this.uuid, "-", "_")}/apiDiscovery`;
    try {
      let url = process.env.CODE_API_DISCOVERY_QUEUE_KEY;

      if (!url && !process.env.DEBUG) {
        return null;
      }

      const dirToPutRes = `${apiDiscoveryhDir}/${uniqueId}`;
      fs.mkdirSync(dirToPutRes, { recursive: true });

      const filePathRes = `${dirToPutRes}/codeApiDiscovery.json`;

      let cloneDir = "";
      let toolCopyDestination = "";
      let monoRepoChildSubfolder = "";
      if (repo.realRepo) {
        cloneDir = repo.parentRepoOfMonoRepo != null ? repo.parentRepoOfMonoRepo.codeZipDir : repo.codeZipDir;

        toolCopyDestination = repo.getRepoForToolsBasedOnEnv();

        monoRepoChildSubfolder = repo.insideFolder.startsWith("/") ? repo.insideFolder.slice(1) : repo.insideFolder;
      }

      if (process.env.DEBUG) {
        repo.frameworks.add("ExpressJS");
        repo.frameworks.add("FastAPI");
        repo.frameworks.add("Flask");
      }
      const inputFileName = `${dirToPutRes}/apiDiscoveryInput.json`;
      if ((await this.saveFrameworkList(repo, inputFileName)) === false) {
        return;
      }

      let command = this.getCommand(dirToPutRes, toolCopyDestination, inputFileName);
      command = escapeCharsFromPath(command);
      copyToolInfo(repo.name, inputFileName, "codeApiDiscovery", this.uuid);

      const msg = {
        MessageId: uniqueId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "code-api-discovery",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 1800000,
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

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(
        `[${APIDiscoveryHelper.name}] about to send msg to queue, repo:${repo.fullName}, uniqueId: ${uniqueId}, msg: ${JSON.stringify(
          msg,
        )}`,
      );

      if (process.env.DEBUG) {
        //const reqRes = await runShell(repo.name, msg.localCommand);
        this.extractAPIList(
          repo,
          toolCopyDestination,
          fs.readFileSync(process.cwd() + "/tests/src/apiDiscoveryHelper/response_merge.json", "utf8"),
          apisSecurity,
        );
        //await sleep(10 * 1000);
        //await sleep(10 * 1000);
        return process.cwd() + "/tests/src/apiDiscoveryHelper/response_merge.json";
      }

      const reqRes = await this.serviceHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        repo.addFailedSecurityTools(OXtools.apiDiscovery);
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.apiDiscovery,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          -1,
          ToolError.SendToQueue,
        );
        logger.error(
          `[${APIDiscoveryHelper.name}] failed enter item to Q, uniqueId: ${uniqueId}, repo:${repo.fullName}, msg: ${JSON.stringify(msg)}`,
        );

        repo.addFailedSecurityTools(OXtools.apiDiscovery);
        return null;
      }

      logger.info(
        `[${APIDiscoveryHelper.name}] about to start waiting for requests, uniqueId: ${uniqueId} repo:${
          repo.fullName
        }, msg: ${JSON.stringify(msg)}`,
      );

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromAPIDiscovery = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 30; // 60 seconds * 30 = 30 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          repo.addFailedSecurityTools(OXtools.apiDiscovery);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.apiDiscovery,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );
          let errInfo = `[${APIDiscoveryHelper.name}] failed set timeout, repo:${repo.fullName}, uniqueId: ${uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`;
          logger.error(`${errInfo}`);
          StatesHelper.Instance.scanInfoStats.failedAPIDiscoveryTimeout++;
          StatesHelper.Instance.scanInfoStats.failedAPIDiscoveryTimeoutRepoNames.push(repo.name);

          repo.addFailedSecurityTools(OXtools.apiDiscovery);
          return null;
        }

        //Failed from API Discovery
        if (fs.existsSync(failedFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          repo.addFailedSecurityTools(OXtools.apiDiscovery);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.apiDiscovery,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.ResFileNotFound,
          );
          let errInfo = `[${APIDiscoveryHelper.name}] failed file discovered from service response, repo:${repo.fullName}, uniqueId: ${uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`;
          logger.error(`${errInfo}`);
          StatesHelper.Instance.scanInfoStats.failedAPIDiscoveryBatches++;
          StatesHelper.Instance.scanInfoStats.failedAPIDiscoveryBatchesNames.push(repo.name);

          repo.addFailedSecurityTools(OXtools.apiDiscovery);
          return null;
        }

        //Done from API Discovery
        if (fs.existsSync(doneFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `[${APIDiscoveryHelper.name}] done file discovered from response, uniqueId: ${uniqueId}, repo:${repo.fullName}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromAPIDiscovery = true;
          break;
        }

        //10 seconds
        await sleep(10 * 1000);
        counter--;
      }

      await sleep(10 * 1000);
      if (!fs.existsSync(filePathRes)) {
        let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
        repo.addFailedSecurityTools(OXtools.apiDiscovery);
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.apiDiscovery,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );
        let errInfo = `[${APIDiscoveryHelper.name}] response file not exist on disk, repo: ${repo.fullName}, uniqueId: ${uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, done from API Discovery, done file: ${doneFromAPIDiscovery}, dirToPutRes: ${dirToPutRes}`;
        logger.error(`${errInfo}`);
        StatesHelper.Instance.scanInfoStats.failedAPIDiscoveryBatches++;

        repo.addFailedSecurityTools(OXtools.apiDiscovery);
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      copyToolInfo(repo.name, filePathRes, "codeApiDiscovery", this.uuid);
      this.extractAPIList(repo, toolCopyDestination, fs.readFileSync(filePathRes, "utf8"), apisSecurity);

      logger.info(
        `[${APIDiscoveryHelper.name}] finish waiting, repo: ${repo.fullName}, uniqueId: ${uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, counter: ${counter}`,
      );

      return filePathRes;
    } catch (err) {
      repo.addFailedSecurityTools(OXtools.apiDiscovery);
      ToolsExecutionStats.addExecutionStateOnFail(
        uniqueId,
        OXtools.apiDiscovery,
        repo.fullName,
        repo.id,
        "repo",
        "",
        -1,
        ToolError.Generic,
      );
      let errInfo = `[${APIDiscoveryHelper.name}] failed to send batch of request, repo: ${repo.fullName}, uniqueId: ${uniqueId}, err: ${err}`;
      logger.error(`${errInfo}`);
      StatesHelper.Instance.scanInfoStats.failedAPIDiscoveryBatches++;

      repo.addFailedSecurityTools(OXtools.apiDiscovery);
    }
  }

  getCommand(outputDir: string, repoDir: string, inputFilePath: string) {
    let exec_path: string | undefined = "/src/code-api-discovery.py";
    if (process.env.DEBUG) {
      exec_path = process.env.API_DISCOVERY_PATH;
    }
    return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir} --events-path ${inputFilePath}`;
  }

  async saveFrameworkList(repo: Repo, filePath: string) {
    try {
      if (repo.frameworks.size > 0) {
        const frameworksObject = {};
        //convert set to object for stringify
        frameworksObject["frameworks"] = [...repo.frameworks];
        const jsonData = JSON.stringify(frameworksObject);
        fs.writeFileSync(filePath, jsonData, "utf8");
        return true;
      }
    } catch (err) {
      logger.error(`[${APIDiscoveryHelper.name}] failed to save Framework List, repo:${repo.fullName}, err: ${err}`);
    }
    logger.info(`[${APIDiscoveryHelper.name}] frameworks were not found for repo:${repo.fullName}`);
    return false;
  }

  extractAPIList(repo: Repo, repoDir: string, apiListJSON: string, apisSecurity: ApiSecurityItem[]) {
    try {
      const scanId = StatesHelper?.Instance?.uuid;
      const apiData = JSON.parse(apiListJSON);
      const titlePlaceHolder = APIDiscoveryHelper.getTitleFromRepoName(repo);
      for (const list of apiData) {
        try {
          if (!list?.apiFound) {
            continue;
          }
          const framework = list?.framework;
          for (const apiItem of list?.routes) {
            if (apiItem?.endPoint && apiItem?.method) {
              const apiSecurityItem: ApiSecurityItem = new ApiSecurityItem();
              apiSecurityItem.uuid = apiItem?.uuid;
              apiSecurityItem.scanId = scanId ? scanId : "";
              apiSecurityItem.appId = repo?.repoId;
              apiSecurityItem.appType = repo?.type;
              apiSecurityItem.appName = repo?.fullName;
              apiSecurityItem.appLink = repo?.link;
              const apiSecurityItemDef: ApiSecurityItemDef = new ApiSecurityItemDef();
              apiSecurityItemDef.snippet = apiItem?.snippet;
              apiSecurityItemDef.source = ApiSecurityItemSource.code;
              //remove repo path + '/', keep relative path to the file within the app
              if (apiItem?.filepath.startsWith(repoDir)) {
                apiItem.filepath = apiItem?.filepath.slice(repoDir.length + 1);
              }
              apiSecurityItemDef.fileName = apiItem?.filepath;
              apiSecurityItemDef.line = apiItem?.line;
              apiSecurityItemDef.link = getLinkToFile(repo, apiSecurityItemDef?.fileName, apiSecurityItemDef?.line);

              if (apiItem?.functions) {
                for (const apiItemFunction of apiItem?.functions) {
                  const itemFunction: ApiSecurityItemFunction = new ApiSecurityItemFunction();
                  itemFunction.line = apiItemFunction.line;
                  itemFunction.function = apiItemFunction.function;
                  itemFunction.snippet = apiItemFunction.snippet;
                  itemFunction.filepath = apiItemFunction.filepath?.replace(`${repoDir}/`, "");
                  itemFunction.link = getLinkToFile(repo, itemFunction.filepath, itemFunction.line);
                  apiSecurityItemDef.functions.push(itemFunction);
                }
              }
              apiSecurityItem.definitions.push(apiSecurityItemDef);

              apiSecurityItem.epName = apiItem?.endPoint;
              apiSecurityItem.methodName = apiItem?.method.toLowerCase();
              apiSecurityItem.framework = framework;
              apiSecurityItem.title = apiItem?.title ? apiItem?.title : titlePlaceHolder;
              apiSecurityItem.description = apiItem?.description;
              apiSecurityItem.firstSeen = new Date();
              if (apiItem?.responseStatusCode) {
                for (const responseCode of apiItem?.responseStatusCode) {
                  const response: ApiSecurityItemResponse = new ApiSecurityItemResponse();
                  response.code = responseCode;
                  apiSecurityItem.methodResponses.push(response);
                }
              }
              if (apiItem?.parameters) {
                for (const parameterInfo of apiItem?.parameters) {
                  const param: Parameter = new Parameter();
                  param.name = parameterInfo?.name;
                  param.in = parameterInfo?.in;
                  param.required = parameterInfo?.required;
                  apiSecurityItem.methodParameters.push(parameterInfo);
                }
              }
              apisSecurity.push(apiSecurityItem);
            }
          }
        } catch (err) {
          logger.error(`[${APIDiscoveryHelper.name}] Failed in single item, repo: ${repo.fullName} to extract API List, err: ${err}`);
        }
      }
    } catch (err) {
      logger.error(`[${APIDiscoveryHelper.name}] Failed, repo: ${repo.fullName} to extract API List, err: ${err}`);
    }
  }

  static getTitleFromRepoName(repo: Repo) {
    let title = "";
    if (repo?.name) {
      title = repo?.name;
      const lastIndex = repo?.name.lastIndexOf("/");
      if (lastIndex !== -1) {
        title = repo?.name.substring(lastIndex + 1);
      }
      title = title + " API";
    }
    return title;
  }

  static updateFirstSeen(
    apiSecurityItems: ApiSecurityItem[],
    apiSecurityItemsHistory: ApiSecurityItem[],
    appName: string,
  ): ApiSecurityItem[] {
    try {
      let newApiItems: ApiSecurityItem[] = [];
      for (const apiItem of apiSecurityItems) {
        const matchingItem = apiSecurityItemsHistory.find(
          apiItemHistory =>
            apiItemHistory?.epName?.toLowerCase() === apiItem?.epName?.toLowerCase() &&
            apiItemHistory?.methodName?.toLowerCase() === apiItem?.methodName?.toLowerCase() &&
            apiItemHistory?.title?.toLowerCase() === apiItem?.title?.toLowerCase() &&
            apiItemHistory?.definitions[0]?.fileName?.toLowerCase() === apiItem?.definitions[0]?.fileName?.toLowerCase(),
        );

        if (matchingItem) {
          apiItem.firstSeen = matchingItem?.firstSeen;
        } else {
          newApiItems.push(apiItem);
        }
      }
      apiSecurityItemsHistory = apiSecurityItemsHistory.concat(newApiItems);
    } catch (err) {
      logger.error(`[${APIDiscoveryHelper.name}] failed to updateFirstSeen, repo: ${appName} err: ${err}`);
    }
    return apiSecurityItemsHistory;
  }

  // if we have only one swagger info for specific endpoint add its info to all code with the same endpoint + method
  // remove merged swagger item keep swagger items that do not have similar code source endpoint + method
  //logic may change in the future
  static mergeAPISecurityItems(apiSecurityItems: ApiSecurityItem[], appName: string) {
    const mergedItems: ApiSecurityItem[] = [];
    const codeItems = apiSecurityItems.filter(item => item?.definitions[0]?.source === ApiSecurityItemSource.code);
    const openapiItems = apiSecurityItems.filter(item => item?.definitions[0]?.source === ApiSecurityItemSource.codeOpenApi);
    try {
      for (const apiItem of apiSecurityItems) {
        if (apiItem.definitions[0].source === ApiSecurityItemSource.code) {
          const similarItems = openapiItems.filter(
            item =>
              apiItem?.epName?.toLowerCase() === item?.epName?.toLowerCase() &&
              apiItem?.methodName?.toLowerCase() === item?.methodName?.toLowerCase(),
          );
          if (similarItems.length === 1) {
            const openapiItem = similarItems.pop();
            for (const prop in openapiItem) {
              if (prop === "definitions") {
                apiItem.definitions = apiItem.definitions.concat(openapiItem.definitions);
              } else if (prop === "methodResponses") {
                if (!apiItem.methodResponses) {
                  apiItem.methodResponses = openapiItem?.methodResponses;
                } else {
                  if (openapiItem?.methodResponses) {
                    for (const response of openapiItem?.methodResponses) {
                      const responseItem = apiItem?.methodResponses.filter(item => item?.code === response?.code);
                      if (responseItem?.length > 0) {
                        responseItem[0].description = response?.description;
                      } else {
                        apiItem?.methodResponses.push(response);
                      }
                    }
                  }
                }
              } else if (prop === "methodParameters") {
                if (!apiItem.methodParameters) {
                  apiItem.methodParameters = openapiItem?.methodParameters;
                } else {
                  if (openapiItem?.methodParameters) {
                    for (const param of openapiItem?.methodParameters) {
                      const paramItem = apiItem?.methodParameters.filter(item => item?.name === param?.name);
                      if (paramItem?.length > 0) {
                        paramItem[0].description = param?.description;
                        paramItem[0].required = param?.required;
                      } else {
                        apiItem?.methodParameters.push(param);
                      }
                    }
                  }
                }
              } else if (!apiItem?.["prop"]) {
                apiItem[prop] = openapiItem?.[prop];
              }
            }
          }
          mergedItems.push(apiItem);
        } else {
          const similarItems = codeItems.filter(
            item =>
              apiItem?.epName?.toLowerCase() === item?.epName?.toLowerCase() &&
              apiItem?.methodName?.toLowerCase() === item?.methodName?.toLowerCase(),
          );
          if (similarItems.length === 0) {
            mergedItems.push(apiItem);
          }
        }
      }
      return mergedItems;
    } catch (err) {
      logger.error(`[${APIDiscoveryHelper.name}] failed to merge apiSecurityItems, repo: ${appName} err: ${err}`);
    }
    return apiSecurityItems;
  }

  static async loadOpenAPIFile(filePath: string, repo: Repo): Promise<any> {
    try {
      const pathInfo = `${repo?.cloneDir}/${filePath}`;
      const content = fs.readFileSync(pathInfo, "utf-8");

      //Delete after reading
      const fileHelper: FileHelper = new FileHelper("");
      fileHelper.deleteFile(pathInfo);

      // Check if the file is in YAML or JSON format based on its extension
      if (filePath.endsWith(".json")) {
        return JSON.parse(content);
      } else if (filePath.endsWith(".yaml") || filePath.endsWith(".yml")) {
        return yaml.safeLoad(content);
      }
    } catch (err) {
      logger.error(`[${APIDiscoveryHelper.name}] failed to loadOpenAPIFile, repo: ${repo.fullName} file path: ${filePath} err: ${err}`);
    }
  }

  static async extractAPIsFromSwagger(filePaths: FileWithLanguage[], repo: Repo, apisSecurity: ApiSecurityItem[]) {
    const unique = new Set();
    for (const file of filePaths) {
      try {
        let totalCount = apisSecurity.length;
        const openApiData = await APIDiscoveryHelper.loadOpenAPIFile(file?.filePath, repo);
        if (!openApiData) {
          continue;
        }

        APIDiscoveryHelper.createApiSecurityItem(openApiData, repo, apisSecurity, unique, file?.filePath);
        if (totalCount === apisSecurity.length) {
          logger.info(`[${APIDiscoveryHelper.name}] no apis were found in file, repo: ${repo.fullName} file: ${file?.filePath}`);
        } else {
          logger.info(
            `[${APIDiscoveryHelper.name}] found ${apisSecurity.length - totalCount} apis in file, repo: ${repo.fullName} file: ${
              file?.filePath
            }`,
          );
        }
      } catch (err) {
        logger.error(
          `[${APIDiscoveryHelper.name}] failed to extractAPIsFromSwagger, repo: ${repo.fullName} file: ${file?.filePath}, error: ${err}`,
        );
      }
    }
  }

  static createApiSecurityItem(openApiData: any, repo: Repo, apisSecurity: ApiSecurityItem[], unique: any, filePath: string) {
    try {
      const scanId = StatesHelper.Instance.uuid;
      const titlePlaceHolder = APIDiscoveryHelper.getTitleFromRepoName(repo);

      try {
        const paths = openApiData?.paths;
        if (!paths) {
          logger.info(`[${APIDiscoveryHelper.name}] failed to find path in file, repo: ${repo.fullName} file: ${filePath}`);
          return;
        }
        for (const [ep, methods] of Object.entries(paths)) {
          try {
            let pathGlobalParams: Parameter[] = [];
            if (methods["parameters"] && methods["parameters"].length > 0) {
              pathGlobalParams = methods["parameters"] as Parameter[];
            }
            for (const [methodName, method] of Object.entries(methods)) {
              try {
                const normalizedMethodName = methodName.toLowerCase();
                if (!this.isMethodAllowed(normalizedMethodName)) {
                  if (normalizedMethodName !== "parameters") {
                    logger.warn(
                      `[${APIDiscoveryHelper.name}] unknown method name, repo: ${repo.fullName} method: ${methodName}, file: ${filePath}`,
                    );
                  }
                  continue;
                }

                const apiSecurityItem: ApiSecurityItem = new ApiSecurityItem();
                apiSecurityItem.scanId = scanId;
                apiSecurityItem.appId = repo?.repoId;
                apiSecurityItem.appType = repo?.type;
                apiSecurityItem.appName = repo?.fullName;
                apiSecurityItem.appLink = repo?.link;
                const apiSecurityItemDef: ApiSecurityItemDef = new ApiSecurityItemDef();
                apiSecurityItemDef.source = ApiSecurityItemSource.codeOpenApi;
                try {
                  // keep relative path to the file within the app
                  let fileName = filePath;
                  if (fileName.startsWith(repo.cloneDir)) {
                    fileName = fileName.slice(repo.cloneDir.length + 1);
                  }
                  apiSecurityItemDef.fileName = fileName;
                  apiSecurityItem.fileName = [fileName];
                } catch (err) {
                  logger.error(`[${APIDiscoveryHelper.name}] failed set file name, repo: ${repo.fullName}, err: ${err}, file: ${filePath}`);
                }
                apiSecurityItemDef.link = getLinkToFile(repo, apiSecurityItemDef?.fileName, "", false);
                apiSecurityItem.definitions.push(apiSecurityItemDef);
                const info = openApiData?.info;
                apiSecurityItem.title = info?.title ? info?.title : titlePlaceHolder;
                apiSecurityItem.version = info?.version;
                apiSecurityItem.description = info?.description;

                apiSecurityItem.servers = openApiData?.servers?.map(i => i.url);
                apiSecurityItem.openapi = openApiData?.openapi;
                apiSecurityItem.epName = ep;
                apiSecurityItem.firstSeen = new Date();

                apiSecurityItem.methodName = normalizedMethodName !== "$ref" ? normalizedMethodName : undefined;
                apiSecurityItem.methodDescription = method?.description;
                apiSecurityItem.methodSummary = method?.summary;
                apiSecurityItem.methodOperationId = method?.operationId;

                const responses = method.responses;
                if (responses) {
                  for (const [responseCode, response] of Object.entries(responses)) {
                    try {
                      const r: ApiSecurityItemResponse = new ApiSecurityItemResponse();
                      r.code = responseCode;
                      r.description = (response as any).description;

                      if (!r.code.startsWith("__")) {
                        apiSecurityItem.methodResponses.push(r);
                      }
                    } catch (err) {
                      logger.error(
                        `[${APIDiscoveryHelper.name}] failed single responseCode, repo: ${repo.fullName}, err: ${err}, file: ${filePath}`,
                      );
                    }
                  }
                }

                apiSecurityItem.methodParameters = method?.parameters as Parameter[];
                apiSecurityItem.methodParameters = apiSecurityItem.methodParameters
                  ? apiSecurityItem.methodParameters.concat(pathGlobalParams)
                  : pathGlobalParams;
                apiSecurityItem.methodTags = method?.tags as string[];

                const u = `${apiSecurityItem.title}_${apiSecurityItem.epName}_${apiSecurityItem.methodName}`;
                if (!unique.has(u)) {
                  apisSecurity.push(apiSecurityItem);
                  unique.add(u);
                }
              } catch (err) {
                logger.error(`[${APIDiscoveryHelper.name}] failed single epName, repo: ${repo.fullName}, err: ${err}, file: ${filePath}`);
              }
            }
          } catch (err) {
            logger.error(`[${APIDiscoveryHelper.name}] failed single method, repo: ${repo.fullName}, err: ${err}, file: ${filePath}`);
          }
        }
      } catch (err) {
        logger.error(
          `[${APIDiscoveryHelper.name}] failed getSwaggerFileInfo for single, repo: ${repo.fullName}, err: ${err}, file: ${filePath}`,
        );
      }
    } catch (err) {
      logger.error(
        `[${APIDiscoveryHelper.name}] failed all createApiSecurityItem for repo: ${repo.fullName}, err: ${err}, file: ${filePath}`,
      );
    }
  }

  private static isMethodAllowed(method: string) {
    return Object.keys(httpMethods).includes(method) || method === "$ref";
  }
}

export default APIDiscoveryHelper;
