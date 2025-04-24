const SwaggerParser = require("@apidevtools/swagger-parser");
import loggerImport from "../logger";
import fs from "fs";
const logger = loggerImport.getDebugLogger();
const pathExtension = require("path");
import { File, Repo } from "../entitis/codeRepoTypes";
import StatesHelper from "./statesHelper";
import {
  ApiSecurityItem,
  ApiSecurityItemDef,
  ApiSecurityItemResponse,
  ApiSecurityItemSource,
  Parameter,
  httpMethods,
} from "../entitis/apiTypes";
import { getLinkToFile } from "./commonUtils";

export async function getSwaggerFileInfo(filePath: string, repo: Repo) {
  const res: ApiSecurityItem[] = [];
  let rawdata;

  try {
    if (!StatesHelper.Instance.isApiSecEnable) {
      return [];
    }

    rawdata = fs.readFileSync(filePath, "utf-8");
    const jsObj = JSON.parse(rawdata);

    if (!Array.isArray(jsObj)) {
      return [];
    }

    const unique = new Set();

    const openapiData = jsObj.find(i => i.check_type === "openapi");
    if (openapiData?.results?.failed_checks) {
      createApiSecurityItem(openapiData.results.failed_checks, repo, res, unique);
    }
    if (openapiData?.results?.passed_checks) {
      createApiSecurityItem(openapiData.results.passed_checks, repo, res, unique);
    }
  } catch (err) {
    logger.error(`failed all getSwaggerFileInfo for repo: ${repo.fullName}, err: ${err}, rawdata: ${rawdata}`);
  }
  return res;
}

function createApiSecurityItem(failed_checks: any, repo: Repo, res: ApiSecurityItem[], unique: any) {
  try {
    const scanId = StatesHelper.Instance.uuid;

    for (const result of failed_checks) {
      try {
        const paths = result.check_result.results_configuration.paths;
        if (!paths) {
          continue;
        }
        for (const [ep, methods] of Object.entries(paths)) {
          try {
            let pathGlobalParams: Parameter[] = [];
            if (methods["parameters"] && methods["parameters"].length > 0) {
              pathGlobalParams = methods["parameters"] as Parameter[];
            }
            for (const [methodName, method] of Object.entries(methods)) {
              const normalizedMethodName = methodName.toLowerCase();

              try {
                if (!Object.keys(httpMethods).includes(normalizedMethodName) && normalizedMethodName !== "$ref") {
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
                  if (result.repo_file_path) {
                    const f = result.file_path.substring(1);
                    //const dasd = pathExtension.basename(result.repo_file_path);
                    apiSecurityItemDef.fileName = f;
                    apiSecurityItem.fileName = f;
                  }
                } catch (err) {
                  logger.error(`failed set file name, repo: ${repo.fullName}, err: ${err}`);
                }
                apiSecurityItemDef.link = getLinkToFile(repo, apiSecurityItemDef?.fileName, "", false);
                apiSecurityItem.definitions.push(apiSecurityItemDef);
                const info = result.check_result.results_configuration.info;
                apiSecurityItem.title = info.title;
                apiSecurityItem.version = info.version;
                apiSecurityItem.description = info?.description;

                apiSecurityItem.servers = result?.check_result?.results_configuration?.servers?.map(i => i.url);
                apiSecurityItem.openapi = result?.check_result?.results_configuration?.openapi;
                apiSecurityItem.epName = ep;
                apiSecurityItem.firstSeen = new Date();

                apiSecurityItem.methodName = normalizedMethodName;
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
                      logger.error(`failed single responseCode, repo: ${repo.fullName}, err: ${err}`);
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
                  res.push(apiSecurityItem);
                  unique.add(u);
                }
              } catch (err) {
                logger.error(`failed single epName, repo: ${repo.fullName}, err: ${err}`);
              }
            }
          } catch (err) {
            logger.error(`failed single method, repo: ${repo.fullName}, err: ${err}`);
          }
        }
      } catch (err) {
        logger.error(`failed getSwaggerFileInfo for single, repo: ${repo.fullName}, err: ${err}`);
      }
    }
  } catch (err) {
    logger.error(`failed all createApiSecurityItem for repo: ${repo.fullName}, err: ${err}`);
  }
}

//---------------------------
// VAmPI, books/v1, get, 200, NO PARMAS, alex, description
// ---------------------
