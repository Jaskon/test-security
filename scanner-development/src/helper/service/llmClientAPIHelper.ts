import { ApiSecurityItem, Frameworks } from "../../entitis/apiTypes";
import { Repo, VCSType } from "../../entitis/codeRepoTypes";
import loggerImport from "../../logger";
import { isDevelopment } from "../envUtils";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";
import LlmClientBase from "./llmClientBase";

const fs = require("fs");

const logger = loggerImport.getDebugLogger();

class LlmClientAPIHelper extends LlmClientBase {
  constructor(queue: Iqueue, uuid: string, orgName: string) {
    super(queue, uuid, orgName);
  }

  async callLlmClientForAPIEnrichment(repo: Repo, apiSecurityItems: ApiSecurityItem[]) {
    try {
      if (!isDevelopment()) {
        return;
      }

      if (StatesHelper.Instance.isWalmart) {
        return;
      }

      if (!StatesHelper.Instance.isApiSecEnable) {
        return;
      }

      if (repo.vcsType === VCSType.tfvc) {
        return;
      }

      if (repo.isDelta) {
        logger.info(`[${this.constructor.name}] skipping isDelta, repo:${repo.fullName}`);
        return;
      }

      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      /*if (StatesHelper.Instance.orgName !== "org_YQJjYibqvhrDCBFe" && StatesHelper.Instance.orgName !== "org_bpQgKfoWfnusOKtW") {
        return;
      }*/

      if (apiSecurityItems.length == 0) {
        return;
      }

      this.appName = repo?.fullName;
      this.repo = repo;

      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;

      logger.info(`[${this.constructor.name}] Start, repo:${this.appName}`);
      await this.setInputInfo(apiSecurityItems);
      const resFile = await this.sendAndWaitForRes();
      if (resFile) {
        this.parseLlmRestult(fs.readFileSync(resFile, "utf8"), apiSecurityItems);
      }
      logger.info(`[${this.constructor.name}] End, repo:${this.appName}`);
    } catch (err) {
      logger.error(`[${this.constructor.name}] Failed, repo:${repo.fullName}, err: ${err}`);
    }
  }

  async setInputInfo(apiSecurityItems: ApiSecurityItem[]) {
    logger.info(`[${this.constructor.name}] apiSecurityItems length: ${apiSecurityItems.length}, for ${this.appName}`);
    fs.mkdirSync(this.dirToPutRes, { recursive: true });
    const filteredItems = apiSecurityItems
      .map(obj => ({
        uid: obj.uuid,
        model: "api_enrichment",
        modelInput: {
          snippet: obj.definitions[0].snippet,
          language: this.frameworkToLanguage(obj.framework),
          framework: obj.framework,
          filename: obj.definitions[0].fileName,
          endpoint: obj.epName,
          method: obj.methodName,
          parameters: obj.methodParameters,
          responses: obj.methodResponses,
          repoName: this.appName,
          parentRepoOfMonoRepo: this.repo?.parentRepoOfMonoRepo != null ? this.repo.parentRepoOfMonoRepo?.fullName : "",
        },
      }))
      .flat();
    const jsonData = JSON.stringify(filteredItems);
    fs.writeFileSync(this.inputFileName, jsonData, "utf8");
  }

  frameworkToLanguage(framework: string) {
    switch (framework.toLowerCase()) {
      case Frameworks.django.toLowerCase():
      case Frameworks.fastapi.toLowerCase():
      case Frameworks.flask.toLowerCase():
        return "Python";
      case Frameworks.expressJS.toLowerCase():
      case Frameworks.nestJS.toLowerCase():
        return "Javascript";
      case Frameworks.springBoot.toLowerCase():
        return "Java";
      case Frameworks.gin.toLowerCase():
        return "Go";

      default:
        return "";
    }
  }

  parseLlmRestult(resJson: string, apiSecurityItems: ApiSecurityItem[]) {
    if (apiSecurityItems.length == 0) {
      logger.error(`${this.constructor.name}] apiSecurityItems.length == 0, repo:${this.appName}`);
      return;
    }

    const llmDataRes = JSON.parse(resJson);
    if (llmDataRes.length == 0) {
      logger.error(`${this.constructor.name}] parseLlmRestult.length == 0, repo:${this.appName}`);
      return;
    }

    const apisMap: Record<string, ApiSecurityItem> = apiSecurityItems.reduce((result, obj) => {
      result[obj?.uuid] = obj;
      return result;
    }, {});

    for (const llmRes of llmDataRes) {
      if (llmRes.success !== true) {
        continue;
      }

      let apiItem: ApiSecurityItem = apisMap[llmRes?.uid];
      if (!apiItem) {
        logger.error(`${this.constructor.name}] apiItem was not found by uid, repo:${this.appName}`);
        return;
      }

      apiItem.definitions[0].llmTitle = llmRes?.modelResult?.api_inv_title;
      apiItem.definitions[0].llmDescription = llmRes?.modelResult?.api_inv_description;
    }
  }
}

export default LlmClientAPIHelper;
