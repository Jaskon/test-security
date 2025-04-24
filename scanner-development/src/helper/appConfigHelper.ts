import { CategoryDisplayName, OxCategory } from "@oxappsec/ox-consolidated-categories";
import ToolProgressBase from "../codeOpenSourceTools/base/toolProgressBase";
import { Relevance, Repo, repoResourceType, resourceType, SecurityAlertType } from "../entitis/codeRepoTypes";
import { ScanType } from "../entitis/service/connector-message-types";
import loggerImport from "../logger";
import { Tool } from "../policy/rules/code/policyRulesBase";
import Iqueue from "./queue/Iqueue";
import { ScanMetric, sendScannerStringTelemetry } from "./telemetry-utils";
import { Application } from "../policy/reporting/types";
import { isDevelopment } from "./envUtils";
const logger = loggerImport.getDebugLogger();

class AppConfigHelper {
  private static _instance: AppConfigHelper;

  applicationsConfig: Application[] = [];

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  private constructor() {}
}

export function setConfiguredProps(repo: Repo) {
  try {
    const appConfig = AppConfigHelper.Instance.applicationsConfig.find(app => app.appId === repo.id);
    if (isDevelopment() && appConfig) {
      logger.info(`setConfiguredProps: ${JSON.stringify(appConfig)}`);
    }
    if (appConfig) {
      repo.overrideRelevance = appConfig.overrideRelevance;
      repo.isOverridingPriority = appConfig.isOverridingPriority;
      repo.overridePriority = appConfig.overridePriority;
      repo.appOwners = appConfig.appOwners;
      repo.pipeline = appConfig.pipeline;
    }
  } catch (e) {
    logger.error(`failed set override fields, err: ${e}`);
  }
}

export function appOverrideRelevance(id: string) {
  try {
    const appConfig = AppConfigHelper.Instance.applicationsConfig.find(app => app.appId === id);
    if (appConfig) {
      return appConfig.overrideRelevance;
    }
  } catch (err) {
    logger.error(`failed is app override relevance, err: ${err}`);
  }
  return Relevance.DEFAULT;
}

export default AppConfigHelper;
