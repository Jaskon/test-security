import loggerImport from "../../../../logger";
import { initExcludeFilesRegex } from "../../../IO/fileFilter";
import { ServiceBase } from "../../serviceBase";
import { getSettings } from "../gql/get-settings";
import { GetSettingsRequestsRes, SettingsSubType, SourceControlId } from "../types";

const logger = loggerImport.getDebugLogger();
const SCAN_SETTINGS_SERVICE_HOST_URL = process.env.SCAN_SETTINGS_SERVICE_HOST_URL;

export class SettingsService extends ServiceBase {
  private readonly DEFAULT_IRRELEVANT_APP_TIME_IN_MONTHS = 6;
  private readonly DEFAULT_IRRELEVANT_IMAGE_TIME_IN_MONTHS = 6;
  private readonly DEFINE_BRANCH = "";

  private constructor() {
    super(SCAN_SETTINGS_SERVICE_HOST_URL);
  }
  settings: GetSettingsRequestsRes = null;
  private static _instance: SettingsService;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  async init(orgId: string) {
    try {
      await this.setAuthHeader();
      this.settings = await this.gqlClient.request<GetSettingsRequestsRes>(getSettings, {
        orgId,
      });
      //Init from setting data
      initExcludeFilesRegex();
    } catch (e) {
      logger.error(`failed to get settings requests for settings service. orgId: ${orgId}`, e);
    }
  }

  async getSettings(orgId: string) {
    try {
      await this.setAuthHeader();
      const res = await this.gqlClient.request<GetSettingsRequestsRes>(getSettings, {
        orgId,
      });

      const resSettings = res.getSettings.settings || null;
      if (resSettings && resSettings != null) {
        logger.info(`setting info from service: ${JSON.stringify(resSettings)}`);
      }
      return resSettings;
    } catch (e) {
      logger.error(`failed to get settings requests for settings service. orgId: ${orgId}`, e);
    }
    return null;
  }

  irrelevantAppTimeInMonths(): number {
    const scanSettingsTemp = this?.settings?.getSettings?.settings?.find(
      obj => obj["settingsSubType"] === SettingsSubType.ConfiguredIrrelevantAppsTime,
    );
    return scanSettingsTemp?.configured ?? this.DEFAULT_IRRELEVANT_APP_TIME_IN_MONTHS;
  }

  defineBranch(sourceControlName: string): string {
    const sourceControlId = SourceControlId[sourceControlName];
    const subSettings = this?.settings?.getSettings?.settings?.find(
      obj => obj["settingsSubType"] === SettingsSubType.DefineBranch,
    ).subSettings;

    const subSettingWithId = subSettings?.flatMap(i => i.settings)?.find(setting => setting.idSubSetting === sourceControlId);
    const inputText = subSettingWithId?.inputText;
    return inputText ?? this.DEFINE_BRANCH;
  }

  irrelevantImageTimeInMonths(): number {
    const scanSettingsTemp = this?.settings?.getSettings?.settings?.find(
      obj => obj["settingsSubType"] === SettingsSubType.ConfiguredIrrelevantImagesTime,
    );
    return scanSettingsTemp?.configured ?? this.DEFAULT_IRRELEVANT_IMAGE_TIME_IN_MONTHS;
  }
}
