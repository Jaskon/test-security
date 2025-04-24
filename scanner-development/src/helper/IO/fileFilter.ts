import { isDevelopment, isLocalDevelopment } from "../envUtils";
import { SettingsService } from "../service/scan-settings-service/service/settings-service";
import { SettingsSubType } from "../service/scan-settings-service/types";
import loggerImport from "../../logger";

const logger = loggerImport.getDebugLogger();

export let excludeFilesRegex: RegExp = null;

export function escapeRegex(string) {
  return string.replace(/[/\-\\^$*+?.()|[\]{}]/g, "\\$&");
}

export function initExcludeFilesRegex() {
  try {
    const scanSettingsTemp = SettingsService?.Instance?.settings?.getSettings?.settings?.find(
      obj => obj["settingsSubType"] === SettingsSubType.ExcludeFiles,
    );
    let regexArr: string[] = [];
    let regexStr = "";
    if (scanSettingsTemp && scanSettingsTemp !== null && scanSettingsTemp !== undefined) {
      regexArr = scanSettingsTemp.valueList;
    }

    regexArr.forEach(regex => (regex = escapeRegex(regex)));
    logger.info(`regexArr: ${JSON.stringify(regexArr)}`);
    regexStr = regexArr.length === 0 ? "" : regexArr.join("|");
    if (!regexStr) {
      return;
    }
    excludeFilesRegex = new RegExp(regexStr, "i");

    logger.info(`initExcludeFilesRegex finish: excludeFilesRegex: ${excludeFilesRegex}`);
  } catch (err) {
    logger.error(`initExcludeFilesRegex failed: ${err}`);
  }
}

export function isExcludedAlert(file: string, fullPath: string) {
  try {
    if (file) {
      if (excludeFilesRegex !== null) {
        const isIrrelevantFile = excludeFilesRegex.test(file);
        if (isIrrelevantFile) {
          return true;
        }
      }
    }

    if (fullPath) {
      if (excludeFilesRegex !== null) {
        const isIrrelevantFile = excludeFilesRegex.test(fullPath);
        if (isIrrelevantFile) {
          return true;
        }
      }
    }

    return false;
  } catch (err) {
    logger.error(`failed check regex for file:${file}, err: ${err}`);
  }
  return false;
}
