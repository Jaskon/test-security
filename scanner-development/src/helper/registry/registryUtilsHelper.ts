import { ImageScanInfo } from "../../dal/base/artifactoryBase";
import { ContainerSecurityType, ImageInfo } from "../../entitis/artifactoryTypes";
import { SecurityEvent, addSeverityChangedReason } from "../../entitis/codeRepoTypes";
import Constant from "../../entitis/constant";
import { severityReasons } from "../../entitis/service/blameTypes";
import loggerImport from "../../logger";
import { isDevelopment } from "../envUtils";
const logger = loggerImport.getDebugLogger();

export function identifyUserInstructions(securityAlerts: SecurityEvent[], imageInfo: ImageInfo) {
  const incorrectClassificationLibs = new Set();

  try {
    for (const alert of securityAlerts) {
      try {
        for (const instruction of Constant.dockerUserInstructions) {
          if (alert?.dockerInstructions?.includes(instruction)) {
            if (alert.containerScanType === ContainerSecurityType.baseOnly) {
              break;
            }
            if (alert.containerScanType === ContainerSecurityType.appOnly) {
              break;
            }

            addSeverityChangedReason(severityReasons.userInstructionsContainerVull, alert, undefined, alert.extraInfo);
            alert.containerScanType = ContainerSecurityType.instructionsOnly;
            break;
          }
        }
      } catch (err) {
        logger.error(`failed for single identifyUserInstructions, image: ${imageInfo.image.name}, err: ${err}`);
      }
    }
  } catch (err) {
    logger.error(`failed for all identifyUserInstructions, image: ${imageInfo.image.name}, err: ${err}`);
  }

  if (incorrectClassificationLibs.size > 0 && isDevelopment()) {
    logger.warn(
      `incorrectClassificationLibs , image: ${imageInfo.image.name}, data: ${Array.from(incorrectClassificationLibs).join(", ")}`,
    );
  }
}
