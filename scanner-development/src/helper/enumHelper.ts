import loggerImport from "../logger";
import { SecurityAlertType } from "../entitis/codeRepoTypes";
import Constant from "../entitis/constant";
const logger = loggerImport.getDebugLogger();

class EnumHelper {
  stringToSecurityAlertEnum(str) {
    try {
      if (Constant.secretIdentifierRegex.exec(str) != null) return SecurityAlertType.secrets;
      if (Constant.scaIdentifierRegex.exec(str) != null) return SecurityAlertType.sca;
      if (Constant.iacIdentifierRegex.exec(str) != null) return SecurityAlertType.iac;
      return SecurityAlertType.sast;
    } catch (err) {
      logger.error(`failed convert string to security alert enum err: ${err}, str: ${str}`);
    }
    return SecurityAlertType.Unknown;
  }
}

export default EnumHelper;
