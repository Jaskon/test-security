import { Constant } from "../../entitis/constant";
import loggerImport from "../../logger";
import ToolExclusionsBase from "../base/toolExclusionsBase";

const logger = loggerImport.getDebugLogger();

class ToolExclusions extends ToolExclusionsBase {
  constructor(uuid: string) {
    super(uuid);
  }

  ExcludedAlert(file: string, line: string, object: any) {
    try {
      if (file === "" || file == null || file == undefined) {
        return false;
      }
      if (line === "" || line == null || line == undefined) {
        return false;
      }

      //mishel
      if (Constant.ignoreLineInfo.exec(line) != null) {
        //Debug
        //logger.info(`tool: ${this.toolConfig?.name} excluded: ${file}`);
        return true;
      }
    } catch (err) {
      logger.error(`failed check if alert excluded, tool: ${this.toolConfig?.name}, repo ${JSON.stringify(object, null, 4)} err: ${err}`);
    }
    return false;
  }

  ExcludedSASTAlert(filePath: string, object: any) {
    try {
      if (filePath === "" || filePath == null || filePath == undefined) {
        return false;
      }

      if (Constant.ignoreSastFiles.exec(filePath) != null) {
        logger.debug(`tool: ${this.toolConfig?.name} excluded sast alert: ${JSON.stringify(object, null, 4)}`);
        return true;
      }
    } catch (err) {
      logger.error(
        `failed check if sast alert excluded, tool: ${this.toolConfig?.name}, repo ${JSON.stringify(object, null, 4)} err: ${err}`,
      );
    }
    return false;
  }
}

export default ToolExclusions;
