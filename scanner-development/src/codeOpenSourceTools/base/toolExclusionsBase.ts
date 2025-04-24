import loggerImport from "../../logger";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";

const logger = loggerImport.getDebugLogger();

abstract class ToolExclusionsBase {
  uuid: string;
  severityToolsBaseOnRuleName: any = {};
  toolConfig: ToolConfig;

  constructor(uuid: string) {
    this.uuid = uuid;
  }

  abstract ExcludedAlert(file: string, line: string, object: any);
}

export default ToolExclusionsBase;
