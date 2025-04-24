import { Token } from "../../entitis/collectorEntitisTypes";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";
import Iqueue from "../../helper/queue/Iqueue";
import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import securityToolsJson from "../config/codeSecurityTools.json";
import SecurityToolBase from "./securityToolsBase";

const logger = loggerImport.getDebugLogger();

abstract class ToolsCreatorBase {
  uuid: string;
  orgPolicyParser: OrgPolicyParser;
  orgName: string;
  securityTools: SecurityToolBase[] = [];
  securityToolsQueue: Iqueue;
  token: Token;

  constructor(uuid: string, orgPolicyParser: OrgPolicyParser, orgName: string, securityToolsQueue: Iqueue, token: Token) {
    this.uuid = uuid;
    this.orgPolicyParser = orgPolicyParser;
    this.orgName = orgName;
    this.securityToolsQueue = securityToolsQueue;
    this.token = token;
  }

  abstract setTools();

  setSpecificTool(toolName: string): ToolConfig {
    const tool = securityToolsJson.tools.find(i => i.name === toolName);
    if (tool == undefined) {
      return;
    }

    const copy = JSON.parse(JSON.stringify(tool));
    this.addTool(copy, true);
    return copy;
  }

  addTool(toolInfo, specificTool: boolean) {}

  addScanner(scanner: SecurityToolBase) {
    const enableToolAlways = scanner.toolConfiguration.toolConfig.enableAlways && !process.env.CLOUD_DEBUG_INTERNAL;
    if (!scanner.toolConfiguration.enableByPolicy() && !enableToolAlways) {
      return;
    }
    StatesHelper.Instance.addTotalTools(scanner.toolConfig.name, scanner.toolConfig.critical);

    this.securityTools.push(scanner);
  }
}

export default ToolsCreatorBase;
