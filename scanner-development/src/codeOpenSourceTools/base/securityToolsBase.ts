import { SbomEvent } from "../../entitis/artifactoryTypes";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";
import FileHelper from "../../helper/IO/fileHlper";
import Iqueue from "../../helper/queue/Iqueue";
import ToolSeverity from "../../helper/tools/toolSeverity";
import loggerImport from "../../logger";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import ToolExclusions from "../codeTools/codeToolExclusions";
import ToolConfigurationBase from "./toolConfigurationBase";

const logger = loggerImport.getDebugLogger();

abstract class SecurityToolBase {
  uuid: string;
  orgPolicyParser: OrgPolicyParser;
  toolConfig: ToolConfig;
  securityToolsQueue: Iqueue;
  orgName: string;
  fileHelper: FileHelper;
  toolSeverity: ToolSeverity;
  toolConfiguration: ToolConfigurationBase;
  toolExclusions: ToolExclusions;
  requestId?: string;

  constructor(
    uuid: string,
    orgPolicyParser: OrgPolicyParser,
    toolConfig: ToolConfig,
    securityToolsQueue: Iqueue,
    orgName: string,
    toolConfigurationBase: ToolConfigurationBase,
  ) {
    this.uuid = uuid;
    this.toolConfig = toolConfig;
    this.orgPolicyParser = orgPolicyParser;
    this.securityToolsQueue = securityToolsQueue;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
    this.toolConfiguration = toolConfigurationBase;
    this.toolExclusions = new ToolExclusions(this.uuid);

    this.toolSeverity = new ToolSeverity(this.uuid, toolConfig.name);
    this.toolSeverity.parseConfigFile(this.toolConfig.severityConfigName);
  }

  async getToolResourceToRun() {
    return [];
  }
  async createSbomEvents(item: any): Promise<SbomEvent | null> {
    return null;
  }

  async createComplianceAlerts(item: any) {
    return null;
  }

  async applicationSecurity(item: any) {
    return [];
  }

  abstract runViaShell(item: any);
  abstract runViaSQS(item: any, secTool: any, ignoredTools: any, failedTools: any);
  abstract createSecurityEvents(item: any);
}

export default SecurityToolBase;
