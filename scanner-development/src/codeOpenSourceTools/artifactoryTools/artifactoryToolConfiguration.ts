import { ArtifactoryResourceToRun } from "../../entitis/artifactoryTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";
import { isDevelopment } from "../../helper/envUtils";
import loggerImport from "../../logger";
import ToolConfigurationBase from "../base/toolConfigurationBase";
const logger = loggerImport.getDebugLogger();

const localDebug = process.env.DEBUG != undefined;

class ArtifactoryToolConfiguration extends ToolConfigurationBase {
  constructor(uuid: string, toolConfig: ToolConfig, token: Token) {
    super(uuid, toolConfig, token);
  }

  getCommand(resource: ArtifactoryResourceToRun) {
    let command = this.toolConfig.command;
    if (localDebug) {
      command = this.toolConfig.localSshToolName;
    }

    //Example: "trivy image --input {IMAGENAME} -f json -o {FILEDIR}/{FILENAME}";
    let regexToValueMap = {
      "{FILENAME}": this.toolConfig.fileNameOutput, //file name of output
      "{FILEDIR}": resource.dirWhereToPutRes, //dir to put res on network share
      "{IMAGENAME}": resource.netShareDownloadArtifactPathForScan, //full path to network share
      CLONEDIR: resource.toolCopyDestination,
      OUTPUTPATH: `${resource.dirWhereToPutRes}/${this.toolConfig.fileNameOutput}`,
    };

    const commandFromConfig = Object.entries(regexToValueMap).reduce(
      (result, [regex, value]) => this.stringHelper.replaceAllRegex(result, regex, value),
      command,
    );

    logger.info(`Command to run by ${commandFromConfig}`);

    return commandFromConfig;
  }
}

export default ArtifactoryToolConfiguration;
