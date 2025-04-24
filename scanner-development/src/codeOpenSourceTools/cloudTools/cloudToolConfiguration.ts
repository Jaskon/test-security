import loggerImport from "../../logger";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";
import ToolConfigurationBase from "../base/toolConfigurationBase";
import { CloudResourcesToRun } from "../../entitis/cloudTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { isDevelopment, isLocalDevelopment } from "../../helper/envUtils";
import StatesHelper from "../../helper/statesHelper";

const logger = loggerImport.getDebugLogger();

const localDebug = process.env.DEBUG != undefined;

class cloudToolConfiguration extends ToolConfigurationBase {
  constructor(uuid: string, toolConfig: ToolConfig, token: Token) {
    super(uuid, toolConfig, token);
  }

  getCommand(cloudResourcesToExecuteObj: any) {
    const cloudPolicyToExecute: CloudResourcesToRun = cloudResourcesToExecuteObj as CloudResourcesToRun;

    let command = this.toolConfig.localSshToolName;

    if (StatesHelper.Instance.useProwlerWithServices) {
      // Eden to do - put the command in the file cloudSecurityTools.json after using new prowler flow
      command =
        "python /src/oxwrapper.py --base64 --tool prowler --cmd AWS_ACCESS_KEY_ID={KEY} AWS_SECRET_ACCESS_KEY={SECRET} AWS_SESSION_TOKEN={SESSION} prowler -o {MAPDIR} -b -s {ID} -F {ID} -M json";

      if (cloudPolicyToExecute.excludeChecks.length) {
        command += ` -e ${cloudPolicyToExecute.excludeChecks.join(" ")}`;
      }
    }

    let commandFromConfig = this.stringHelper.replaceAllRegex(command, "{MAPDIR}", cloudPolicyToExecute.folderRes);
    commandFromConfig = this.stringHelper.replaceAllRegex(commandFromConfig, "{ID}", cloudPolicyToExecute.id);
    commandFromConfig = this.stringHelper.replaceAllRegex(commandFromConfig, "{KEY}", this.token.password);
    commandFromConfig = this.stringHelper.replaceAllRegex(commandFromConfig, "{SECRET}", this.token.secret);
    commandFromConfig = this.stringHelper.replaceAllRegex(commandFromConfig, "{SESSION}", this.token.tokenSession);

    return commandFromConfig;
  }
}

export default cloudToolConfiguration;
