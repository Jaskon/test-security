import { Repo, VCSType } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";
import { escapeCharsFromPath as escapeChars } from "../../helper/commonUtils";
import { isK8Mode } from "../../helper/envUtils";
import localToolRunner from "../../helper/localToolRunner";
import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";
import ToolConfigurationBase from "../base/toolConfigurationBase";

const logger = loggerImport.getDebugLogger();

const localDebug = process.env.DEBUG != undefined && !process.env.DOCKER_DEBUG;
const onPrem = process.env.redisOnPrem != undefined;
const isk8 = isK8Mode();

class codeToolConfiguration extends ToolConfigurationBase {
  devLanToCommandForSemgrep = {
    c: "--config=/var/semgrep-rules/c",
    "c++": "--config=/var/semgrep-rules/c",
    "c#": "--config=/var/semgrep-rules/csharp",
    go: "--config=/var/semgrep-rules/go",
    java: "--config=/var/semgrep-rules/java --config=/var/semgrep-rules/scala",
    javascript: "--config=/var/semgrep-rules/javascript --config=/var/semgrep-rules/typescript",
    python: "--config=/var/semgrep-rules/python",
    kotlin: "--config=/var/semgrep-rules/kotlin",
    php: "--config=/var/semgrep-rules/php",
    ruby: "--config=/var/semgrep-rules/ruby",
    rust: "--config=/var/semgrep-rules/rust",
    scala: "--config=/var/semgrep-rules/scala --config=/var/semgrep-rules/java",
    typescript: "--config=/var/semgrep-rules/typescript --config=/var/semgrep-rules/javascript",
  };
  defaultSemGrepCommand =
    "--config=/var/semgrep-rules/c --config=/var/semgrep-rules/csharp --config=/var/semgrep-rules/go --config=/var/semgrep-rules/java --config=/var/semgrep-rules/javascript --config=/var/semgrep-rules/python --config=/var/semgrep-rules/kotlin --config=/var/semgrep-rules/php --config=/var/semgrep-rules/ruby --config=/var/semgrep-rules/scala --config=/var/semgrep-rules/typescript";

  constructor(uuid: string, toolConfig: ToolConfig, token: Token) {
    super(uuid, toolConfig, token);
  }

  getCommand(repoObj: any) {
    const repo: Repo = repoObj as Repo;

    let outputDir =
      this.toolConfig.fileNameAutomaticallyCreated === "true"
        ? `${repo.securityResDir}/`
        : `${repo.securityResDir}/${this.toolConfig.fileNameOutput}`;

    let command = repo.isMonoRepoParentOrChild || repo.vcsType === VCSType.tfvc ? this.toolConfig.monoRepoCommand : this.toolConfig.command;
    if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
      command = this.toolConfig.localSshToolName;
    }

    const isGitleaks = this.toolConfig.name.toLowerCase() === "gitleaks";
    const isGitleaksPipelineScan = StatesHelper.Instance.isPipelineScan && isGitleaks;

    if (isGitleaksPipelineScan) {
      // since it includes --no-git option
      command = this.toolConfig.monoRepoCommand;
    }

    if (onPrem && !isk8) {
      command = repo.isMonoRepoParentOrChild ? this.toolConfig.onPremMonoRepo : this.toolConfig.onPrem;
      if (isGitleaksPipelineScan) {
        // since it includes --no-git option
        command = this.toolConfig.onPremMonoRepo;
      }
    }

    let cloneRepoPath = repo.getRepoPathForToolCommand();
    if (localToolRunner().isConfiguredToRunToolsLocally()) {
      // command = this.toolConfig.onPrem;
      outputDir = localToolRunner().updatePath(outputDir);
      cloneRepoPath = localToolRunner().updateMntPath(cloneRepoPath);
    } else if (localDebug) {
      command = this.toolConfig.localSshToolName;
    }

    //Use this to ignore update of the db
    if (StatesHelper.Instance.isHilan) {
      if (this.toolConfig.name.toLowerCase() === "trivy") {
        command = this.toolConfig.onPrem;
      }
    }

    let commandFromConfig = this.stringHelper.replaceAllRegex(command, "CLONEDIR", cloneRepoPath);
    commandFromConfig = this.stringHelper.replaceAllRegex(commandFromConfig, "OUTPUTPATH", outputDir);

    if (!process.env.DEBUG) {
      commandFromConfig = escapeChars(commandFromConfig);
    }

    const enableByLowSeverity = StatesHelper.Instance.tooByCatLowEnabled[this.toolConfig.defaultType];
    if (enableByLowSeverity) {
      if (this.toolConfig.injectToCommand !== "") {
        commandFromConfig = this.stringHelper.replaceAllRegex(commandFromConfig, "injectToCommand", "");
      }
      //Disable tool by command
    } else {
      if (this.toolConfig.injectToCommand !== "") {
        commandFromConfig = this.stringHelper.replaceAllRegex(commandFromConfig, "injectToCommand", this.toolConfig.injectToCommand);
      }
    }

    commandFromConfig = this.getToolCommandByDevLan(repo, commandFromConfig).trim();
    return commandFromConfig;
  }

  getToolCommandByDevLan(repo: Repo, commandFromConfig: string) {
    if (this.toolConfig.name.toLowerCase() === "semgrep") {
      try {
        const commandBaseOnDevLen = new Set();
        for (const language of repo.languages) {
          const devCommand = this.devLanToCommandForSemgrep[language.language.toLowerCase()];
          if (devCommand == undefined) {
            continue;
          }
          commandBaseOnDevLen.add(devCommand);
        }

        if (commandBaseOnDevLen.size == 0) {
          commandBaseOnDevLen.add(this.defaultSemGrepCommand);
          logger.info(`using default for semgrep: ${this.toolConfig?.name}, repo ${repo.fullName}`);
        }

        let c = Array.from(commandBaseOnDevLen).join(" ");
        commandFromConfig = this.stringHelper.replaceAllRegex(commandFromConfig, "DEVLAN", c);
      } catch (err) {
        logger.error(`using default for semgrep: ${this.toolConfig?.name}, repo ${repo.fullName}, err: ${err}`);
        commandFromConfig = this.stringHelper.replaceAllRegex(commandFromConfig, "DEVLAN", this.defaultSemGrepCommand);
      }
    }

    return commandFromConfig;
  }
}

export default codeToolConfiguration;
