import { Token } from "../../entitis/collectorEntitisTypes";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";
import { isK8Mode } from "../../helper/envUtils";
import localToolRunner from "../../helper/localToolRunner";
import StringHelper from "../../helper/stringHelper";
import loggerImport from "../../logger";

const logger = loggerImport.getDebugLogger();
const util = require("util");
const exec = util.promisify(require("child_process").exec);
const onPrem = process.env.redisOnPrem != undefined;
const isk8 = isK8Mode();

abstract class ToolConfigurationBase {
  uuid: string;
  severityToolsBaseOnRuleName: any = {};
  toolConfig: ToolConfig;
  stringHelper: StringHelper;
  token: Token;

  constructor(uuid: string, toolConfig: ToolConfig, token: Token) {
    this.uuid = uuid;
    this.toolConfig = toolConfig;
    this.stringHelper = new StringHelper();
    this.token = token;
  }

  abstract getCommand(item: any);

  enableByPolicy() {
    const toolName = this.toolConfig.name.toUpperCase();
    const toolNameEnv = `TOOLS_${toolName}`;

    if (this.toolConfig.disableByOx) return false;

    if (toolNameEnv in process.env && process.env[toolNameEnv] === "enabled") {
      return true;
    }

    return false;
  }

  getFromEnv(envVar) {
    const res = process.env[envVar];
    if (res === undefined) {
      logger.error(`cannot find env ${envVar}`);
      return null;
    }
    return res;
  }

  getUrlForSqs(heavyTask: boolean = false) {
    if (localToolRunner().isConfiguredToRunToolsLocally()) {
      return process.env[this.toolConfig.env_redis_url];
    }

    let key = onPrem || isk8 || process.env.DOCKER_DEBUG ? this.toolConfig.env_redis_url : this.toolConfig.env_sqs_url;
    if (heavyTask) {
      key += "_HEAVY_TASK";
    }
    let url = process.env[key];

    if (url == undefined) {
      throw new Error(`failed to get url for ${this.toolConfig.name} due to undefined, env_redis_url: ${key}`);
    }
    if (url == "") {
      throw new Error(`failed to get url for ${this.toolConfig.name} due to empty, env_redis_url: ${key}`);
    }
    return url;
  }

  async runShell(requesterName: string, command: string) {
    try {
      await this.shell(requesterName, command);
      return true;
    } catch (err) {
      logger.error(`failed run shell command: ${command} to run err: ${err}`);
    }
    return false;
  }

  async shell(requesterName, command: string) {
    try {
      command = command.replace("#OX_CONFIG#", "--config=/var/ox");
      logger.info(`try run from shell, repo: ${requesterName}: cmd: ${command}`);

      const { stdout, stderr } = await exec(command, {
        maxBuffer: 1024 * 1024 * 10,
        env: { ...process.env, FOO: "ah" },
      });
      logger.debug(`stdout:, ${JSON.stringify(stdout, null, 4)}`);
      logger.debug(`stderr:, ${JSON.stringify(stderr, null, 4)}`);
    } catch (err) {
      logger.error(
        `uuid: ${this.uuid} shell command: ${command} failed to run error: ${err} stdout: ${err.stdout.slice(0, 100) + "\n"} stderr: ${
          err.stderr.slice(0, 100) + "\n"
        }`,
      );

      logger.info(`finish run from shell, requester name: ${requesterName} cmd: ${command}`);
    }
  }
}

export default ToolConfigurationBase;
