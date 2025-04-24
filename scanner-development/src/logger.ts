import ms from "ms";
import { createLogger, format, Logger as WinstonLogger, transports } from "winston";
import { AsyncTracker } from "./async-tracker.service";
import { ServerEnvironmentType } from "./entitis/commonTypes";
import { getEnvironmentType, isLocalDevelopment } from "./helper/envUtils";

let g_uid = "";
let g_org = "";

class Logger {
  private readonly logger: WinstonLogger = createLogger({
    level: "info",
    transports: [new transports.Console({ format: format.combine(...this.getConsoleFormat()) })],
  });

  debug(msg: string, additionalArgs: Record<string, unknown> = {}): void {
    this.logger.debug(msg, { ...additionalArgs, ...this.getLogArgs() });
  }

  info(msg: string, additionalArgs: Record<string, unknown> = {}): void {
    this.logger.info(msg, { ...additionalArgs, ...this.getLogArgs() });
  }

  warn(msg: string, err?: unknown, additionalArgs: Record<string, unknown> = {}): void {
    this.logger.warn(msg, { ...additionalArgs, ...this.getLogArgs(err) });
  }

  error(msg: string, err?: unknown, additionalArgs: Record<string, unknown> = {}): void {
    this.logger.error(msg, { ...additionalArgs, ...this.getLogArgs(err) });
  }

  time(msg: string, startTime: number, additionalArgs: Record<string, unknown> = {}): void {
    this.info(`${msg} ${ms(Date.now() - startTime)}`, additionalArgs);
  }

  private getConsoleFormat(): Parameters<typeof format.combine> {
    return [
      ServerEnvironmentType.Development,
      ServerEnvironmentType.Staging,
      ServerEnvironmentType.Beta,
      ServerEnvironmentType.Production,
      ServerEnvironmentType.Testing,
    ].includes(getEnvironmentType() as ServerEnvironmentType)
      ? [format.timestamp(), format.json()]
      : [format.timestamp(), format.colorize(), format.simple()];
  }

  private getLogArgs(err?: unknown): Record<string, unknown> {
    const correlatedInfo = { ...AsyncTracker.getLoggerInfo() };
    if ((err as Error)?.message) {
      correlatedInfo.error = (err as Error).message;
    }
    if ((err as Error)?.stack && !isLocalDevelopment()) {
      correlatedInfo.stackTrace = (err as Error).stack;
    }
    if (g_uid) {
      correlatedInfo.uid = g_uid;
    }
    if (g_org) {
      correlatedInfo.org = g_org;
    }
    return correlatedInfo;
  }
}

const logger = new Logger();
const getDebugLogger = () => {
  return logger;
};

const updateUniqueId = (uid, org) => {
  g_uid = uid;
  g_org = org;
};

export default { getDebugLogger, updateUniqueId };
