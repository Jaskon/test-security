import { readFile } from "node:fs/promises";
import os from "node:os";
import { join } from "node:path";
import loggerImport from "../../logger";
import { isLocalDevelopment } from "../envUtils";
const logger = loggerImport.getDebugLogger();

class MemoryMonitorHelper {
  private static _instance: MemoryMonitorHelper;
  private constructor() {}

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  async printSnapshot(orgName: string, uuid: string, step: string) {
    try {
      const used = process.memoryUsage();
      const js = [];
      for (let key in used) {
        const i = `${key} - ${this.bytesToMb(used[key])} MB`;
        js.push(i);
      }
      logger.info(
        `step: ${step}.` +
          ` container memory snapshot: ${await this.createPrintableContainerMemorySnaphshotMessage()}.` +
          ` node memory snapshot: ${js.join(", ")}.` +
          ` host memory snapshot: ${this.createPrintableHostMemorySnaphshotMessage()}`,
      );
    } catch (err) {
      logger.error(`step: ${step}, failed print memory snapshot, err: ${err}`);
    }

    return -1;
  }

  private createPrintableHostMemorySnaphshotMessage() {
    const freemem = this.bytesToMb(os.freemem());
    const totalmem = this.bytesToMb(os.totalmem());

    return `freemem - ${freemem} MB, totalmem - ${totalmem} MB`;
  }

  private async createPrintableContainerMemorySnaphshotMessage() {
    const usage = this.bytesToMb(await this.getContainerMemFileValue("memory.usage_in_bytes"));
    const limit = this.bytesToMb(await this.getContainerMemFileValue("memory.limit_in_bytes"));

    return `usage - ${usage} MB, limit - ${limit} MB`;
  }

  private async getContainerMemFileValue(filename: string) {
    if (isLocalDevelopment()) return NaN;

    const memFolder = "/sys/fs/cgroup/memory";
    try {
      const contents = await readFile(join(memFolder, filename), "utf-8");
      return parseInt(contents.trim());
    } catch (e) {
      logger.error(`[${MemoryMonitorHelper.name}] unable to read ${filename} at ${memFolder}`, e);
      return NaN;
    }
  }

  private bytesToMb(bytes: number) {
    return Math.round((bytes / 1024 / 1024) * 100) / 100;
  }
}

export default MemoryMonitorHelper;
