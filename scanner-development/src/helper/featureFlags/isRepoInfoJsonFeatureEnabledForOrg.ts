import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();
export class isRepoInfoJsonFeatureEnabled {
  static async isEnabled(org: string): Promise<boolean> {
    return process.env.DEBUG == undefined;
  }
}
