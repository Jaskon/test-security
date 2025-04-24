import axios from "axios";
import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { s3File, S3Service } from "../../helper/aws/s3Service";
import { isLocalDevelopment } from "../../helper/envUtils";
import loggerImport from "../../logger";
import { KongResource, ToolDefinition, ToolType } from "./types";
const logger = loggerImport.getDebugLogger();

export class InterceptConfig {
  private static readonly fileMap: Record<ToolType, string> = { kong: "Kong.json", solace: "Solace.json", generic: "Generic.json" };
  private static readonly toolDefinitionMap: Record<ToolType, Promise<s3File | undefined> | undefined> = {
    kong: undefined,
    solace: undefined,
    generic: undefined,
  };

  static async fetchToolDefinition(type: ToolType, orgId: string): Promise<ToolDefinition | undefined> {
    if (isLocalDevelopment() && !process.env.INTERCEPT_CONFIG_BUCKET) {
      return JSON.parse(await readFile(join(__dirname, "mocks", this.fileMap[type]), "utf-8"));
    }
    if (!this.toolDefinitionMap[type]) {
      this.toolDefinitionMap[type] = S3Service.getFileAndLastModified(
        S3Service.getClient({ region: process.env.INTERCEPT_CONFIG_AWS_REGION || "eu-west-1" }),
        { Bucket: process.env.INTERCEPT_CONFIG_BUCKET || "ox-download-bucket-test-k8s", Key: `PolicyFiles/${orgId}/${this.fileMap[type]}` },
      );
    }
    const { rawContent, lastModified } = await this.toolDefinitionMap[type];
    const config = JSON.parse(rawContent);
    logger.info(`[${InterceptConfig.name}] got config ${JSON.stringify(config.metadata)} and last modified ${lastModified}`);
    config.metadata.lastUploadDate = lastModified.toISOString();
    return config;
  }

  static async fetchKongConfiguration(resource: KongResource): Promise<string> {
    const result = await axios.get<string>(resource.url, {
      timeout: 60 * 1000,
      headers: { Authorization: "Bearer " + resource.token, "Content-Type": "application/json" },
    });

    if (result?.data) {
      return result.data;
    }
    throw new Error("Failed to get Kong configuration");
  }
}
