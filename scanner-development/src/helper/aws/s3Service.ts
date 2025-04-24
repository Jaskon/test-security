import { GetObjectCommand, GetObjectCommandInput, S3Client, S3ClientConfig } from "@aws-sdk/client-s3";
import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();

export class S3Service {
  static getClient(config: S3ClientConfig): S3Client {
    return new S3Client(config);
  }

  static async getFileAndLastModified(client: S3Client, file: GetObjectCommandInput): Promise<s3File | undefined> {
    try {
      const { Body, LastModified } = await client.send(new GetObjectCommand(file));
      if (!Body) {
        return;
      }
      return { rawContent: await Body.transformToString('utf-8'), lastModified: LastModified };
    } catch (error) {
      logger.error(`[${S3Service.name}] Failed to get file from S3`, error);
    }
  }
}

export interface s3File {
  rawContent: string;
  lastModified: Date;
}