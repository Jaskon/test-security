import loggerImport from "../../logger";
import clientEncryptionApi from "@oxappsec/ox-unified-client-encryption";
import { Binary } from "bson";

const logger = loggerImport.getDebugLogger();

const decryptBase64Credential = async (credentials: any) => {
  try {
    const buf = Buffer.from(credentials as string, "base64");
    const binData = new Binary(buf, 6);

    const res = await clientEncryptionApi.decryptField.execute(binData as any);

    return res;
  } catch (error) {
    logger.error(`decrypt base 64 credential err: ${error}`);
  }
};

export { decryptBase64Credential };
