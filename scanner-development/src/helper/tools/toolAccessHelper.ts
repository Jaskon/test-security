import { ECRClient, GetAuthorizationTokenCommand } from "@aws-sdk/client-ecr";
import { Credentials } from "@aws-sdk/types/dist-types/credentials";
import loggerImport from "../../logger";
import { hash } from "../hash";

const logger = loggerImport.getDebugLogger();

class ToolAccessHelper {
  async getIsECRConfigureForDownload(token: Credentials & { region?: string }): Promise<string> {
    try {
      const ecrClient = new ECRClient({
        region: token.region,
        credentials: { accessKeyId: token.accessKeyId, secretAccessKey: token.secretAccessKey, sessionToken: token.sessionToken },
      });
      const res = await ecrClient.send(new GetAuthorizationTokenCommand({}));
      logger.info(`isTrivyArtifactsHaveAccess - have access, account name: ${hash(token.accessKeyId)}`);
      for (const authorizationData of res.authorizationData) {
        let base64Rebased = Buffer.from(authorizationData.authorizationToken, "base64").toString("utf8");
        let rebased = base64Rebased.split(":");
        logger.info(`this is rebased ${rebased} and this is base64 ${base64Rebased} and this is region ${token.region}`);
        return rebased[1] ?? "";
      }
    } catch (err) {
      if ("name" in err && err.name === "AccessDeniedException") {
        logger.info(
          `(isTrivyArtifactsHaveAccess): ${
            err.message ??
            `Supplied Token does not have permissions to perform ecr:GetAuthorizationToken on resource, account name: ${hash(
              token.accessKeyId,
            )}`
          }`,
        );
      } else {
        logger.error(
          `(isTrivyArtifactsHaveAccess): Failed to verify authorization to perform ecr:GetAuthorizationToken on resource with error: ${err}, account name: ${hash(
            token.accessKeyId,
          )}`,
        );
      }
    }
    return "";
  }
}

export default ToolAccessHelper;
