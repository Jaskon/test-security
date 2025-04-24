import { AssumeRoleCommandOutput } from "@aws-sdk/client-sts";
import { Dirent, opendirSync, readFileSync, Stats, statSync } from "node:fs";
import { AWSCredReturnType, Token } from "../../entitis/collectorEntitisTypes";
import Constant from "../../entitis/constant";

import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();

const getCredentialsFromLocalCache = () => {
  interface AWSCachedKey {
    ProviderType: string;
    Credentials: {
      AccessKeyId: string;
      SecretAccessKey: string;
      SessionToken: string;
      Expiration: string;
    };
  }

  const initialFolder = process.env.HOME + "/.aws/cli/cache/";
  let newestFile = "";
  let lastModifiedFile = new Date(0);

  try {
    const dir = opendirSync(initialFolder);
    let dirent: Dirent | null;
    while ((dirent = dir.readSync()) !== null) {
      const statData: Stats = statSync(initialFolder + dirent.name);

      if (statData.ctime > lastModifiedFile) {
        lastModifiedFile = statData.ctime;
        newestFile = dirent.name;
      }
    }
    dir.closeSync();
  } catch (err) {
    logger.info(`Cannot find the cached AWS key, run aws configure sso (error: ${err})`);
  }

  if (newestFile) {
    const awsKey = readFileSync(initialFolder + newestFile);
    if (awsKey) {
      const parsedKey = JSON.parse(awsKey.toString()) as AWSCachedKey;

      return parsedKey.Credentials;
    }

    return {
      AccessKeyId: undefined,
      SecretAccessKey: undefined,
      SessionToken: undefined,
      Expiration: undefined,
    };
  }
};

const getFakeToken: AWSCredReturnType = async () => {
  return {
    getAssumedRole: (): AssumeRoleCommandOutput => {
      return {} as AssumeRoleCommandOutput;
    },

    getToken: () => {
      const parsedToken = getCredentialsFromLocalCache();

      if (process.env.MOCK_AWS_CREDENTIALS) {
        return new Token(
          "cloud",
          Constant.oxCloudConnectorName,
          Constant.oxCloudConnectorName,
          process.env.MOCK_AWS_ARN,
          "",
          process.env.MOCK_AWS_ACCESS_KEY_ID,
          false,
          "",
          "",
          "",
          true,
          1,
          process.env.MOCK_AWS_SECRET_ACCESS_KEY,
          process.env.MOCK_AWS_SESSION_TOKEN,
          "AWS",
        );
      }

      return new Token(
        "cloud",
        Constant.oxCloudConnectorName,
        Constant.oxCloudConnectorName,
        "arn:aws:iam::472441269583:role/OxAWSIntegrationRole-0208db34df87",
        "",
        parsedToken.AccessKeyId,
        false,
        "",
        "",
        "",
        true,
        1,
        parsedToken.SecretAccessKey,
        parsedToken.SessionToken,
        "AWS",
      );
    },
  };
};
export const getFakeCredentials = (): AWSCredReturnType[] => {
  return [getFakeToken];
};
