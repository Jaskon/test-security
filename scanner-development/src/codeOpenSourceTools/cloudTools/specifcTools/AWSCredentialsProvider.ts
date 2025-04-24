import { Credentials } from "@aws-sdk/types/dist-types/credentials";
import { AWSCredReturnType } from "../../../entitis/collectorEntitisTypes";
import loggerImport from "../../../logger";
const logger = loggerImport.getDebugLogger();
export interface AWSAccountCredentials extends Credentials {
  name: string; // Account Name
}
const AWSCredentialsProvider = () => {
  const allCredentials: AWSCredReturnType[] = [];
  const ecrCredentials = new Map<string, string>();
  return {
    addECRCredentials: (name: string, password: string) => {
      ecrCredentials.set(name, password);
    },
    getECRCredentials: (name: string): string | undefined => {
      return ecrCredentials.get(name);
    },
    registerKeys: (credentials: AWSCredReturnType[]) => {
      allCredentials.push(...credentials);
    },
    fetchAllKeys: (): AWSCredReturnType[] => {
      return allCredentials;
    },
    fetchKeyByName: async (name: string): Promise<AWSAccountCredentials | null> => {
      for (const key of allCredentials) {
        const token = (await key(false)).getToken();
        if (token.accountName === name) {
          return {
            name: name,
            accessKeyId: token.password,
            secretAccessKey: token.secret,
            sessionToken: token.tokenSession,
          };
        }
      }
      return null;
    },
    fetchCredentials: async (): Promise<AWSAccountCredentials[]> => {
      const credentials: AWSAccountCredentials[] = [];
      for (const key of allCredentials) {
        const token = (await key(false)).getToken();
        credentials.push({
          name: token.accountName ?? "empty-account-name",
          accessKeyId: token.password,
          secretAccessKey: token.secret,
          sessionToken: token.tokenSession,
        });
      }
      return credentials;
    },
  };
};
let instance: ReturnType<typeof AWSCredentialsProvider>;
const getAwsKeys = () => {
  if (!instance) {
    instance = AWSCredentialsProvider();
    return instance;
  }
  return instance;
};
export default getAwsKeys;
