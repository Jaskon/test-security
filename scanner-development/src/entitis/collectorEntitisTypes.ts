import { DescribeRegionsCommandOutput } from "@aws-sdk/client-ec2";
import { AssumeRoleCommandOutput } from "@aws-sdk/client-sts";
import { AsyncTracker } from "../async-tracker.service";
import getAwsKeys from "../codeOpenSourceTools/cloudTools/specifcTools/AWSCredentialsProvider";
import AWSQueries from "../codeOpenSourceTools/cloudTools/specifcTools/AWSQueries";
import AwsSTSHelper from "../helper/connectorsSpecific/awsSTShelper";
import ToolAccessHelper from "../helper/tools/toolAccessHelper";
import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();
export interface AWSCredReturnType {
  (refresh: boolean): Promise<{
    getAssumedRole: () => AssumeRoleCommandOutput;
    getToken: () => Token;
  }>;
}
//Token
export class Token {
  type: string;
  name: string;
  userName: string;
  host: string;
  password: string;
  protocol: string;
  port: string;
  apiVersion: string;
  strictSSL: boolean;
  secret: string;
  tokenSession: string;
  globalRepositories: boolean;
  executionOrder: number;
  isTool: boolean;
  accountName: string;
  isOxBuiltIn: boolean;
  family: string;
  region: string = process.env.REGION;
  friendlyName: string;
  tenantId: string;
  clientId: string;
  clientSecret: string;
  subscriptionId: string;
  accessToDownloadECRonAWS: string = "";
  apiKey: string = "";
  organizationId: string = "";
  authUrl: string = "";
  sshToken: string = "";
  configFilePath: string = "";
  apiUrl: string = "";

  // Bitbucket app
  appKey: string = null;
  clientKey: string = null;
  sharedSecret: string = null;

  constructor(
    type: string,
    name: string,
    friendlyName: string,
    userName: string,
    host: string,
    password: string,
    isTool: boolean,
    protocol: string,
    port: string,
    apiVersion: string,
    strictSSL: boolean,
    executionOrder: number,
    secret: string = "",
    tokenSession: string = "",
    accountName: string = "",
    tenantId: string = "",
    clientId: string = "",
    clientSecret: string = "",
    subscriptionId: string = "",
    apiKey: string = "",
    organizationId: string = "",
    apiUrl: string = "",
  ) {
    this.type = type;
    this.name = name;
    this.userName = userName;
    this.apiVersion = apiVersion;
    this.strictSSL = strictSSL;
    this.password = password;
    this.host = host;
    this.protocol = protocol;
    this.port = port;
    this.secret = secret;
    this.tokenSession = tokenSession;
    this.executionOrder = executionOrder;
    this.isTool = isTool;
    this.accountName = accountName;
    this.friendlyName = friendlyName;
    this.tenantId = tenantId;
    this.clientId = clientId;
    this.clientSecret = clientSecret;
    this.subscriptionId = subscriptionId;
    this.apiKey = apiKey;
    this.organizationId = organizationId;
    this.apiUrl = apiUrl;
    if (type === "" || this.name === "") {
      throw `token missing data, name: ${name}, type: ${type}, password: ${password}`;
    }
  }
  //
  // Return AssumeRoleResponse instead of the regular token
  //
  async getAWSCredAccountsEx(uuid: string, orgId: string): Promise<AWSCredReturnType[]> {
    try {
      const tokenGetters: AWSCredReturnType[] = [];
      const awsHelper: AwsSTSHelper = new AwsSTSHelper(uuid, this.accountName, this.secret);
      const accounts = await awsHelper.getAccounts(this.userName, "verify-credentials-role", this.password);
      logger.info(`found aws accounts: ${accounts.length}`);

      for (const account of accounts) {
        tokenGetters.push(async (refresh = false) => {
          AsyncTracker.setValue("ox-aws-account-id", account?.account?.Id);
          AsyncTracker.setValue("ox-aws-account-name", account?.account?.Name);
          const currentDate = new Date();
          const expirationDate = account.assumeRoleResponse.Credentials.Expiration;
          if (refresh || (expirationDate && currentDate > expirationDate)) {
            // Generate new token
            const toolAccessHelper: ToolAccessHelper = new ToolAccessHelper();
            const awsHelper: AwsSTSHelper = new AwsSTSHelper(uuid, this.accountName, this.secret);
            const allAccounts = await awsHelper.getAccounts(this.userName, "verify-credentials-role", this.password);
            logger.info(`found aws allAccounts: ${accounts.length}`);
            const currentAccount = allAccounts.filter(acc => {
              return acc?.account?.Id === account?.account?.Id;
            });
            if (currentAccount.length > 0) {
              const currentAccountData = currentAccount[0];
              let isECREnabled = "";
              let accountName = currentAccountData.account == null ? "emptyAccount" : currentAccountData.account.Name;
              const cachedECRCredentials = getAwsKeys().getECRCredentials(accountName);
              if (cachedECRCredentials) {
                isECREnabled = cachedECRCredentials;
              } else {
                isECREnabled = await toolAccessHelper.getIsECRConfigureForDownload({
                  accessKeyId: currentAccountData.assumeRoleResponse.Credentials.AccessKeyId,
                  secretAccessKey: currentAccountData.assumeRoleResponse.Credentials.SecretAccessKey,
                  sessionToken: currentAccountData.assumeRoleResponse.Credentials.SessionToken,
                });
                getAwsKeys().addECRCredentials(accountName, isECREnabled);
                // generate ecr token region wise for all accounts
                await this.generateRegionWiseECRtoken(currentAccountData, toolAccessHelper);
              }
              return {
                getAssumedRole: () => {
                  return currentAccountData.assumeRoleResponse;
                },
                getToken: () => {
                  const newToken = new Token(
                    this.type,
                    this.name,
                    this.name,
                    this.userName,
                    this.host,
                    currentAccountData.assumeRoleResponse.Credentials.AccessKeyId,
                    this.isTool,
                    this.protocol,
                    this.port,
                    this.apiVersion,
                    this.strictSSL,
                    this.executionOrder,
                    currentAccountData.assumeRoleResponse.Credentials.SecretAccessKey,
                    currentAccountData.assumeRoleResponse.Credentials.SessionToken,
                    currentAccountData.account == null ? "" : currentAccountData.account.Name,
                  );
                  newToken.accessToDownloadECRonAWS = isECREnabled;
                  return newToken;
                },
              };
            }
          } else {
            const toolAccessHelper: ToolAccessHelper = new ToolAccessHelper();
            let isECREnabled = "";
            const accountName = account.account == null ? "emptyAccount" : account.account.Name;
            const cachedECRCredentials = getAwsKeys().getECRCredentials(accountName);
            if (cachedECRCredentials) {
              isECREnabled = cachedECRCredentials;
            } else {
              isECREnabled = await toolAccessHelper.getIsECRConfigureForDownload({
                accessKeyId: account.assumeRoleResponse.Credentials.AccessKeyId,
                secretAccessKey: account.assumeRoleResponse.Credentials.SecretAccessKey,
                sessionToken: account.assumeRoleResponse.Credentials.SessionToken,
              });
              getAwsKeys().addECRCredentials(accountName, isECREnabled);
              // generate ecr token region wise
              await this.generateRegionWiseECRtoken(account, toolAccessHelper);
            }
            // Use existing token
            return {
              getAssumedRole: () => {
                return account.assumeRoleResponse;
              },
              getToken: () => {
                const newToken = new Token(
                  this.type,
                  this.name,
                  this.name,
                  this.userName,
                  this.host,
                  account.assumeRoleResponse.Credentials.AccessKeyId,
                  this.isTool,
                  this.protocol,
                  this.port,
                  this.apiVersion,
                  this.strictSSL,
                  this.executionOrder,
                  account.assumeRoleResponse.Credentials.SecretAccessKey,
                  account.assumeRoleResponse.Credentials.SessionToken,
                  account.account == null ? "" : account.account.Name,
                );
                newToken.accessToDownloadECRonAWS = isECREnabled;
                return newToken;
              },
            };
          }
        });
      }
      return tokenGetters as any;
    } catch (err) {
      const errInfoEx = `uuid: ${uuid}, failed get aws session token: (${err})`;
      logger.error(errInfoEx);
      const errInfo = {
        code: err?.$response?.statusCode,
        message: `Incident ID: ${uuid}, organization ID: ${orgId} - ${err.name}`,
        description: `uuid: ${uuid}, failed to get aws session`,
      };
      throw errInfo;
    }
  }
  getAccountName(cred) {
    try {
      if (cred.account != null && cred.account != undefined) {
        if (cred.account.name != null && cred.account.name != undefined && cred.account.name !== "") {
          return cred.account.name;
        }
      }
    } catch (err) {
      logger.error("cannot find account name");
    }
    return "generic";
  }
  getID(): string {
    return this.type + "_" + this.name + "_" + this.userName + "_" + this.password + "_" + this.host;
  }

  // Here we are generating ECR token for all regions under every account
  async generateRegionWiseECRtoken(accountData, toolAccessHelper: ToolAccessHelper) {
    let accountId = "";
    try {
      accountId = this.getAccountIdFormArn(accountData);
      if (!accountId) {
        return;
      }
      const awsQueries = AWSQueries(
        accountData.assumeRoleResponse.Credentials.AccessKeyId,
        accountData.assumeRoleResponse.Credentials.SecretAccessKey,
        accountData.assumeRoleResponse.Credentials.SessionToken,
      );
      const regions = await awsQueries.describeRegions();
      const regionArray: DescribeRegionsCommandOutput = JSON.parse(regions);

      for (const regionData of regionArray.Regions) {
        await AsyncTracker.runWithAsyncTracker(async () => {
          AsyncTracker.setValue("ox-aws-region", regionData.RegionName);
          const region = regionData.RegionName;
          try {
            const ecrTokenKey = `${accountId}:${region}`;
            const cachedECRCredentials = getAwsKeys().getECRCredentials(ecrTokenKey);
            if (cachedECRCredentials) {
              return;
            }
            logger.info(`Generating new ECR token`);
            const ecrCredentials = await toolAccessHelper.getIsECRConfigureForDownload({
              accessKeyId: accountData.assumeRoleResponse.Credentials.AccessKeyId,
              secretAccessKey: accountData.assumeRoleResponse.Credentials.SecretAccessKey,
              sessionToken: accountData.assumeRoleResponse.Credentials.SessionToken,
              region,
            });
            // create token object and cache it
            const newToken = new Token(
              this.type,
              this.name,
              this.name,
              this.userName,
              this.host,
              accountData.assumeRoleResponse.Credentials.AccessKeyId,
              this.isTool,
              this.protocol,
              this.port,
              this.apiVersion,
              this.strictSSL,
              this.executionOrder,
              accountData.assumeRoleResponse.Credentials.SecretAccessKey,
              accountData.assumeRoleResponse.Credentials.SessionToken,
              accountData.account == null ? "" : accountData.account.Name,
            );
            newToken.accessToDownloadECRonAWS = ecrCredentials;
            getAwsKeys().addECRCredentials(ecrTokenKey, JSON.stringify(newToken));
          } catch (error) {
            logger.error(`Failed to generate ECR token for accountId: ${accountId}, region: ${region}, err: ${error}`);
          }
        });
      }
    } catch (error) {
      logger.error(`Failed to generate ECR tokens for all regions accountId: ${accountId}, err: ${error}`);
    }
  }

  // here we are generating account id from arn
  getAccountIdFormArn(accountData) {
    try {
      if (accountData?.assumeRoleResponse?.AssumedRoleUser?.Arn) {
        const arn = accountData.assumeRoleResponse.AssumedRoleUser.Arn;
        const accountIdWithRoleId = arn.split("::").pop();
        const accountId = accountIdWithRoleId.slice(0, accountIdWithRoleId.indexOf(":"));
        return accountId;
      }
      logger.warn(`No Arn found in aws account: ${JSON.stringify(accountData)}`);
    } catch (error) {
      logger.warn(`failed to getAccountIdFormArn aws account: ${JSON.stringify(accountData)}, err: ${error}`);
    }
    return null;
  }

  getEcrCredentials(accountId: string, region: string) {
    try {
      const ecrTokenKey = `${accountId}:${region}`;
      const cachedECRCredentials = getAwsKeys().getECRCredentials(ecrTokenKey);
      if (cachedECRCredentials) {
        return JSON.parse(cachedECRCredentials);
      }
    } catch (error) {
      logger.error(`Failed to getEcrCredentials for accountId: ${accountId}, region: ${region}, err: ${error}`);
    }
    return null;
  }
}
export enum ResourceType {
  Unknown,
  code_repo,
  citool,
  cloud,
  artifactory,
  external,
}
