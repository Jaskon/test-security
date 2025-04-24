import { Account, ListAccountsCommand, ListAccountsCommandInput, OrganizationsClient } from "@aws-sdk/client-organizations";
import { AssumeRoleCommand, AssumeRoleCommandInput, AssumeRoleCommandOutput, STSClient } from "@aws-sdk/client-sts";
import loggerImport from "../../logger";
import StatesHelper from "../statesHelper";

const isOnPrem = process.env.LOCAL_KMS === "true" ? true : false;
const ACCOUNTS_MAX_RESULTS = 20;

const logger = loggerImport.getDebugLogger();

const AWS_ASSUME_ROLE_ACCESS_KEY_ID = process.env.CLOUD_AWS_ACCESS_KEY || "";
const AWS_ASSUME_ROLE_SECRET_ACCESS_KEY = process.env.CLOUD_AWS_SECRET_ACCESS_KEY || "";

const debugLocal = process.env.DEBUG != undefined;

class AwsSTSHelper {
  uuid: string;
  client: STSClient;

  constructor(uuid: string, awsAccessKey: string, awsAccessSecret: string) {
    this.uuid = uuid;

    let accessKeyId = awsAccessKey ? awsAccessKey : AWS_ASSUME_ROLE_ACCESS_KEY_ID;
    let secretAccessKey = awsAccessSecret ? awsAccessSecret : AWS_ASSUME_ROLE_SECRET_ACCESS_KEY;

    let credentials = null;

    if (isOnPrem || process.env.DOCKER_DEBUG) {
      credentials = {
        accessKeyId: accessKeyId,
        secretAccessKey: secretAccessKey,
      };
    }

    this.client = new STSClient({
      credentials,
      region: process.env.REGION,
    });
  }

  async getCredentials(
    roleArn: string,
    roleSessionName: string,
    externalId: string,
    account: Account = null,
    durationSeconds: number = 2000,
  ): Promise<getCredentialsResponse> {
    try {
      const input: AssumeRoleCommandInput = {
        RoleArn: roleArn,
        RoleSessionName: roleSessionName,
        DurationSeconds: durationSeconds,
        ExternalId: externalId,
      };
      const command = new AssumeRoleCommand(input);
      const assumeRoleResponse = await this.client.send(command);

      logger.info(`finish init aws credentials for arn: ${roleArn}, externalId: ${externalId}`);

      return { account, assumeRoleResponse };
    } catch (err) {
      logger.error(`failed get cred for arn: ${roleArn}, externalId: ${externalId}`, err);
    }
    return null;
  }

  async listAccounts(accessKeyId: string, secretAccessKey: string, sessionToken: string) {
    try {
      let credentials = {
        accessKeyId,
        secretAccessKey,
        sessionToken,
      };

      const client = new OrganizationsClient({
        credentials,
        region: process.env.REGION,
      });

      const input: ListAccountsCommandInput = {
        MaxResults: ACCOUNTS_MAX_RESULTS,
        NextToken: null,
      };
      const command = new ListAccountsCommand(input);
      let listAccountsCommandOutput = await client.send(command);

      const accounts: Account[] = [];
      if (listAccountsCommandOutput.Accounts) {
        accounts.push(...listAccountsCommandOutput.Accounts);
      }

      while (listAccountsCommandOutput.NextToken) {
        const input: ListAccountsCommandInput = {
          MaxResults: 1,
          NextToken: listAccountsCommandOutput.NextToken,
        };
        const command = new ListAccountsCommand(input);
        listAccountsCommandOutput = await client.send(command);

        if (listAccountsCommandOutput.Accounts) {
          accounts.push(...listAccountsCommandOutput.Accounts);
        }
      }

      return accounts;
    } catch (error) {
      if ("name" in error && error.name === "AccessDeniedException") {
        logger.info(`listAccounts: Failed to list accounts, will try to use the assumed role account`);
      } else {
        logger.error(`listAccounts: Failed to list accounts, with an error: ${error}`);
      }
    }
    return [];
  }

  async getAccounts(roleArn: string, roleSessionName: string, externalId: string): Promise<getCredentialsResponse[]> {
    try {
      let res: getCredentialsResponse[] = [];

      const assumeRoleResponse = await this.getCredentials(roleArn, roleSessionName, externalId);

      if (!assumeRoleResponse || !assumeRoleResponse.assumeRoleResponse.Credentials) {
        logger.error(`Validating credentials for AWS assume role failed`);
        return [];
      }

      const { AccessKeyId, SecretAccessKey, SessionToken } = assumeRoleResponse.assumeRoleResponse.Credentials;

      let accounts = await this.listAccounts(AccessKeyId, SecretAccessKey, SessionToken);
      logger.info(`AWS STS listAccounts, accounts length: ${accounts.length}`);

      if (accounts.length > 0) {
        accounts = accounts.filter(account => account.Status.toLowerCase() === "active");

        const assumeRolePromises = accounts.map(account => {
          // "arn:aws:iam::857809147732:role/DevOxAWSIntegrationRole"
          const accountRoleArn = roleArn.replace(/arn:aws:iam::\d+:/g, `arn:aws:iam::${account.Id}:`);

          return this.getCredentials(accountRoleArn, roleSessionName, externalId, account);
        });

        const assumedRoles = await Promise.all(assumeRolePromises);
        res = assumedRoles.filter(i => i != null);
      }

      logger.info(`AWS STS listAccounts after getCredentials filter, accounts length: ${res.length}`);

      if (res.length == 0) {
        logger.info(`cannot list account using assume rule`);
        res.push(assumeRoleResponse);
      }

      return res;
    } catch (err) {
      logger.error(`failed to get accounts for aws err: ${err}`);
    }
    return [];
  }
}

export interface getCredentialsResponse {
  account: Account;
  assumeRoleResponse: AssumeRoleCommandOutput;
}

export default AwsSTSHelper;
