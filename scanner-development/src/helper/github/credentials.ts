import _ from "lodash";
import { Token } from "../../entitis/collectorEntitisTypes";
import { isJson } from "../../entitis/commonTypes";
import loggerImport from "../../logger";
import { millis } from "../time-unit-utils";
const logger = loggerImport.getDebugLogger();

export enum GitHubCredentialsType {
  App = "GitHubAppInstallation",
  PAT = "PersonalAccessToken",
  IDP = "IdentityProvider",
}

export type GitHubCredentials =
  | { type: GitHubCredentialsType.IDP | GitHubCredentialsType.PAT; token: string }
  | { type: GitHubCredentialsType.App; token: string; gitHubAppId: string; installationId: number };

interface GitHubIDPCredentials {
  access_token: string;
  token_type: string;
  scope: string;
}

interface GitHubAppInstallationCredentials {
  token: string;
  createdAt: string;
  expiresAt: string;
}

const isGitHubIDPCredentials = (i: unknown): i is GitHubIDPCredentials => _.isObject(i) && "access_token" in i && "token_type" in i;
const isGitHubAppInstallationCredentials = (i: unknown): i is GitHubAppInstallationCredentials =>
  _.isObject(i) && "token" in i && "createdAt" in i;

export const resolveGitHubCredentials = (token: Token): GitHubCredentials => {
  const secret = token.password;
  const isJSONCredentials = isJson(secret);

  if (!isJSONCredentials) {
    return {
      type: GitHubCredentialsType.PAT,
      token: secret,
    };
  }

  const parsedCredentials = JSON.parse(secret);

  if (isGitHubIDPCredentials(parsedCredentials)) {
    return {
      type: GitHubCredentialsType.IDP,
      token: parsedCredentials.access_token,
    };
  }

  if (isGitHubAppInstallationCredentials(parsedCredentials)) {
    const installationId = parseInt(token.userName);
    if (!Number.isFinite(installationId)) {
      throw new Error(
        `[resolveGitHubCredentials][GitHubApp] installationId is not a finite number: ${installationId}. ` +
          `Please make sure you provide a valid installationId to Token constructor`,
      );
    }

    // fallback for stg-prod in case scanner promoted before connectors
    const gitHubAppId = token.accountName ?? process.env.GITHUB_APP_ID;
    logger.info(
      `[resolveGitHubCredentials] gitHubAppId from connectors: ${token.accountName}, used gitHubAppId: ${gitHubAppId}, installationId: ${installationId}`,
    );

    return {
      type: GitHubCredentialsType.App,
      token: parsedCredentials.token,
      gitHubAppId,
      installationId,
    };
  }

  logger.error(`Unhandled credentials type in ${JSON.stringify(token)}`);
  throw new Error("Unhandled credentials type");
};

export const GITHUB_APP_INSTALLATION_TOKEN_REFRESH_INTERVAL = millis.from.minutes(40); // installation tokens are issued for 1 hour
