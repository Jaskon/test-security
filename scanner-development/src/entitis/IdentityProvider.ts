export type IdentityProviderToken = GitHubIDPToken | GitLabIDPToken | BitbucketIDPToken | AzureIDPToken;
export interface GitHubIDPToken {
  access_token: string;
  token_type: string;
  scope: string;
}
export interface GitLabIDPToken {
  access_token: string;
  token_type: string;
  refresh_token: string;
  scope: string;
  created_at: number;
}
export interface BitbucketIDPToken {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
  state: string;
}

export interface AzureIDPToken {
  access_token: string;
  token_type: string;
  expires_in: number;
  refresh_token: string;
  scope: string;
}

export enum CredentialsType {
  UserPassword = "UserPassword",
  Token = "Token",
  TokenAndUser = "TokenAndUser",
  IdentityProvider = "IdentityProvider",
  TokenAndProjectId = "TokenAndProjectId",
  TenantClientsubscriptionIdSecret = "TenantClientsubscriptionIdSecret",
  APISecretAndAccessKey = "APISecretAndAccessKey",
  None = "None",
  GitHubApp = "GitHubApp",
  BitbucketApp = "BitbucketApp",
  OrganizationIdAndApiKey = "OrganizationIdAndApiKey",
  ClientIdSecretApiUrl = "ClientIdSecretApiUrl",
  TokenOnly = "TokenOnly",
  UserPasswordOnly = "UserPasswordOnly",
  AWSAssumeRoleCodeCommit = "AWSAssumeRoleCodeCommit",
  AWSAssumeRoleCodeCommitOrganization = "AWSAssumeRoleCodeCommitOrganization",
  ClientIdClientSecret = "ClientIdClientSecret",
}
