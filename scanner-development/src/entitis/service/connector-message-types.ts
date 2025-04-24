import { CategoryKey } from "@oxappsec/ox-consolidated-categories/lib/src/ox-categories/types";
import { PerformanceType } from "../../helper/statesHelper";
import { Dictionary, Nullable } from "../commonTypes";

export interface ScannerMessage {
  org_id: string;
  startTime: number;
  org_display_name: string;
  configuredConnectors: Connector[];
  isScheduledScan: boolean;
  isDemoScan: boolean;
  isFullScan: boolean;
  isPipelineScan: boolean;
  scanType: ScanType;
  pipelineScanJobInfo?: string; // if isPipelineScan, contains stringified JSON with job information relevant to specific CI/CD system
  timeout?: number; // if isPipelineScan, contains timeout in minutes after which scan should be terminated
  performance?: PerformanceType;
}
export enum ScanType {
  Full = "full",
  Delta = "delta",
  Demo = "demo",
  Pipeline = "pipeline",
}

export enum ConnectorName {
  EKS = "AWS EKS",
}

export interface Connector {
  id: string;
  name: string;
  displayName: string;
  description: string;
  hostURL: string;
  iconURL: string;
  family: CategoryKey;
  credentialsType: CredentialsType;
  credentialsTypes: CredentialsType[];
  isConfigured: boolean;
  isResourceAvailable: boolean;
  monitoredResources?: ResourcesMap;
  monitorAllResources?: boolean;
  monitorAllNewlyCreatedResources?: number;
  credentials: Credential[];
  isOxBuiltIn: boolean;
  isOpenSource: boolean;
  openSourceWebsiteUrl?: string;
  openSourceLicense?: string;
  openSourceAuthor?: string;
  defaultEnabled?: boolean;
  comingSoon?: boolean;
  aliasFor?: string;
  identityProviderInfo?: IdentityProviderInfo;
  awsCloudFormationInfo?: AWSCloudFormationInfo;
  awsCloudFormationOrganizationInfo?: AWSCloudFormationInfo;
  connectionInstructions?: ConnectionInstructions[];
  isDiscovered?: boolean;
  isEmptyOfRepos?: boolean;
  optionalInputFields?: OptionalConnectorInput;
  position: number | string;
}

export interface OptionalConnectorInput {
  name: string;
  credsTypes: CredentialsType[];
  inputType: InputTypes;
}

export enum InputTypes {
  password = "password",
  text = "text",
  number = "number",
}

export enum CredentialsType {
  UserPassword = "UserPassword",
  UserPasswordAndTenant = "UserPasswordAndTenant",
  Token = "Token",
  TokenAndUser = "TokenAndUser",
  TokenAndProjectId = "TokenAndProjectId",
  TenantClientsubscriptionIdSecret = "TenantClientsubscriptionIdSecret",
  APISecretAndAccessKey = "APISecretAndAccessKey",
  IdentityProvider = "IdentityProvider",
  ClientIdSecretKey = "ClientIdSecretKey",
  AWSAssumeRole = "AWSAssumeRole",
  AWSAssumeRoleCloudFormation = "AWSAssumeRoleCloudFormation",
  AWSOrganizationConnection = "AWSOrganizationConnection",
  AWSAssumeRoleOnprem = "AWSAssumeRoleOnprem",
  AWSAssumeRoleCloudFormationOnprem = "AWSAssumeRoleCloudFormationOnprem",
  AWSOrganizationConnectionOnprem = "AWSOrganizationConnectionOnprem",
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
  AWSEKS = "AWSEKS",
  AWSEKSDirect = "AWSEKSDirect",
  AWSEKSPrivateLink = "AWSEKSPrivateLink",
}

export interface Resource {
  id: string;
  parentId?: string;
  name: string;
  isMonitored: boolean;
  resourceType: ResourceType;
  children?: Resource[];
  sourceBranch?: string;
  targetBranch?: string;
  sha?: string;
  baseSha?: string;
}

export type ResourcesMap = Nullable<Dictionary<Resource>>;

export interface ConnectionInstructions {
  type: CredentialsType;
  title: string;
  details: string[];
}

export type Credential =
  | TokenCredentials
  | OrganizationIdAndApiKeyCredentials
  | IDPTokenCredentials
  | UserPasswordCredentials
  | TokenAndProjectIdCredentials
  | TokenOnlyCredentials
  | UserPasswordOnlyCredentials
  | TenantClientsubscriptionIdSecretCredentials
  | APISecretAndAccessKeyCredentials
  | TokenAndUserCredentials
  | ClientIdSecretKeyCredentials
  | AWSAssumeRoleCredentials
  | AWSAssumeRoleCredentialsOnprem
  | UserPasswordAndTenantCredentials
  | ClientIdSecretApiUrlCredentials
  | AWSAssumeRoleCodeCommitCredentials
  | GitHubAppInstallationCredentials
  | ClientIdClientSecretCredentials
  | BitbucketAppCredentials;

export interface TokenCredentials extends CredentialBase {
  token: string;
}

export interface IDPTokenCredentials extends CredentialBase {
  idpToken: string;
}

export interface ClientIdSecretKeyCredentials extends CredentialBase {
  clientIdSecretKey: string;
}

export interface UserPasswordCredentials extends CredentialBase {
  name: string;
  password: string;
}

export interface AWSAssumeRoleCodeCommitCredentials extends CredentialBase {
  awsRoleArn: string;
  awsExternalId: string;
}

export interface UserPasswordAndTenantCredentials extends CredentialBase {
  tenant: string;
  name: string;
  password: string;
}

export interface AWSAssumeRoleCredentials extends CredentialBase {
  awsRoleArn: string;
  awsExternalId: string;
}

export interface AWSAssumeRoleCredentialsOnprem extends CredentialBase {
  awsRoleArn: string;
  awsAccessKey: string;
  awsOnpremEncryptedCredentials: string;
}

export interface AWSOnpremEncryptedCredentials {
  awsExternalId: string;
  awsAccessSecret: string;
}

export interface TokenAndUserCredentials extends CredentialBase {
  name: string;
  token: string;
}

export interface TokenAndProjectIdCredentials extends CredentialBase {
  projectId: string;
  token: string;
}

export interface TokenOnlyCredentials extends CredentialBase {
  password: string;
}

export interface UserPasswordOnlyCredentials extends CredentialBase {
  name: string;
  password: string;
}

export interface ClientIdClientSecretCredentials extends CredentialBase {
  clientId: string;
  clientSecret: string;
}

export interface OrganizationIdAndApiKeyCredentials extends CredentialBase {
  apiKey: string;
  organizationId: string;
  name: string;
  password: string;
}

export interface ClientIdSecretApiUrlCredentials extends CredentialBase {
  clientId: string;
  clientSecret: string;
  apiUrl: string;
}

export interface TenantClientsubscriptionIdSecretCredentials extends CredentialBase {
  tenantId: string;
  clientId: string;
  clientSecret: string;
  subscriptionId: string;
}

export interface APISecretAndAccessKeyCredentials extends CredentialBase {
  apiAccessKey: string;
  apiSecretKey: string;
}

export interface GitHubAppInstallationCredentials extends CredentialBase {
  gitHubAppId: string;
  installationId: number;
  installationToken: string;
}

export interface BitbucketAppCredentials extends CredentialBase {
  appKey: string;
  clientKey: string;
  sharedSecret: string;
}

export interface CredentialBase {
  tokenExpirationDate?: string;
  credentialsType?: CredentialsType;
  hostURL?: string;
  optionalFields?: {
    SSHKey?: string;
    Config?: string;
    [key: string]: string;
  };
  extraOptionalCreds?: {
    atlassian: {
      apiKey: string;
      organizationId: string;
    };
    [key: string]: {
      [key: string]: string;
    };
  };
}

export interface IdentityProviderInfo {
  baseURL: string;
  urlParams: string;
  scope: string;
  configText: string;
}

export interface AWSCloudFormationInfoResponse {
  baseURL: string;
  urlParams: string;
}

export interface AWSCloudFormationInfo {
  baseURL: string;
  stackName: string;
  oxAWSAccountId: string;
}

export interface IdentityProviderInput {
  code: string;
  state: string;
  identityProviderBaseURL: string;
}

export enum ResourceType {
  Node = "node",
  Edge = "edge",
}
