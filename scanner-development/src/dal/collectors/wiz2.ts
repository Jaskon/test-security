//https://snyk.docs.apiary.io/#reference/reporting-api/latest-issues/get-list-of-latest-issues
import axios, { AxiosResponse, AxiosRequestConfig, AxiosError } from "axios";

import {
  AlertSeverity,
  SecurityAlertType,
  SecurityEvent,
  addSeverityChangedReason,
  addSeverityCloudChangedReason,
} from "../../entitis/codeRepoTypes";
import { CloudSecurityEvent } from "../../entitis/cloudTypes";

import { Token } from "../../entitis/collectorEntitisTypes";

import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import { cleanToolName, flatNestedJson } from "../../helper/commonUtils";
import { ArtifactorySecEventSystem, ArtifactorySecEventType, guessArtifactSystem } from "../../entitis/ArtifactTypes";
import { isLocalDevelopment } from "../../helper/envUtils";
import { severityReasons } from "../../entitis/service/blameTypes";
import Constant from "../../entitis/constant";
import { ContainerSecurityType } from "../../entitis/artifactoryTypes";
import { getHashType } from "../../helper/hash";
import { HahsType } from "../../entitis/applicationsFlowTypes";
import StatesHelper from "../../helper/statesHelper";
import { ExtraInfo } from "../../entitis/issuesTypes";
import { addRunningInCloudExtraInfo } from "../../helper/policy/severityHelper";
import { Tool } from "../../policy/rules/code/policyRulesBase";
import PromisePool from "@supercharge/promise-pool";

const { MongoClient } = require("mongodb");

const logger = loggerImport.getDebugLogger();

const DB_NAME = "WizDoubleVerify";

const PAGE_SIZE = {
  DEFAULT: 500,
  ISSUES: 500,
  CONFIGURATION_FINDINGS: 500,
  VULNERABILITY_FINDINGS: 500,
};

const RETRY_COUNT = 4;
const LOG_NAME = Constant.wiz;

const linkToExternalProduct = `https://app.wiz.io/issues#~(issue~'{issueID})`;

interface WizIssueV2Entity {
  id: string;
  type: string;
  properties: any;
  providerData: any;
}

interface WizIssueV2EntitySnapshot {
  id: string;
  name: string;

  type: string;
  nativeType: string;

  providerId: string;
  region: string;
  status: string;

  resourceGroupExternalId: string;
  resourceGroupId: string;

  subscriptionId: string;
  subscriptionExternalId: string;

  cloudPlatform: string;
  cloudProviderURL: string;

  containerServiceId: string;
  containerServiceName: string;

  externalId: string;

  kubernetesClusterId: string;
  kubernetesClusterName: string;
  kubernetesNamespaceName: string;

  subscriptionName: any;
}

interface WizIssueSourceRule {
  id: string;
  name: string;
  type: string;
}

interface WizIssueV2 {
  id: string;
  type: string;
  severity: string;
  status: string;

  description: string;
  createdAt: string;
  entity: WizIssueV2Entity;
  entitySnapshot: WizIssueV2EntitySnapshot;

  sourceRule: WizIssueSourceRule;
  control: any;
}

interface WizConfigurationFindingRule {
  id: string;
  shortId: string;
  graphId: string;
  name: string;
  remediationInstructions: string;
}

interface WizConfigurationFindingEvidence {
  cloudConfigurationLink: string;
  configurationPath: string;
  currentValue: string;
  expectedValue: string;
}

interface WizConfigurationFindingSecuritySubCategory {
  id: string;
  name: string;
}

interface WizConfigurationFinding {
  analyzedAt: string;
  evidence: WizConfigurationFindingEvidence;
  id: string;
  name: string;
  remediation: string;
  resolutionReason: string;
  resource: WizIssueV2Entity;
  result: string;
  rule: WizConfigurationFindingRule;
  source: string;
  status: string;
  securitySubCategories: WizConfigurationFindingSecuritySubCategory[];
}

enum WizIssueStatus {
  Open = "OPEN",
  InProgress = "IN_PROGRESS",
}

enum WizEntityType {
  AccessKey = "ACCESS_KEY",
  AccessRole = "ACCESS_ROLE",
  AccessRoleBinding = "ACCESS_ROLE_BINDING",
  AccessRolePermission = "ACCESS_ROLE_PERMISSION",
  Any = "ANY",
  ApiGateway = "API_GATEWAY",
  Application = "APPLICATION",
  AuthenticationConfiguration = "AUTHENTICATION_CONFIGURATION",
  AuthenticationPolicy = "AUTHENTICATION_POLICY",
  BackendBucket = "BACKEND_BUCKET",
  BackupService = "BACKUP_SERVICE",
  BranchPackage = "BRANCH_PACKAGE",
  Bucket = "BUCKET",
  CallCenterService = "CALL_CENTER_SERVICE",
  Cdn = "CDN",
  Certificate = "CERTIFICATE",
  CicdService = "CICD_SERVICE",
  CloudLogConfiguration = "CLOUD_LOG_CONFIGURATION",
  CloudOrganization = "CLOUD_ORGANIZATION",
  CloudResource = "CLOUD_RESOURCE",
  ComputeInstanceGroup = "COMPUTE_INSTANCE_GROUP",
  ConfigurationFinding = "CONFIGURATION_FINDING",
  ConfigurationRule = "CONFIGURATION_RULE",
  ConfigurationScan = "CONFIGURATION_SCAN",
  ConfigMap = "CONFIG_MAP",
  Container = "CONTAINER",
  ContainerGroup = "CONTAINER_GROUP",
  ContainerImage = "CONTAINER_IMAGE",
  ContainerInstanceGroup = "CONTAINER_INSTANCE_GROUP",
  ContainerRegistry = "CONTAINER_REGISTRY",
  ContainerRepository = "CONTAINER_REPOSITORY",
  ContainerService = "CONTAINER_SERVICE",
  ControllerRevision = "CONTROLLER_REVISION",
  DaemonSet = "DAEMON_SET",
  Database = "DATABASE",
  DataFinding = "DATA_FINDING",
  DataInventory = "DATA_INVENTORY",
  DataResource = "DATA_RESOURCE",
  DataSchema = "DATA_SCHEMA",
  DataStore = "DATA_STORE",
  DataWorkflow = "DATA_WORKFLOW",
  DataWorkload = "DATA_WORKLOAD",
  DbServer = "DB_SERVER",
  Deployment = "DEPLOYMENT",
  DnsRecord = "DNS_RECORD",
  DnsZone = "DNS_ZONE",
  Domain = "DOMAIN",
  EmailService = "EMAIL_SERVICE",
  EncryptionKey = "ENCRYPTION_KEY",
  Endpoint = "ENDPOINT",
  ExcessiveAccessFinding = "EXCESSIVE_ACCESS_FINDING",
  FileDescriptor = "FILE_DESCRIPTOR",
  FileDescriptorFinding = "FILE_DESCRIPTOR_FINDING",
  FileSystemService = "FILE_SYSTEM_SERVICE",
  Firewall = "FIREWALL",
  Gateway = "GATEWAY",
  GovernancePolicy = "GOVERNANCE_POLICY",
  GovernancePolicyGroup = "GOVERNANCE_POLICY_GROUP",
  Group = "GROUP",
  HostedApplication = "HOSTED_APPLICATION",
  HostedTechnology = "HOSTED_TECHNOLOGY",
  HostConfigurationFinding = "HOST_CONFIGURATION_FINDING",
  HostConfigurationRule = "HOST_CONFIGURATION_RULE",
  IacDeclarationInstance = "IAC_DECLARATION_INSTANCE",
  IacResourceDeclaration = "IAC_RESOURCE_DECLARATION",
  IacStateInstance = "IAC_STATE_INSTANCE",
  IamBinding = "IAM_BINDING",
  IdentityProvider = "IDENTITY_PROVIDER",
  IpRange = "IP_RANGE",
  KubernetesCluster = "KUBERNETES_CLUSTER",
  KubernetesCronJob = "KUBERNETES_CRON_JOB",
  KubernetesIngress = "KUBERNETES_INGRESS",
  KubernetesIngressController = "KUBERNETES_INGRESS_CONTROLLER",
  KubernetesJob = "KUBERNETES_JOB",
  KubernetesNetworkPolicy = "KUBERNETES_NETWORK_POLICY",
  KubernetesNode = "KUBERNETES_NODE",
  KubernetesPersistentVolume = "KUBERNETES_PERSISTENT_VOLUME",
  KubernetesPersistentVolumeClaim = "KUBERNETES_PERSISTENT_VOLUME_CLAIM",
  KubernetesPodSecurityPolicy = "KUBERNETES_POD_SECURITY_POLICY",
  KubernetesService = "KUBERNETES_SERVICE",
  KubernetesStorageClass = "KUBERNETES_STORAGE_CLASS",
  KubernetesVolume = "KUBERNETES_VOLUME",
  LastLogin = "LAST_LOGIN",
  LateralMovementFinding = "LATERAL_MOVEMENT_FINDING",
  LoadBalancer = "LOAD_BALANCER",
  LocalUser = "LOCAL_USER",
  Malware = "MALWARE",
  MalwareInstance = "MALWARE_INSTANCE",
  ManagedCertificate = "MANAGED_CERTIFICATE",
  ManagementService = "MANAGEMENT_SERVICE",
  MapReduceCluster = "MAP_REDUCE_CLUSTER",
  MessagingService = "MESSAGING_SERVICE",
  MonitorAlert = "MONITOR_ALERT",
  Namespace = "NAMESPACE",
  Nat = "NAT",
  NetworkAddress = "NETWORK_ADDRESS",
  NetworkAppliance = "NETWORK_APPLIANCE",
  NetworkInterface = "NETWORK_INTERFACE",
  NetworkRoutingRule = "NETWORK_ROUTING_RULE",
  NetworkSecurityRule = "NETWORK_SECURITY_RULE",
  Package = "PACKAGE",
  Peering = "PEERING",
  Pod = "POD",
  PortRange = "PORT_RANGE",
  PredefinedGroup = "PREDEFINED_GROUP",
  Principal = "PRINCIPAL",
  PrivateEndpoint = "PRIVATE_ENDPOINT",
  PrivateLink = "PRIVATE_LINK",
  Project = "PROJECT",
  Proxy = "PROXY",
  ProxyRule = "PROXY_RULE",
  RawAccessPolicy = "RAW_ACCESS_POLICY",
  Region = "REGION",
  RegisteredDomain = "REGISTERED_DOMAIN",
  ReplicaSet = "REPLICA_SET",
  Repository = "REPOSITORY",
  RepositoryBranch = "REPOSITORY_BRANCH",
  RepositoryTag = "REPOSITORY_TAG",
  ResourceGroup = "RESOURCE_GROUP",
  RouteTable = "ROUTE_TABLE",
  SearchIndex = "SEARCH_INDEX",
  Secret = "SECRET",
  SecretContainer = "SECRET_CONTAINER",
  SecretData = "SECRET_DATA",
  SecretInstance = "SECRET_INSTANCE",
  SecurityEventFinding = "SECURITY_EVENT_FINDING",
  SecurityToolFinding = "SECURITY_TOOL_FINDING",
  SecurityToolFindingType = "SECURITY_TOOL_FINDING_TYPE",
  SecurityToolScan = "SECURITY_TOOL_SCAN",
  Serverless = "SERVERLESS",
  ServerlessPackage = "SERVERLESS_PACKAGE",
  ServiceAccount = "SERVICE_ACCOUNT",
  ServiceConfiguration = "SERVICE_CONFIGURATION",
  ServiceUsageTechnology = "SERVICE_USAGE_TECHNOLOGY",
  Snapshot = "SNAPSHOT",
  StatefulSet = "STATEFUL_SET",
  StorageAccount = "STORAGE_ACCOUNT",
  Subnet = "SUBNET",
  Subscription = "SUBSCRIPTION",
  Switch = "SWITCH",
  Technology = "TECHNOLOGY",
  UserAccount = "USER_ACCOUNT",
  VirtualDesktop = "VIRTUAL_DESKTOP",
  VirtualMachine = "VIRTUAL_MACHINE",
  VirtualMachineImage = "VIRTUAL_MACHINE_IMAGE",
  VirtualNetwork = "VIRTUAL_NETWORK",
  Volume = "VOLUME",
  Vulnerability = "VULNERABILITY",
  Weakness = "WEAKNESS",
  WebService = "WEB_SERVICE",
}

enum WizVulnerabilityDetectionMethod {
  ArtifactsOnDisk = "ARTIFACTS_ON_DISK",
  ClonedRepository = "CLONED_REPOSITORY",
  Configuration = "CONFIGURATION",
  ConfigFile = "CONFIG_FILE",
  DefaultPackage = "DEFAULT_PACKAGE",
  FilePath = "FILE_PATH",
  HostedDatabaseScan = "HOSTED_DATABASE_SCAN",
  InstalledProgram = "INSTALLED_PROGRAM",
  InstalledProgramByService = "INSTALLED_PROGRAM_BY_SERVICE",
  Library = "LIBRARY",
  OpenPort = "OPEN_PORT",
  Os = "OS",
  Package = "PACKAGE",
  StartupService = "STARTUP_SERVICE",
  Unknown = "UNKNOWN",
  WindowsRegistry = "WINDOWS_REGISTRY",
  WindowsService = "WINDOWS_SERVICE",
}

const QUERY = {
  AUTH_VALIDATION: `
    query Query($first: Int) {
      issuesV2(first: $first) {
        nodes {
            ...IssueDetails,
        }
      }
    }
        
    fragment IssueDetails on Issue {
      id  
      createdAt
    }
  `,

  ISSUES: `
    query Query($filterBy: IssueFilters, $first: Int, $after: String, $orderBy: IssueOrder) {
      issuesV2(filterBy: $filterBy, first: $first, after: $after, orderBy: $orderBy) {
        pageInfo {
          hasNextPage
          endCursor
        }     
        
        totalCount
        
        nodes{ 
          id
          type
          severity
          status

          description
          createdAt

          entity{
            id 
            type
            properties
            providerData
          }

          entitySnapshot{
            cloudPlatform
            cloudProviderURL
            containerServiceId
            containerServiceName
            createdAt
            externalId
            id
            type
            kubernetesClusterId
            kubernetesClusterName
            kubernetesNamespaceName
            name
            nativeType
            providerId
            region
            resourceGroupExternalId
            resourceGroupId
            status
            subscriptionExternalId
            subscriptionId
          }
          
          sourceRule{
              __typename
              id
              name
          }
        }
      }
    }    
  `,

  CONFIGURATION_FINDINGS: `
    query Query($first: Int, $filterBy: ConfigurationFindingFilters , $after: String) {
      configurationFindings(filterBy: $filterBy, first: $first , after:$after ) {
        totalCount
        pageInfo{
            endCursor
            hasNextPage
        }
        nodes {
          analyzedAt
          evidence {
            cloudConfigurationLink
            configurationPath
            currentValue
            expectedValue
          }
          firstSeenAt
          id
          name
          
          remediation
          resolutionReason
    
          resource{
            id
            type
            nativeType
          }

          result
          rule{
    
              subjectEntityType
              graphId
              id
              name
              shortId
              externalReferences{
                  id
                  name
              }
    
              control{
                  id
              }
    
              targetNativeType
              remediationInstructions
          }
          source
          status
    
          targetExternalId
          targetObjectProviderUniqueId
        }    
      }
    }
  `,

  VULNERABILITY_FINDINGS: `
    query Query(
      $filterBy: VulnerabilityFindingFilters
      $first: Int
      $after: String
    ) {
      vulnerabilityFindings(filterBy: $filterBy, first: $first, after: $after) {
        totalCount
        pageInfo {
          endCursor
          hasNextPage
        }
        nodes {
          cisaKevDueDate
          cisaKevReleaseDate
          CVEDescription
          CVSSSeverity
          cvssv2 {
            attackComplexity
            attackVector
            confidentialityImpact
            integrityImpact
            privilegesRequired
            userInteractionRequired
          }
          cvssv3 {
            attackComplexity
            attackVector
            confidentialityImpact
            integrityImpact
            privilegesRequired
            userInteractionRequired
          }
          dataSourceName
          description
          detailedName
          detectionMethod
          epssPercentile
          epssProbability
          epssSeverity
          exploitabilityScore
          firstDetectedAt
          fixDate
          fixDateBefore
          fixDateDescription
          fixedVersion
          hasCisaKevExploit
          hasExploit
          id
          
          impactScore
          lastDetectedAt
          layerMetadata{
              details
              id
              isBaseLayer
          }
          link
          locationPath
          name
          note{
              id
              text
              user{
                  id
                  email
                  name
              }
              serviceAccount{
                  id
                  name
                  type
              }
          }
          portalUrl
          projects{
              id
              name
          }
          publishedDate
          remediation
          resolutionReason
          resolvedAt
          score
          status
          validatedInRuntime
          validatedInRuntimeEvidence{
              executions{
                  commandLines
                  evidenceEntity{
                      id
                      name
                      type
                      externalId
                  }
                  evidenceGraphEntity{
                      id
                      name
                      type
                  }
                  executablePath
                  loadedFilePath
                  modulePath
              }
          }
          vendorSeverity
          version
          vulnerabilityExternalId
          vulnerabilityId
          vulnerableAsset{
              __typename
              ... on VulnerableAssetVirtualMachine{
                cloudPlatform
                cloudProviderURL
                hasLimitedInternetExposure
                hasWideInternetExposure
                id
                imageExternalId
                VMImageId : imageId
                imageName
                imageNativeType
                imageProviderUniqueId
                ipAddresses
                isAccessibleFromOtherSubscriptions
                isAccessibleFromOtherVnets
                isAccessibleFromVPN
                name
                nativeType
                operatingSystem
                providerUniqueId
                region
                scanSource
                status
                subscriptionExternalId
                subscriptionId
                subscriptionName
                tags
                type
              }
    
              ... on VulnerableAssetServerless{
                cloudPlatform
                cloudProviderURL
                hasLimitedInternetExposure
                hasWideInternetExposure
                id
                isAccessibleFromOtherSubscriptions
                isAccessibleFromOtherVnets
                isAccessibleFromVPN
                name
                nativeType
                providerUniqueId
                region
                runtime
                scanSource
                status
                subscriptionExternalId
                subscriptionId
                subscriptionName
                tags
                type
              }
    
              ... on VulnerableAssetContainer{
                cloudPlatform
                cloudProviderURL
                executionControllers{
                    ancestors{
                        entityType
                        externalId
                        id
                        name
                        providerUniqueId
                    }
                    entityType
                    externalId
                    id
                    name
                    providerUniqueId
                    subscriptionExternalId
                    subscriptionId
                    subscriptionName
                }
    
                hasLimitedInternetExposure
                hasWideInternetExposure
                id
                ImageExternalId
                isAccessibleFromOtherSubscriptions
                isAccessibleFromOtherVnets
                isAccessibleFromVPN
                name
                nativeType
                NodeName
                PodName
                PodNamespace
                providerUniqueId
                region
                scanSource
                ServerlessContainer
                status
                subscriptionExternalId
                subscriptionId
                subscriptionName
                tags
                type
                VmExternalId
              }
    
              ... on VulnerableAssetContainerImage{
                  cloudPlatform
                  cloudPlatform
                  executionControllers{
                    ancestors{
                        entityType
                        externalId
                        id
                        name
                        providerUniqueId
                    }
                    entityType
                    externalId
                    id
                    name
                    providerUniqueId
                    subscriptionExternalId
                    subscriptionId
                    subscriptionName
                }
                hasLimitedInternetExposure
                hasWideInternetExposure
                id
                CIImageId : imageId
                isAccessibleFromOtherSubscriptions
                isAccessibleFromOtherVnets
                isAccessibleFromVPN
                name
                nativeType
                providerUniqueId
                region
                registry{
                    accessibleFrom{
                        customIPRanges
                        internet
                        otherSubscriptions
                        otherVnets
                        vertexId
                        VPN
                    }
                    allowsExternalRead
                    allowsExternalWrite
                    baseLayerCreatedAt
                    cloudPlatform
                    cloudProviderURL
                    containerImageLayers{
                        command
                        layerID
                        vertexId
                    }
                    creationDate
                    danglingDomain
                    externalId
                    externalOwners
                    hasAdminKubernetesPrivileges
                    hasAdminPrivileges
                    hasHighKubernetesPrivileges
                    hasHighPrivileges
                    hasIAMAccessFromExternalSubscription
                    hasIAMAccessToExternalSubscription
                    hasIAMAccessToOutsideOrganization
                    hasSensitiveData
                    httpContentType
                    httpGETStatus
                    httpGETStatusCode
                    httpTitleSnippet
                    isManaged
                    isPaaS
                    name
                    nativeType
                    numAddressesOpenForHTTP
                    numAddressesOpenForHTTPS
                    numAddressesOpenForNonStandardPorts
                    numAddressesOpenForRDP
                    numAddressesOpenForSSH
                    numAddressesOpenForWINRM
                    numAddressesOpenTo{
                        CustomIPRanges
                        Internet
                        OtherSubscriptions
                        OtherVnets
                        vertexId
                        VPN
                    }
                    numPortsOpenTo{
                        CustomIPRanges
                        Internet
                        OtherSubscriptions
                        OtherVnets
                        vertexId
                        VPN
                    }
                    openPorts
                    openToAllInternet
                    portValidationResult
                    potentialSubdomainTakeover
                    privateIPRangesWithAccess
                    providerUniqueId
                    publicAccessTypes
                    region
                    regionLocation
                    resourceGroupExternalId
                    screenshotError
                    status
                    subscriptionExternalId
                    tags
                    topLayerCreatedAt
                    validatedOpenPorts
                    vertexId
                    wizMockResource
                    zone
                }
                repository{
                    accessibleFrom{
                        customIPRanges
                        internet
                        otherSubscriptions
                        otherVnets
                        vertexId
                        VPN
                    }
                    allowsExternalRead
                    allowsExternalWrite
                    baseLayerCreatedAt
                    cloudPlatform
                    cloudProviderURL
                    containerImageLayers{
                        command
                        layerID
                        vertexId
                    }
                    containsContainerHosts
                    creationDate
                    danglingDomain
                    externalId
                    externalOwners
                    hasAdminKubernetesPrivileges
                    hasAdminPrivileges
                    hasHighKubernetesPrivileges
                    hasHighPrivileges
                    hasIAMAccessFromExternalSubscription
                    hasIAMAccessToExternalSubscription
                    hasIAMAccessToOutsideOrganization
                    hasSensitiveData
                    httpContentType
                    httpGETStatus
                    httpGETStatusCode
                    httpTitleSnippet
                    name
                    nativeType
                    numAddressesOpenForHTTP
                    numAddressesOpenForHTTPS
                    numAddressesOpenForNonStandardPorts
                    numAddressesOpenForRDP
                    numAddressesOpenForSSH
                    numAddressesOpenForWINRM
                    numAddressesOpenTo{
                        CustomIPRanges
                        Internet
                        OtherSubscriptions
                        OtherVnets
                        vertexId
                        VPN
                    }
                    numPortsOpenTo{
                        CustomIPRanges
                        Internet
                        OtherSubscriptions
                        OtherVnets
                        vertexId
                        VPN
                    }
                    openPorts
                    openToAllInternet
                    portValidationResult
                    potentialSubdomainTakeover
                    privateIPRangesWithAccess
                    providerUniqueId
                    publicAccessTypes
                    region
                    regionLocation
                    resourceGroupExternalId
                    screenshotError
                    status
                    subscriptionExternalId
                    tags
                    topLayerCreatedAt
                    validatedOpenPorts
                    vertexId
                    wizMockResource
                    zone
                }
                scanSource
                subscriptionExternalId
                subscriptionId
                subscriptionName
                tags
                type
              }
          }
          weightedSeverity
        }
      }
    }
  `,
};

class WizAPI {
  private apiUrl: string;
  private authUrl: string;

  private token: Token;
  public mode: string;

  public isValidToken: boolean = false;
  private accessToken: string;
  accountIds = new Set();
  count = 0;

  private TIME_UNITS = {
    SEC: 1000,
    MIN: 60 * 1000,
  };

  private TIME_OUTS = {
    SHORT: 10 * this.TIME_UNITS.SEC,
    MEDIUM: 50 * this.TIME_UNITS.SEC,
    LONG: 2 * this.TIME_UNITS.MIN,
  };

  constructor(token: Token) {
    this.authUrl = token.authUrl;
    try {
      logger.info(`${LOG_NAME} - original authUrl: ${token.authUrl}, apiUrl: ${token.apiUrl}`);

      if (token.apiUrl.endsWith("/")) {
        const i = token.apiUrl.lastIndexOf("/");
        token.apiUrl = token.apiUrl.substring(0, i);
        logger.info(`${LOG_NAME} - removing slash from apiUrl: ${token.apiUrl}`);
      }
      if (!token.apiUrl.endsWith("graphql")) {
        token.apiUrl = `${token.apiUrl}/graphql`;
        logger.info(`${LOG_NAME} - adding graphql to apiUrl: ${token.apiUrl}`);
      }
      this.apiUrl = `${token.apiUrl}`;

      logger.info(`${LOG_NAME} - final authUrl: ${token.authUrl}, apiUrl: ${token.apiUrl}`);

      this.token = token;
      this.isValidToken = false;
    } catch (err) {
      logger.error(`${LOG_NAME} - constructor failed, err: ${err}`);
    }
  }

  /**
   * validateApiUrl - Validates user input , apiUrl.
   *
   * @notes : to validate the apiUrl , we call the issue api with limit 1
   * @returns {Boolean} isValid - Indicates if the apiUrl is valid
   */
  async validateApiUrl() {
    let isValid = false;

    const errMessage = `${LOG_NAME} - Error in validate apiUrl : err: `;

    try {
      const variables = {
        first: 1,
      };

      const result: AxiosResponse<any> = await axios.post(
        this.apiUrl,
        { query: QUERY.AUTH_VALIDATION, variables: variables },
        {
          timeout: this.TIME_OUTS.MEDIUM,
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            "Content-Type": "application/json",
          },
        },
      );

      if (result.status == 200) {
        isValid = true;
      } else {
        logger.error(`${errMessage} ${result.status}!`);
        StatesHelper.Instance.globalApisFails.add("wiz");
      }
    } catch (error: any) {
      logger.error(`${errMessage} ${error}`);
      StatesHelper.Instance.globalApisFails.add("wiz");
    }

    return isValid;
  }

  async auth() {
    const errMessage = `${LOG_NAME} - Authenticate Failed : for token ${this.token.name}, host: ${this.token.host}, err: `;

    try {
      logger.info(`${LOG_NAME} - Authentication ** Begin **`);
      logger.info(`${LOG_NAME} - authUrl: ${this.authUrl}, apiUrl:${this.apiUrl}`);

      const data = {
        grant_type: "client_credentials",
        client_id: this.token.clientId,
        client_secret: this.token.clientSecret,
        audience: "wiz-api",
      };

      const result: AxiosResponse<any> = await axios.post(this.authUrl, new URLSearchParams(data), {
        timeout: this.TIME_OUTS.MEDIUM,
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
        },
      });

      if (result.status == 200) {
        this.accessToken = result.data.access_token;

        const apiUrlValidation = await this.validateApiUrl();
        if (apiUrlValidation) {
          this.isValidToken = true;
          logger.info(`${LOG_NAME} - Authentication ** Success **`);
        } else {
          this.isValidToken = false;
        }
      } else {
        this.isValidToken = false;
        logger.error(`${errMessage} Not a valid Token!`);
      }
    } catch (error: any) {
      this.isValidToken = false;
      logger.error(`${errMessage} ${error}`);
    }
  }

  async alertHasNextPage(result) {
    return result && result.pageInfo && result.pageInfo.hasNextPage;
  }

  async insertData(collection_name, data) {
    const connectionUrl = `mongodb://localhost:27017`;
    return;
    try {
      const client = new MongoClient(connectionUrl, { useNewUrlParser: true, useUnifiedTopology: true, connectTimeoutMS: 5 * 60 * 1000 });

      try {
        // Connect to the client
        await client.connect();

        // Access the database and collection
        const collection = client.db(DB_NAME).collection(collection_name);

        // Insert one document
        const result = await collection.insertMany(data);

        console.log(`Inserted ${result.insertedCount} document into the collection`);
      } catch (err) {
        console.error(err);
      }

      await client.close();
    } catch (e) {
      console.error(e);
    }
  }

  async getDataFromDb(collection_name) {
    let docs = [];
    try {
      const connectionUrl = `mongodb://localhost:27017`;

      const client = new MongoClient(connectionUrl, { useNewUrlParser: true, useUnifiedTopology: true });

      try {
        // Connect to the client
        await client.connect();

        // Access the database and collection
        const collection = client.db(DB_NAME).collection(collection_name);

        // Insert one document
        docs = await collection.find({}).toArray();

        console.log(`Found ${docs.length} document from collection ${collection_name}`);
      } catch (err) {
        console.error(err);
      }

      await client.close();
    } catch (e) {
      console.error(e);
    }

    return docs;
  }

  async getIssuesV2API(nextPageToken) {
    const errMessage = `${LOG_NAME} - Error in fetching all alerts : err: `;

    try {
      const variables = {
        first: PAGE_SIZE.ISSUES,
        filterBy: {
          status: ["OPEN", "IN_PROGRESS"],
        },
      };

      if (nextPageToken) {
        variables["after"] = `${nextPageToken}`;
      }

      const result: AxiosResponse<any> = await axios.post(
        this.apiUrl,
        { query: QUERY.ISSUES, variables: variables },
        {
          timeout: this.TIME_OUTS.MEDIUM,
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            "Content-Type": "application/json",
          },
        },
      );

      if (result.status == 200) {
        return result && result.data && result.data.data && result.data.data.issuesV2;
      } else {
        StatesHelper.Instance.globalApisFails.add("wiz-cspm");
        logger.error(`${errMessage} ${result.status}!`);
      }
    } catch (error: any) {
      logger.error(`${errMessage} ${error}`);
      StatesHelper.Instance.globalApisFails.add("wiz-cspm");
    }
  }

  async getIssuesV2(issuesList: WizIssueV2[]) {
    let alertCount = 0;
    let failedAttempt = 0;
    let currPage = 0;
    let totalAlertCount = 0;
    let nextPageToken = "";
    let callApi = true;

    while (callApi) {
      try {
        if (totalAlertCount > 0 && currPage * PAGE_SIZE.ISSUES >= totalAlertCount) {
          break;
        }

        this.logAlertsInfo(currPage, totalAlertCount, "IssuesV2", PAGE_SIZE.ISSUES);

        const result = await this.getIssuesV2API(nextPageToken);

        if (result) {
          if (result.pageInfo && result.pageInfo.hasNextPage) {
            nextPageToken = result.pageInfo.endCursor;
          }

          if (result.nodes == null) {
            break;
          }

          const alerts: WizIssueV2[] = result.nodes;
          if (alerts.length == 0) {
            break;
          } else {
            for (const issue of result.nodes) {
              issuesList.push(issue);
            }
          }

          this.insertData("IssuesV2", alerts);

          alertCount += alerts.length;

          if (currPage == 0) {
            totalAlertCount = result.totalCount;
            logger.info(`${LOG_NAME} - Getting IssuesV2 Alerts , Get Total : ${result.totalCount} Alerts`);
          }

          // for the logging purpose only
          currPage += 1;

          if (isLocalDevelopment()) {
            if (currPage > 2) {
              break;
            }
          }
        } else {
          failedAttempt += 1;
          if (failedAttempt > RETRY_COUNT) {
            logger.error(`${LOG_NAME} - Fetch Alerts failed safe limit reached!`);
            callApi = false;
          }
        }

        callApi = await this.alertHasNextPage(result);
      } catch (e) {
        logger.error(`${LOG_NAME} - Error in Fetching Alerts! : ${e}`);
        callApi = false;
      }
    }

    if (totalAlertCount != 0) {
      if (alertCount == totalAlertCount) {
        logger.info(`${LOG_NAME} - Getting IssuesV2 Alerts, Successfully fetched All ${totalAlertCount} alerts!`);
      } else {
        if (totalAlertCount != 0) {
          logger.warn(
            `${LOG_NAME} - Getting IssuesV2 Alerts, Missing ${
              totalAlertCount - alertCount
            } alerts , Fetched ${alertCount} out of ${totalAlertCount}!`,
          );
        }
      }
    } else {
      logger.warn(`${LOG_NAME} - Getting IssuesV2 Alerts, No Issues Found!`);
    }

    return issuesList;
  }

  async getAllIssuesV2() {
    const issuesList: WizIssueV2[] = [];
    logger.info(`Getting All IssuesV2 ** Begin **`);

    await this.getIssuesV2(issuesList);

    logger.info(`Getting All IssuesV2 ** Completed **, issuesList count: ${issuesList.length}`);

    return issuesList;
  }

  async getConfigurationFinding(nextPageToken, entityType: string, resourceIds: string[]) {
    const errMessage = `${LOG_NAME} - Error in fetching all alerts : err: `;

    try {
      const variables = {
        first: PAGE_SIZE.CONFIGURATION_FINDINGS,
        filterBy: {
          status: ["OPEN", "IN_PROGRESS"],
          resource: {
            type: entityType,
            id: resourceIds,
          },
        },
      };

      if (nextPageToken) {
        variables["after"] = `${nextPageToken}`;
      }

      const result: AxiosResponse<any> = await axios.post(
        this.apiUrl,
        { query: QUERY.CONFIGURATION_FINDINGS, variables: variables },
        {
          timeout: this.TIME_OUTS.MEDIUM,
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            "Content-Type": "application/json",
          },
        },
      );

      if (result.status == 200) {
        return result && result.data && result.data.data && result.data.data.configurationFindings;
      } else {
        StatesHelper.Instance.globalApisFails.add("wiz-cspm");
        logger.error(`${errMessage} ${result.status}!`);
      }
    } catch (error: any) {
      logger.error(`${errMessage} ${error}`);
      StatesHelper.Instance.globalApisFails.add("wiz-cspm");
    }
  }

  async getCSPMforEntityId(entityType: string, resourceIds: string[], configurationFindings: any[]) {
    let alertCount = 0;
    let failedAttempt = 0;
    let currPage = 0;
    let totalAlertCount = 0;
    let nextPageToken = "";
    let callApi = true;

    logger.info(`${LOG_NAME} - Getting ConfigurationFindings Alerts entityType: ${entityType}, ** Begin **`);

    while (callApi) {
      try {
        if (totalAlertCount > 0 && currPage * PAGE_SIZE.CONFIGURATION_FINDINGS >= totalAlertCount) {
          break;
        }

        this.logAlertsInfo(currPage, totalAlertCount, "ConfigurationFindings", PAGE_SIZE.CONFIGURATION_FINDINGS);

        const result = await this.getConfigurationFinding(nextPageToken, entityType, resourceIds);

        if (result) {
          if (result.pageInfo && result.pageInfo.hasNextPage) {
            nextPageToken = result.pageInfo.endCursor;
          }

          if (result.nodes === null) {
            break;
          }

          if (result.nodes?.length == 0) {
            break;
          }

          const alerts: any[] = result.nodes;

          configurationFindings.push(...result.nodes);

          if (result.nodes.length > 0) {
            this.insertData("ConfigurationFindings", result.nodes);
          }

          alertCount += alerts.length;

          if (currPage == 0) {
            totalAlertCount = result.totalCount;
            logger.info(
              `${LOG_NAME} - Getting ConfigurationFindings Alerts , Get Total : ${result.totalCount} Alerts, entityType : ${entityType}`,
            );
          }

          // for the logging purpose only
          currPage += 1;

          if (isLocalDevelopment()) {
            if (currPage > 2) {
              break;
            }
          }
        } else {
          failedAttempt += 1;
          if (failedAttempt > RETRY_COUNT) {
            logger.error(`${LOG_NAME} - Fetch Alerts failed safe limit reached!, entityType : ${entityType}`);
            callApi = false;
          }
        }

        callApi = await this.alertHasNextPage(result);
      } catch (e) {
        logger.error(`${LOG_NAME} - Error in Fetching Alerts!, entityType : ${entityType}, err: ${e}`);
        callApi = false;
      }
    }

    if (totalAlertCount != 0 && alertCount == totalAlertCount) {
      logger.info(
        `${LOG_NAME} - Getting ConfigurationFindings Alerts , Successfully fetched All ${totalAlertCount} alerts!, entityType : ${entityType}`,
      );
    } else {
      logger.warn(
        `${LOG_NAME} - Getting ConfigurationFindings Alerts , Missing ${
          totalAlertCount - alertCount
        } alerts , Fetched ${alertCount} out of ${totalAlertCount}!, entityType : ${entityType}`,
      );
    }

    logger.info(`${LOG_NAME} - Getting ConfigurationFindings Alerts entityType : ${entityType} ** Completed **`);
  }

  /**
   * findIssueUniqueEntity
   *
   *  this function is to find the unique entity ids from the issues
   *
   * @param issues : WizIssueV2
   * @returns entityIds : object
   */
  findIssueUniqueEntityType(issues: WizIssueV2[]) {
    const entityIds = {};
    let totalTypes = 0;
    let totalIds = 0;
    for (const issue of issues) {
      try {
        const type = issue.entity?.type || issue.entitySnapshot.type;
        const id = issue.entity?.id || issue.entitySnapshot.id;

        if (entityIds[type] === undefined) {
          entityIds[type] = new Set();
          totalTypes++;
        }
        if (!entityIds[type].has(id)) {
          entityIds[type].add(id);
          totalIds++;
        }
      } catch (err) {
        logger.error(`${LOG_NAME} - findIssueUniqueEntityType for single issue: ${issue.id}, err: ${err}`);
      }
    }

    logger.info(`finish findIssueUniqueEntityType, totalTypes: ${totalTypes},  totalIds: ${totalIds}`);
    return entityIds;
  }

  chunks(arr: any[], n: number) {
    const chunkArr = [];
    for (let i = 0; i < arr.length; i += n) {
      chunkArr.push(arr.slice(i, i + n));
    }

    return chunkArr;
  }

  async getAllConfigurationFindings(entityIds) {
    const configurationFindings = [];

    logger.info(`getAllConfigurationFindings ** Begin **`);

    for (const [entityType, entityIdList] of Object.entries(entityIds)) {
      try {
        logger.info(`Getting Configuration Findings for ${entityType} ** Begin **`);

        const uniqueIds = Array.from(entityIdList as any);
        const chunkEntityIds = this.chunks(uniqueIds, 50);

        await PromisePool.for(chunkEntityIds)
          .withConcurrency(5)
          .process(async (entityIds: string[]) => {
            try {
              await this.getCSPMforEntityId(entityType, entityIds, configurationFindings);
            } catch (err) {
              logger.error(`failed getCSPMforEntityId, err: ${err}`);
            }
          });

        logger.info(`Getting Configuration Findings for ${entityType} ** Completed **`);
      } catch (err) {
        logger.error(`${LOG_NAME} - getAllConfigurationFindings for single entityType: ${entityType}, err: ${err}`);
      }
    }

    logger.info(`getAllConfigurationFindings, configurationFindings: ${configurationFindings.length} ** End **`);

    return configurationFindings;
  }

  async getVulnerabilityFinding(nextPageToken, assetIds: string[]) {
    const errMessage = `${LOG_NAME} - Error in fetching all alerts : err: `;

    try {
      const variables = {
        first: PAGE_SIZE.VULNERABILITY_FINDINGS,
        filterBy: {
          assetId: assetIds,
          status: [WizIssueStatus.Open, WizIssueStatus.InProgress],
        },
      };

      if (nextPageToken) {
        variables["after"] = `${nextPageToken}`;
      }

      const result: AxiosResponse<any> = await axios.post(
        this.apiUrl,
        { query: QUERY.VULNERABILITY_FINDINGS, variables: variables },
        {
          timeout: this.TIME_OUTS.MEDIUM,
          headers: {
            Authorization: `Bearer ${this.accessToken}`,
            "Content-Type": "application/json",
          },
        },
      );

      if (result.status == 200) {
        return result && result.data && result.data.data && result.data.data.vulnerabilityFindings;
      } else {
        StatesHelper.Instance.globalApisFails.add("wiz-cspm");
        logger.error(`${errMessage} ${result.status}!`);
      }
    } catch (error: any) {
      logger.error(`${errMessage} ${error}`);
      StatesHelper.Instance.globalApisFails.add("wiz-cspm");
    }
  }

  async getVulnerabilityFindings(assetIds: string[], vulnerabilityFindings: any[]) {
    let alertCount = 0;
    let failedAttempt = 0;
    let currPage = 0;
    let totalAlertCount = 0;
    let nextPageToken = "";
    let callApi = true;

    logger.info(`${LOG_NAME} - Getting VulnerabilityFindings Alerts ** Begin **`);

    while (callApi) {
      try {
        if (totalAlertCount > 0 && currPage * PAGE_SIZE.VULNERABILITY_FINDINGS >= totalAlertCount) {
          break;
        }

        this.logAlertsInfo(currPage, totalAlertCount, "VulnerabilityFindings", PAGE_SIZE.VULNERABILITY_FINDINGS);

        const result = await this.getVulnerabilityFinding(nextPageToken, assetIds);

        if (result) {
          if (result.pageInfo && result.pageInfo.hasNextPage) {
            nextPageToken = result.pageInfo.endCursor;
          }

          if (result.nodes === null) {
            break;
          }

          if (result.nodes?.length == 0) {
            break;
          }

          const alerts: any[] = result.nodes;

          if (result.nodes.length > 0) {
            this.insertData("VulnerabilityFindings", result.nodes);
            result.nodes.forEach(i => {
              vulnerabilityFindings.push(i);
            });
          }

          alertCount += alerts.length;

          if (currPage == 0) {
            totalAlertCount = result.totalCount;
            logger.info(`${LOG_NAME} - Getting VulnerabilityFindings Alerts , Get Total : ${result.totalCount} Alerts`);
          }

          // for the logging purpose only
          currPage += 1;

          if (isLocalDevelopment()) {
            if (currPage > 2) {
              break;
            }
          }
        } else {
          failedAttempt += 1;
          if (failedAttempt > RETRY_COUNT) {
            logger.error(`${LOG_NAME} - Fetch Alerts failed safe limit reached!`);
            callApi = false;
          }
        }

        callApi = await this.alertHasNextPage(result);
      } catch (e) {
        logger.error(`${LOG_NAME} - Error in Fetching Alerts! : ${e}`);
        callApi = false;
      }
    }

    if (totalAlertCount != 0 && alertCount == totalAlertCount) {
      logger.info(`${LOG_NAME} - Getting VulnerabilityFindings Alerts , Successfully fetched All ${totalAlertCount} alerts!`);
    } else {
      logger.warn(
        `${LOG_NAME} - Getting VulnerabilityFindings Alerts , Missing ${
          totalAlertCount - alertCount
        } alerts , Fetched ${alertCount} out of ${totalAlertCount}!`,
      );
    }

    logger.info(`${LOG_NAME} - Getting VulnerabilityFindings Alerts ** Completed **`);
  }

  async getAllVulnerabilityFindings(entityIds) {
    const vulnerableAssetTypes = ["CONTAINER", "CONTAINER_IMAGE", "SERVERLESS", "VIRTUAL_MACHINE"];
    const vulnerabilityFindings = [];

    for (const [entityType, entityId] of Object.entries(entityIds)) {
      try {
        if (vulnerableAssetTypes.includes(entityType) == false) {
          logger.info(`Skipping entity type ${entityType}`);
          continue;
        }

        logger.info(`Getting Vulnerability Findings for ${entityType} ** Begin **`);

        const uniqueIds = Array.from(entityId as any);
        const chunkEntityIds = this.chunks(uniqueIds, 2);

        await PromisePool.for(chunkEntityIds)
          .withConcurrency(5)
          .process(async (assetIds: string[]) => {
            try {
              await this.getVulnerabilityFindings(assetIds, vulnerabilityFindings);
            } catch (err) {
              logger.error(`failed getVulnerabilityFindings, err: ${err}`);
            }
          });

        logger.info(`Getting VulnerabilityFindings Findings for ${entityType} ** Completed **`);
      } catch (err) {
        //add
      }
    }

    return vulnerabilityFindings;
  }

  setAlertSCA(alert: any, containerEvents: SecurityEvent[]) {
    try {
      const securityEvent = new SecurityEvent(
        Constant.wiz,
        true,
        alert.portalUrl,
        alert.createdAt,
        "",
        "",
        "",
        alert.description ? alert.description : alert.CVEDescription,
        alert.detailedName,
        `${alert.detailedName}@${alert.version}`,
        alert.weightedSeverity ? alert.weightedSeverity : alert.CVSSSeverity,
        "",
        0,
        AlertSeverity[AlertSeverity.High],
        SecurityAlertType.container,
        "",
        `${alert.detailedName}@${alert.version}`,
        "",
        -1,
        false,
        false,
        "",
        "",
        "",
        "",
        alert.vulnerabilityExternalId,
        "",
        "",
        "",
        "",
        "",
        "wiz",
      );

      if (alert.id) {
        securityEvent.linkToExternalProduct = linkToExternalProduct.replace(`{issueID}`, alert.id);
      }

      if (alert.fixedVersion) {
        securityEvent.fixedVersion = alert.fixedVersion;
      }

      if (alert.remediation) {
        securityEvent.recommendation = alert.remediation;
      }
      // if (securityEvent.severity === AlertSeverity.Critical) {
      //   const adsd = "";
      // }

      securityEvent.blame.cve = alert.vulnerabilityExternalId;
      if (securityEvent.blame.cve) {
        securityEvent.cves.push(securityEvent.blame.cve);
      }
      securityEvent.blame.cvssScore = alert.score;
      securityEvent.securitySubTypeAlertType = SecurityAlertType.cloudRunTime;

      if (alert.hasExploit) {
        securityEvent.blame.hasPublicExploit = true;
        addSeverityChangedReason(severityReasons.noPublicExpolit, securityEvent, undefined);
        // if (securityEvent.blame.hasPublicExploit) {
        //   securityEvent.blame.publicExploitLink = cve.exploits[0].url;
        //   addSeverityChangedReason(severityReasons.hasPublicExpolit, securityEvent, undefined);
        // } else {
        //   addSeverityChangedReason(severityReasons.noPublicExpolit, securityEvent, undefined);
        // }
      }

      //Exposed outside --> NOT mandatory
      // const serviceExposed = item?.severity_contributing_factors?.find(i => i === "The resource is publicly exposed to the internet");
      // if (serviceExposed) {
      //   addSeverityChangedReason(severityReasons.netExposed, securityEvent, undefined);
      // }

      //Network exploitable vector
      if (alert?.cvssv2?.attackVector === "NETWORK" || alert?.cvssV3?.attackVector === "NETWORK") {
        securityEvent.blame.attackVector = "NETWORK";
      }
      if (alert?.cvssv2?.attackVector === "LOCAL" || alert?.cvssV3?.attackVector === "LOCAL") {
        securityEvent.blame.attackVector = "LOCAL";
      }

      //Pkg name
      securityEvent.pkgName = `${alert.detailedName}`;
      securityEvent.installedVersion = alert.version;

      const os = {
        name: "N/A",
        version: "N/A",
      };

      if (alert.detectionMethod === WizVulnerabilityDetectionMethod.Os) {
        if (alert.vulnerableAsset.type === WizEntityType.VirtualMachine) {
          os.name = alert.operatingSystem;
          os.version = alert.detailedName;
        } else if (alert.vulnerableAsset.type === WizEntityType.Serverless) {
          os.name = alert.detailedName;
          os.version = alert.version;
        }
      } else if (alert.detectionMethod === WizVulnerabilityDetectionMethod.Library) {
      } else if (alert.detectionMethod === WizVulnerabilityDetectionMethod.FilePath) {
      } else if (alert.detectionMethod === WizVulnerabilityDetectionMethod.InstalledProgram) {
      } else if (alert.detectionMethod === WizVulnerabilityDetectionMethod.Package) {
      }

      // const imageInfo = alert.scanOriginResource.name;
      // if (imageInfo.includes("base")) {
      // }

      // let created_at = new Date().toDateString();
      // let accountId = "";
      // let region = "";
      // let hostname = "";
      // let registryName = "";
      // let tag = "";
      // let sha = "";
      // let os = "";
      // let baseImageOsVersion = "";
      // let baseImageSha = "";
      // let baseImage = "";
      // let imageName = "";

      // if (imageInfo.includes(":")) {
      //   const sp = imageInfo.split(":");
      //   sha = sp[1];
      //   imageName = sp[0];
      //   const t = getHashType(sha);
      //   if (t === HahsType.Unknown) {
      //     imageName = imageInfo;
      //     sha = "";
      //   }
      // } else {
      //   imageName = imageInfo;
      // }

      // registryName = guessArtifactSystem(imageName);
      // if (registryName === ArtifactorySecEventSystem.ECR) {
      //   const i = imageName.indexOf(".");
      //   if (i != -1) {
      //     accountId = imageName.substring(0, i);
      //     this.accountIds.add(accountId);
      //   } else {
      //     this.accountIds.add("n/a");
      //   }
      // }

      // if (registryName === ArtifactorySecEventSystem.Generic && imageName.includes("/")) {
      //   const i = imageName.indexOf("/");
      //   registryName = imageName.substring(0, i);
      //   imageName = imageName.substring(i + 1, imageName.length);
      // }

      // const artifacts = {
      //   system: ArtifactorySecEventSystem.Generic,
      //   subType: ArtifactorySecEventType.Docker,
      //   repoFullName: "N/A",
      //   imageCreatedAt: created_at,
      //   dockerVer: "",
      //   hasPackageManager: false,
      //   os: os,
      //   sha: sha ? sha : "N/A",
      //   binariesCount: 0,
      //   pkgCount: 0,
      //   dockerFileInRunTime: imageName,
      //   registry: registryName,
      //   tag: tag,
      //   linkToRegistry: "N/A",
      //   linkToTask: "",
      //   baseImage: baseImage,
      //   baseImageSha: baseImageSha,
      //   baseImageOsVersion: baseImageOsVersion,
      //   registryName: registryName,
      //   runningOnHost: hostname,
      //   region: region,
      //   accountId: accountId,
      // };

      // securityEvent.artifacts = artifacts;
      securityEvent.realMatch = `${alert.detailedName}@${alert.version}`;

      containerEvents.push(securityEvent);
    } catch (err) {
      logger.error(`${LOG_NAME} - failed for SCA alert ${alert.id} , err : ${err}`);
    }
  }

  async setAlertCSPM(alert: WizIssueV2, configurationFinding: WizConfigurationFinding, cloudSecurityEvents: CloudSecurityEvent[]) {
    try {
      let account_name = alert?.entitySnapshot?.subscriptionExternalId;
      let accountId = account_name;
      let resource = alert?.entitySnapshot?.name;

      let owners = alert?.entitySnapshot?.subscriptionName ? [alert.entitySnapshot.subscriptionName] : [];
      if (alert.entity.type === WizEntityType.UserAccount) {
        resource = alert?.entity?.properties?.name;
        account_name = "Global";
        accountId = "Global";
        owners = [];
        owners.push(resource);
      } else if (
        [
          WizEntityType.Serverless as string,
          WizEntityType.ComputeInstanceGroup,
          WizEntityType.ServiceAccount,
          WizEntityType.VirtualMachine,
        ].includes(alert.entity.type)
      ) {
        resource = alert?.entitySnapshot?.name;
      } else if (alert.entity.type === "KUBERNETES_JOB") {
        resource = alert?.entitySnapshot?.kubernetesClusterName;
      } else {
        resource = alert?.entitySnapshot?.name;
      }

      if (alert?.entitySnapshot?.cloudPlatform?.toLowerCase()?.includes("aws")) {
        if (!account_name && alert?.entity?.properties?.subscriptionExternalId)
          account_name = alert?.entity?.properties?.subscriptionExternalId;
      }

      let cloudPlatform = alert.entitySnapshot.cloudPlatform;
      if (!alert?.entitySnapshot?.cloudPlatform) {
        account_name = alert?.entity?.providerData?.projectId;
        accountId = alert?.entity?.providerData?.projectId;
        resource = alert?.entity?.providerData?.name;
        if (!cloudPlatform) {
          cloudPlatform = alert?.entity?.properties?.userDirectory;
        }
      }

      if (!account_name) {
        account_name = "Global";
      }
      if (!resource) {
        resource = "N/A";
      }

      const securityEvent = new CloudSecurityEvent(
        cloudPlatform,
        Constant.wiz,
        "",
        alert.createdAt,
        configurationFinding.name,
        alert.description ? alert.description : "N/A",
        alert.severity,
        "",
        "",
        configurationFinding.remediation ? configurationFinding.remediation : configurationFinding.rule.remediationInstructions,
        false,
        configurationFinding.rule.shortId || "N/A",
        "",
        account_name,
        configurationFinding.securitySubCategories?.map(a => a.name && a.name)?.join(" , "),
        alert.entitySnapshot.region,
        alert.entity.type.toLowerCase(),
        resource,
        "",
        "",
        false,
        true,
        "wiz-cspm" as Tool,
      );

      if (alert.id) {
        securityEvent.linkToExternalProduct = linkToExternalProduct.replace(`{issueID}`, alert.id);
      }

      securityEvent.accountId = accountId;
      securityEvent.cloudAccountOwners = owners;

      if (alert?.entity?.properties?.["accessibleFrom.internet"] || alert?.description?.includes("is exposed to the public internet")) {
        addSeverityCloudChangedReason(severityReasons.netExposed, securityEvent, undefined);
      }
      if (alert?.entity?.properties?.hasAdminPrivileges) {
        addSeverityCloudChangedReason(severityReasons.adminPrivilege, securityEvent, undefined);
      }
      if (alert?.entity?.properties?.hasHighPrivileges) {
        addSeverityCloudChangedReason(severityReasons.highPrivilege, securityEvent, undefined);
      }
      if (alert?.control?.impactSeverityExplanation === "High privileges") {
        addSeverityCloudChangedReason(severityReasons.highPrivilege, securityEvent, undefined);
      }
      if (alert?.entitySnapshot?.status === "Active") {
        const extraInfo: ExtraInfo[] = addRunningInCloudExtraInfo(securityEvent);
        addSeverityCloudChangedReason(severityReasons.runningInCloud, securityEvent, extraInfo);
      }

      if (alert.entity.type === "USER_ACCOUNT") {
        addSeverityCloudChangedReason(severityReasons.userAccount, securityEvent, undefined);
      }
      if (alert.entity.type === "SERVERLESS") {
        addSeverityCloudChangedReason(severityReasons.serverless, securityEvent, undefined);
      }
      if (alert.entity.type === "COMPUTE_INSTANCE_GROUP") {
        addSeverityCloudChangedReason(severityReasons.computeInstanceGroup, securityEvent, undefined);
      }
      if (alert.entity.type === "SERVICE_ACCOUNT") {
        addSeverityCloudChangedReason(severityReasons.serviceAccount, securityEvent, undefined);
      }
      if (alert.entity.type === "VIRTUAL_MACHINE") {
        addSeverityCloudChangedReason(severityReasons.virtualMachine, securityEvent, undefined);
      }
      if (
        alert?.entitySnapshot?.cloudPlatform?.toLowerCase().includes("kubernetes") ||
        alert?.entity?.type === WizEntityType.KubernetesJob
      ) {
        addSeverityCloudChangedReason(severityReasons.kubernetes, securityEvent, undefined);
      }

      if (alert?.entity?.providerData?.containers) {
        const container = alert.entity.providerData.containers[0];

        let sha;
        let tag;
        let registry;

        // uniqueContainer.add(container.name);

        let dockerFileInRunTime = container.name;
        if (dockerFileInRunTime.includes(":")) {
          const splitted = dockerFileInRunTime.split(":");
          dockerFileInRunTime = splitted[0];
          tag = splitted[1];
        }
        if (container.image.includes("@sha256:")) {
          const i = container.image.indexOf("@sha256:");
          sha = container.image.substring(i + "@sha256:".length, container.image.length);
        }
        if (container.image.includes("/")) {
          const i = container.image.indexOf("/");
          registry = container.image.substring(0, i);
        }

        const artifacts = {
          system: ArtifactorySecEventSystem.Generic,
          subType: ArtifactorySecEventType.Docker,
          repoFullName: "N/A",
          imageCreatedAt: alert.createdAt,
          dockerVer: "",
          hasPackageManager: false,
          os: "",
          sha: sha ? sha : "N/A",
          binariesCount: 0,
          pkgCount: 0,
          dockerFileInRunTime: dockerFileInRunTime,
          registry: registry,
          tag: tag,
          linkToRegistry: "N/A",
          linkToTask: "",
          baseImage: "",
          baseImageSha: "",
          baseImageOsVersion: "",
          registryName: registry,
          runningOnHost: "",
          region: alert.entitySnapshot.region,
          accountId: securityEvent.accountId,
        };

        securityEvent.artifacts = artifacts;
      }

      cloudSecurityEvents.push(securityEvent);
    } catch (err) {
      logger.error(`${LOG_NAME} - failed for alert ${alert.id} , err : ${err}`);
    }
  }

  async getAllAlerts(cloudSecurityEvents: CloudSecurityEvent[], containerEvents: SecurityEvent[]) {
    try {
      if (this.mode === "db") {
        const issuesList: WizIssueV2[] = await this.getDataFromDb("IssuesV2");
        const configurationFindings: WizConfigurationFinding[] = await this.getDataFromDb("ConfigurationFindings");
        const vulnerabilityFindings = await this.getDataFromDb("VulnerabilityFindings");

        for (const configurationFinding of configurationFindings) {
          const issue: WizIssueV2 = issuesList.filter(item => item.entity.id == configurationFinding.resource.id)[0];
          this.setAlertCSPM(issue, configurationFinding, cloudSecurityEvents);
        }

        for (const vulnerabilityFinding of vulnerabilityFindings) {
          this.setAlertSCA(vulnerabilityFinding, containerEvents);
        }
      } else {
        let issuesList: WizIssueV2[] = await this.getAllIssuesV2();
        if (isLocalDevelopment()) {
          issuesList = issuesList.slice(0, 20);
        }

        const entityIds = this.findIssueUniqueEntityType(issuesList);
        const configurationFindings = await this.getAllConfigurationFindings(entityIds);
        const vulnerabilityFindings = await this.getAllVulnerabilityFindings(entityIds);

        for (const configurationFinding of configurationFindings) {
          const issue: WizIssueV2 = issuesList.filter(item => item?.entity?.id == configurationFinding?.resource?.id)[0];
          this.setAlertCSPM(issue, configurationFinding, cloudSecurityEvents);
        }

        for (const vulnerabilityFinding of vulnerabilityFindings) {
          this.setAlertSCA(vulnerabilityFinding, containerEvents);
        }
      }
    } catch (e) {
      console.log(e);
    }

    console.log("Complete");
  }

  logAlertsInfo(currPage, totalAlertCount, type, pageSize = PAGE_SIZE.DEFAULT) {
    const start = currPage * pageSize;

    let end = start + pageSize;
    if (totalAlertCount != 0) {
      end = end > totalAlertCount ? totalAlertCount : end;
    }

    logger.info(`${LOG_NAME} - Getting ${type} Alerts from ${start} - ${end}`);
  }
}

class Wiz extends ExternalSecurityProviderBase {
  public token: Token;
  private clientApi: WizAPI;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.token = token;
  }

  async initLib() {
    try {
      logger.info(`set ${this.token.name}, host: ${this.token.host}`);
      this.clientApi = new WizAPI(this.token);
      this.clientApi.mode = "api";

      await this.clientApi.auth();
    } catch (err) {
      logger.error(`failed to initialize ${this.token.name}, host: ${this.token.host}, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add("wiz");
      StatesHelper.Instance.globalApisFails.add("wiz-cspm");
    }
  }

  async securityEvents() {
    const cloudSecurityEvents: CloudSecurityEvent[] = [];
    const containerEvents: SecurityEvent[] = [];

    try {
      if (true || this.clientApi.isValidToken) {
        try {
          logger.info(`${this.token.name} - try Collect Security Events`);

          await this.clientApi.getAllAlerts(cloudSecurityEvents, containerEvents);
        } catch (err) {
          logger.error(`${this.token.name} - failed to set all ${this.token.name} security events, err: ${err}`);
        }

        logger.info(
          `${this.token.name} - finish Collecting Security Events with, cloudSecurityEvents: ${
            cloudSecurityEvents.length
          }, containerEvents: ${containerEvents.length}, accountIds: ${Array.from(this.clientApi.accountIds)}`,
        );
      }
    } catch (err) {
      logger.error(`${this.token.name} - failed to set all ${this.token.name} security events, err: ${err}`);
    }
    return { cloudSecurityEvents: cloudSecurityEvents, containerEvents: containerEvents };
  }
}

export default Wiz;
