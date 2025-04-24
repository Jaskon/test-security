import { v4 } from "uuid";
import { ChangeReason } from "../entitis/service/blameTypes";
import FileHelper from "../helper/IO/fileHlper";
import { SbomHelper } from "../helper/sbom/sbomHelper";
import loggerImport from "../logger";
import { Tool } from "../policy/rules/code/policyRulesBase";
import { ImageDetail } from "./cloudTypes";
import { replaceAll, Repo, SecurityEvent } from "./codeRepoTypes";

const logger = loggerImport.getDebugLogger();
const uuidGenerator = require("uuid");

export interface OS {
  Family: string;
  Name: string;
}

export interface History {
  created: string;
  created_by: string;
  empty_layer?: boolean;
  comment: string;
}

export interface Rootfs {
  type: string;
  diff_ids: string[];
}

export interface Labels {
  created: Date;
  description: string;
  documentation: string;
  revision: string;
  source: string;
  title: string;
  url: string;
  vendor: string;
  version: string;
}

export interface Config {
  Entrypoint: string[];
  Env: string[];
  Labels: Labels;
}

export interface ImageConfig {
  architecture: string;
  created: string;
  history: History[];
  os: string;
  rootfs: Rootfs;
  config: Config;
}

export interface Metadata {
  OS: OS;
  ImageID: string;
  DiffIDs: string[];
  ImageConfig: ImageConfig;
}

export interface MisconfSummary {
  Successes: number;
  Failures: number;
  Exceptions: number;
}

export interface Layer {}

export interface Line {
  Number: number;
  Content: string;
  IsCause: boolean;
  Annotation: string;
  Truncated: boolean;
  FirstCause: boolean;
  LastCause: boolean;
}

export interface Code {
  Lines: Line[];
}

export interface CauseMetadata {
  Provider: string;
  Service: string;
  Code: Code;
  StartLine?: number;
  EndLine?: number;
}

export interface Misconfiguration {
  Type: string;
  ID: string;
  AVDID: string;
  Title: string;
  Description: string;
  Message: string;
  Namespace: string;
  Query: string;
  Resolution: string;
  Severity: string;
  PrimaryURL: string;
  References: string[];
  Status: string;
  Layer: Layer;
  CauseMetadata: CauseMetadata;
}

export interface Result {
  Target: string;
  Class: string;
  Type: string;
  MisconfSummary: MisconfSummary;
  Misconfigurations: Misconfiguration[];
}

export interface ComplianceJson {
  SchemaVersion: number;
  ArtifactName: string;
  ArtifactType: string;
  Metadata: Metadata;
  Results: Result[];
}
export enum ArtifactoryTypes {
  Unknown,
  registryImage,
  sbom,
  image,
}

export class ImageInfo {
  image: ImageDetail = new ImageDetail();
  sbomEvents: SbomEvent[] = [];
  securityEvents: SecurityEvent[] = [];
  objType: ArtifactoryTypes = ArtifactoryTypes.registryImage;
  objTypeStr: string = ArtifactoryTypes[ArtifactoryTypes.registryImage];
  severityChangeReasons: ChangeReason[] = [];
  isDelta?: boolean;
}

export const isSbomEvent = (i: any): i is SbomEvent => i instanceof SbomEvent;
export const isImageInfo = (i: any): i is ImageInfo => i instanceof ImageInfo;

export class SbomEvent {
  public objType: ArtifactoryTypes = ArtifactoryTypes.sbom;
  public objTypeStr = ArtifactoryTypes[ArtifactoryTypes.sbom];
  public sbomHelper: SbomHelper;
  public tool: Tool = "UNKNOWN";

  constructor(public sbom: Sbom, tool: Tool) {
    this.sbomHelper = new SbomHelper(this.sbom);
    this.tool = tool;
  }
}

export interface Link {
  Label: string;
  URL: string;
}

export class Version {
  sha: string;
  licenses: string[] = [];
  version: string;
  timeStr: string;
  timeInDays: number;
  timeInMili: number;
  main: string;
}

export interface Maintainer {
  email: string;
  name: string;
}

export interface Advisory {
  Source: string;
  SourceID: string;
}

export interface SnapshotAt {
  value: Date;
}

export interface SnapshotAt2 {
  value: Date;
}

export class ProjectInfo {
  Name: string;
  Type: string;
  OpenIssuesCount: number;
  StarsCount: number;
  ForksCount: number;
  Description: string;
  Homepage: string;
  disabled: boolean;
  SnapshotAt: SnapshotAt2;
  deprecated: boolean;
  deprecatedRecommendation: string;
  contributors: number;
  linters: string[] = [];
}

export class GoogleLicenseInsight {
  Name: string;
  Version: string;

  //From GCP
  Licenses: string[];
  Links: Link[];
  Advisories: Advisory[];
  SnapshotAt: SnapshotAt;
  projectInfo: ProjectInfo;
  projectFromGCP: string;
  System: string;

  maintainers: Maintainer[];
  publisher: Maintainer;
  totalCountOfVers: number;
  linkToActualSite: string;
  linkToFix: string;
  downloads: number;

  //Versions
  latestVer: Version;
  currentVer: Version;
  nextVersionAfterCurrent: Version;
  nextReleasesVer: Version[] | Version;

  //Times
  createdAt: string;
  createdAtDays: number;

  //Queried by external api
  cashQueryNpmVer: number;
  cashQueryMavenVer: number;
  cashQueryPython: number;

  copyrightInfo: string[] = [];
  copyWriteInfoLink: string;

  constructor() {
    this.Advisories = [];
    this.Links = [];
    this.Licenses = [];
    this.maintainers = [];
    this.latestVer = new Version();
    this.currentVer = new Version();
    this.totalCountOfVers = -1;
    this.projectInfo = new ProjectInfo();
  }
}

export interface GoogleLicenseInsightCache extends GoogleLicenseInsight {
  cachedAt: Date;
}

// SBOM CycloneDX spec ----------------------------
export interface Sbom {
  bomFormat: "CycloneDX";
  specVersion: string;
  serialNumber: string;
  version: number;
  metadata: SbomMetadata;
  components: SbomComponent[];
  dependencies: SbomDependency[];
  vulnerabilities: SbomVulnerability[];
}

export interface SbomCSVLib {
  "Package Name": string;
  "Library Name": string;
  Version: string;
  License: string;
  "App Name": string;
  Dependency: string;
  Source: string;
  Location: string;
}

export enum ContainerSecurityType {
  appOnly = "appOnly",
  possibleOsOnly = "possibleOsOnly",
  baseOnly = "baseOnly",
  instructionsOnly = "instructionsOnly",
}

export enum SbomComponentType {
  Library = "library",
  Os = "operating-system",
  Organization = "organization",
  Application = "application",
}
export interface SbomComponent {
  dependencies?: string[];
  "bom-ref": string;
  type: SbomComponentType;
  name: string;
  group?: string;
  version?: string;
  purl?: string;
  properties: SbomComponentProperty[];
  licenses?: SbomLicense[];
  copyRight?: string[];
}

export interface SbomLicense {
  expression: string; // Apache-2.0, MIT, ISC, etc.
}

export interface SbomComponentProperty {
  name: string;
  value: string;
}
export interface SbomDependency {
  ref: string;
  dependsOn: string[];
}

export interface SbomMetadata {
  timestamp: string;
  tools: SbomTool[];
  component: SbomComponent;
}

export interface SbomTool {
  vendor: string;
  name: string;
  version: string;
}

export interface SbomVulnerability {
  id: string;
  source: SbomVulnerabilitySource;
  ratings: SbomVulnerabilityRating[] | null;
  cwes: number[] | null;
  description?: string;
  advisories: SbomVulnerabilityAdvisory[] | null;
  published?: string;
  updated?: string;
  affects: SbomVulnerabilityAffect[];
}

export interface SbomVulnerabilityAdvisory {
  url: string;
}

export interface SbomVulnerabilityAffect {
  ref: string;
  versions: SbomVulnerabilityAffectVersion[];
}

export interface SbomVulnerabilityAffectVersion {
  version: string;
  status: string; // affected, etc...
}

export interface SbomVulnerabilityRating {
  source: SbomVulnerabilityRatingSource;
  severity: SbomVulnerabilityRatingSeverity;
  score?: number;
  method?: string; // CVSSv2, CVSSv3, CVSSv31, etc...
  vector?: string;
}

export enum SbomVulnerabilityRatingSeverity {
  Critical = "critical",
  High = "high",
  Info = "info",
  Low = "low",
  Medium = "medium",
}

export interface SbomVulnerabilityRatingSource {
  name: string; // amazon, arch-linux, nvd, oracle-oval, ubuntu, etc...
}

export interface SbomVulnerabilitySource {
  name: string; // debian, ghsa, etc...
  url: string;
}
// SBOM CycloneDX spec ----------------------------

export enum AppSbomType {
  image = "image",
  repo = "repo",
}

interface AppSbomCommon {
  appId: string;
  scanId: string;
  scanDate: Date;
  type: AppSbomType;
  sbom: Sbom;
}

export interface AppSbomImage extends AppSbomCommon {
  type: AppSbomType.image;
  imageDetail: ImageDetail;
}

export interface AppSbomRepo extends AppSbomCommon {
  type: AppSbomType.repo;
  repo: Repo;
}

export type AppSbom = AppSbomRepo | AppSbomImage;

export class ArtifactoryResourceToRun {
  netShareDownloadArtifactPathForScan: string;
  dirWhereToPutRes: string;
  toolCopyDestination: string;
  scannedImage: boolean = false;

  constructor(private uuid: string, private orgName: string, public imageDetail: ImageDetail) {
    this.dirWhereToPutRes = this.getPathToArtifactoryResultsDir();
    new FileHelper(this.uuid).createDir(this.dirWhereToPutRes);
    const u = uuidGenerator.v4().replace(/-/g, "_");

    const orgGitCloneDirLocal = `/mnt/scratch/${orgName}/scan_${replaceAll(uuid, "-", "_")}/artifact/${u}`;
    this.toolCopyDestination = orgGitCloneDirLocal;
  }

  private getPathToArtifactoryResultsDir() {
    const shared = process.env.OX_SHARED_DATA == undefined ? "/var/shared-data" : process.env.OX_SHARED_DATA;
    const fsFriendlyImageName = this.imageDetail.name.replace(/\./g, "_").replace(/\-/g, "_").replace(/\//g, "_");
    return `${shared}/${this.orgName}/${this.uuid}/artifactory_scan/${v4()}/${fsFriendlyImageName}`;
  }
}

export class ArtifactoryDownloadToRun {
  artifactoryResultsDir: string;

  constructor(private uuid: string, private orgName: string, public imageDetail: ImageDetail) {
    const path = this.getPathToArtifactoryResultsDir();
    new FileHelper(this.uuid).createDir(path);
    this.artifactoryResultsDir = path;
  }

  private getPathToArtifactoryResultsDir() {
    const shared = process.env.OX_SHARED_DATA == undefined ? "/var/shared-data" : process.env.OX_SHARED_DATA;
    const fsFriendlyImageName = this.imageDetail.name.replace(/\./g, "_").replace(/\-/g, "_").replace(/\//g, "_");
    return `${shared}/${this.orgName}/${this.uuid}/download_artifactory/${v4()}/${fsFriendlyImageName}`;
  }
}
