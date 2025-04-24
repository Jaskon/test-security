export declare namespace Syft {
  export interface SbomJSON {
    artifacts: Artifact[];
    artifactRelationships: ArtifactRelationship[];
    files: SbomJSONFile[];
    source: Source;
    distro: Distro;
    descriptor: Descriptor;
    schema: Schema;
  }

  export interface ArtifactRelationship {
    parent: string;
    child: string;
    type: ArtifactRelationshipType;
  }

  export enum ArtifactRelationshipType {
    Contains = "contains",
  }

  export interface Artifact {
    id: string;
    name: string;
    version: string;
    type: ArtifactType;
    foundBy: FoundBy;
    locations: Location[];
    licenses: string[];
    language: string;
    cpes: string[];
    purl: string;
    metadataType: MetadataType;
    metadata: Metadata;
  }

  export enum FoundBy {
    ApkdbCataloger = "apkdb-cataloger",
  }

  export interface Location {
    path: string;
    layerID: string;
  }

  export interface Metadata {
    package: string;
    originPackage: string;
    maintainer: string;
    version: string;
    license: string;
    architecture: Architecture;
    url: string;
    description: string;
    size: number;
    installedSize: number;
    pullDependencies: string;
    pullChecksum: string;
    gitCommitOfApkPort: string;
    files: MetadataFile[];
  }

  export enum Architecture {
    X8664 = "x86_64",
  }

  export interface MetadataFile {
    path: string;
    digest?: Digest;
    ownerUid?: string;
    ownerGid?: string;
    permissions?: string;
  }

  export interface Digest {
    algorithm: Algorithm;
    value: string;
  }

  export enum Algorithm {
    Q1Base64Sha1 = "'Q1'+base64(sha1)",
  }

  export enum MetadataType {
    ApkMetadata = "ApkMetadata",
  }

  export enum ArtifactType {
    Apk = "apk",
  }

  export interface Descriptor {
    name: string;
    version: string;
    configuration: Configuration;
  }

  export interface Configuration {
    configPath: string;
    verbosity: number;
    quiet: boolean;
    output: string[];
    "output-template-path": string;
    file: string;
    "check-for-app-update": boolean;
    dev: Dev;
    log: Log;
    catalogers: null;
    package: Package;
    "file-metadata": FileMetadata;
    "file-classification": FileClassification;
    "file-contents": FileContents;
    secrets: Secrets;
    registry: Registry;
    exclude: any[];
    attest: Attest;
    platform: string;
  }

  export interface Attest {
    key: string;
    cert: string;
    noUpload: boolean;
    force: boolean;
    recursive: boolean;
    replace: boolean;
    fulcioUrl: string;
    fulcio_identity_token: string;
    insecure_skip_verify: boolean;
    rekorUrl: string;
    oidcIssuer: string;
    oidcClientId: string;
    OIDCRedirectURL: string;
  }

  export interface Dev {
    "profile-cpu": boolean;
    "profile-mem": boolean;
  }

  export interface FileClassification {
    cataloger: Cataloger;
  }

  export interface Cataloger {
    enabled: boolean;
    scope: string;
  }

  export interface FileContents {
    cataloger: Cataloger;
    "skip-files-above-size": number;
    globs: any[];
  }

  export interface FileMetadata {
    cataloger: Cataloger;
    digests: string[];
  }

  export interface Log {
    structured: boolean;
    level: string;
    "file-location": string;
  }

  export interface Package {
    cataloger: Cataloger;
    "search-unindexed-archives": boolean;
    "search-indexed-archives": boolean;
  }

  export interface Registry {
    "insecure-skip-tls-verify": boolean;
    "insecure-use-http": boolean;
    auth: any[];
  }

  export interface Secrets {
    cataloger: Cataloger;
    "additional-patterns": AdditionalPatterns;
    "exclude-pattern-names": any[];
    "reveal-values": boolean;
    "skip-files-above-size": number;
  }

  export interface AdditionalPatterns {}

  export interface Distro {
    prettyName: string;
    name: string;
    id: string;
    versionID: string;
    homeURL: string;
    bugReportURL: string;
  }

  export interface SbomJSONFile {
    id: string;
    location: Location;
  }

  export interface Schema {
    version: string;
    url: string;
  }

  export interface Source {
    id: string;
    type: string;
    target: Target;
  }

  export interface Target {
    userInput: string;
    imageID: string;
    manifestDigest: string;
    mediaType: string;
    tags: string[];
    imageSize: number;
    layers: Layer[];
    manifest: string;
    config: string;
    repoDigests: string[];
    architecture: string;
    os: string;
  }

  export interface Layer {
    mediaType: string;
    digest: string;
    size: number;
  }
}
