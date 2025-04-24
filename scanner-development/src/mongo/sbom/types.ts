import { IOxTag } from "@oxappsec/ox-consolidated-tags";
import { SbomCSVLib } from "../../entitis/artifactoryTypes";
import { ExtraInfo } from "../../entitis/issuesTypes";
import { LanguageInfo } from "../../entitis/service/blameTypes";
import { SCAVulnerability } from "../../helper/policy/scaVulHelper";
import { SbomPackageInfo, VulnerabilityCount } from "../../helper/sbom/sbomHelper";
import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();

export class ArtifactInSbomLib {
  image: string;
  imageLink: string;
  imageCreatedAt: string;
  sha: string;
  os: string;
  osVersion: string;
  baseImage: string;
  baseImageVersion: string;
  tag: string;
  layer: string;
  registryName: string;
}

export class SbomMongoDocument {
  //Pure sbom data
  libId: string;
  libraryName: string = "";
  libraryVersion: string = "";
  licenses: string[] = [];
  location: string = "";
  locationLink: string = "";
  appId: string = "";
  appType: string = "";
  requestId: string = "";
  appLink: string = "";
  source: string = "";
  libForSearch: string = "";
  pkgName: string = "";
  pkgManager?: string;
  pkgManagerLink?: string;
  latestVersion?: {
    version: string;
    publishedAt: string;
  };
  commit?: {
    commitedAt: string;
    committerName: string;
    committerEmail: string;
  };
  projectContributorsCount?: number;
  sbomCsv: SbomCSVLib = null;
  libLink: string = "";

  vulnerabilityCounts?: Record<string, number> = {};
  vulnerabilities: SCAVulnerability[];
  triggerPackage?: string;

  languageInfo: LanguageInfo;
  language?: string;
  codeReference: string;
  dependencyLevel?: number;

  //App
  scanId: string = "";
  appName: string = "";

  //Blame
  dependencyType: string = "";

  //Project data
  stars: number = -1;
  forks: number = -1;
  downloads: number = -1;
  isDeprecated: boolean = false;
  usedVersionReleaseDate: Date = null;
  copyWriteInfo: string[] = [];
  copyWriteInfoLink: string = "";

  //Policy res
  notPopular: boolean = null;
  notImported: boolean = null;
  licenseIssue: boolean = false;
  notUpdated?: boolean;

  //Artifact info
  baseImage: string = "";
  os: string = "";

  registryName?: string = "";
  imageName?: string = "";
  imageLocation?: string = "";

  artifactInSbomLibs: ArtifactInSbomLib[] = [];

  extraInfo?: ExtraInfo[];
  hasVulnerabilities?: boolean;
  vulnerabilityCountsArr?: VulnerabilityCount[];
  packageInfo?: SbomPackageInfo[];
  tags: IOxTag[];

  setSbomScv() {
    try {
      if (!this.libraryName) {
        return null;
      }

      const cp = this.copyWriteInfo && this.copyWriteInfo.length > 0 ? this.copyWriteInfo.map(c => c.replace(/\n|\r|,|'|"/g, " ")) : [];

      return {
        "Package Name": this.libraryName ? this.libraryName : "N/A",
        "Library Name": this.libraryName ? this.libraryName : "N/A",
        Version: this.libraryVersion ? this.libraryVersion : "N/A",
        License: this.licenses && this.licenses.length ? this.licenses.join("| ") : "N/A",
        "License Link": this.copyWriteInfoLink ? this.copyWriteInfoLink : "N/A",
        Copyright: cp && cp.length > 0 ? cp.join("| ") : "N/A",
        "App Name": this.appName ? this.appName : "N/A",
        Dependency: this.dependencyType ? this.dependencyType : "N/A",
        Location: this.location ? this.location : "N/A",
        "Location Link": this.locationLink ? this.locationLink : "N/A",
        Source: this.source ? this.source : "N/A",
      } as SbomCSVLib;
    } catch (err) {
      logger.error(`failed set single sbom lib: ${JSON.stringify(this)}`);
    }
  }
}

export enum DependencyType {
  Unknown = "unknown",
  Direct = "direct",
  Indirect = "indirect",
  Development = "development",
}
