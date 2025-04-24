import mongoose from "mongoose";
import { ExtraInfo } from "../../../entitis/issuesTypes";
import { LanguageInfo } from "../../../entitis/service/blameTypes";
import { VulnerabilityCount } from "../../../helper/sbom/sbomHelper";
import { ScaVulnerabilitySchema, TagSchema } from "../../schemas";
import { ArtifactInSbomLib, SbomMongoDocument } from "../types";

export const SbomSchema = new mongoose.Schema<SbomMongoDocument>(
  {
    libId: { type: String },
    libraryName: { type: String },
    libraryVersion: { type: String },
    requestId: { type: String },
    libForSearch: { type: String },
    locationLink: { type: String },
    libLink: { type: String },
    appType: { type: String },
    pkgName: { type: String },
    appLink: { type: String },
    appId: { type: String },
    location: { type: String },
    source: { type: String },
    licenses: [{ type: String }],
    copyWriteInfo: [{ type: String }],
    copyWriteInfoLink: { type: String },
    languageInfo: {
      type: new mongoose.Schema<LanguageInfo>({
        version: { type: String },
        name: { type: String },
      }),
    },
    artifactInSbomLibs: [
      {
        type: new mongoose.Schema<ArtifactInSbomLib>({
          image: { type: String },
          imageLink: { type: String },
          imageCreatedAt: { type: String },
          sha: { type: String },
          os: { type: String },
          osVersion: { type: String },
          baseImage: { type: String },
          baseImageVersion: { type: String },
          tag: { type: String },
          layer: { type: String },
          registryName: { type: String },
        }),
      },
    ],
    baseImage: { type: String },
    os: { type: String },
    language: { type: String },
    scanId: { type: String },
    appName: { type: String },
    dependencyType: { type: String },
    registryName: { type: String },
    imageName: { type: String },
    imageLocation: { type: String },
    downloads: { type: Number },
    forks: { type: Number },
    stars: { type: Number },
    isDeprecated: { type: Boolean },
    usedVersionReleaseDate: { type: Date },
    notPopular: { type: Boolean },
    notImported: { type: Boolean },
    licenseIssue: { type: Boolean },
    notUpdated: { type: Boolean },
    hasVulnerabilities: { type: Boolean },
    vulnerabilityCounts: { type: Map },
    vulnerabilityCountsArr: [
      {
        type: new mongoose.Schema<VulnerabilityCount>({
          severity: { type: String },
          count: { type: Number },
        }),
      },
    ],
    vulnerabilities: [{ type: ScaVulnerabilitySchema }],
    triggerPackage: { type: String },
    pkgManager: { type: String },
    pkgManagerLink: { type: String },
    extraInfo: [{ type: new mongoose.Schema<ExtraInfo>({ key: { type: String }, value: { type: String } }) }],
    latestVersion: {
      version: { type: String },
      publishedAt: { type: String },
    },
    commit: {
      commitedAt: { type: String },
      committerName: { type: String },
      committerEmail: { type: String },
    },
    projectContributorsCount: { type: Number },
    codeReference: { type: String },
    dependencyLevel: { type: Number },
    packageInfo: [{ type: String }],
    tags: [{ type: TagSchema }],
  },
  { timestamps: true },
);

SbomSchema.index({ scanId: 1, appId: 1, libId: 1 });
SbomSchema.index({ appId: 1 });
