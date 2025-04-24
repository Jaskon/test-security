import { GoogleLicenseInsight, Sbom, SbomComponent } from "../../entitis/artifactoryTypes";
import { ExtraInfo } from "../../entitis/issuesTypes";
import { BlameResponse } from "../../entitis/service/blameTypes";
import { ScaValidatorTypesResponse } from "../../entitis/service/scaValidatorTypes";
import loggerImport from "../../logger";
import { Edge, Node } from "../graphHelper";
import { SbomLicenseExpressionHelper, ValidatedLicenseExpression } from "./sbomLicenseExpressionHelper";

const logger = loggerImport.getDebugLogger();
const uuid = require("uuid");
const path = require("path");
const skipFiles = require("../../policy/org/config/dependencyFiles.json");

export interface ExtendedSbomComponent extends SbomComponent {
  validatedLicenseExpressions: ValidatedLicenseExpression[];
  uid: null;

  //Not save in DB
  fileName: string;
  filePath: string;
  blame: BlameResponse;
  scaValidator: ScaValidatorTypesResponse;
  additionalInsight: GoogleLicenseInsight;
  extraInfo?: ExtraInfo[];
  pkgManager: string;

  licenseIssue: boolean;
  notPopular: boolean;
  notImported: boolean;
  isDeprecated: boolean;
  notUpdated?: boolean;

  dependencyGraphNodes?: Node[];
  dependencyGraphEdges?: Edge[];

  triggerPackage?: string;

  vulnerabilityCounts?: Record<string, number>;
  vulnerabilityCountsArr?: VulnerabilityCount[];

  layerId?: string;
  askedOnce: boolean;
  isOldEvent: boolean;
}

export interface VulnerabilityCount {
  severity: string;
  count: number;
}
export enum SbomPackageInfo {
  NotPopular = "Not Popular",
  NotUsed = "Not Used",
  NotUpdated = "Not Updated",
  NotImported = "Not Imported",
  NotMaintained = "Not Maintained",
  UnapprovedLicense = "Unapproved License",
  Deprecated = "Deprecated",
  HasVulnerabilities = "Has Vulnerabilities",
}
export interface ExtendedSbom extends Sbom {
  components: ExtendedSbomComponent[];
}

export class SbomHelper {
  extendedSbom: ExtendedSbom;

  constructor(sbom: Sbom) {
    if (sbom == null) {
      return;
    }
    try {
      this.extendedSbom = toExtendedSbom(sbom);

      const newComponents = [];
      const skipFilesSbom = Object.values(skipFiles.languages).flat() as any;

      this.extendedSbom.components.forEach(i => {
        const fileName = path.basename(i.name);
        i.version = cleanVer(i.version, "");
        if (skipFilesSbom.find(j => j === fileName) == undefined) {
          newComponents.push(i);
        }
      });

      this.extendedSbom.components = newComponents;
    } catch (err) {
      logger.error(`failed to set extended sbom, err: ${err}`, err);
    }
  }
}

export function getPkgName(sbomCom: ExtendedSbomComponent) {
  try {
    if (!sbomCom.properties) {
      return "";
    }
    const prop = sbomCom.properties.find(i => i.name.toLowerCase().includes("srcname"));
    if (prop) {
      return prop.value;
    }
  } catch (err) {
    logger.error(`failed to get pkg name: ${JSON.stringify(sbomCom.properties)}, err: ${err}`, err);
  }
  return "";
}

export function toExtendedSbom(sbom: Sbom): ExtendedSbom {
  return {
    ...sbom,
    components: sbom.components.map(c => ({
      licenseIssue: false,
      notPopular: false,
      filePath: undefined,
      notImported: false,
      askedOnce: false,
      isDeprecated: false,
      ...c,
      licenses: c.licenses ?? [],
      additionalInsight: new GoogleLicenseInsight(),
      validatedLicenseExpressions: (c.licenses ?? []).map(l => l.expression).map(SbomLicenseExpressionHelper.toValidatedExpression),
      uid: uuid.v4(),
      blame: new BlameResponse(),
      scaValidator: new ScaValidatorTypesResponse(),
      fileName: undefined,
      pkgManager: getPkgManager(c),
      layerId: getLayerId(c),
      isOldEvent: false,
    })),
  };
}

export function getLayerId(sbomComponent: SbomComponent) {
  try {
    if (sbomComponent.type !== "library") {
      return "";
    }
    const r = sbomComponent.properties.find(i => i.name.includes("LayerDiffID"));
    if (r) {
      r.value;
    }
  } catch (err) {
    logger.error(`failed to get layer for lib name: ${sbomComponent.name} version: ${sbomComponent.version}, err: ${err}`, err);
  }
}

export function getPkgManager(sbomComponent: SbomComponent) {
  try {
    if (sbomComponent.type !== "library") {
      return "";
    }
    return extractPkgManagerFromPurl(sbomComponent.purl);
  } catch (err) {
    logger.error(`failed to get pkg manager for lib name: ${sbomComponent.name} version: ${sbomComponent.version}, err: ${err}`, err);
  }
  return "";
}

export function extractPkgManagerFromPurl(purl: string): string {
  const pkgIndex = purl.indexOf(":") + 1;
  const pkgEndIndex = purl.indexOf("/");
  return purl.substring(pkgIndex, pkgEndIndex);
}

export function cleanVer(installedVer: string, repoName: string) {
  try {
    if (!installedVer) {
      return installedVer;
    }

    let res = installedVer;
    const index = installedVer.indexOf("_");
    if (index != -1) {
      res = installedVer.substring(0, index);
    }
    if (installedVer.includes("=")) {
      res = res.replace("=", "");
    }
    if (installedVer.includes(">")) {
      res = res.replace(">", "");
    }
    if (installedVer.includes("<")) {
      res = res.replace("<", "");
    }
    return res.trim();
  } catch (err) {
    logger.error(`failed clean trivy ver installedVer: ${installedVer}, repoName: ${repoName} err: ${err}`, err);
  }
  return installedVer;
}
