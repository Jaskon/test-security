export class AlertRecommendationRequest {
  uid: string;
  analysisUid: string;
  orgId: string;
  category: string;
  ruleId: string;
  match: string;
  snippet: string;
  fileName: string;
  pkgName: string;
  pkgManager: string;
  installedVersion: string;
  triggerPkgName: string;
  triggerPkgVersion: string;
  fixedVersion: string;
  languageName: string;
  languageVersion: string;
  directCount: number;
  layer: string;
  indirectCount: number;
  devCount: number;
  pkgImported: boolean;
  lockfile: string;
  groupId: string;
  type: string;
  baseDigest?: string;
  baseRepoName?: string;
  baseTags?: Array<{ name: string; current: boolean }>;
  severityCounts?: any;
  baseOsName?: string;
  baseOsVersion?: string;
  toolsName = new Set<string>();
}

export class AlertRecommendationResponse {
  uid: string;
  ruleId: string;
  success: boolean = false;
  processed: boolean = false;
  autofixable: boolean = false;
  fixable: boolean = false;
  triggerPkgName: string;
  triggerPkgVersion: string;
  recommendation: string;
  upgradeVersion: string = "";
  ScaFixType: ScaFixType;
}

export enum ScaFixType {
  MAJOR = "MAJOR",
  MINOR = "MINOR",
  PATCH = "PATCH",
  UNKNOWN = "UNKNOWN",
  UNAVAILABLE = "UNAVAILABLE",
}
