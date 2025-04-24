import { OxCategoriesIds } from "@oxappsec/ox-consolidated-categories";
import { ChangeReason, severityReasons } from "../package-index";
import { CloudGraphRes } from "./CloudGraphTypes";
import { DotNode } from "../helper/dotGraph";

export class AttackPathInputSecurityEvents {
  securityAlertType: string = "";
  uid: string = "";
  locations: AttackPathInputCodeLocation[] = [];
  filePath: string = "";
  fileName: string = "";
  startLineNumber: number = -1;
  endLineNumber: number = -1;
}

export class AttackPathInputCodeLocation {
  filePath: string = "";
  startLineNumber: number = -1;
  endLineNumber: number = -1;
}
export class AttackPathInputImageDetails {
  name: string;
  location: string;
  imageId: string;
  cloudEnv: string;
  region: string;
  imageTags: string[];
  imageDigestWithoutPrefix: string;
  repositoryName: string;
}

export class AttackPathJSON {
  callGraphInfo: string;
  cloudGraphInfo: CloudGraphRes[];
  api: string;
  vulnerabilities: AttackPathInputSecurityEvents[];
  repoPath: string;
  images: AttackPathInputImageDetails[];
}
export interface AttackPathhRes {
  dot: string;
  uid: string[];
  success: boolean;
  severityFactors: string;
  type: string;
}
export interface AttackGraph {
  scanId: string;
  type: string;
  issues: string[] | null;
  createdAt: Date;
  appId: string;
}

export interface ParsedAttackGraph {
  nodes?: DotNode<AttackPathNode>[];
  edges?: { v: string; w: string }[];
}

export type AttackGraphMongo = AttackGraph & { graph: ParsedAttackGraph };

export enum AttackPathInputCategoryName {
  secrets = OxCategoriesIds.SecretScan,
  sast = OxCategoriesIds.CodeSecurity,
  iac = OxCategoriesIds.IaC,
  sca = OxCategoriesIds.OpenSourceSecurity,
  container = OxCategoriesIds.ContainerSecurity,
  sbom = OxCategoriesIds.SBOM,
}

export interface AttackPathBaseNode extends Record<string, string> {
  node_type: string;
  severityFactors: string;
}

export interface AttackPathApiNode extends AttackPathBaseNode {
  endPoint: string;
  filepath: string;
  function: string;
  line: string;
  method: string;
}
export interface AttackPathFuncNode extends AttackPathBaseNode {}
export interface AttackPathImageNode extends AttackPathBaseNode {}
export interface AttackPathCloudNode extends AttackPathBaseNode {}

export interface AttackPathNode extends AttackPathApiNode, AttackPathFuncNode, AttackPathImageNode, AttackPathCloudNode {}
export class AttackPathSeverityFactor {
  name: string;
  severityReason: ChangeReason;
}

export const attackPathSeverityFactors: AttackPathSeverityFactor[] = [
  {
    name: "Reachable via API",
    severityReason: severityReasons.codeExposedByAPI,
  },
];
