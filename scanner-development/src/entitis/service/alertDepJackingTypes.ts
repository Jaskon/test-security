export class AlertDepJackingRequest {
  dependencyGraphInfo: any;
  depJackingFiles: DepJackingFileInfo[] = [];
}

export class DepJackingFileInfo {
  type: string;
  filepath: string;
  content: string;
}

export class Typosquatted {
  pkgName: string;
  installedVersion: string;
  legitimatePkgName: string;
  isJacked: boolean;
  similarityScore: number;
  registry: string;
  fileName: string;
  legitimatePkgLink: string;
}

export class DepConfusionScopes {
  orgScopeId: string;
  privateRegistryName: string;
  privateRegistryUrl: string;
  isOrgScopeAvailable: boolean;
  publicRegistry: string;
  scopeRegisteredBy: string[];
  filePath: string;
  type: string;
}

export class DepConfusionPkgs {
  packageNameId: string;
  packageVersion: string;
  privateRegistryName: string;
  privateRegistryUrl: string;
  isPkgAvailable: boolean;
  publicRegistry: string;
  pkgRegisteredBy: string[];
  language: string;
  filePath: string;
  lineNumDetected: number;
  type: string;
}

export class AlertDepJackingResponse {
  typosquatted: Typosquatted[];
  depConfusionScopes: DepConfusionScopes[];
  depConfusionPkgs: DepConfusionPkgs[];
  isSuccessful: boolean;
}

export class AlertDepConfusionResponse {}
