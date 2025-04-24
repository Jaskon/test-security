import { Dependency } from "../codeRepoTypes";

export class DependencyChain {
  name: string;
  version?: string;
  imports?: Match[];
  pkgImported?: boolean;
  pkgUsage: Match[];
}

export class ScaValidatorTypesRequest {
  dependencyChain: Dependency[] = [];
  uid: string;
  pkgName: string;
  cve: string[] = [];
  language: string;
  fileName: string;
  toolsName = new Set<string>();
}

export class Match {
  fileName: string;
  snippet: string;
  line: number;
  endLine: number; // to remove?
}

export class ScaValidatorTypesResponse {
  pkgName: string;
  pkgImported: boolean;
  dependencyChain: DependencyChain[];
  success: boolean;
  uid: string;
  pkgUsed: boolean;
  vulnerableFunctionUsed: boolean;
  vulnerableComponentUsed: boolean;
  vulnerableComponentAnalyzed: boolean;
  cveApplicability: CveApplicability[];
  wasPkgChecked: boolean;
  specialCase: boolean;
}

export class CveApplicability {
  cve: string;
  vulnerableFunction: string;
  vulnerableFunctionUsed: boolean;
  vulnerableComponentUsed: boolean;
  vulnerableComponentAnalyzed: boolean;
  isPreconditionMet: boolean;
  explanation: string;
  usage: Match[];
}
