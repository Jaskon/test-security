import { ExtraInfo } from "../issuesTypes";

export class IacValidatorTypesRequest {
  uid: string;
  analysisUid: string;
  orgId: string;
  category: string;
  ruleId: string;
  snippet: string;
  fileName: string;
  pkgName: string;
  installedVersion: string;
  fixedVersion: string;
  toolName: string;
}

export class IacValidatorTypesResponse {
  uid: string;
  ruleId: string;
  snippet: string;
  processed: boolean;
  success: boolean;
  fieldName: string;
  deployments: Deployment[];
  extraInfo: ExtraInfo[];
}

export class Deployment {
  valid: boolean;
  variableValue: string;
}
