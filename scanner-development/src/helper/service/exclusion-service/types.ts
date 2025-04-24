import { Match, OxExclusionMode, OxExclusionScope, OxExclusionType } from "@oxappsec/ox-consolidated-exclusions";

export interface GetAlertExclusionsByMode {
  getAlertExclusionsByMode: {
    exclusions: ExclusionFromDB[];
  };
}

export interface ExclusionFromDB {
  exclusionType: OxExclusionType;
  exclusionId: string;
  modifiedBy: string;
  modifiedIssues: number;
  issueId: string;
  issueName: string;
  appId: string;
  appName: string;
  policyId: string;
  policyName: string;
  policyCategory: string;
  appType: string;
  match: Match[];
  exclusionScope: OxExclusionScope;
  exclusionMode: OxExclusionMode;
  isActive: boolean;
  comment?: string;
  expiredAt?: Date;
  oxIssueId?: string;
}

export interface GetAlertExclusionsByModeVariables {
  orgId: string;
  exclusionMode: OxExclusionMode;
}
