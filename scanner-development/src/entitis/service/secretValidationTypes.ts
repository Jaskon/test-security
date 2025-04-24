import { ExtraInfo } from "../issuesTypes";

export class SecretValidationRequest {
  uid: string;
  ruleId: string;
  snippet: string;
  toolName: string;
}

export class SecretValidationResponse {
  uid: string;
  ruleId: string;
  snippet: string;
  valid: boolean;
  processed: boolean;
  success: boolean;
  extraInfo: ExtraInfo[];
  toolName: string;
}
