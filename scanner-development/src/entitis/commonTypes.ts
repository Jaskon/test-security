export type Nullable<T> = T | null;

export interface Dictionary<T> {
  [Key: string]: T;
}

export enum ServerEnvironmentType {
  Local = "local-development",
  OnPrem = "on-prem",
  Development = "development",
  Beta = "beta",
  Staging = "staging",
  Production = "production",
  Testing = "testing",
}

export enum ScanStatus {
  Failed = "failed",
  Succeeded = "succeeded",
  TimedOut = "timedOut",
}

export function isJson(str) {
  try {
    JSON.parse(str);
  } catch (e) {
    return false;
  }
  return true;
}
