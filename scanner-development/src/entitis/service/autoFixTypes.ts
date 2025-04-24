import { BaseDocument } from "@oxappsec/ox-cache-db/lib/src/cache-db/cache-db-types";
import { IndexDirection } from "mongodb";
import { Runtime } from "./blameTypes";

export class AutoFixRequest {
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
  issueId: string;
  branch: string;
  triggerPkgName: string;
  triggerPkgVersion: string;
  triggerPkgUpgradeVersion: string;
  originalFileHash: string;
  isLockFile: boolean;
  languageName: string;
  languageVersion: string;
}

export class AutoFixResponse {
  uid: string = "";
  autofixable: boolean = false;
  ruleId: string = "";
  success: boolean = false;
  processed: boolean = false;
  chatgpt_autofixable: boolean = false;
}

export const autoFixDeclaredIndexes: {
  index: [string, IndexDirection];
  unique: boolean;
}[] = [
  { index: ["id", 1], unique: true },
  { index: ["languageInfo", 1], unique: false },
  { index: ["osInfo", 1], unique: false },
];

export interface RunTimeBaseDoc extends Runtime, BaseDocument {
  id: string;
}
