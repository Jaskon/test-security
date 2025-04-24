import { replaceAll } from "./generalUtils";

export class ShardFolderUtils {
  public static getBaseSharedFolderPath() {
    return process.env.OX_SHARED_DATA === "undefined" ? "/var/shared-data" : process.env.OX_SHARED_DATA;
  }

  public static getScanSharedFolderPath(orgId: string, scanId: string) {
    const sharedDir = ShardFolderUtils.getBaseSharedFolderPath();
    return `${sharedDir}/${orgId}/scan_${replaceAll(scanId, "-", "_")}`;
  }
}
