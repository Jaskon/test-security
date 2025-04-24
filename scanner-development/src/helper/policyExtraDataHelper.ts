const fs = require("fs");
import { CweObject } from "../entitis/codeRepoTypes";
import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

import cweMapping from "../policy/org/config/cwe.json";
import { getOscarMatrix, getOscarTechnique } from "@oxsecurity/oscar";

export class OscarInfo {
  name: string;
  description: string;
  url: string;
  id: string;
}

export function getInfoBasedOnCWE(cweId: string) {
  try {
    if (cweMapping.hasOwnProperty(cweId)) {
      const cweInfo: CweObject = cweMapping[cweId];
      return cweInfo;
    }
  } catch (err) {
    logger.error(`failed get info based on cwe, cweId: ${cweId}, err: ${err}`);
  }
}

export function getInfoBasedOnOscar(oscarId: string) {
  try {
    const cweInfo: OscarInfo = getOscarTechnique(oscarId);
    if (!cweInfo) {
      return;
    }
    return cweInfo;
  } catch (err) {
    logger.error(`failed get info based on oscar, oscarId: ${oscarId}, err: ${err}`);
  }
}
