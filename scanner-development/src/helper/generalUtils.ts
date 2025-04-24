import * as fs from "fs";
import dependencyFiles from "../policy/org/config/dependencyFiles.json";

import path from "path";
import loggerImport from "../logger";
import { capitalizeFirstLetter } from "./commonUtils";
const logger = loggerImport.getDebugLogger();

const fileToDevLan = {};
let setFileToDevLan = false;

export async function delay(ms) {
  return new Promise(res => setTimeout(res, ms));
}

export function replaceAll(str, find, replace) {
  try {
    return str.replace(new RegExp(find, "g"), replace);
  } catch (err) {
    //error
  }
  return str;
}

export async function probeFile(file: string) {
  for (let i = 0; i < 10; i++) {
    if (fs.existsSync(file)) {
      if (i !== 0) await delay(1000 * 5);
      return file;
    }

    await delay(1000 * 5);
  }

  return file;
}

export function getDevLanBasedOnFileName(devLan: string, fileName: string) {
  let fileNameOnly;
  try {
    fileNameOnly = path.basename(fileName).toLowerCase();
    if (!setFileToDevLan) {
      for (const [key, val] of Object.entries(dependencyFiles.languages)) {
        const arr = val as any as string[];
        arr.forEach(i => {
          if (fileToDevLan[i.toLowerCase()]) {
            return;
          }
          fileToDevLan[i.toLowerCase()] = key;
        });
      }
      setFileToDevLan = true;
    }
    if (fileToDevLan[fileNameOnly]) {
      const res = fileToDevLan[fileNameOnly];
      return capitalizeFirstLetter(res);
    }
  } catch (err) {
    logger.error(`failed getDevLanBasedOnFileName err: ${err}, file name only: ${fileNameOnly}, devLan: ${devLan}`);
  }
  return devLan;
}

export function getSharedFolder(uuid: string): string {
  const sharedDir = process.env.OX_SHARED_DATA === "undefined" ? "/var/shared-data" : process.env.OX_SHARED_DATA;

  return sharedDir + "/" + uuid;
}

export function formatSizeUnits(bytes: number) {
  if (!bytes) return "unknown";

  let output = "unknown";
  if (bytes >= 1073741824) {
    output = (bytes / 1073741824).toFixed(2) + " GB";
  } else if (bytes >= 1048576) {
    output = (bytes / 1048576).toFixed(2) + " MB";
  } else if (bytes >= 1024) {
    output = (bytes / 1024).toFixed(2) + " KB";
  } else if (bytes > 1) {
    output = bytes + " bytes";
  } else if (bytes == 1) {
    output = bytes + " byte";
  } else {
    output = "0 bytes";
  }

  return output;
}
