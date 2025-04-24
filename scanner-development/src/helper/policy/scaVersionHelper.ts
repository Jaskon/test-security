import { SecurityEvent } from "../../entitis/codeRepoTypes";
import loggerImport from "../../logger";

const logger = loggerImport.getDebugLogger();
const semver = require("semver");

export function getLatestVer(versionsInfo: string[]) {
  try {
    if (versionsInfo.length == 0) {
      return;
    }

    let semverFormat = versionsInfo.map(i => {
      const newItem = semver.coerce(i, { rtl: true, loose: true });
      if (newItem == null) {
        //Debug
        //logger.warn(`failed find fixed transform sca fixed version: ${i} to semver format`);
      } else {
        newItem.realRaw = i;
      }
      return newItem;
    });

    semverFormat = semverFormat.filter(i => i != null);
    const forCompare = semverFormat.map(i => i.version);

    const res = semver.maxSatisfying(forCompare, "*", {
      loose: true,
      includePrerelease: true,
    });

    if (res != null) {
      const r = semverFormat.find(i => i.version === res);
      return r.realRaw;
    }
  } catch (e) {
    logger.error(`failed find fixed get latest ver. err: ${e}, versions: ${versionsInfo.join(", ")}`);
  }
  return versionsInfo[0]; //Return any version
}

export function splitVersions(version: string) {
  if (!version) {
    return [];
  }

  const versions = version.split(",");
  let cleaned = versions.map(i => {
    const j = i.replace(/[^a-zA-Z0-9.]/g, "");
    return j;
  });
  return cleaned;
}

export function getFixVersionsFromSecEvent(securityEvent: SecurityEvent, allAlerts: SecurityEvent[], ignoreMinorMajorVer: boolean = false) {
  const installedVersion = securityEvent.installedVersion.trim();
  const currentVerFirstNum = Array.from(installedVersion)[0];
  const minorVersions = [];
  const majorVersions = [];
  const uniqueFixVerMinor = new Set();
  const uniqueFixVerMajor = new Set();
  let itemsCount = 0;

  allAlerts.forEach(i => {
    try {
      const fixedVersions = splitVersions(i.fixedVersion);
      if (fixedVersions.length > 0) {
        itemsCount++;
      }
      fixedVersions.forEach(fixedVer => {
        const firstNum = Array.from(fixedVer)[0];
        if (currentVerFirstNum === firstNum) {
          minorVersions.push(fixedVer);
          uniqueFixVerMinor.add(i.uid);
        } else {
          majorVersions.push(fixedVer);
          uniqueFixVerMajor.add(i.uid);
        }
      });
    } catch (err) {
      logger.error(`failed split versions. err: ${err}}`);
    }
  });

  if (ignoreMinorMajorVer) {
    const fixVer = getLatestVer([...minorVersions, ...majorVersions]);
    const isMajor = majorVersions.find(i => i === fixVer);
    return {
      fixVer: fixVer,
      isMajor: isMajor != undefined ? true : false,
      numberIssuesFixed: itemsCount,
    };
  } else {
    const fixedMinorVer = getLatestVer(minorVersions);
    const fixedMajorVer = getLatestVer(majorVersions);

    return {
      fixedMinorVer: fixedMinorVer,
      fixedMajorVer: fixedMajorVer,
      uniqueFixVerMinorCount: uniqueFixVerMinor.size,
      uniqueFixVerMajorCount: uniqueFixVerMajor.size,
    };
  }
}
