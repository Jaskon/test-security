import { AlertSeverity, CweObject, SecurityEvent } from "../../entitis/codeRepoTypes";
import loggerImport from "../../logger";
import { getInfoBasedOnCWE } from "../policyExtraDataHelper";
import { getFixVersionsFromSecEvent } from "./scaVersionHelper";

const logger = loggerImport.getDebugLogger();

export class SCAVulnerability {
  libName: string;
  libVersion: string;
  chainDepth: string;
  cwe: CweObject[] = [];
  cve: string;
  cveLink: string;
  cvsVer: string;
  dependencyChain: string;
  exploitInTheWild: boolean = false;
  exploitInTheWildLink: string;
  description: string;
  dateDiscovered: string;
  minorVerWithFix: string;
  majorVerWithFix: string;
  exploitRequirement: string;
  originalSeverity: string;
  linkToExternalProduct: string;
  exploitCode: string;
  originalSeverityNumber: number;
  alert: SecurityEvent;
  dependencyType: string;
}

export function getScaVul(allSecEvents: SecurityEvent[], repoName: string) {
  const directPkg: SecurityEvent[] = [];
  const noneDirectPkg: SecurityEvent[] = [];
  let doesPkgImportedChecked = false;

  allSecEvents.forEach(i => {
    if (i?.scaValidatorTypesResponse?.pkgImported == undefined) {
      noneDirectPkg.push(i);
    } else {
      doesPkgImportedChecked = true;
      if (i?.scaValidatorTypesResponse?.pkgImported == false) {
        noneDirectPkg.push(i);
      } else {
        directPkg.push(i);
      }
    }
  });

  const directSCAVulnerability = getSCAVulnerabilityList(directPkg, repoName);
  const noneDirectSCAVulnerability = getSCAVulnerabilityList(noneDirectPkg, repoName);

  return { directSCAVulnerability, noneDirectSCAVulnerability, doesPkgImportedChecked };
}

function getSCAVulnerabilityList(allSecAlerts: SecurityEvent[], repoName: string) {
  try {
    const list: SCAVulnerability[] = [];
    const unique = new Set();

    let missingCve = 0;
    let duplicate = 0;

    allSecAlerts.forEach(i => {
      try {
        const uniqueCVS = new Set();
        if (i?.blame?.cve) {
          uniqueCVS.add(i.blame.cve);
        }

        i.cves.forEach(c => {
          uniqueCVS.add(c);
        });

        const cvsToReport = new Set();
        if (uniqueCVS.size > 0) {
          for (const c of uniqueCVS) {
            const key = `${i.pkgName}@${i.installedVersion}:${c}`;
            if (unique.has(key)) {
              duplicate++;
            } else {
              unique.add(key);
              cvsToReport.add(c);
            }
          }
        } else {
          missingCve++;
          cvsToReport.add("N/A");
        }

        for (const cve of Array.from(cvsToReport)) {
          const c: SCAVulnerability = new SCAVulnerability();
          c.description = i.blame.cveDescription;
          c.cve = cve as any;
          c.alert = i;
          c.cveLink = i.moreInfoLink;

          if (!c.cveLink) {
            if (c.cve.toLowerCase().startsWith("cve")) {
              c.cveLink = `https://nvd.nist.gov/vuln/detail/${cve}`;
            }
            if (c.cve.toLowerCase().startsWith("ghsa")) {
              c.cveLink = `https://github.com/advisories/${cve}`;
            }
          }

          c.originalSeverity = i.originalSeverityStr;
          c.linkToExternalProduct = i.linkToExternalProduct;
          c.originalSeverityNumber = i.originalSeverity;

          if (i.blame.cvssScore) {
            if (i.blame.cvssScore === 10) {
              if (i.severity === AlertSeverity.Critical || i.severity === AlertSeverity.Appoxalypse) {
                //do nothing
              }
              if (i.severity === AlertSeverity.High) {
                i.blame.cvssScore = 9;
              }
              if (i.severity === AlertSeverity.Medium) {
                i.blame.cvssScore = 7;
              }
              if (i.severity === AlertSeverity.Low) {
                i.blame.cvssScore = 5;
              }
              if (i.severity === AlertSeverity.Info) {
                i.blame.cvssScore = 3;
              }
            }
          }
          c.cvsVer = i.blame.cvssScore ? i.blame.cvssScore.toString() : null;

          const uniqueCwe = new Set();

          for (const info of i.blame.cweList) {
            try {
              const cweE: CweObject = new CweObject();
              cweE.description = "";
              cweE.url = info.url || "";
              cweE.name = info.name || "";
              cweE.shortName = info.name || "";
              if (!cweE.name) {
                continue;
              }

              const index = info.name.indexOf(":");
              if (index != -1) {
                cweE.shortName = info.name.substring(0, index);
              } else {
                cweE.shortName = info.name;
              }

              if (uniqueCwe.has(cweE.shortName)) {
                continue;
              }

              c.cwe.push(cweE);
              uniqueCwe.add(cweE.shortName);
            } catch (err) {
              logger.error(`failed get CWE new list, err: ${err}, item: ${JSON.stringify(i)}`);
            }
          }

          if (i.cweList && Array.isArray(i.cweList)) {
            try {
              for (const cwe of i.cweList) {
                if (uniqueCwe.has(cwe)) {
                  continue;
                }
                let cweInfo = getInfoBasedOnCWE(cwe);
                if (!cweInfo) {
                  continue;
                }

                const item: CweObject = new CweObject();
                item.name = cweInfo.name;
                item.shortName = cweInfo.name;
                item.description = cweInfo.description || "";
                item.url = cweInfo.url || "";
                c.cwe.push(item);
              }
            } catch (error) {
              logger.error(
                `getSCAVulnerabilityList failed get CWE list from i.cweList, cweList: ${JSON.stringify(i.cweList)}, err: ${error}`,
              );
            }
          }

          c.exploitInTheWild = i.blame.hasPublicExploit == true;
          c.exploitInTheWildLink = i.blame.publicExploitLink;
          if (c.exploitInTheWild && !i.blame.publicExploitLink) {
            c.exploitInTheWildLink = "lnk";
          }

          c.libName = adjustTitle(i.pkgName);
          c.libVersion = i.installedVersion;
          c.chainDepth = (
            i.blame.dependencyChain && i.blame.dependencyChain.length > 0 ? i.blame.dependencyChain.length - 1 : 0
          ).toString();
          c.dependencyChain = i.blame.dependencyChain.map(u => u.name).join(" -> ");
          c.dateDiscovered = i.blame.publishedExploitDate;
          try {
            if (c.dateDiscovered) {
              c.dateDiscovered = new Date(c.dateDiscovered).toDateString();
            }
          } catch (err) {}
          c.exploitRequirement;
          if (i.blame.attackVector) {
            c.exploitCode = i.blame.attackVector;
            if (i.blame.attackVector == "NETWORK") {
              c.exploitRequirement = "Network access required to system with installed dependency";
            } else if (i.blame.attackVector == "LOCAL") {
              c.exploitRequirement = "Local user access required on system with installed dependency";
            }
          }

          const fix = getFixVersionsFromSecEvent(i, [i]);
          c.majorVerWithFix = fix.fixedMajorVer ? fix.fixedMajorVer : "Not Available";
          c.minorVerWithFix = fix.fixedMinorVer ? fix.fixedMinorVer : "Not Available";

          if (!c.majorVerWithFix && !c.minorVerWithFix) {
            c.majorVerWithFix = i.fixedVersion ? i.fixedVersion : "Not Available";
          }

          list.push(c);
        }
      } catch (err) {
        logger.error(`failed get single getSCAVulnerabilityList list, stack: ${err.stack}, alert: ${JSON.stringify(i)}`, err);
      }
    });

    try {
      const sorted = list.sort(function (a, b) {
        if (a.originalSeverityNumber === b.originalSeverityNumber) {
          // Price is only important when cities are the same
          return Number(b.cvsVer) < Number(a.cvsVer) ? -1 : 1;
        }
        return b.originalSeverityNumber < a.originalSeverityNumber ? -1 : 1;
      });

      return sorted;
    } catch (err) {
      logger.error(`failed get single SCA Vulnerability sort list, repoName: ${repoName}, err:`, err);
    }

    return list;
  } catch (err) {
    logger.error(`failed get SCA Vulnerability list, repoName: ${repoName}. err: ${err}`);
  }
  return [];
}

export function adjustTitle(mainTitle: string) {
  try {
    if (mainTitle.startsWith("github.com/")) {
      mainTitle = mainTitle.replace("github.com/", "");
    }
    const index = mainTitle.indexOf(":");
    if (index != -1) {
      mainTitle = mainTitle.substring(index + 1, mainTitle.length);
    }
  } catch (err) {
    logger.error(`failed adjust title: ${mainTitle}, err: ${err}`);
  }
  return mainTitle;
}

export function getUniqueKeyBaseOnSCAlib(pkgName: string, installedVersion: string) {
  let key = `${pkgName}@${installedVersion}`;
  if (pkgName.includes(":")) {
    const index = pkgName.lastIndexOf(":");
    const pkgNameInfo = pkgName.substring(index + 1, key.length);
    key = `${pkgNameInfo}@${installedVersion}`;
  }
  return key;
}
