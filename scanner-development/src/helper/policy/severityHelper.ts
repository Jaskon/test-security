import { ImageInfo } from "../../entitis/artifactoryTypes";
import { CloudSecurityEvent } from "../../entitis/cloudTypes";
import { AlertSeverity, getUniqueInfoForCloudAggregation, SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { ExtraInfo, Issue } from "../../entitis/issuesTypes";
import { Severity } from "../../entitis/reportTypes";
import { ChangeReason, SeverityChange, severityReasons } from "../../entitis/service/blameTypes";
import loggerImport from "../../logger";
import { Application, ScanSummaryHistory, severityConst } from "../../policy/reporting/types";
import RulesParser from "../../policy/rules/rulesParser";
import { isInt } from "../commonUtils";
import { isDevelopment, isLocalDevelopment } from "../envUtils";
import { Policy } from "../service/policy-service/types";
import StatesHelper from "../statesHelper";
const logger = loggerImport.getDebugLogger();

export function getSeverityChanges(originalSeverity: AlertSeverity, newSeverity: AlertSeverity) {
  try {
    if (originalSeverity === newSeverity) return SeverityChange.Unchanged;
    if (originalSeverity > newSeverity) return SeverityChange.Decreased;
    if (originalSeverity < newSeverity) return SeverityChange.Increased;
  } catch (err) {
    logger.error(`failed get severity change for originalSeverity: ${originalSeverity}, newSeverity: ${newSeverity}, err: ${err}`);
  }
  SeverityChange.NotApplicable;
}

export function getAllInfoForSeverity(alerts: SecurityEvent[], repoName: string) {
  try {
    const uniqueSeverityReasons = getUniqueSeverityReasons(alerts, repoName);
    const res = getOriginalSeverityAndNewBaseOnSeverityReasons(uniqueSeverityReasons, alerts, repoName);
    return res;
  } catch (err) {
    logger.error(`failed getAllInfoForSeverity for repo: ${repoName}, err: ${err}`);
  }
}

export function getCloudSecAllInfoForSeverity(alerts: CloudSecurityEvent[], repoName: string) {
  try {
    const uniqueSeverityReasons = getUniqueCloudSeverityReasons(alerts, repoName);
    const res = getCloudSecvOriginalSeverityAndNewBaseOnSeverityReasons(uniqueSeverityReasons, alerts, repoName);
    return res;
  } catch (err) {
    logger.error(`failed getCloudSecAllInfoForSeverity for repo: ${repoName}, err: ${err}`);
  }
}

export function getOriginalSeverityAndNewBaseOnSeverityReasons(
  uniqueSeverityFromAllAlerts: ChangeReason[],
  alerts: SecurityEvent[],
  repoName: string,
) {
  try {
    const isInfoOrAppox = alerts.find(i => i.originalSeverity === AlertSeverity.Appoxalypse || i.originalSeverity === AlertSeverity.Info);
    //Dont handle if original severity is appox or info
    if (isInfoOrAppox) {
      return {
        originalSeverity: isInfoOrAppox.originalSeverity,
        originalSeverityStr: isInfoOrAppox.originalSeverityStr,
        newSeverityForPolicy: isInfoOrAppox.originalSeverity,
        newSeverityForPolicyStr: isInfoOrAppox.originalSeverityStr,
        uniqueSeverityFromAllAlerts: uniqueSeverityFromAllAlerts,
      };
    }

    const sortedBySeverity: SecurityEvent[] = alerts.sort((a, b) => Number(b.originalSeverity) - Number(a.originalSeverity));

    //Take the highest one
    let originalSeverity = sortedBySeverity[0].originalSeverity;
    let originalSeverityStr = sortedBySeverity[0].originalSeverityStr;
    //Calc new severity
    let newSeverityForPolicy;
    let newSeverityForPolicyStr;

    let recalcSeverity = originalSeverity;

    uniqueSeverityFromAllAlerts.forEach(s => {
      if (isInt(s.changeNumber)) {
        recalcSeverity += s.changeNumber;
      }
    });

    //Due to severity changes this number at this point can be 2.xxx so we round it
    const newSeverity = Math.floor(recalcSeverity);
    if (newSeverity > AlertSeverity.Critical || newSeverity < AlertSeverity.Low) {
      //Critical
      if (newSeverity > AlertSeverity.Critical) {
        newSeverityForPolicyStr = AlertSeverity[AlertSeverity.Critical];
        newSeverityForPolicy = AlertSeverity.Critical;
      }
      //Info
      if (newSeverity < AlertSeverity.Low) {
        newSeverityForPolicyStr = AlertSeverity[AlertSeverity.Low];
        newSeverityForPolicy = AlertSeverity.Low;
      }
    } else {
      newSeverityForPolicyStr = AlertSeverity[newSeverity];
      newSeverityForPolicy = newSeverity;
    }

    return {
      originalSeverity: originalSeverity,
      originalSeverityStr: originalSeverityStr,
      newSeverityForPolicy: newSeverityForPolicy,
      newSeverityForPolicyStr: newSeverityForPolicyStr,
      uniqueSeverityFromAllAlerts: uniqueSeverityFromAllAlerts,
    };
  } catch (err) {
    logger.error(`failed getOriginalSeverityAndNewBaseOnSeverityReasons repo: ${repoName}, err: ${err}`);
  }
}

export function getCloudSecvOriginalSeverityAndNewBaseOnSeverityReasons(
  uniqueSeverityFromAllAlerts: ChangeReason[],
  alerts: CloudSecurityEvent[],
  repoName: string,
) {
  try {
    const isInfoOrAppox = alerts.find(i => i.originalSeverity === AlertSeverity.Appoxalypse || i.originalSeverity === AlertSeverity.Info);
    //Dont handle if original severity is appox or info
    if (isInfoOrAppox) {
      return {
        originalSeverity: isInfoOrAppox.originalSeverity,
        originalSeverityStr: isInfoOrAppox.originalSeverityStr,
        newSeverityForPolicy: isInfoOrAppox.originalSeverity,
        newSeverityForPolicyStr: isInfoOrAppox.originalSeverityStr,
        uniqueSeverityFromAllAlerts: uniqueSeverityFromAllAlerts,
      };
    }

    const sortedBySeverity: CloudSecurityEvent[] = alerts.sort((a, b) => Number(b.originalSeverity) - Number(a.originalSeverity));

    //Take the highest one
    let originalSeverity = sortedBySeverity[0].originalSeverity;
    let originalSeverityStr = sortedBySeverity[0].originalSeverityStr;
    //Calc new severity
    let newSeverityForPolicy;
    let newSeverityForPolicyStr;

    let recalcSeverity = originalSeverity;

    uniqueSeverityFromAllAlerts.forEach(s => {
      if (isInt(s.changeNumber)) {
        recalcSeverity += s.changeNumber;
      }
    });

    //Due to severity changes this number at this point can be 2.xxx so we round it
    const newSeverity = Math.floor(recalcSeverity);
    if (newSeverity > AlertSeverity.Critical || newSeverity < AlertSeverity.Low) {
      //Critical
      if (newSeverity > AlertSeverity.Critical) {
        newSeverityForPolicyStr = AlertSeverity[AlertSeverity.Critical];
        newSeverityForPolicy = AlertSeverity.Critical;
      }
      //Info
      if (newSeverity < AlertSeverity.Low) {
        newSeverityForPolicyStr = AlertSeverity[AlertSeverity.Low];
        newSeverityForPolicy = AlertSeverity.Low;
      }
    } else {
      newSeverityForPolicyStr = AlertSeverity[newSeverity];
      newSeverityForPolicy = newSeverity;
    }

    return {
      originalSeverity: originalSeverity,
      originalSeverityStr: originalSeverityStr,
      newSeverityForPolicy: newSeverityForPolicy,
      newSeverityForPolicyStr: newSeverityForPolicyStr,
      uniqueSeverityFromAllAlerts: uniqueSeverityFromAllAlerts,
    };
  } catch (err) {
    logger.error(`failed getCloudSecvOriginalSeverityAndNewBaseOnSeverityReasons repo: ${repoName}, err: ${err}`);
  }
}

export function getUniqueSeverityReasons(alerts: SecurityEvent[], repoName: string) {
  try {
    //Step 1 sent all unique
    const uniqueSeverityFromAllAlerts: ChangeReason[] = [];
    const unique = new Set();
    alerts.forEach(i => {
      if (i.severityChangedReason) {
        i.severityChangedReason.forEach(s => {
          if (!unique.has(s.shortName)) {
            uniqueSeverityFromAllAlerts.push(s);
            unique.add(s.shortName);
          }
        });
      }
    });

    //Step 2 add cvs score
    const cvssAlertsSorted: SecurityEvent[] = alerts.sort((a, b) => Number(b.blame.cvssScore) - Number(a.blame.cvssScore));
    let cvssReason: ChangeReason = null;
    if (cvssAlertsSorted[0]?.blame?.cvssScore) {
      if (cvssAlertsSorted[0].blame.cvssScore >= 9) {
        cvssReason = ChangeReason.copy(severityReasons.criticalCvssScore);
      } else if (cvssAlertsSorted[0].blame.cvssScore >= 7) {
        cvssReason = ChangeReason.copy(severityReasons.highCvssScore);
      } else if (cvssAlertsSorted[0].blame.cvssScore >= 4) {
        cvssReason = ChangeReason.copy(severityReasons.mediumCvssScore);
      } else if (cvssAlertsSorted[0].blame.cvssScore < 4) {
        cvssReason = ChangeReason.copy(severityReasons.lowCvssScore);
      }
      if (cvssReason) {
        uniqueSeverityFromAllAlerts.push(cvssReason);
      }
    }

    //Step 3 remove some severity reason
    let frequentPublicExploit = false;
    let frequentPublicExploitCVEs: string[] = alerts.filter(i => i.blame.frequentPublicExploit).map(i => i.blame.cve);

    let someSeenExploit = false;
    let someSeenExploitCVEs: string[] = alerts.filter(i => i.blame.someSeenExploit).map(i => i.blame.cve);

    if (frequentPublicExploitCVEs.length > 0) {
      frequentPublicExploit = true;
      const uniqueSet = new Set(frequentPublicExploitCVEs);
      frequentPublicExploitCVEs = Array.from(uniqueSet);
    }

    if (someSeenExploitCVEs.length > 0) {
      someSeenExploit = true;
      const uniqueSet = new Set(someSeenExploitCVEs);
      someSeenExploitCVEs = Array.from(uniqueSet);
    }

    let pkgImported = false;
    let pkgUsed = false;
    let isDevDependency = false;
    let activeSecret = false;
    let inactiveSecret = false;
    let isDirectAppear = false;
    let firstLevelIndirectDependency = false;
    let exploitApplicable = false;

    // Notice the order is important, e.g. chose 1 before 2 and 2 before 3.
    // Widespread Active Attack Usage
    // Active Attack Usage
    // No Known Attack Usage
    let extremelyFrequentlyExpolitITW = false; //Widespread Active Attack Usage
    let frequentlyExpolitITW = false; //Active Attack Usage
    let rarelyExpolitITW = false; //No Known Attack Usage
    let hasPublicExpolit = false;
    let noPublicExpolit = false;
    let prodSecret = false;
    let nonProdSecret = false;
    let rarelySeenExploit = false;

    uniqueSeverityFromAllAlerts.forEach(i => {
      if (i.reason.toLowerCase().startsWith("direct") || i.shortName.toLowerCase().startsWith("direct")) {
        isDirectAppear = true;
      } else if (i.shortName === severityReasons.hasPublicExpolit.shortName) {
        hasPublicExpolit = true;
      } else if (i.shortName === severityReasons.noPublicExpolit.shortName) {
        noPublicExpolit = true;
      } else if (i.shortName === severityReasons.exploitApplicable.shortName) {
        exploitApplicable = true;
      } else if (i.shortName === severityReasons.rarelyExpolitITW.shortName) {
        rarelyExpolitITW = true;
      } else if (i.shortName === severityReasons.frequentlyExpolitITW.shortName) {
        frequentlyExpolitITW = true;
      } else if (i.shortName === severityReasons.extremelyFrequentlyExpolitITW.shortName) {
        extremelyFrequentlyExpolitITW = true;
      } else if (i.shortName === severityReasons.firstLevelIndirectDependency.shortName) {
        firstLevelIndirectDependency = true;
      } else if (i.shortName === severityReasons.packageImported.shortName) {
        pkgImported = true;
      } else if (i.shortName === severityReasons.packageUsed.shortName) {
        pkgUsed = true;
      } else if (i.shortName === severityReasons.devDependency.shortName) {
        isDevDependency = true;
      } else if (i.shortName === severityReasons.activeSecret.shortName) {
        activeSecret = true;
      } else if (i.shortName === severityReasons.inactiveSecret.shortName) {
        inactiveSecret = true;
      } else if (i.shortName === severityReasons.prodSecret.shortName) {
        prodSecret = true;
      } else if (i.shortName === severityReasons.nonProdSecret.shortName) {
        nonProdSecret = true;
      }
    });

    const newChangeReasons: ChangeReason[] = [];
    const privateVisability = alerts[0].privateVisability;
    const ruleId = alerts[0].ruleId.split(":")[0];
    const securityAlertType = alerts[0].securityAlertType;
    if (ruleId) {
      if (
        securityAlertType === SecurityAlertType.secrets &&
        !inactiveSecret &&
        !activeSecret &&
        (ruleId.endsWith("client-id") ||
          ruleId.endsWith("app-id") ||
          ruleId.endsWith("app-key") ||
          ruleId.endsWith("private-key") ||
          ruleId.endsWith("project-key") ||
          ruleId.endsWith("access-key"))
      ) {
        const infoReqReason = ChangeReason.copy(severityReasons.additionalInfoRequired);
        newChangeReasons.push(infoReqReason);
      } else if (
        privateVisability === false &&
        ((securityAlertType === SecurityAlertType.secrets && ruleId.startsWith("sensitive-logs.")) ||
          securityAlertType === SecurityAlertType.sca ||
          securityAlertType === SecurityAlertType.sast)
      ) {
        const vulnInPublicReason = ChangeReason.copy(severityReasons.vulnInPublicRepo);
        newChangeReasons.push(vulnInPublicReason);
      }
    }

    uniqueSeverityFromAllAlerts.forEach(i => {
      //Remove this reason if at least one of the alerts have production secret
      if (prodSecret && i.shortName === severityReasons.nonProdSecret.shortName) {
        return;
      }

      // Notice the order is important, e.g. chose 1 before 2 and 2 before 3.
      // Widespread Active Attack Usage
      // Active Attack Usage
      // No Known Attack Usage
      if (extremelyFrequentlyExpolitITW) {
        if (i.shortName === severityReasons.frequentlyExpolitITW.shortName || i.shortName === severityReasons.rarelyExpolitITW.shortName) {
          return;
        }
      }
      if (frequentlyExpolitITW) {
        if (
          i.shortName === severityReasons.extremelyFrequentlyExpolitITW.shortName ||
          i.shortName === severityReasons.rarelyExpolitITW.shortName
        ) {
          return;
        }
      }
      if (rarelyExpolitITW) {
        if (
          i.shortName === severityReasons.frequentlyExpolitITW.shortName ||
          i.shortName === severityReasons.extremelyFrequentlyExpolitITW.shortName
        ) {
          return;
        }
      }

      //Remove this reason if at least one of the alerts have frequently seen exploit attepmts
      if (frequentPublicExploit) {
        if (i.shortName === severityReasons.rarelyExpolitITW.shortName || i.shortName === severityReasons.frequentlyExpolitITW.shortName) {
          return;
        }
      } else if (someSeenExploit) {
        if (i.shortName === severityReasons.rarelyExpolitITW.shortName) {
          return;
        }
      } else if (rarelySeenExploit) {
        if (i.shortName === severityReasons.rarelyExpolitITW.shortName) {
          i.reason = `According the the Exploit Prediction Scoring System (EPSS) model all vulnerabilies found related to this issue has a slight chance to be attempted to exploit. Because ${severityReasons.rarelyExpolitITW.reason}`;
        }
      }

      if (i.shortName === severityReasons.extremelyFrequentlyExpolitITW.shortName) {
        let cves = "";
        // if (frequentPublicExploitCVEs.length > 5) {
        //   cves = `${frequentPublicExploitCVEs.join(", ")} and a ${frequentPublicExploitCVEs.length - 5} other`;
        // } else {
        //   cves = frequentPublicExploitCVEs.join(", ");
        // }
        cves = frequentPublicExploitCVEs.join(", ");
        i.reason = `According the the Exploit Prediction Scoring System (EPSS) model ${cves} found related to this issue has a high chance to be attempted to exploit. Because ${severityReasons.extremelyFrequentlyExpolitITW.reason}`;
      } else if (i.shortName === severityReasons.frequentlyExpolitITW.shortName) {
        let cves = "";
        if (someSeenExploitCVEs.length > 5) {
          cves = `${someSeenExploitCVEs.join(", ")} and a ${someSeenExploitCVEs.length} other`;
        } else {
          cves = someSeenExploitCVEs.join(", ");
        }
        i.reason = `According the the Exploit Prediction Scoring System (EPSS) model ${cves} found related to this issue has a high chance to be attempted to exploit. Because ${severityReasons.frequentlyExpolitITW.reason}`;
      }

      //Remove this reason if at least one of the alerts have public exploit
      if (hasPublicExpolit) {
        if (i.shortName === severityReasons.noPublicExpolit.shortName) {
          return;
        }
      } else {
        if (i.shortName === severityReasons.exploitDiversity.shortName) {
          return;
        }
      }
      if (isDirectAppear) {
        if (i.reason.toLowerCase().startsWith("indirect") || i.shortName.toLowerCase().startsWith("indirect")) {
          return;
        }
      }
      if (firstLevelIndirectDependency) {
        if (i.shortName === severityReasons.deepLevelIndirectDependency.shortName) {
          return;
        }
      }
      if (exploitApplicable) {
        if (i.shortName === severityReasons.exploitNotApplicable.shortName) {
          return;
        }
      }
      // if we have imported or used, we remove the opposite
      if (i.shortName === severityReasons.packageNotUsed.shortName && pkgUsed) {
        return;
      }

      if (i.shortName === severityReasons.packageNotImported.shortName && pkgImported) {
        return;
      }

      // if dev dependency, remove SF from scaValidator
      if (
        (i.shortName === severityReasons.packageImported.shortName || i.shortName === severityReasons.packageNotImported.shortName) &&
        isDevDependency
      ) {
        return;
      }
      if (
        (i.shortName === severityReasons.packageUsed.shortName || i.shortName === severityReasons.packageNotUsed.shortName) &&
        isDevDependency
      ) {
        return;
      }
      if (
        (i.shortName === severityReasons.vulnerableFnUsed.shortName || i.shortName === severityReasons.vulnerableFnNotUsed.shortName) &&
        isDevDependency
      ) {
        return;
      }
      if (activeSecret) {
        if (
          i.shortName === severityReasons.lowConfidenceDetection.shortName ||
          i.shortName === severityReasons.mediumConfidenceDetection.shortName
        ) {
          logger.info(`active secret always has high confidence: ${alerts[0].ruleId}`);
          newChangeReasons.push(severityReasons.highConfidenceDetection);
          return;
        }
        if (i.shortName === severityReasons.inactiveSecret.shortName) {
          logger.info(`secret cannot be active and inactive for: ${repoName}, secret type: ${alerts[0].ruleId}`);
          return;
        }
      }
      newChangeReasons.push(i);
    });

    //Debug
    //logger.info(`finish set changeSeverityBasedOnEvents for repo: ${repoName}, newChangeReasons:${JSON.stringify(newChangeReasons)}`);

    return newChangeReasons;
  } catch (err) {
    logger.error(`failed getUniqueSeverityReasons repo: ${repoName}, err: ${err}`);
  }
}

export function getUniqueSeverityReasonsBetweenTwoCollections(severityFromRepo: ChangeReason[], severityFromImage: ChangeReason[]) {
  if (!severityFromRepo) {
    severityFromRepo = [];
  }
  if (!severityFromImage) {
    severityFromImage = [];
  }
  const newCollection: ChangeReason[] = JSON.parse(JSON.stringify(severityFromRepo));
  severityFromImage.forEach(i => {
    if (newCollection.find(s => s.shortName === i.shortName)) {
      return;
    }
    newCollection.push(JSON.parse(JSON.stringify(i)));
  });
  return newCollection;
}

export function getUniqueCloudSeverityReasons(alerts: CloudSecurityEvent[], repoName: string) {
  try {
    //Step 1 sent all unique
    const uniqueSeverityFromAllAlerts: ChangeReason[] = [];
    const unique = new Set();
    alerts.forEach(i => {
      if (i.severityChangedReason) {
        i.severityChangedReason.forEach(s => {
          if (!unique.has(s.shortName)) {
            uniqueSeverityFromAllAlerts.push(s);
            unique.add(s.shortName);
          }
        });
      }
    });

    //Debug
    //logger.info(`finish set changeSeverityBasedOnEvents for repo: ${repoName}, newChangeReasons:${JSON.stringify(newChangeReasons)}`);

    return uniqueSeverityFromAllAlerts;
  } catch (err) {
    logger.error(`failed getUniqueCloudSeverityReasons repo: ${repoName}, err: ${err}`);
  }
}

export function changeSeverityBasedOnCloudEvents(alerts: CloudSecurityEvent[], repoName: string) {
  try {
    if (alerts.length == 0) {
      return;
    }

    const items = {};
    alerts.forEach(i => {
      const key = getUniqueInfoForCloudAggregation(i);
      if (items[key]) {
        items[key].push(i);
      } else {
        items[key] = [i];
      }
    });

    const stats = {};
    for (const [name, entry] of Object.entries(items)) {
      const alerts: CloudSecurityEvent[] = entry as CloudSecurityEvent[];
      const highestSeventy = getHighestCloudSeventy(alerts);
      for (const alert of alerts) {
        if (alert.severity < highestSeventy) {
          alert.severity = highestSeventy;
          alert.severityStr = AlertSeverity[highestSeventy];
        } else if (alert.severity > highestSeventy) {
          logger.error(`something went wrong for calc highest severity: ${repoName} alert: ${JSON.stringify(alert)}`);
        }
        const key = `${alert.severityStr}_${name}`;
        if (stats[key]) {
          stats[key]++;
        } else {
          stats[key] = 1;
        }
      }
    }
  } catch (err) {
    logger.error(`failed change severity based on events for repo: ${repoName} err: ${err}`);
  }
}

export function setSeverityFromPolicy(originalSeverity: string, newSeverityInfo, policy: Policy, severityChangedReason: ChangeReason[]) {
  try {
    let newSeverity = newSeverityInfo;
    const categoryId = policy.categoryId.toLowerCase();

    //If original severity is appox or info always use it!
    if (originalSeverity) {
      if (originalSeverity.toLowerCase() === AlertSeverity[AlertSeverity.Info].toLowerCase()) {
        //Debug
        //logger.info(`original severity: ${originalSeverity}, new severity not changing, pol: ${policyName}`);
        return Severity.INFO;
      }
      if (originalSeverity.toLowerCase() === AlertSeverity[AlertSeverity.Appoxalypse].toLowerCase()) {
        //Debug
        //logger.info(`original severity: ${originalSeverity}, new severity not changing, pol: ${policyName}`);
        return Severity.APPOXALYPSE;
      }
    }

    if (
      severityChangedReason.find(
        changeReason =>
          changeReason.shortName === severityReasons.configuredSevIsLower.shortName ||
          changeReason.shortName === severityReasons.configuredSevIsHigher.shortName,
      )
    ) {
      if (policy.severity === AlertSeverity.Appoxalypse) {
        return Severity.APPOXALYPSE;
      } else if (policy.severity === AlertSeverity.Info) {
        return Severity.INFO;
      }
    }

    const shouldIgnoreCheck =
      categoryId === "cspm" ||
      categoryId === "containerscan" ||
      categoryId === "iac" ||
      categoryId === "sast" ||
      categoryId === "sca" ||
      categoryId === "secret";
    if (shouldIgnoreCheck) {
      //Debug
      //logger.info(`ignore check original severity: ${originalSeverity}, new severity not changing: ${newSeverity}, pol: ${policyName}`);
      return;
    }

    if (newSeverity === Severity.APPOXALYPSE) {
      const appoxOrInfoSev = getSeverityAppoxOrInfo(severityChangedReason);
      if (appoxOrInfoSev != undefined) {
        //Unless it should be appox hard coded dont increase to appox
        if (appoxOrInfoSev !== AlertSeverity.Appoxalypse) {
          newSeverity = Severity.CRITICAL;
          //Debug
          //logger.info(`setting limit for secret as critical, pol: ${policyName}`);
        }
      } else {
        newSeverity = Severity.CRITICAL;
        //Debug
        //logger.info(`setting limit for secret as critical, pol: ${policyName}`);
      }
    } else if (newSeverity === Severity.INFO) {
      //Unless it should be appox hard coded dont increase to appox
      const appoxOrInfoSev = getSeverityAppoxOrInfo(severityChangedReason);
      if (appoxOrInfoSev != undefined) {
        if (appoxOrInfoSev !== AlertSeverity.Info) {
          newSeverity = Severity.LOW;
          //Debug
          //logger.info(`setting limit for secret as low, pol: ${policyName}`);
        }
      } else {
        newSeverity = Severity.LOW;
        //Debug
        //logger.info(`setting limit for secret as low, pol: ${policyName}`);
      }
    }
    return newSeverity;
  } catch (err) {
    logger.error(`failed set severity from policy: ${policy.name} err: ${err}`);
  }
}

export function setNewIssueSeverityBasedOnBP(issue: Issue, app: Application, rulesParser: RulesParser, ss: ScanSummaryHistory) {
  try {
    const ignoreChangedSeverity =
      StatesHelper.Instance.isCharterBank || StatesHelper.Instance.isPipelineScan || StatesHelper.Instance.dontChangeSeverity;
    if (ignoreChangedSeverity) {
      return;
    }

    let shouldRunChangesBasedOnBp = issue.overrightBP;
    if (
      StatesHelper.Instance.orgName === "org_9lzVYnxPlP8GMDCe" ||
      StatesHelper.Instance.orgName === "org_8BVISNnfAJTNwOsJ" ||
      StatesHelper.Instance.orgName === "org_ZTgPJnqytiHMwFNY"
    ) {
      return;
    }

    if (rulesParser.ignoreBusinessPriorityPolicies.has(issue.pId)) {
      setHardCodedSeverityBasedOnSeverityReasons(issue, ss, app);
      return;
    }

    if (shouldRunChangesBasedOnBp) {
      const shouldChangedActualSeverity =
        issue.originalToolSeverity.toLowerCase() != AlertSeverity[AlertSeverity.Appoxalypse].toLowerCase() &&
        issue.originalToolSeverity.toLowerCase() != AlertSeverity[AlertSeverity.Info].toLowerCase();

      let newSeverity = issue.severity;
      let appBp = app.businessPriority;

      const severityChangedReason: ChangeReason[] = [];
      //Ignore this for secrets
      if (!issue.appName.startsWith("*")) {
        if (appBp >= 0 && appBp < 30) {
          if (shouldChangedActualSeverity) {
            newSeverity += -2;
          }
          severityChangedReason.push(severityReasons.lowBusinessPriority);
        } else if (appBp >= 30 && appBp < 60) {
          if (shouldChangedActualSeverity) {
            newSeverity += -1;
          }
          severityChangedReason.push(severityReasons.mediumBusinessPriority);
        } else if (appBp >= 60 && appBp < 90) {
          severityChangedReason.push(severityReasons.highBusinessPriority);
        } else if (appBp >= 90) {
          severityChangedReason.push(severityReasons.criticalBusinessPriority);
        }
      }

      //Dont go over critical or low
      if (newSeverity !== issue.severity && shouldChangedActualSeverity) {
        if (newSeverity > AlertSeverity.Critical) {
          newSeverity = AlertSeverity.Critical;
        }
        if (newSeverity < AlertSeverity.Low) {
          newSeverity = AlertSeverity.Low;
        }
      }

      //Change actual severity
      if (newSeverity !== issue.severity && shouldChangedActualSeverity) {
        //Set original severity as we going to changed the to new one
        if (!issue.originalToolSeverity) {
          issue.originalToolSeverity = AlertSeverity[issue.severity];
        }

        issue.reducedSeverity = true;
        ss.reduceFromAppSeverities(app.appId, issue.severity);
        ss.reduceFromTotalIssues(issue.severity);
        const cat = app.categories.find(c => c.catId === issue.categoryId);
        cat.severities[severityConst[issue.severity]]--;
        ss.addToAppSeverities(app.appId, newSeverity);
        ss.addToTotalSeverities(newSeverity);
        cat.severities[severityConst[newSeverity]]++;
        issue.severity = newSeverity;
        issue.severityChangedReason = [...severityChangedReason, ...issue.severityChangedReason];
        issue.severityChange = getSeverityChanges(getSeverityFromStr(issue.originalToolSeverity), issue.severity);

        const p: Policy = rulesParser.getDisablePolicyBasedOnSeverity(issue.pId, issue.pName, newSeverity);
        if (p) {
          issue.needToBeRemoved = true;
          StatesHelper.Instance.scanInfoStats.removedAlertsDueToReduceSeverity++;
        } else {
          StatesHelper.Instance.scanInfoStats.reducedSeverity++;
        }
      }
      //no change to actual severity, just add reasons
      else {
        if (severityChangedReason.length > 0) {
          if (!issue.originalToolSeverity) {
            issue.originalToolSeverity = AlertSeverity[issue.severity];
          }
          issue.severityChangedReason = [...severityChangedReason, ...issue.severityChangedReason];
          issue.severityChange = getSeverityChanges(getSeverityFromStr(issue.originalToolSeverity), issue.severity);
        }
      }
    }
    setHardCodedSeverityBasedOnSeverityReasons(issue, ss, app);
  } catch (err) {
    StatesHelper.Instance.scanInfoStats.failedSetNewSeverity++;
    logger.error(`failed set new issue severity based on BP: ${app.appName}, err: ${err}`);
  }
}

export function addSeverityChangedReasonToImage(
  newSeverityChangedReason: ChangeReason,
  image: ImageInfo,
  extraInfo?: ExtraInfo[],
  compareKey: boolean = false,
) {
  const existAlready = image.severityChangeReasons.find(s => s.shortName == newSeverityChangedReason.shortName);
  if (existAlready) {
    if (extraInfo) {
      extraInfo.forEach((ei: ExtraInfo) => {
        if (compareKey) {
          if (!existAlready.extraInfo.some((obj: ExtraInfo) => obj.key === ei.key)) {
            existAlready.extraInfo.push(ei);
          }
        } else {
          if (!existAlready.extraInfo.some((obj: ExtraInfo) => obj.link === ei.link)) {
            existAlready.extraInfo.push(ei);
          }
        }
      });
    }
    return;
  }
  const copySeverityChangedReason = ChangeReason.copy(newSeverityChangedReason);
  if (extraInfo) {
    // deep copy since we use same object in a loop at calling function
    copySeverityChangedReason.extraInfo = JSON.parse(JSON.stringify(extraInfo));
  }
  image.severityChangeReasons.push(copySeverityChangedReason);
}

export function addSeverityChangedReasonToIssue(newSeverityChangedReason: ChangeReason, issue: Issue, extraInfo?: ExtraInfo[]) {
  const existAlready = issue.severityChangedReason.find(s => s.shortName == newSeverityChangedReason.shortName);
  if (existAlready) {
    if (extraInfo) {
      extraInfo.forEach((ei: ExtraInfo) => {
        if (!existAlready.extraInfo.some((obj: ExtraInfo) => obj.link === ei.link)) {
          existAlready.extraInfo.push(ei);
        }
      });
    }
    return;
  }
  const copySeverityChangedReason = ChangeReason.copy(newSeverityChangedReason);
  if (extraInfo) {
    copySeverityChangedReason.extraInfo = extraInfo;
  }
  issue.severityChangedReason.push(copySeverityChangedReason);
}

export function getSeverityAppoxOrInfo(severityChangedReasons: ChangeReason[]) {
  let newSeverity;

  try {
    let saasSecret = false;
    let userMgmtSecret = false;
    let activeSecret = false;
    let saasSecrsecretInPublicRepo = false;

    //Lop for single match
    for (const severityChangedReason of severityChangedReasons) {
      try {
        if (!severityChangedReason) {
          logger.error(`failed getSeverityAppoxOrInfo`);
          continue;
        }

        if (
          severityChangedReason.shortName === severityReasons.packageNotImported.shortName ||
          severityChangedReason.shortName === severityReasons.inactiveSecret.shortName ||
          severityChangedReason.shortName === severityReasons.devDependency.shortName
        ) {
          newSeverity = AlertSeverity.Info;
          break;
        }

        if (severityChangedReason.shortName === severityReasons.repoForkedSetting.shortName) {
          newSeverity = AlertSeverity.Appoxalypse;
          break;
        }

        //Set specific checks
        if (severityChangedReason.shortName === severityReasons.saasSecret.shortName) {
          saasSecret = true;
        }
        if (severityChangedReason.shortName === severityReasons.userMgmtSecret.shortName) {
          userMgmtSecret = true;
        }
        if (severityChangedReason.shortName === severityReasons.activeSecret.shortName) {
          activeSecret = true;
        }
        if (severityChangedReason.shortName === severityReasons.secretInPublicRepo.shortName) {
          saasSecrsecretInPublicRepo = true;
        }
      } catch (err) {
        logger.error(`failed single getSeverityAppoxOrInfo, err: ${err}`);
      }
    }

    if ((saasSecret || userMgmtSecret) && activeSecret && saasSecrsecretInPublicRepo) {
      newSeverity = AlertSeverity.Appoxalypse;
    }
  } catch (err) {
    logger.error(`failed getSeverityAppoxOrInfo, err: ${err}`);
  }
  return newSeverity;
}

function setHardCodedSeverityBasedOnSeverityReasons(issue: Issue, ss: ScanSummaryHistory, app: Application) {
  try {
    let newSeverity = issue.severity;
    const sev = getSeverityAppoxOrInfo(issue.severityChangedReason);
    if (sev != undefined) {
      newSeverity = sev;
    }

    if (issue.severity === newSeverity) {
      return;
    }
    ss.reduceFromAppSeverities(issue.appId, issue.severity);
    ss.reduceFromTotalIssues(issue.severity);
    const cat = app.categories.find(c => c.catId === issue.categoryId);
    cat.severities[severityConst[issue.severity]]--;
    ss.addToAppSeverities(issue.appId, newSeverity);
    cat.severities[severityConst[newSeverity]]++;
    ss.addToTotalSeverities(newSeverity);

    StatesHelper.Instance.scanInfoStats.hardCodedSeverityLogic++;

    issue.severity = newSeverity;
    issue.severityChange = getSeverityChanges(getSeverityFromStr(issue.originalToolSeverity), issue.severity);
  } catch (err) {
    StatesHelper.Instance.scanInfoStats.failedSetNewSeverity++;
    logger.error(`failed set hard coded severity based on severity reasons: ${issue.appName}, err: ${err}`);
  }
}

export function getSeverityFromStr(severity: string) {
  if (severity.toLowerCase() === AlertSeverity[AlertSeverity.Info].toLowerCase()) {
    return AlertSeverity.Info;
  }
  if (severity.toLowerCase() === AlertSeverity[AlertSeverity.Low].toLowerCase()) {
    return AlertSeverity.Low;
  }
  if (severity.toLowerCase() === AlertSeverity[AlertSeverity.Medium].toLowerCase()) {
    return AlertSeverity.Medium;
  }
  if (severity.toLowerCase() === AlertSeverity[AlertSeverity.High].toLowerCase()) {
    return AlertSeverity.High;
  }
  if (severity.toLowerCase() === AlertSeverity[AlertSeverity.Critical].toLowerCase()) {
    return AlertSeverity.Critical;
  }
  if (severity.toLowerCase() === AlertSeverity[AlertSeverity.Appoxalypse].toLowerCase()) {
    return AlertSeverity.Appoxalypse;
  }
}

export class SeverityOptions {
  appoxOnly: boolean = false;
  criticalAndAppox: boolean = false;
  highCriticalAndAppox: boolean = false;
  midAndHigher: boolean = false;
  lowAndHigher: boolean = false;
  all: boolean = false;
}

export function getPolicyInfo(displayIssueSeverity: number) {
  let arg = displayIssueSeverity;
  const severityOptions: SeverityOptions = new SeverityOptions();
  if (arg === 5) {
    severityOptions.appoxOnly = true;
  } else if (arg === 4) {
    severityOptions.criticalAndAppox = true;
  } else if (arg === 3) {
    severityOptions.highCriticalAndAppox = true;
  } else if (arg === 2) {
    severityOptions.midAndHigher = true;
  } else if (arg === 1) {
    severityOptions.lowAndHigher = true;
  } else if (arg === 0) {
    severityOptions.all = true;
  }
  return severityOptions;
}

export function addRunningInCloudExtraInfo(secEvent: SecurityEvent | CloudSecurityEvent, item?) {
  try {
    const extraCloudInfo: ExtraInfo[] = [];
    if (secEvent instanceof CloudSecurityEvent) {
      if (item && item.asset_type_string && item.asset_type_string !== "") {
        extraCloudInfo.push({
          key: "Resource type",
          value: item.asset_type_string,
        });
      }
      if (secEvent.resource && secEvent.resource !== "") {
        extraCloudInfo.push({
          key: "Resource name",
          value: secEvent.resource,
        });
      }
      if (secEvent.region && secEvent.region !== "") {
        extraCloudInfo.push({
          key: "Zone",
          value: secEvent.region,
        });
      }
      if (secEvent.cloudEnv && secEvent.cloudEnv !== "") {
        extraCloudInfo.push({
          key: "Cloud env",
          value: secEvent.cloudEnv,
        });
      }

      if (secEvent.accountName && secEvent.accountName !== "") {
        extraCloudInfo.push({
          key: "Account name",
          value: secEvent.accountName,
        });
      }
    } else {
      const artifacts = secEvent.artifacts;
      if (artifacts.runningOnHost) {
        extraCloudInfo.push({
          key: "Host name",
          value: artifacts.runningOnHost,
        });
      }
      if (artifacts.registryName && artifacts.registryName !== "") {
        extraCloudInfo.push({
          key: "Registry name",
          value: artifacts.registryName,
        });
      }

      if (artifacts.os && artifacts.os !== "") {
        extraCloudInfo.push({
          key: "OS",
          value: artifacts.os,
        });
      }

      if (artifacts.region && artifacts.region !== "") {
        extraCloudInfo.push({
          key: "Zone",
          value: artifacts.region,
        });
      }

      if (artifacts.imageCreatedAt && artifacts.imageCreatedAt !== "") {
        extraCloudInfo.push({
          key: "Image creation date",
          value: artifacts.imageCreatedAt,
        });
      }

      if (artifacts.baseImageOsVersion && artifacts.baseImageOsVersion !== "") {
        extraCloudInfo.push({
          key: "Base image OS version",
          value: artifacts.baseImageOsVersion,
        });
      }

      if (artifacts.dockerFileInRunTime && artifacts.dockerFileInRunTime !== "") {
        extraCloudInfo.push({
          key: "Docker name",
          value: artifacts.dockerFileInRunTime,
        });
      }
    }
    return extraCloudInfo;
  } catch (e) {
    logger.error(`Could not create extraInfo for cloudResoutce SF, err: ${e}`);
    return [];
  }
}

export function shouldIncludeByPolicy(alertSeverity: AlertSeverity, severityOptions: SeverityOptions) {
  if (severityOptions.all) {
    return true;
  }
  //Low and higher
  if (severityOptions.lowAndHigher) {
    if (alertSeverity >= AlertSeverity.Low) {
      return true;
    }
    return false;
  }
  //Mid and higher
  if (severityOptions.midAndHigher) {
    if (alertSeverity >= AlertSeverity.Medium) {
      return true;
    }
    return false;
  }
  //High or critical or appox
  if (severityOptions.highCriticalAndAppox) {
    if (alertSeverity == AlertSeverity.High) {
      return true;
    }
    if (alertSeverity == AlertSeverity.Critical) {
      return true;
    }
    if (alertSeverity == AlertSeverity.Appoxalypse) {
      return true;
    }
    return false;
  }
  //Critical or appox
  if (severityOptions.criticalAndAppox) {
    if (alertSeverity == AlertSeverity.Critical) {
      return true;
    }
    if (alertSeverity == AlertSeverity.Appoxalypse) {
      return true;
    }
    return false;
  }
  //Appox
  if (severityOptions.highCriticalAndAppox) {
    if (alertSeverity == AlertSeverity.Appoxalypse) {
      return true;
    }
    return false;
  }
  return false;
}

export function getUniqueSeverityChanges(securityEvent: SecurityEvent, allSecurityEvent: SecurityEvent[]) {
  try {
    const newChangeReasons: ChangeReason[] = [];

    const cvssAlertsSorted: SecurityEvent[] = allSecurityEvent.sort((a, b) => Number(b.blame.cvssScore) - Number(a.blame.cvssScore));
    let cvssReason: ChangeReason = null;
    if (cvssAlertsSorted[0]?.blame?.cvssScore) {
      if (cvssAlertsSorted[0].blame.cvssScore >= 9) {
        cvssReason = ChangeReason.copy(severityReasons.criticalCvssScore);
      } else if (cvssAlertsSorted[0].blame.cvssScore >= 7) {
        cvssReason = ChangeReason.copy(severityReasons.highCvssScore);
      } else if (cvssAlertsSorted[0].blame.cvssScore >= 4) {
        cvssReason = ChangeReason.copy(severityReasons.mediumCvssScore);
      } else if (cvssAlertsSorted[0].blame.cvssScore < 4) {
        cvssReason = ChangeReason.copy(severityReasons.lowCvssScore);
      }
      if (cvssReason) {
        newChangeReasons.push(cvssReason);
      }
    }

    const publicExploitsExist = allSecurityEvent.filter(i => i.blame.hasPublicExploit).length > 0;
    const frequentPublicExploit = allSecurityEvent.filter(i => i.blame.frequentPublicExploit).length > 0;
    const someSeenExploit = allSecurityEvent.filter(i => i.blame.someSeenExploit).length > 0;
    // const rarelySeenExploit = allSecurityEvent.filter(i => i.blame.rarelySeenExploit).length > 0;

    const allChangeReasons: ChangeReason[] = cvssAlertsSorted.map(i => i.severityChangedReason).flat();
    const u = new Set();

    let isDirectAppear = false;
    let firstLevelIndirectDependency = false;
    allChangeReasons.forEach(i => {
      if (i.reason.toLowerCase().startsWith("direct") || i.shortName.toLowerCase().startsWith("direct")) {
        isDirectAppear = true;
      }
      if (i.reason === severityReasons.firstLevelIndirectDependency.reason) {
        firstLevelIndirectDependency = true;
      }
    });

    allChangeReasons.forEach(i => {
      //Remove this reason if at least one of the alerts have frequently seen exploit attepmts
      if (frequentPublicExploit) {
        if (i.shortName === severityReasons.rarelyExpolitITW.shortName || i.shortName === severityReasons.frequentlyExpolitITW.shortName) {
          return;
        }
      } else if (someSeenExploit) {
        if (i.shortName === severityReasons.rarelyExpolitITW.shortName) {
          return;
        }
      }
      //Remove this reason if at least one of the alerts have public exploit
      if (publicExploitsExist) {
        if (i.shortName === severityReasons.noPublicExpolit.shortName) {
          return;
        }
      } else {
        if (i.shortName === severityReasons.exploitDiversity.shortName) {
          return;
        }
      }
      if (isDirectAppear) {
        if (i.reason.toLowerCase().startsWith("indirect") || i.shortName.toLowerCase().startsWith("indirect")) {
          return;
        }
      }
      if (firstLevelIndirectDependency) {
        if (i.shortName === severityReasons.deepLevelIndirectDependency.shortName) {
          return;
        }
      }
      if (u.has(i.shortName)) {
        return;
      }
      u.add(i.shortName);
      newChangeReasons.push(i);
    });
    return newChangeReasons;
  } catch (err) {
    logger.error(`failed get severity changes unique, err: ${err}`);
  }
  return securityEvent.severityChangedReason;
}

function getHighestSeventy(scaAlerts: SecurityEvent[]) {
  let highestSeverity: AlertSeverity = AlertSeverity.Info;
  scaAlerts.forEach(i => {
    if (i.severity > highestSeverity) {
      highestSeverity = i.severity;
    }
  });
  return highestSeverity;
}

function getHighestCloudSeventy(scaAlerts: CloudSecurityEvent[]) {
  let highestSeverity: AlertSeverity = AlertSeverity.Info;
  scaAlerts.forEach(i => {
    if (i.severity > highestSeverity) {
      highestSeverity = i.severity;
    }
  });
  return highestSeverity;
}
