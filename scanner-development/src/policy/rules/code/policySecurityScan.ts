import { Fix } from "sarif";
import {
  CodeRepoTypes,
  CweObject,
  Dependency,
  getToolsNames,
  getUniqueInfoForAggregation,
  IssueOwner,
  Repo,
  SecurityAlertType,
  SecurityEvent,
} from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { ExtraInfo, SecretStatus } from "../../../entitis/issuesTypes";
import { severityReasons } from "../../../entitis/service/blameTypes";
import { AggregatedCodeData, AggregatedInfoForExclusion } from "../../../entitis/service/exclusionTypes";
import { ToolNameForUI } from "../../../entitis/tool/toolsTypes";
import { enableByPolicy } from "../../../helper/commonUtils";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { getFixVersionsFromSecEvent } from "../../../helper/policy/scaVersionHelper";
import { SCAVulnerability } from "../../../helper/policy/scaVulHelper";
import { getSeverityChanges, getUniqueSeverityChanges } from "../../../helper/policy/severityHelper";
import StringHelper from "../../../helper/stringHelper";
import TimeHelper from "../../../helper/timeHelper";
import PasswordHelper from "../../../helper/tools/passwordHelper";
import loggerImport from "../../../logger";
import { DependencyType } from "../../../mongo/sbom/types";
import { cicdPostureRules } from "./policyCICDContextValues";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class PolicySecurityScan extends PolicyRulesBase {
  private commiters: IssueOwner[] = [];
  private timeHelper: TimeHelper = new TimeHelper("");
  private passwordHelper: PasswordHelper = new PasswordHelper();

  async eval(jsonData) {
    const isSemGrepEnabled = enableByPolicy(ToolNameForUI.semgrep);
    const isCheckovEnabled = enableByPolicy(ToolNameForUI.checkov);

    let securityEvents: SecurityEvent[] = jsonData.securityEvents;

    // if semgrep/checkov is off by user, filter out events found by semgrep/checkov
    if (!isSemGrepEnabled) {
      securityEvents = securityEvents.filter(i => i.tool === "semgrep" && i.securityProvidersArr.length > 1);
    }
    if (!isCheckovEnabled) {
      securityEvents = securityEvents.filter(i => i.tool === "checkov" && i.securityProvidersArr.length > 1);
    }

    // get only values from map with iterator
    const rules = [...cicdPostureRules.values()];
    // filter out rules from this list, and also filter rules PIPELINES_ rules
    securityEvents = this.filterOutSecurityEventsByRules(securityEvents, rules);

    const scanTypeFromArgs = this.getValueFromRuleArgs("scanType");

    if (Array.isArray(scanTypeFromArgs)) {
      throw `scanType is array and not string type, ${scanTypeFromArgs.toString()}`;
    }
    if (!scanTypeFromArgs) {
      throw `scanType is not exist string type, ${scanTypeFromArgs}`;
    }

    const scanHistory = this.getValueFromRuleArgs("scanHistory") == null ? false : true;
    const alertSeverityFromArgs = this.getValueFromRuleArgs("alertSeverity");

    securityEvents = securityEvents.filter(i => {
      return (
        this.isExistInStringArr(alertSeverityFromArgs, i.severityStr, i) &&
        scanTypeFromArgs.toLowerCase() === i.securityAlertTypeStr.toLowerCase() &&
        scanHistory === i.fromCommitHistory
      );
    });

    if (securityEvents.length === 0) {
      return [];
    }

    const repo: Repo = jsonData.code_repo;

    const aggragatedInfo = this.getKeyValueMapByRuleIdAndData(jsonData, securityEvents);

    let res = [];
    for (const events of Object.values(aggragatedInfo) as any) {
      if (events.length == 0) {
        continue;
      }

      //Get the hights original severity alert
      let topLevelEventData = events.aggregated[0].securityAlert as SecurityEvent;

      const isSecret = topLevelEventData.securityAlertType === SecurityAlertType.secrets;
      const isSast = topLevelEventData.securityAlertType === SecurityAlertType.sast;

      this.commiters.push({
        name: topLevelEventData.blame.commiterName,
        email: topLevelEventData.blame.commiterEmail,
      });

      const violationInfoTitle = "";
      const aggregated = {
        aggregatedItems: this.sortEvents(events.aggregated),
        columns: "policySecurityScan",
        violationInfoTitle,
      };

      //Set additional info for secrets
      let extraInfo = topLevelEventData.extraInfo;
      let isPrivate = true;
      if (isSecret) {
        if (jsonData.code_repo != undefined) {
          isPrivate = jsonData.code_repo.privateVisability;
        }
        extraInfo.push({
          key: "Repository visibility",
          value: isPrivate ? "private" : "public",
        });
      }

      const aggregatedItems: PolicySecurityScanAggItem[] = events.aggregated;
      const issueOwners = this.getIssueOwners(jsonData, aggregatedItems);

      let secretStatus: SecretStatus = null;
      if (isSecret) {
        if (topLevelEventData.secretChecked) {
          if (topLevelEventData.validSecret) {
            secretStatus = "active";
            topLevelEventData.recommendation = `Contact ${
              issueOwners.length > 0 ? issueOwners.map(u => u.name).join(", ") : topLevelEventData.blame.commiterName
            } to remove the ${
              topLevelEventData.violationInfo
            } from the source code to an environment variable or a vault.\nFollowing that generate a new ${
              topLevelEventData.violationInfo
            } and revoke the previous one.`;
          } else {
            secretStatus = "inactive";
            topLevelEventData.recommendation = `Contact ${topLevelEventData.blame.commiterName} and inform the developer that putting secrets in code exposes the organization to unnecessary security risks. Secrets should be read by the application from an environment variable or a vault.`;
          }

          extraInfo.push({
            key: "Secret status",
            value: secretStatus,
          });
        } else {
          if (topLevelEventData.fromCommitHistory) {
            if (aggregatedItems.length == 1) {
              topLevelEventData.recommendation = `Please verify that the secret is not in use. If it is in use, please consider revoking the token.`;
            } else {
              topLevelEventData.recommendation = `Please verify that the secrets are not in use. If some or all are in use, please consider revoking the tokens.`;
            }
          }
          //Git secrets
          else {
            if (aggregatedItems.length == 1) {
              topLevelEventData.recommendation = `Please move the secret from the code to an environment variable or a vault.`;
            } else {
              topLevelEventData.recommendation = `Please move the secrets from the code to environment variables or a vault.`;
            }
          }
        }
      }

      let mainTitle = topLevelEventData.blame.summaryTitle || topLevelEventData.violationInfo;

      const SCAVulnerability = this.getSCAVulnerabilityList(topLevelEventData, events.aggregated);
      mainTitle = this.getIssueInfoPretty(topLevelEventData, isPrivate, mainTitle, secretStatus, SCAVulnerability);
      const secondaryTitle = this.getDescriptionInfoPretty(topLevelEventData, SCAVulnerability);
      const recommendation = this.getRecommendationInfoPretty(topLevelEventData, SCAVulnerability);

      if (topLevelEventData.blame.eduVideoLink !== undefined) {
        extraInfo.push({
          key: "Recommended Video",
          value: topLevelEventData.blame.eduVideoLink,
        });
      }

      const securityItems: SecurityEvent[] = (events.aggregated as PolicySecurityScanAggItem[]).map(i => i.securityAlert);
      const cweList = this.getCWEList(topLevelEventData, securityItems);
      const uniqueSeverityChanges = getUniqueSeverityChanges(
        topLevelEventData,
        (events.aggregated as PolicySecurityScanAggItem[]).map(i => i.securityAlert),
      );

      let uniqueProviders = [];
      let learnMore = topLevelEventData.moreInfoLink;
      if (topLevelEventData.securityAlertType === SecurityAlertType.sca) {
        if (events.aggregated.length > 1) {
          learnMore = topLevelEventData.blame.versionsPageUrl;
        }
        uniqueProviders = this.getUniqueSecurityProviders(
          SCAVulnerability.map(i => i.alert.securityProviders),
          topLevelEventData.securityProvider,
        );
      } else {
        uniqueProviders = this.getUniqueSecurityProviders(
          events.aggregated.map(i => i.securityAlert.securityProviders),
          topLevelEventData.securityProvider,
        );
      }

      const uniqueAgg = this.getCustomIssueId(getUniqueInfoForAggregation(topLevelEventData));
      if (topLevelEventData.ruleId) {
        extraInfo.push({
          key: "Rule Name",
          value: `${topLevelEventData.ruleId}`,
        });
      }

      if (topLevelEventData.securityAlertType === SecurityAlertType.ox) {
        uniqueSeverityChanges.push(severityReasons.hasHighRCE);
      }

      let item = this.generateItemForReport(
        isSecret ? false : true,
        mainTitle,
        secondaryTitle,
        "",
        topLevelEventData.recommendation,
        topLevelEventData.securityProvider,
        topLevelEventData.securityAlertTypeStr,
        [],
        "",
        true,
        events.uniqueFiles.size > 0 ? "" : topLevelEventData.link,
        aggregated,
        uniqueProviders,
        getToolsNames(topLevelEventData.securityProviders, topLevelEventData.tools),
        extraInfo,
        uniqueAgg,
        issueOwners,
        learnMore,
        topLevelEventData.ruleId,
        this.generateCWElist(securityItems),
        topLevelEventData.snippetContent,
        cweList,
        this.policyRuleMetadata.severity,
        topLevelEventData.blame.dependencyChain,
        topLevelEventData.blame.publicExploitLink,
        topLevelEventData.originalSeverityStr,
        [],
        getSeverityChanges(topLevelEventData.originalSeverity, topLevelEventData.severity),
        uniqueSeverityChanges,
        SCAVulnerability,
        this.getOriginalSev(securityItems),
        topLevelEventData?.blame?.runtime?.languageInfo,
        false,
        "",
        this.getOscarIdForSecretEvent(securityItems),
        this.setScaFixType(topLevelEventData, this.policyRuleMetadata.functionName),
      );
      if (secretStatus !== null) {
        item["secretStatus"] = secretStatus;
      }

      item.eventFromExternalTool = securityItems.filter(i => !i.oxTool).length > 0;

      res.push(item);
    }

    return res;
  }

  getUniqueAggSCAalerts(aggItems: PolicySecurityScanAggItem[]) {
    const newAggItems: PolicySecurityScanAggItem[] = [];
    const uniqueSet = new Set();
    aggItems.forEach(i => {
      try {
        const key = `${getUniqueInfoForAggregation(i.securityAlert)}_${i.securityAlert.fileName}`;
        if (uniqueSet.has(key)) {
          return;
        }
        uniqueSet.add(key);
        newAggItems.push(i);
      } catch (err) {
        logger.error(`failed get single unique agg SCA alert, err: ${err}`);
      }
    });

    if (newAggItems.length == 0) {
      return aggItems;
    }
    return newAggItems;
  }

  addSCAExtraInfo(topLevelEventData: SecurityEvent, extraInfo: ExtraInfo[]) {
    if (topLevelEventData.blame.dependencyType !== undefined) {
      let dependencyType = "";
      if (topLevelEventData.blame.dependencyType === "indirect") {
        dependencyType = "The vulnerable library is indirectly referenced in the source code";
      } else if (topLevelEventData.blame.dependencyType === "direct") {
        dependencyType = "The vulnerable library is directly referenced in the source code";
      } else if (topLevelEventData.blame.dependencyType === "dev") {
        dependencyType = "The vulnerable library is unlikely to be deployed to production";
      }
      extraInfo.push({ key: "Code reference", value: dependencyType });

      if (
        (topLevelEventData.blame.dependencyType.startsWith("indirect") || topLevelEventData.blame.dependencyType.startsWith("dev")) &&
        topLevelEventData.blame.dependencyChain &&
        topLevelEventData.blame.dependencyChain.length > 1
      ) {
        extraInfo.push({
          key: "Dependency depth",
          value: `${topLevelEventData.blame.dependencyChain.length - 1}`,
        });
        extraInfo.push({
          key: "Dependency chain",
          value: topLevelEventData.blame.dependencyChain.map(u => u.name).join(" -> "),
        });
      }
    }
  }

  getIssueInfoPretty(
    securityEvent: SecurityEvent,
    isPrivate: boolean,
    mainTitle: string,
    secretStatus: string,
    SCAVulnerability: SCAVulnerability[],
  ) {
    try {
      //Secret
      if (securityEvent.securityAlertType === SecurityAlertType.secrets) {
        mainTitle = `${secretStatus ? secretStatus[0].toUpperCase() + secretStatus.slice(1) + " " : ""}${mainTitle} was found in the ${
          securityEvent.fromCommitHistory ? "history" : "code"
        } of a ${isPrivate ? "private" : "public"} repository`;
      }
      //SCA
      if (securityEvent.securityAlertType === SecurityAlertType.sca) {
        if (SCAVulnerability.length > 1) {
          const singleSecAlert: SecurityEvent = SCAVulnerability[0].alert;
          const allSecAlerts: SecurityEvent[] = SCAVulnerability.map(i => i.alert);
          const cvssAlerts: SecurityEvent[] = allSecAlerts.filter(i => i?.blame?.cvssScore && i?.blame?.cve && i?.blame?.exploitType);
          const cvssAlertsSorted: SecurityEvent[] = cvssAlerts.sort((a, b) => Number(b.blame.cvssScore) - Number(a.blame.cvssScore));

          let directStr: string;
          if (securityEvent.blame.dependencyType === "direct") {
            directStr = "directly referenced in code";
          } else if (securityEvent.blame.dependencyType === "indirect") {
            directStr = "indirectly referenced in code";
          } else {
            directStr = "used as a development dependency";
          }

          if (cvssAlertsSorted.length > 0) {
            let exploitType: string = "";
            if (cvssAlertsSorted[0].blame.exploitType) {
              exploitType = ` of type "${cvssAlertsSorted[0].blame.exploitType}"`;
            }
            return `${singleSecAlert.pkgName}@${singleSecAlert.installedVersion} is a ${singleSecAlert.language} package ${directStr} with ${SCAVulnerability.length} vulnerabilities. The most severe vulnerability has a CVSS Score of ${cvssAlertsSorted[0].blame.cvssScore}${exploitType} (${cvssAlertsSorted[0].blame.cve})`;
          }
          return `${singleSecAlert.pkgName}@${singleSecAlert.installedVersion} is a ${singleSecAlert.language} package ${directStr} with ${SCAVulnerability.length} vulnerabilities. The most severe vulnerability is ${securityEvent.severityStr}`;
        }
      }
    } catch (err) {
      logger.error(`failed get issue title info pretty`, err);
    }

    return mainTitle;
  }

  getDescriptionInfoPretty(securityEvent: SecurityEvent, SCAVulnerability: SCAVulnerability[]) {
    try {
      if (securityEvent.securityAlertType === SecurityAlertType.sca) {
        if (SCAVulnerability.length > 1) {
          const singleSecAlert: SecurityEvent = SCAVulnerability[0].alert;
          const allSecAlerts: SecurityEvent[] = SCAVulnerability.map(i => i.alert);

          const isDirect = allSecAlerts.find(i => i.blame.dependencyType === DependencyType.Direct);
          const publicExploits = allSecAlerts.filter(i => i.blame.hasPublicExploit);
          let publicExploitStr;
          if (publicExploits.length === 1) {
            publicExploitStr = `Additionally, it has 1 publicly available exploit which increases your app exposure to the vulnerability.`;
          } else if (publicExploits.length > 1) {
            publicExploitStr = `Additionally, it has ${publicExploits.length} publicly available exploits which increases your app exposure to the vulnerability.`;
          }

          let basicStr;
          if (isDirect) {
            basicStr = `${singleSecAlert.pkgName}\\@${singleSecAlert.installedVersion} is a ${singleSecAlert.language} package with ${SCAVulnerability.length} vulnerabilities. The package is directly referenced in your code, which increases your app exposure to the vulnerability.`;
          } else {
            basicStr = `${singleSecAlert.pkgName}\\@${singleSecAlert.installedVersion} is a ${singleSecAlert.language} package with ${SCAVulnerability.length} vulnerabilities.`;
          }

          if (publicExploitStr) return `${basicStr} ${publicExploitStr}`;
          return basicStr;
        }
      }
    } catch (err) {
      logger.error(`failed get description info pretty in: ${this.policyRuleMetadata.name}`, err);
    }

    return securityEvent.title;
  }

  getRecommendationInfoPretty(securityEvent: SecurityEvent, SCAVulnerability: SCAVulnerability[]) {
    try {
      if (SCAVulnerability.length > 0) {
        if (SCAVulnerability[0].alert?.alertRecommendationResponse?.recommendation) {
          return SCAVulnerability[0].alert.alertRecommendationResponse.recommendation;
        }
      }

      // if (securityEvent.securityAlertType === SecurityAlertType.sca) {
      //   if (SCAVulnerability.length > 1) {
      //     const singleSecAlert: SecurityEvent = SCAVulnerability[0].alert;
      //     const allSecAlerts: SecurityEvent[] = SCAVulnerability.map(
      //       (i) => i.alert
      //     );
      //     const fix = getFixVersionsFromSecEvent(securityEvent, allSecAlerts);
      //     const fixedMinorVer = fix.fixedMinorVer;
      //     const fixedMajorVer = fix.fixedMajorVer;
      //     const uniqueFixVerMinorCount = fix.uniqueFixVerMinorCount;
      //     const uniqueFixVerMajorCount = fix.uniqueFixVerMajorCount;

      //     if (!fixedMinorVer && !fixedMajorVer)
      //       return securityEvent.recommendation;
      //     if (
      //       fixedMinorVer &&
      //       fixedMajorVer &&
      //       uniqueFixVerMinorCount > 0 &&
      //       uniqueFixVerMajorCount > 0
      //     )
      //       return `The currently used vulnerable version of ${singleSecAlert.pkgName} is ${singleSecAlert.installedVersion}. Upgrading to the minor version ${fixedMinorVer} will resolve ${uniqueFixVerMinorCount} of the ${SCAVulnerability.length} vulnerabilities. Upgrading to the major version ${fixedMajorVer} resolves ${uniqueFixVerMajorCount} of the ${SCAVulnerability.length} vulnerabilities.`;
      //     if (fixedMinorVer && uniqueFixVerMinorCount > 0)
      //       return `The currently used vulnerable version of ${singleSecAlert.pkgName} is ${singleSecAlert.installedVersion}. Upgrading to the minor version ${fixedMinorVer} will resolve ${uniqueFixVerMinorCount} of the ${SCAVulnerability.length} vulnerabilities.`;
      //     if (fixedMajorVer && uniqueFixVerMajorCount > 0)
      //       return `The currently used vulnerable version of ${singleSecAlert.pkgName} is ${singleSecAlert.installedVersion}. Upgrading to the major version ${fixedMajorVer} will resolve ${uniqueFixVerMajorCount} of the ${SCAVulnerability.length} vulnerabilities.`;
      //     if (uniqueFixVerMinorCount == 0 && uniqueFixVerMajorCount == 0)
      //       return `The currently used vulnerable version of ${singleSecAlert.pkgName} is ${singleSecAlert.installedVersion}. Currently, no fixed version is available. You should reconsider the usage of this library, or sanitize your code surrounding library usage to reduce the risk.`;
      //   }
      // }

      if (securityEvent.securityAlertType === SecurityAlertType.ox) {
        return securityEvent.recommendation;
      }
    } catch (err) {
      logger.error(`failed get recommendation info pretty, err: ${err}`);
    }

    return securityEvent.recommendation;
  }

  filterOutSecurityEventsByRules(securityEvents: SecurityEvent[], rules) {
    try {
      return securityEvents.filter(
        i =>
          !rules.includes(i.ruleId) &&
          !i.ruleId.includes("CKV_CIRCLECIPIPELINES_") &&
          !i.ruleId.includes("CKV_AZUREPIPELINES_") &&
          !i.ruleId.includes("CKV_BITBUCKETPIPELINES_") &&
          !i.ruleId.includes("CKV_GITLABCI_") &&
          !i.ruleId.includes("CKV_ARGO_") &&
          !i.ruleId.includes("CKV_GHA_"),
      );
    } catch (e) {
      logger.error(`failed filterOutSecurityEventsByRules err: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
    return securityEvents;
  }

  getCWEList(securityEvent: SecurityEvent, securityEventArray: SecurityEvent[]) {
    try {
      const exist = new Set();
      const r = [];
      securityEventArray.forEach(i => {
        if (!i.blame.cweList) {
          return;
        }
        i.blame.cweList.forEach(j => {
          if (exist.has(j.name)) {
            return;
          }
          exist.add(j.name);
          r.push(j);
        });
      });
      return r;
    } catch (err) {
      logger.error(`failed get CWE list, err: ${err}`, err);
    }
    return securityEvent.blame.cweList;
  }

  getSCAVulnerabilityList(securityEvent: SecurityEvent, aggregated: PolicySecurityScanAggItem[]) {
    try {
      if (securityEvent.securityAlertType === SecurityAlertType.sca) {
        const allSecAlerts: SecurityEvent[] = aggregated.map(i => i.securityAlert);

        const list: SCAVulnerability[] = [];
        const unique = new Set();

        allSecAlerts.forEach(i => {
          try {
            let cveInfo = i.blame.cve;
            if (!cveInfo) {
              //Try use rule ID
              cveInfo = i.ruleId;
            }
            if (!cveInfo) {
              logger.info(`failed get cve info, alert: ${JSON.stringify(i)}`);
              return;
            }
            if (unique.has(cveInfo)) {
              return;
            }
            unique.add(cveInfo);

            const c: SCAVulnerability = new SCAVulnerability();
            c.description = i.blame.cveDescription;
            c.cve = cveInfo;
            c.alert = i;
            c.cveLink = i.moreInfoLink;
            c.originalSeverity = i.originalSeverityStr;
            c.originalSeverityNumber = i.originalSeverity;
            c.cvsVer = i.blame.cvssScore ? i.blame.cvssScore.toString() : null;
            c.cwe = i.blame.cweList
              ? i.blame.cweList.map(i => {
                  try {
                    const cweE: CweObject = new CweObject();
                    cweE.description = "";
                    cweE.url = i.url;
                    cweE.name = i.name;
                    cweE.shortName = i.name;
                    if (i.name) {
                      const index = i.name.indexOf(":");
                      if (index != -1) {
                        cweE.shortName = i.name.substring(0, index);
                      }
                    }
                    return cweE;
                  } catch (err) {
                    logger.error(`failed get CWE new list, err: ${err}, item: ${JSON.stringify(i)}`);
                    return i;
                  }
                })
              : [];

            c.exploitInTheWild = i.blame.hasPublicExploit !== undefined;
            c.exploitInTheWildLink = i.blame.publicExploitLink;
            c.dateDiscovered = i.blame.publishedExploitDate;
            c.exploitCode;
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

            list.push(c);
          } catch (err) {
            logger.error(`failed get single SCA Vulnerability list`, err);
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
          logger.error(`failed get single SCA Vulnerability sort list`, err);
        }
        return list;
      }
    } catch (err) {
      logger.error(`failed get SCA Vulnerability list, err: ${err}`);
    }
    return [];
  }

  getSecretsBasedOnFileName(securityEvents: SecurityEvent[], repo: Repo) {
    const fileToSecrets = {};
    try {
      if (securityEvents.length == 0) {
        return fileToSecrets;
      }
      if (securityEvents[0].securityAlertType !== SecurityAlertType.secrets) {
        return fileToSecrets;
      }

      securityEvents.forEach(i => {
        if (!i.fileName) {
          return;
        }
        if (fileToSecrets[i.fileName]) {
          fileToSecrets[i.fileName].push(i.lineContent);
        } else {
          fileToSecrets[i.fileName] = [i.lineContent];
        }
      });
    } catch (err) {
      logger.error(`failed get secrets based on file name, repo: ${repo.fullName}, err: ${err}`);
    }
    return fileToSecrets;
  }

  getKeyValueMapByRuleIdAndData(jsonData: any, securityEvents: SecurityEvent[]) {
    let aggregatedItems = {};

    const repo: Repo = jsonData.code_repo;
    const fileToSecrets = this.getSecretsBasedOnFileName(securityEvents, repo);

    for (const event of securityEvents) {
      if (!event.fileName) {
        logger.error(`failed to add event to security event ${JSON.stringify(event)} due to file name empty`);
        continue;
      }

      let reviewersAsString = "";
      let pushType = "";
      let link = event.link;
      let mergedBy = "";
      if (event.relatedPR !== undefined) {
        try {
          //if there's no related PR will return blanks
          const reviewers = event.relatedPR.reviewers.map(reviewer => reviewer.author);
          if (reviewers.length) {
            reviewersAsString = reviewers.join(",");
          } else {
            reviewersAsString = Constant.NO_REVIEWER;
          }
          pushType = event.relatedPR.objType == CodeRepoTypes.pulls ? "Pull Request" : "Push";
          link = event.relatedPR.link;
          mergedBy = event.relatedPR.mergeUser.author;
        } catch (err) {
          logger.error(`failed set pr security event ${JSON.stringify(event, null, 4)}`);
        }
      }

      let titleInfo = "";
      if (event.blame.commitDescription != undefined) {
        titleInfo =
          event.blame.commitDescription.length > 1000 ? event.blame.commitDescription.substring(0, 1000) : event.blame.commitDescription;
      }

      const singleItem: PolicySecurityScanAggItem = new PolicySecurityScanAggItem();
      singleItem.isOldEvent = event.isOldEvent;

      let lineContent =
        event.lineContent.length > Constant.MATCH_CHARS_LIMIT
          ? event.lineContent.substring(0, Constant.MATCH_CHARS_LIMIT)
          : event.lineContent;
      let snippet =
        event.snippetContent.length > Constant.SNIPPET_CHARS_LIMIT
          ? event.snippetContent.substring(0, Constant.SNIPPET_CHARS_LIMIT)
          : event.snippetContent;

      const isSecret = event.securityAlertType === SecurityAlertType.secrets;
      if (isSecret) {
        let secretsToObfuscate = [];
        if (fileToSecrets[event.fileName]) {
          secretsToObfuscate = fileToSecrets[event.fileName];
        }
        secretsToObfuscate.push(lineContent);

        lineContent = this.passwordHelper.getObfuscatedPass(secretsToObfuscate, lineContent, repo.fullName);
        snippet = this.passwordHelper.getObfuscatedPass(secretsToObfuscate, snippet, repo.fullName);
      }

      //Set fix available
      let isFixAvailable = false;
      if (event.securityAlertType === SecurityAlertType.iac || event.securityAlertType === SecurityAlertType.sast) {
        if (
          event?.autoFixResponse?.autofixable ||
          ((isDevelopment() || isLocalDevelopment()) && event?.autoFixResponse?.chatgpt_autofixable)
        ) {
          isFixAvailable = true;
        }
      }

      if (event.securityAlertType === SecurityAlertType.sca) {
        if (event?.alertRecommendationResponse?.autofixable && event?.autoFixResponse?.autofixable) {
          isFixAvailable = true;
        }
      }

      //Set fix applied
      let isFixApplied = false;

      singleItem.isSilent = event.isSilent || false;
      singleItem.fileName = event.fileName || "";
      singleItem.fileUri = event.link;
      singleItem.version = event.branch || "";
      singleItem.startLine = event.startLineNumber != undefined && event.startLineNumber != -1 ? event.startLineNumber : undefined;
      singleItem.endLine = event.endLineNumber;
      singleItem.match = lineContent;
      singleItem.snippet = snippet;
      singleItem.date = event.blame.commitDate;
      singleItem.commitLink =
        event.blame.commitSha && jsonData.code_repo != undefined ? `${jsonData.code_repo.commitLink}/${event.blame.commitSha}` : "";
      singleItem.commitBy = `${event.blame.commiterName || ""} ${event.blame.commiterEmail || ""}`;
      singleItem.commiterName = event.blame.commiterName || "";
      singleItem.commiterEmail = event.blame.commiterEmail || "";
      singleItem.pushType = pushType;
      singleItem.title = titleInfo;
      singleItem.mergedBy = mergedBy;
      singleItem.link = link;
      singleItem.reviewers = reviewersAsString;
      singleItem.fixes = event.fixes;
      singleItem.fromCommitHistory = event.fromCommitHistory;
      singleItem.eduVideoLink = event.blame.eduVideoLink;
      singleItem.source = event.securityProvider;
      singleItem.ruleId = event.ruleId || "";
      singleItem.realMatch = event.realMatch || ""; //Dont change it!!!
      singleItem.snippetLineNumber = event.blame.snippetLineNumber;
      singleItem.securityAlert = event;
      singleItem.isFixAvailable = isFixAvailable;
      singleItem.isChatGPTFixable = event?.autoFixResponse?.chatgpt_autofixable || false;
      singleItem.isFixApplied = isFixApplied;
      singleItem.fixAppliedBy = singleItem.fixAppliedBy;
      singleItem.fixedVersion = event.fixedVersion;
      singleItem.installedVersion = event.installedVersion;
      singleItem.language = event?.blame?.language ? event?.blame?.language : "";
      singleItem.branch = repo.defaultBranch;
      singleItem.filePath = event.filePath || "";
      singleItem.lockfile = event.lockfile;
      if (event.alertRecommendationResponse.triggerPkgName) {
        singleItem.triggerPkgName = event.alertRecommendationResponse.triggerPkgName;
        singleItem.triggerPkgVersion = event.alertRecommendationResponse.triggerPkgVersion;
        singleItem.triggerPkgUpgradeVersion = event.alertRecommendationResponse.upgradeVersion;
      }

      if (!singleItem.realMatch) {
        logger.error(`failed add ${event.securityProvider} for repo: ${repo.name}, no match, policy: ${this.policyRuleMetadata.name}`);
        continue;
      }

      singleItem.setAggId();

      let unique = getUniqueInfoForAggregation(event);

      if (aggregatedItems.hasOwnProperty(unique)) {
        let info = aggregatedItems[unique];
        info.aggregated.push(singleItem);
        info.uniqueFiles.add(event.fileName);
      } else {
        const info = {
          aggregated: [],
          uniqueFiles: new Set(),
        };
        info.uniqueFiles.add(event.fileName);
        info.aggregated.push(singleItem);
        aggregatedItems[unique] = info;
      }
    }
    return aggregatedItems;
  }

  sortEvents(securityEvents: PolicySecurityScanAggItem[]) {
    try {
      const res = securityEvents.sort(
        (a, b) => this.timeHelper.getTimeIntervalFronNowInMili(a.date) - this.timeHelper.getTimeIntervalFronNowInMili(b.date),
      );
      return res;
    } catch (err) {
      logger.error(`failed sort ${this.policyRuleMetadata.name}, err: ${err}`);
    }
    return securityEvents;
  }

  private getIssueOwners(jsonData, aggregatedItems: PolicySecurityScanAggItem[]) {
    let issueOwners: IssueOwner[] = [];
    try {
      const map = new Map<string, IssueOwner>();
      for (const singleItem of aggregatedItems) {
        const { commiterName, commiterEmail } = singleItem;
        if (commiterName || commiterEmail) {
          issueOwners.push({
            name: commiterName || commiterEmail,
            email: commiterEmail,
          });
          break;
        }
      }

      // DOR TODO - rearrange order in all sast (code) pols

      if (issueOwners.length === 0 || issueOwners.every(i => i.name === "")) {
        //  if issue owners empty - find veteran reviewers
        issueOwners = this.getOwnersFromUsers(jsonData);
      }
      if (issueOwners.length === 0) {
        // get owner from Application owners (defined by users)
        issueOwners = this.getOwnersFromAppOwnersConfig(jsonData);
      }
      if (issueOwners.length === 0) {
        // get owners from app creator
        issueOwners = this.getOwnersFromAppCreator(jsonData);
      }

      return issueOwners;
    } catch (e) {
      logger.error(`failed to get issue owners, error; ${e}`);
    }
    return [];
  }
}

export class PolicySecurityScanAggItem extends AggregatedInfoForExclusion {
  fileName: string;
  fileUri: string;
  startLine: number;
  linkToExternalProduct: string;
  uid: string;
  endLine: number;
  match: string;
  realMatch: string;
  snippet: string;
  date: string;
  commitLink: string;
  commitBy: string;
  commiterName: string;
  additionalToolData: string;
  commiterEmail: string;
  pushType: string;
  title: string;
  mergedBy: string;
  link: string;
  reviewers: string;
  fixes: Fix[];
  fromCommitHistory: boolean;
  eduVideoLink: string;
  language: string;
  snippetLineNumber: number;
  securityAlert: SecurityEvent;
  isFixAvailable: boolean;
  isChatGPTFixable: boolean;
  isFixApplied: boolean;
  fixAppliedBy: string;
  installedVersion: string;
  pkgName: string;
  libName: string;
  libVersion: string;
  fixedVersion: string;
  branch: string;
  filePath: string;
  lockfile: string;
  version: string;

  triggerPkgName: string;
  triggerPkgVersion: string;
  triggerPkgUpgradeVersion: string;

  //Additional data need
  source: string;
  ruleId: string;

  //SCA
  sCAVulnerability: SCAVulnerability[] = [];
  dependencyType: string;
  dependencyChain: Dependency[];

  //Artifacts
  dockerVer: string;
  imageCreatedAt: string;
  pkgCount: number;
  binariesCount: number;
  sha: string;
  layer: string;
  baseImage: string;
  os: string;
  image: string;
  tag: string;
  imageLink: string;
  registryName: string;
  issueOwner: string;
  blameExists: boolean;
  graphExists: boolean;
  isOldEvent: boolean;

  getExclusionObj() {
    const i: AggregatedCodeData = new AggregatedCodeData();
    i.fileName = this.fileName;
    i.match = this.realMatch;
    i.ruleID = this.ruleId;
    return i;
  }

  setAggId() {
    try {
      this.aggId = StringHelper.combineStrings(this.realMatch, this.fileName);
      this.hashAggId = StringHelper.hashMd5(this.aggId);
    } catch (e) {
      logger.error(`failed to set agg id, error: ${e}`);
    }
  }
}

export default PolicySecurityScan;
