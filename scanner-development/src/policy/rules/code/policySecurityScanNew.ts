import { OxExclusionCategories } from "@oxappsec/ox-consolidated-exclusions";
import { capitalize } from "lodash";
import {
  CodeRepoTypes,
  getToolsNames,
  getUniqueInfoForAggregation,
  IssueOwner,
  Repo,
  SecurityAlertType,
  SecurityEvent,
} from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { ExtraInfo, SecretStatus } from "../../../entitis/issuesTypes";
import { ChangeReason, severityReasons } from "../../../entitis/service/blameTypes";
import { ToolNameForUI } from "../../../entitis/tool/toolsTypes";
import { enableByPolicy } from "../../../helper/commonUtils";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { getAllInfoForSeverity, getSeverityChanges } from "../../../helper/policy/severityHelper";
import StatesHelper from "../../../helper/statesHelper";
import TimeHelper from "../../../helper/timeHelper";
import PasswordHelper from "../../../helper/tools/passwordHelper";
import loggerImport from "../../../logger";
import cweMapping from "../../../policy/org/config/cwe.json";
import { cicdPostureRules } from "./policyCICDContextValues";
import PolicyRulesBase from "./policyRulesBase";
import { PolicySecurityScanAggItem } from "./policySecurityScan";
const util = require("util");

const logger = loggerImport.getDebugLogger();

class policySecurityScanNew extends PolicyRulesBase {
  private commiters: IssueOwner[] = [];
  private timeHelper: TimeHelper = new TimeHelper("");
  private passwordHelper: PasswordHelper = new PasswordHelper();

  async eval(jsonData) {
    let securityEvents: SecurityEvent[] = jsonData.securityEvents;

    const isSemGrepEnabled = enableByPolicy(ToolNameForUI.semgrep);
    const isCheckovEnabled = enableByPolicy(ToolNameForUI.checkov);

    // if semgrep/checkov is off by user, filter out events found by semgrep/checkov
    if (!isSemGrepEnabled) {
      securityEvents = securityEvents.filter(i => i.tool !== "semgrep" && i.securityProvidersArr.length === 1);
    }
    if (!isCheckovEnabled) {
      securityEvents = securityEvents.filter(i => i.tool !== "checkov" && i.securityProvidersArr.length == 1);
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

    //API security
    if ("oxPolicy_apiSecurity_1" === this.policyRuleMetadata.policyId) {
      if (!StatesHelper.Instance.isApiSecEnable) {
        return [];
      }
      securityEvents = securityEvents.filter(i => {
        return (
          scanTypeFromArgs.toLowerCase() === i.securityAlertTypeStr.toLowerCase() &&
          i.securitySubTypeAlertType === SecurityAlertType.securityApi
        );
      });
    }
    //Default all rest of policy
    else {
      securityEvents = securityEvents.filter(i => {
        return (
          scanTypeFromArgs.toLowerCase() === i.securityAlertTypeStr.toLowerCase() &&
          scanHistory === i.fromCommitHistory &&
          i.securitySubTypeAlertType !== SecurityAlertType.securityApi
        );
      });
    }

    // filter PII events that have PII tag from gitleaks
    const isPiiPolicy =
      "oxPolicy_policyPiiHardcoded_1" === this.policyRuleMetadata.policyId ||
      "oxPolicy_policyPiiHistory_1" === this.policyRuleMetadata.policyId;
    if (isPiiPolicy) {
      securityEvents = securityEvents.filter(i => i.isPII);
    } else {
      securityEvents = securityEvents.filter(i => !i.isPII);
    }

    //Secrets in logs
    if ("oxPolicy_policySecretLoggingInCode_1" === this.policyRuleMetadata.policyId) {
      securityEvents = securityEvents.filter(i => {
        return i.ruleId.includes("sensitive-logs.secrets");
      });
    } else {
      // exclude this rule so it would not trigger on other policies
      securityEvents = securityEvents.filter(i => {
        return !i.ruleId.includes("sensitive-logs.secrets");
      });
    }

    // pii in logs (semgrep)
    if ("oxPolicy_policyPiiLoggingInCode_1" === this.policyRuleMetadata.policyId) {
      securityEvents = securityEvents.filter(i => {
        return i.ruleId.includes("sensitive-logs.pii");
      });
    } else {
      // exclude this rule so it would not trigger on other policies
      securityEvents = securityEvents.filter(i => {
        return !i.ruleId.includes("sensitive-logs.pii");
      });
    }

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

      if (!this.shouldIncludeByPolicyEx(topLevelEventData.severity)) {
        continue;
      }

      const isSecret = topLevelEventData.securityAlertType === SecurityAlertType.secrets;
      const isSast = topLevelEventData.securityAlertType === SecurityAlertType.sast;

      this.commiters.push({
        name: topLevelEventData.blame.commiterName,
        email: topLevelEventData.blame.commiterEmail,
      });

      const violationInfoTitle = "";

      // for development - aggregated should be const
      let aggregated;

      if (isPiiPolicy) {
        aggregated = {
          aggregatedItems: this.arrangeForPII(events.aggregated, this.sortEvents), // special order for PII, with fallback method
          columns: "policySecurityScan",
          violationInfoTitle,
        };
      } else {
        aggregated = {
          aggregatedItems: this.sortEvents(events.aggregated),
          columns: "policySecurityScan",
          violationInfoTitle,
        };
      }

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
            if (topLevelEventData.fromCommitHistory) {
              topLevelEventData.recommendation = `This is an **active** ${topLevelEventData.violationInfo} in the Git History. Removing the secret from Git History is a dangerous operation that is discouraged. Please do the following:\n
              1. Revoke/Disable the ${topLevelEventData.violationInfo}.
              2. Moving forward, store secrets in an environment variable or secret manager.
              3. Change the code to access secrets using the method chosen above.`;
            } else {
              topLevelEventData.recommendation = `This is an **active** ${topLevelEventData.violationInfo} in the code. Please do the following:\n
              1. Revoke/Disable the found ${topLevelEventData.violationInfo}.
              2. Generate a new ${topLevelEventData.violationInfo}.
              3. Store the new ${topLevelEventData.violationInfo} in an environment variable or secret manager.
              4. Change the code to utilize the new ${topLevelEventData.violationInfo} via the method chosen above.
              5. Remove all mentions of the found ${topLevelEventData.violationInfo} from the code.
              \nWARNING: The found ${topLevelEventData.violationInfo} will still be visible in the Git History. Ensure it is revoked/disabled.`;
            }
          } else {
            secretStatus = "inactive";
            if (topLevelEventData.fromCommitHistory) {
              topLevelEventData.recommendation = `This is an **inactive** ${topLevelEventData.violationInfo} in the Git History. Removing the secret from Git History is a dangerous operation and not recommended. Please do the following:\n
              1. Moving forward, store secrets in an environment variable or secret manager.
              2. Change the code to access secrets using the method chosen above.
              \nWARNING: Removing secrets from Git History is a dangerous operation and not recommended.`;
            } else {
              topLevelEventData.recommendation = `This is an **inactive** ${topLevelEventData.violationInfo} in the code. Please do the following:\n
              1. Moving forward, store secrets in an environment variable or secret manager.
              2. Change the code to access secrets using the method chosen above.
              3. Remove all mentions of the found ${topLevelEventData.violationInfo} from the code.
              \nWARNING: The found ${topLevelEventData.violationInfo} will still be visible in the Git History. Ensure it is revoked/disabled.`;
            }
          }

          extraInfo.push({
            key: "Secret status",
            value: secretStatus,
          });
        } else {
          if (topLevelEventData.fromCommitHistory) {
            if (aggregatedItems.length == 1) {
              topLevelEventData.recommendation = `Please verify if the ${topLevelEventData.violationInfo} in the Git History is in use. Then do the following:\n
              1. If the secret is in use, please revoke it.
              2. Moving forward, store secrets in an environment variable or secret manager.
              3. Change the code to access secrets using the method chosen above.
              \nWARNING: Removing secrets from Git History is a dangerous operation and not recommended.`;
            } else {
              topLevelEventData.recommendation = `Please verify if the ${topLevelEventData.violationInfo} secrets in the Git History are in use. Then do the following:\n
              1. If the secrets are in use, please revoke them.
              2. Moving forward, store secrets in an environment variable or secret manager.
              3. Change the code to access secrets using the method chosen above.
              \nWARNING: Removing secrets from Git History is a dangerous operation and not recommended.`;
            }
          }
          //Git secrets
          else {
            if (aggregatedItems.length == 1) {
              topLevelEventData.recommendation = `Please verify if the ${topLevelEventData.violationInfo} in the code is in use. Then do the following:\n
              1. If the secret is in use, please revoke it.
              2. Moving forward, store secrets in an environment variable or secret manager.
              3. Change the code to access secrets using the method chosen above.
              \nWARNING: The found ${topLevelEventData.violationInfo} will still be visible in the Git History. Ensure it is revoked/disabled.`;
            } else {
              topLevelEventData.recommendation = `Please verify if the ${topLevelEventData.violationInfo} secrets in the code are in use. Then do the following:\n
              1. If the secrets are in use, please revoke them.
              2. Moving forward, store secrets in an environment variable or secret manager.
              3. Change the code to access secrets using the method chosen above.
              \nWARNING: The found ${topLevelEventData.violationInfo} secrets will still be visible in the Git History. Ensure they are revoked/disabled.`;
            }
          }
        }
      }

      let mainTitle = topLevelEventData.title || topLevelEventData.blame.summaryTitle || topLevelEventData.violationInfo;

      const securityItems: SecurityEvent[] = (events.aggregated as PolicySecurityScanAggItem[]).map(i => i.securityAlert);

      mainTitle = this.getIssueInfoPretty(topLevelEventData, isPrivate, mainTitle, secretStatus);
      const secondaryTitle = this.getDescriptionInfoPretty(topLevelEventData, mainTitle, secretStatus, securityItems, isPrivate, repo);
      const recommendation = this.getRecommendationInfoPretty(topLevelEventData, securityItems);

      if (topLevelEventData.eduVideoLink) {
        extraInfo.push({
          key: "Recommended Video",
          value: topLevelEventData.eduVideoLink,
        });
      } else if (topLevelEventData.blame.eduVideoLink) {
        extraInfo.push({
          key: "Recommended Video",
          value: topLevelEventData.blame.eduVideoLink,
        });
      }

      const cweObjectList = this.getCWEList(topLevelEventData, securityItems);

      const resInfo = getAllInfoForSeverity(securityItems, repo.fullName);
      const uniqueSeverityChanges = resInfo.uniqueSeverityFromAllAlerts as ChangeReason[];
      const originalSeverity = resInfo.originalSeverity;
      const originalSeverityStr = resInfo.originalSeverityStr;
      const newSeverityForPolicy = resInfo.newSeverityForPolicy;

      let learnMore = topLevelEventData.moreInfoLink;
      let uniqueProviders = this.getUniqueSecurityProviders(
        events.aggregated.map(i => i.securityAlert.securityProviders),
        topLevelEventData.securityProvider,
      );

      if (topLevelEventData.ruleId) {
        extraInfo.push({
          key: "Rule Name",
          value: `${topLevelEventData.ruleId}`,
        });
      }

      if (topLevelEventData.securityAlertType === SecurityAlertType.ox) {
        uniqueSeverityChanges.push(severityReasons.hasHighRCE);
      }

      if (isPiiPolicy) {
        this.handlePiiSevExtraInfo(uniqueSeverityChanges, events.aggregated);
      }

      const uniqueAgg = this.getCustomIssueId(getUniqueInfoForAggregation(topLevelEventData));

      let item = this.generateItemForReport(
        isSecret ? false : true,
        mainTitle,
        secondaryTitle,
        "",
        recommendation,
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
        cweObjectList,
        newSeverityForPolicy,
        topLevelEventData.blame.dependencyChain,
        topLevelEventData.blame.publicExploitLink,
        originalSeverityStr,
        [],
        getSeverityChanges(originalSeverity, newSeverityForPolicy),
        uniqueSeverityChanges,
        [],
        this.getOriginalSev(securityItems),
        topLevelEventData?.blame?.runtime?.languageInfo,
        false,
        "",
        this.getOscarIdForSecretEvent(securityItems),
        this.setScaFixType(topLevelEventData, this.policyRuleMetadata.functionName),
      );

      item.oxRecommendationExists = topLevelEventData?.alertRecommendationResponse?.recommendation ? true : false;
      item.commitInfoExists = topLevelEventData?.blame?.commitSha ? true : false;

      //Set silent
      let isActive = securityItems.find(i => !i.isSilent);
      if (!isActive) {
        item.isSilent = true;
      }

      item.eventFromExternalTool = securityItems.filter(i => !i.oxTool).length > 0;
      if (secretStatus !== null) {
        item["secretStatus"] = secretStatus;
      }

      if (isSecret) {
        if (!topLevelEventData.ruleId.toLowerCase().includes("generic")) {
          item.exclusionCategory = OxExclusionCategories.known_secrets;
        }
      }

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

  getIssueInfoPretty(securityEvent: SecurityEvent, isPrivate: boolean, mainTitle: string, secretStatus: string) {
    try {
      //Secret
      if (securityEvent.securityAlertType === SecurityAlertType.secrets) {
        if (
          "oxPolicy_policySecretLoggingInCode_1" === this.policyRuleMetadata.policyId ||
          "oxPolicy_policyPiiLoggingInCode_1" === this.policyRuleMetadata.policyId
        ) {
          return capitalize(mainTitle);
        } else if ("oxPolicy_policyPiiHardcoded_1" === this.policyRuleMetadata.policyId) {
          mainTitle = `${securityEvent.violationInfo} is exposed in code`;
        } else if ("oxPolicy_policyPiiHistory_1" === this.policyRuleMetadata.policyId) {
          mainTitle = `${securityEvent.violationInfo} was found in the history of a ${isPrivate ? "private" : "public"} repository`;
        } else {
          mainTitle = `${secretStatus ? secretStatus[0].toUpperCase() + secretStatus.slice(1) + " " : ""}${mainTitle} was found in the ${
            securityEvent.fromCommitHistory ? "history" : "code"
          } of a ${isPrivate ? "private" : "public"} repository`;
        }
      }
    } catch (err) {
      logger.error(`failed get issue title info pretty`, err);
    }

    return mainTitle;
  }

  getDescriptionInfoPretty(
    securityEvent: SecurityEvent,
    mainTitle: string,
    secretStatus: string,
    securityItems: SecurityEvent[],
    isPrivate: boolean,
    repo: Repo,
  ) {
    try {
      if (securityEvent.description) {
        return securityEvent.description;
      }

      //Secret
      if (securityEvent.securityAlertType === SecurityAlertType.secrets) {
        if ("oxPolicy_policySecretLoggingInCode_1" === this.policyRuleMetadata.policyId) {
          const secret = mainTitle.split(" is leaked via logging in code")[0];
          mainTitle = `Secret leaking code detected. ${secret} is being leaked to a logger`;

          if (securityEvent.blame?.detailedTitle) {
            mainTitle = `${mainTitle}.

${securityEvent.blame?.detailedTitle}`;
          }

          return `${mainTitle}`;
        }

        if ("oxPolicy_policyPiiLoggingInCode_1" === this.policyRuleMetadata.policyId) {
          if (securityEvent.blame?.detailedTitle) {
            return `${securityEvent.blame?.detailedTitle}`;
          }
          return `${mainTitle}`;
        }

        if ("oxPolicy_policyPiiHardcoded_1" === this.policyRuleMetadata.policyId) {
          let secondaryTitle = `${mainTitle}.
          `;
          if (isPrivate) {
            secondaryTitle += `All developers with minimal access to the repo will be able to access this PII. This may violate any number of compliance and privacy standards.`;
          } else {
            secondaryTitle += `Anyone can access the public repo and view the PII. This may violate any number of compliance and privacy standards.`;
          }

          try {
            const key = `${repo.name}_${securityEvent.ruleId}_code`;
            const total = StatesHelper.Instance.piiEventsCounter[key];
            const remaining = total - Constant.piiCollectLimit;
            if (remaining > 0) {
              secondaryTitle += `<br>
There are ${remaining} more occurences of this violation. <br><br>`;

              secondaryTitle += `To see all events please run this command on your repo code: <br>

grep -r -E -o --exclude-dir=node_modules "mail[^\r\n]{0,50}[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"`;
            }
          } catch (e) {
            logger.error(`failed to get total pii events from counter for ${repo.name}`);
          }

          return secondaryTitle;
        }

        if ("oxPolicy_policyPiiHistory_1" === this.policyRuleMetadata.policyId) {
          let secondaryTitle = `${mainTitle}
          `;
          if (isPrivate) {
            secondaryTitle += `All developers with minimal access to the repo will be able to access this PII. This may violate any number of compliance and privacy standards.`;
          } else {
            secondaryTitle += `Anyone can access the public repo and view the PII. This may violate any number of compliance and privacy standards.`;
          }

          try {
            const key = `${repo.name}_${securityEvent.ruleId}_history`;
            const total = StatesHelper.Instance.piiEventsCounter[key];
            const remaining = total - Constant.piiCollectLimit;

            if (remaining > 0) {
              secondaryTitle += `<br>
  There are ${remaining} more occurences of this violation.`;
            }
          } catch (e) {
            logger.error(`failed to get total pii events from counter for ${repo.name}`);
          }

          return secondaryTitle;
        }

        if (secretStatus == "active") {
          return `${mainTitle}. The secret is considered live or active by the system it is meant to connect to.
          <br/>${securityEvent.title}`;
        } else if (secretStatus == "inactive") {
          return `${mainTitle}. The secret is disabled or revoked by the system it is meant to connect to.
          <br/>${securityEvent.title}`;
        } else {
          return `${mainTitle}.`;
        }
      }
    } catch (err) {
      logger.error(`failed get description info pretty in: ${this.policyRuleMetadata.name}`, err);
    }
    return securityEvent.title;
  }

  getRecommendationInfoPretty(securityEvent: SecurityEvent, securityItems: SecurityEvent[]) {
    try {
      if ("oxPolicy_policySecretLoggingInCode_1" === this.policyRuleMetadata.policyId) {
        return `Add OX to your repos pipeline to detect and block secrets from being logged in your code.

Educate developers about the security risks associated with logging secrets and emphasize the importance of masked or tokenized log entries for sensitive data. Implement rigorous code review processes to detect and prevent this vulnerability before production deployment.`;
      }

      if ("oxPolicy_policyPiiLoggingInCode_1" === this.policyRuleMetadata.policyId) {
        return `Add OX to your repos pipeline to detect and block PII from being logged in your code.

Train developers on the importance of preserving user privacy by not logging PII and emphasize using anonymization or tokenization techniques when logging user-related data. Strengthen code review processes to detect and rectify PII disclosure before code reaches production.`;
      }

      if ("oxPolicy_policyPiiHardcoded_1" === this.policyRuleMetadata.policyId) {
        return `Add OX to your repos pipeline to detect and block PII from being exposed in your code.

Educate developers on the potential ramifications of embedding PII directly within code and provide guidelines for safer alternatives, such as using environment variables or secure storage solutions. Strengthen code review processes and ensure adherence to data protection principles, emphasizing the importance of keeping PII out of the codebase.`;
      }

      if ("oxPolicy_policyPiiHistory_1" === this.policyRuleMetadata.policyId) {
        return `Add OX to your repos pipeline to detect and block PII from being exposed in your git history.

Educate developers on the potential ramifications of embedding PII directly within code and provide guidelines for safer alternatives, such as using environment variables or secure storage solutions. Strengthen code review processes and ensure adherence to data protection principles, emphasizing the importance of keeping PII out of the codebase.`;
      }

      const exist = securityItems.find(i => i.alertRecommendationResponse?.recommendation);
      if (exist) {
        return exist?.alertRecommendationResponse?.recommendation;
      }
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
    let r = [];
    try {
      const exist = new Set();
      securityEventArray.forEach(i => {
        if (i.cweList?.length) {
          const cweList = Array.from(new Set(i.cweList));
          if (!cweList) {
            return;
          }
          cweList.forEach(j => {
            if (exist.has(j)) {
              return;
            }
            exist.add(j);
            r.push(j);
          });
        }
      });
    } catch (err) {
      logger.error(`failed get CWE list, err: ${err}`, err);
    }
    if (r.length == 0) {
      r = securityEvent.cweList;
    }
    const cweObjectList = [];
    for (const cwe of r) {
      if (cweMapping.hasOwnProperty(cwe)) {
        cweObjectList.push(cweMapping[cwe]);
      }
    }
    return cweObjectList;
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
          fileToSecrets[i.fileName].push(i.secretWithoutObfuscation);
        } else {
          fileToSecrets[i.fileName] = [i.secretWithoutObfuscation];
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
        if (
          "oxPolicy_policySecretLoggingInCode_1" !== this.policyRuleMetadata.policyId &&
          "oxPolicy_policyPiiLoggingInCode_1" !== this.policyRuleMetadata.policyId
        ) {
          let secretsToObfuscate = [];
          if (fileToSecrets[event.fileName]) {
            secretsToObfuscate = fileToSecrets[event.fileName];
          }
          secretsToObfuscate.push(lineContent);

          lineContent = this.passwordHelper.getObfuscatedPass(secretsToObfuscate, lineContent, repo.fullName);
          snippet = this.passwordHelper.getObfuscatedPass(secretsToObfuscate, snippet, repo.fullName);
        }
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
      singleItem.linkToExternalProduct = event.linkToExternalProduct;
      singleItem.uid = event?.uid || "";

      // Special handling of bitbucket stash
      if (isSecret && jsonData.code_repo != undefined && jsonData.code_repo.type === "Bitbucket-Stash") {
        if (event.blame.commitSha) {
          singleItem.commitLink = `${jsonData.code_repo.commitLink}${event.fileName}?at=${event.blame.commitSha}#${
            event.startLineNumber ?? 0
          }`;

          singleItem.fileUri = singleItem.commitLink;
        }
      } else {
        singleItem.commitLink =
          event.blame.commitSha && jsonData.code_repo != undefined ? `${jsonData.code_repo.commitLink}/${event.blame.commitSha}` : "";
      }

      if (event.blame.commiterName && event.blame.commiterEmail) {
        singleItem.commitBy = `${event.blame.commiterName || ""} ${event.blame.commiterEmail || ""}`;
      } else if (event.blame.commiterName) {
        singleItem.commitBy = event.blame.commiterName;
      } else if (event.blame.commiterEmail) {
        singleItem.commitBy = event.blame.commiterEmail;
      } else {
        singleItem.commitBy = "";
      }

      //dor tests
      // BB
      // if (StatesHelper.Instance.orgName === "org_SHCed8jc0D3ct4kw") {
      //   link = `${link.replace("commits", "src")}/${event.fileName}#lines-${event.startLineNumber}`;
      //   singleItem.fileUri = link;
      //   singleItem.commitLink = link;
      // }

      // // azure
      // if (StatesHelper.Instance.orgName === "org_4lp2ahIToo4hQx7q") {
      //   // ?refName=refs%2Fheads%2Fmain&path=%2Ftest.ts
      //   // ?refName=refs%2Fheads%2Fmain&path=%2Fhello.ts&_a=compare
      //   link = `${event.link}?path=/${event.fileName}`;
      //   singleItem.fileUri = link;
      //   singleItem.commitLink = link;
      // }

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
      singleItem.filePath = event.filePath;
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

      if (issueOwners.length === 0 || issueOwners.every(i => i.name === "")) {
        issueOwners = this.getOwnersFromUsers(jsonData);
      }
      if (issueOwners.length === 0) {
        issueOwners = this.getOwnersFromAppOwnersConfig(jsonData);
      }
      if (issueOwners.length === 0) {
        issueOwners = this.getOwnersFromAppCreator(jsonData);
      }

      return issueOwners;
    } catch (e) {
      logger.error(`failed to get issue owners, error; ${e}`);
    }
    return [];
  }
}

export default policySecurityScanNew;
