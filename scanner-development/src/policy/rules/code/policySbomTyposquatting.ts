import { ProcessCustomizationType } from "azure-devops-node-api/interfaces/CoreInterfaces";
import { SbomEvent } from "../../../entitis/artifactoryTypes";
import {
  CodeRepoTypes,
  getUniqueInfoForAggregation,
  IssueOwner,
  Repo,
  repoResourceType,
  SecurityAlertType,
  SecurityEvent,
} from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { ExtraInfo } from "../../../entitis/issuesTypes";
import { ChangeReason, getDependencyType, severityReasons } from "../../../entitis/service/blameTypes";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import { ExtendedSbomComponent } from "../../../helper/sbom/sbomHelper";
import TimeHelper from "../../../helper/timeHelper";
import loggerImport from "../../../logger";
import { DependencyType } from "../../../mongo/sbom/types";
import PolicyRulesBase from "./policyRulesBase";
import { PolicySecurityScanAggItem } from "./policySecurityScan";
import { SourceToolType } from "@oxappsec/ox-consolidated-categories";

const logger = loggerImport.getDebugLogger();

class PolicySbomTyposquatting extends PolicyRulesBase {
  private commiters: IssueOwner[] = [];

  async eval(jsonData) {
    let securityEvents: SecurityEvent[] = jsonData.securityEvents;
    securityEvents = securityEvents.filter(i => i.securityAlertType === SecurityAlertType.typosquatting);
    const pkgToPass = this.getValueFromRuleArgs("ignoreInternalPackageScopes");
    const relevantSecEvents = [];

    for (const event of securityEvents) {
      if (pkgToPass.find(i => i === event.pkgName)) {
        logger.info(`event was ignored, pkgName: ${event.pkgName}`);
        continue;
      }
      relevantSecEvents.push(event);
    }

    if (relevantSecEvents.length === 0) {
      return [];
    }

    let sbomEvent: SbomEvent[] = jsonData.sbom;
    if (!sbomEvent) {
      sbomEvent = [];
    }

    const aggregatedInfo = this.getKeyValueMapByRuleIdAndData(jsonData, relevantSecEvents, sbomEvent);

    let res = [];
    for (const events of Object.values(aggregatedInfo) as any) {
      if (events.length == 0) {
        continue;
      }

      //Get the hights original severity alert
      let topLevelEventData = events.aggregated[0].securityAlert as SecurityEvent;

      this.commiters.push({
        name: topLevelEventData.blame.commiterName,
        email: topLevelEventData.blame.commiterEmail,
      });

      const violationInfoTitle = "";
      const aggregated = {
        aggregatedItems: events.aggregated,
        columns: "policySecurityScan",
        violationInfoTitle,
      };

      //Set additional info for secrets
      let extraInfo = topLevelEventData.extraInfo;

      const aggregatedItems: PolicySecurityScanAggItem[] = events.aggregated;
      const issueOwners = this.getIssueOwners(jsonData, aggregatedItems);
      const repo = jsonData.code_repo;
      const securityItems = aggregatedItems.map(i => i.securityAlert);
      const lib: ExtendedSbomComponent = this.getCorrespondedLib(topLevelEventData, sbomEvent, repo.fileLink);

      let mainTitle = this.getIssueInfoPretty(topLevelEventData, lib);
      const secondaryTitle = this.getDescriptionInfoPretty(topLevelEventData, lib);
      const recommendation = this.getRecommendationInfoPretty(topLevelEventData, lib);

      if (topLevelEventData.blame.eduVideoLink !== undefined) {
        extraInfo.push({
          key: "Recommended Video",
          value: topLevelEventData.blame.eduVideoLink,
        });
      }

      const uniqueAgg = this.getCustomIssueId(getUniqueInfoForAggregation(topLevelEventData));

      //Keep this last before the generate item function
      if (topLevelEventData.ruleId) {
        extraInfo.push({
          key: "Rule Name",
          value: `${topLevelEventData.ruleId}`,
        });
      }

      const changeReasons = [];
      if (topLevelEventData.similarityScore >= 0.75) {
        const changeReason: ChangeReason = new ChangeReason(
          severityReasons.highMatchJaking.shortName,
          severityReasons.highMatchJaking.reason,
          severityReasons.highMatchJaking.changeNumber,
          severityReasons.highMatchJaking.changeCategory,
        );
        changeReasons.push(changeReason);
      } else if (topLevelEventData.similarityScore >= 0.6 && topLevelEventData.similarityScore < 0.75) {
        const changeReason: ChangeReason = new ChangeReason(
          severityReasons.midMatchJaking.shortName,
          severityReasons.midMatchJaking.reason,
          severityReasons.midMatchJaking.changeNumber,
          severityReasons.midMatchJaking.changeCategory,
        );
        changeReasons.push(changeReason);
      } else {
        const changeReason: ChangeReason = new ChangeReason(
          severityReasons.lowhMatchJaking.shortName,
          severityReasons.lowhMatchJaking.reason,
          severityReasons.lowhMatchJaking.changeNumber,
          severityReasons.lowhMatchJaking.changeCategory,
        );
        changeReasons.push(changeReason);
      }

      let item = this.generateItemForReport(
        true,
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
        [SourceToolType.SBOM],
        ["trivy", repoResourceType.depJacking],
        extraInfo,
        uniqueAgg,
        issueOwners,
        "",
        topLevelEventData.ruleId,
        topLevelEventData.blame.cwe,
        topLevelEventData.snippetContent,
        [],
        this.policyRuleMetadata.severity,
        topLevelEventData.blame.dependencyChain,
        topLevelEventData.blame.publicExploitLink,
        topLevelEventData.originalSeverityStr,
        [],
        getSeverityChanges(topLevelEventData.originalSeverity, topLevelEventData.severity),
        changeReasons,
        [],
        this.getOriginalSev(securityItems),
        topLevelEventData?.blame?.runtime?.languageInfo,
      );
      item.blameExists = !!lib.blame;
      item.graphExists = lib.blame?.graphExists || false;

      if (lib?.blame?.triggerPackage) {
        item.scaTriggerPkg = `${lib.blame.triggerPackage.name}@${lib?.blame?.triggerPackage.version}`;
      }
      if (lib) {
        item.libId = `${lib.pkgManager}|${lib.name}|${lib.version}`;
      }

      res.push(item);
    }

    return res;
  }

  getCorrespondedLib(securityEvent: SecurityEvent, sbomEvents: SbomEvent[], fileName: string) {
    const verKey = `${securityEvent.pkgName}@${securityEvent.installedVersion}`;
    for (const sbomEvent of sbomEvents) {
      for (const lib of sbomEvent.sbomHelper.extendedSbom.components) {
        try {
          const name = `${lib.name}@${lib.version}`;
          if (name === verKey) {
            if (!securityEvent.fileName) {
              securityEvent.fileName = lib.fileName || "";
            }
            if (!securityEvent.link) {
              securityEvent.link = lib?.blame?.link || "";
            }
            if (securityEvent.link) {
              securityEvent.link = fileName + lib?.blame?.fileName + securityEvent.linkPrefix + lib?.blame?.startLineNumber || "";
            }
            if (securityEvent.startLineNumber == 0) {
              securityEvent.startLineNumber = lib?.blame?.startLineNumber || 0;
            }
            if (securityEvent.endLineNumber == 0) {
              securityEvent.endLineNumber = lib?.blame?.endLineNumber || 0;
            }
            if (!securityEvent.lineContent) {
              securityEvent.lineContent = lib?.blame?.lineContent || "";
            }
            if (!securityEvent.snippetContent) {
              securityEvent.snippetContent = lib?.blame?.snippetContent || "";
            }
            if (!securityEvent.filePath) {
              securityEvent.filePath = lib?.blame?.fileName || "";
            }
            return lib;
          }
        } catch (err) {
          logger.error(`failed process single lib in code lib outdated: ${JSON.stringify(lib.additionalInsight)} err: ${err}`);
        }
      }
    }
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
        logger.error(`failed get single unique agg typeSq alert, err: ${err}`);
      }
    });

    if (newAggItems.length == 0) {
      return aggItems;
    }
    return newAggItems;
  }

  addExtraInfo(topLevelEventData: SecurityEvent, extraInfo: ExtraInfo[]) {
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

  getIssueInfoPretty(securityEvent: SecurityEvent, i: ExtendedSbomComponent) {
    if (i) {
      try {
        const dependencyType: DependencyType = getDependencyType(i?.blame?.dependencyType);
        const lang = i?.blame?.language ? ` ${i?.blame?.language}` : ``;

        if (dependencyType === DependencyType.Direct) {
          return `${i.blame.triggerPackage.name}@${i.blame.triggerPackage.version} is a${lang} direct dependency typosquatting '${securityEvent.legitimatePkgName}'`;
        } else if (dependencyType === DependencyType.Indirect) {
          return `${i.blame.triggerPackage.name}@${i.blame.triggerPackage.version} is a${lang} direct dependency containing ${securityEvent.pkgName}@${securityEvent.installedVersion} which is typosquatting '${securityEvent.legitimatePkgName}'`;
        }
      } catch (err) {
        logger.error(`failed, name: ${this.policyRuleMetadata.name}, get issue title info pretty, err: ${err}`);
      }
    }
    return `${securityEvent.pkgName}@${securityEvent.installedVersion} is dependency typosquatting '${securityEvent.legitimatePkgName}'`;
  }

  getDescriptionInfoPretty(securityEvent: SecurityEvent, i: ExtendedSbomComponent) {
    let description;
    if (i) {
      try {
        const dependencyType: DependencyType = getDependencyType(i?.blame?.dependencyType);

        if (dependencyType === DependencyType.Direct) {
          description = `${i.blame.triggerPackage.name}&#64;${i.blame.triggerPackage.version} is a ${i.blame.language} direct open-source malicious dependency typosquatting the library '${securityEvent.legitimatePkgName}'. Typosquatting was determined due to the name and metadata similarity between the malicious library ‘${securityEvent.pkgName}' and the legitimate library '${securityEvent.legitimatePkgName}’.`;
        } else if (dependencyType === DependencyType.Indirect) {
          description = `${i.blame.triggerPackage.name}&#64;${i.blame.triggerPackage.version} is a ${i.blame.language} direct open-source containing the indirect malicious ${securityEvent.pkgName}&#64;${securityEvent.installedVersion} dependency typosquatting the library '${securityEvent.legitimatePkgName}'. Typosquatting was determined due to the name and metadata similarity between the malicious library ‘${securityEvent.pkgName}' and the legitimate library '${securityEvent.legitimatePkgName}’.`;
        }
      } catch (err) {
        logger.error(`failed name: ${this.policyRuleMetadata.name}, get issue title info pretty, err: ${err}`);
      }
    }

    if (!description) {
      description = `${securityEvent.pkgName}&#64;${securityEvent.installedVersion} is open-source dependency typosquatting the library ${securityEvent.legitimatePkgName}. Typosquatting was determined due to the name and metadata similarity between the malicious library ‘${securityEvent.pkgName}' and the legitimate library '${securityEvent.legitimatePkgName}.`;
    }

    description = `${description}<br>`;

    if (i?.scaValidator?.pkgImported != undefined) {
      if (i?.scaValidator?.pkgImported == true) {
        description = `${description}<br>&bull; Malicious library '${securityEvent.pkgName}' is referenced in your code`;
      } else {
        description = `${description}<br>&bull; Malicious library '${securityEvent.pkgName}' are NOT referenced in your code`;
      }
    }

    if (securityEvent.registry) {
      description = `${description}<br>&bull; Malicious library '${securityEvent.pkgName}' is hosted in registry '${securityEvent.registry}'`;
      description = `${description}<br>&bull; Legitimate library '${securityEvent.legitimatePkgName}' is hosted in registry '${securityEvent.registry}'`;
    }

    const additional =
      "Typosquatting is a malicious tactic where attackers publish packages with names resembling legitimate ones, exploiting typing errors to trick users into downloading harmful code or vulnerabilities.";
    description = `${description}<br><br>${additional}`;

    if (i) {
      if (
        i?.additionalInsight?.downloads != undefined ||
        i?.additionalInsight?.projectInfo?.StarsCount != undefined ||
        i?.additionalInsight?.projectInfo?.OpenIssuesCount != undefined ||
        i?.additionalInsight?.projectInfo?.deprecated ||
        i?.additionalInsight?.projectInfo?.Homepage != undefined
      ) {
        description = `${description}<br><br>Typosquatting ${securityEvent.pkgName}&#64;${securityEvent.installedVersion} has:`;
      }
      if (i?.additionalInsight?.downloads != undefined) {
        description = `${description}<br>&bull; Downloaded - ${i?.additionalInsight?.downloads}`;
      }
      if (i?.additionalInsight?.projectInfo?.StarsCount != undefined) {
        description = `${description}<br>&bull; Starts - ${i?.additionalInsight?.projectInfo?.StarsCount}`;
      }
      if (i?.additionalInsight?.projectInfo?.OpenIssuesCount != undefined) {
        description = `${description}<br>&bull; Open issues count - ${i?.additionalInsight?.projectInfo?.OpenIssuesCount}`;
      }
      if (i?.additionalInsight?.projectInfo?.deprecated) {
        description = `${description}<br>&bull; Deprecated`;
      }
      if (i?.additionalInsight?.projectInfo?.Homepage != undefined) {
        description = `${description}<br>&bull; Homepage - ${i?.additionalInsight?.projectInfo?.Homepage}`;
      }
    }
    return description;
  }

  getRecommendationInfoPretty(securityEvent: SecurityEvent, i: ExtendedSbomComponent) {
    let res;
    if (i) {
      try {
        const dependencyType: DependencyType = getDependencyType(i?.blame?.dependencyType);
        if (dependencyType === DependencyType.Direct) {
          res = `Immediately remove the library ${i.blame.triggerPackage.name}&#64;${i.blame.triggerPackage.version} from your repo. Utilize dependency '${securityEvent.legitimatePkgName}' instead.`;
        } else if (dependencyType === DependencyType.Indirect) {
          res = `Consider moving to an alternative to ${i.blame.triggerPackage.name}&#64;${i.blame.triggerPackage.version} from your repo. This will remove references to ${securityEvent.pkgName}&#64;${securityEvent.installedVersion}`;
        }
      } catch (err) {
        logger.error(`failed, name: ${this.policyRuleMetadata.name}, get recommendation title info pretty, err: ${err}`);
      }
    }
    if (!res) {
      res = `Consider moving to an alternative to ${securityEvent.pkgName}&#64;${securityEvent.installedVersion} from your repo.`;
    }
    if (securityEvent.legitimatePkgLink) {
      res = `${res}<br><br>Dependency '${securityEvent.legitimatePkgName}' can be downloaded from: ${securityEvent.legitimatePkgLink}`;
    }
    return res;
  }

  getKeyValueMapByRuleIdAndData(jsonData: any, securityEvents: SecurityEvent[], sbomEvent) {
    const aggregatedItems = {};
    const repo: Repo = jsonData.code_repo;

    for (const event of securityEvents) {
      const lib: ExtendedSbomComponent = this.getCorrespondedLib(event, sbomEvent, repo.fileLink);
      if (lib) {
        event.blame = lib.blame;
      }

      if (!event.fileName) {
        logger.error(`failed to add event to security due to file name empty, pol: ${this.policyRuleMetadata.name}`);
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

      //Set fix available
      let isFixAvailable = false;
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

      if (event.blame.commiterName && event.blame.commiterEmail) {
        singleItem.commitBy = `${event.blame.commiterName || ""} ${event.blame.commiterEmail || ""}`;
      } else if (event.blame.commiterName) {
        singleItem.commitBy = event.blame.commiterName;
      } else if (event.blame.commiterEmail) {
        singleItem.commitBy = event.blame.commiterEmail;
      } else {
        singleItem.commitBy = "";
      }

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
      singleItem.isFixApplied = isFixApplied;
      singleItem.fixAppliedBy = singleItem.fixAppliedBy;
      singleItem.fixedVersion = event.fixedVersion;
      singleItem.installedVersion = event.installedVersion;
      singleItem.language = event?.blame?.language ? event?.blame?.language : "";
      singleItem.branch = repo.defaultBranch;
      singleItem.filePath = event.filePath || "";
      singleItem.lockfile = event.lockfile;
      if (event.blame?.triggerPackage) {
        singleItem.triggerPkgName = event.blame.triggerPackage.name;
        singleItem.triggerPkgVersion = event.blame.triggerPackage.version;
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

  private getIssueOwners(jsonData, aggregatedItems: PolicySecurityScanAggItem[]) {
    let issueOwners: IssueOwner[] = [];
    try {
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
export default PolicySbomTyposquatting;
