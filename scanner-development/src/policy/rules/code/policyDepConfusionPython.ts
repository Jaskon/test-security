import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
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
import { Severity } from "../../../entitis/reportTypes";
import { ChangeCategory, ChangeReason, getDependencyType, severityReasons } from "../../../entitis/service/blameTypes";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { getSeverityChanges } from "../../../helper/policy/severityHelper";
import { ExtendedSbomComponent } from "../../../helper/sbom/sbomHelper";
import TimeHelper from "../../../helper/timeHelper";
import loggerImport from "../../../logger";
import { DependencyType } from "../../../mongo/sbom/types";
import PolicyRulesBase from "./policyRulesBase";
import { PolicySecurityScanAggItem } from "./policySecurityScan";

const logger = loggerImport.getDebugLogger();

class PolicyDepConfusionPython extends PolicyRulesBase {
  private commiters: IssueOwner[] = [];

  async eval(jsonData) {
    try {
      let securityEvents: SecurityEvent[] = jsonData.securityEvents;

      securityEvents = securityEvents.filter(i => i.securityAlertType === SecurityAlertType.depConfusionPkgs);
      securityEvents = securityEvents.filter(i => i.isPkgAvailable);

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

      let changedSev = this.policyRuleMetadata.severity;
      let res = [];

      for (const events of Object.values(aggregatedInfo) as any) {
        if (events.length == 0) {
          continue;
        }

        const securityItems: SecurityEvent[] = events.aggregated.map(i => i.securityAlert);
        const changeReasons = [];
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

        const lib: ExtendedSbomComponent = this.getCorrespondedLib(topLevelEventData, sbomEvent, repo.fileLink);

        const fixLink = "https://packaging.python.org/en/latest/tutorials/packaging-projects/";
        const website = "https://pypi.org/";
        const mainTitle = `The internal package "${topLevelEventData.pkgName}" is open to dependency confusion attacks through the "${topLevelEventData.publicRegistry}" public registry`;
        const secondaryTitle = `Dependency confusion attacks can lead to severe consequences such as data theft, service interruptions, and resource misuse. <br>
        <br>
        Specifically, if internal package '${topLevelEventData.pkgName}' is available for public registration on the registry '${topLevelEventData.publicRegistry}', you are vulnerable to these attacks. An attacker could register a harmful package with the same name but a higher version number. This could trick your systems into downloading this malicious package, instead of the correct, internal one you intended to use.
        <br>
        <br>
        &bull; '${topLevelEventData.pkgName}' is used as an internal package from the private registry ${topLevelEventData.privateRegistryName}, at:  ${topLevelEventData.privateRegistryUrl}.`;

        const recommendation = `&bull; Use --index-url instead of --extra-index-url in your requirements.txt file. By doing this, the package manager will only gather data from the URL you've specified, instead of fetching from the public registry.<br>
&bull; Immediately register the exact internal package name ${topLevelEventData.pkgName} on the public registry "${topLevelEventData.publicRegistry}" in this [link](${fixLink}).<br>
Registering the package name as a placeholder, requires uploading a new, empty package on the official public registry "${topLevelEventData.publicRegistry}".<br>
The official website is available at this [link](${website}).<br>
Follow the instructions on how to upload a new package. Upload the package with a version lower than the one used internally, like 0.0.1. <br>
This measure is designed to stop a potential intruder from taking control of the internal package name.`;

        const isPrivate = repo.privateVisability;

        const availableForRegistryReason = ChangeReason.copy(severityReasons.availableForRegistry);
        const rceReason = ChangeReason.copy(severityReasons.potentialRCE);
        changeReasons.push(availableForRegistryReason);
        changeReasons.push(rceReason);

        if (!isPrivate) {
          changedSev = changedSev + 1;
          const reason = new ChangeReason(
            "Internal Package Exposure",
            "The issue is associated with a public repository that exposes internal Package for libraries, increasing the risk of unauthorized access and potential exploitation of proprietary information and systems.",
            1,
            ChangeCategory.Reachable,
          );
          changeReasons.push(reason);
        } else {
          const reason = new ChangeReason(
            "Internal Package Hidden",
            "The issue is associated with a private repository that does not expose internal Package for libraries. This reduces the risk of unauthorized access and potential exploitation of proprietary information and systems.",
            -0.1,
            ChangeCategory.Reachable,
          );
          changeReasons.push(reason);
        }

        const uniqueAgg = this.getCustomIssueId(getUniqueInfoForAggregation(topLevelEventData));

        //Keep this last before the generate item function
        if (topLevelEventData.ruleId) {
          extraInfo.push({
            key: "Rule Name",
            value: `${topLevelEventData.ruleId}`,
          });
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
          [repoResourceType.depConfusionPkgAlert],
          extraInfo,
          uniqueAgg,
          issueOwners,
          "",
          topLevelEventData.ruleId,
          topLevelEventData.blame.cwe,
          topLevelEventData.snippetContent,
          [],
          changedSev,
          topLevelEventData.blame.dependencyChain,
          topLevelEventData.blame.publicExploitLink,
          Severity[this.policyRuleMetadata.severity],
          [],
          getSeverityChanges(this.policyRuleMetadata.severity, changedSev),
          changeReasons,
          [],
          this.getOriginalSev(securityItems),
        );

        if (lib?.blame?.triggerPackage) {
          item.scaTriggerPkg = `${lib.blame.triggerPackage.name}@${lib?.blame?.triggerPackage.version}`;
        }
        if (lib) {
          item.libId = `${lib.pkgManager}|${lib.name}|${lib.version}`;
        }
        item.blameExists = lib ? !!lib.blame : false;
        item.graphExists = lib.blame?.graphExists || false;

        res.push(item);
      }

      return res;
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
  }

  getCorrespondedLib(securityEvent: SecurityEvent, sbomEvents: SbomEvent[], fileName: string) {
    const verKey = `${securityEvent.pkgName}`;

    for (const sbomEvent of sbomEvents) {
      for (const lib of sbomEvent.sbomHelper.extendedSbom.components) {
        try {
          const name = `${lib.name}`;
          if (name === verKey) {
            if (!securityEvent.link) {
              securityEvent.link = lib?.blame?.link || "";
            }
            if (securityEvent.link) {
              if (this.orgName === "org_5rvGe4lwDV8RhaIA") {
                logger.info(
                  `in getCorrespondedLib dep confusion, repo fileName: ${securityEvent.link}, fileName from lib: ${lib?.blame?.fileName}, link from lib: ${lib?.blame?.link}`,
                );
              }

              securityEvent.link = fileName + lib?.blame?.fileName + securityEvent.linkPrefix + lib?.blame?.startLineNumber || "";
              // securityEvent.link = securityEvent.link + lib?.blame?.link  || "";
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

  getKeyValueMapByRuleIdAndData(jsonData: any, securityEvents: SecurityEvent[], sbomEvent) {
    const aggregatedItems = {};
    const repo: Repo = jsonData.code_repo;

    for (const event of securityEvents) {
      if (this.orgName === "org_5rvGe4lwDV8RhaIA" || this.orgName === "org_OqUihy0OIgK9JeeQ") {
        logger.info(`inside getKeyValueMapByRuleIdAndData, secEvent link: ${event.link}`);
      }
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

      if (this.orgName === "org_OqUihy0OIgK9JeeQ" || this.orgName === "org_5rvGe4lwDV8RhaIA") {
        logger.info(`inside dependency confusion, event link: ${event.link}, event: ${JSON.stringify(event)}`);
      }

      let titleInfo = "";
      if (event.blame?.commitDescription != undefined) {
        titleInfo =
          event.blame.commitDescription.length > 1000 ? event.blame.commitDescription.substring(0, 1000) : event.blame.commitDescription;
      }

      const singleItem: PolicySecurityScanAggItem = new PolicySecurityScanAggItem();
      singleItem.isOldEvent = event.isOldEvent;

      let lineContent = "";
      if (event.lineContent) {
        lineContent =
          event.lineContent?.length > Constant.MATCH_CHARS_LIMIT
            ? event.lineContent.substring(0, Constant.MATCH_CHARS_LIMIT)
            : event.lineContent;
      }

      let snippet = "";
      if (event.snippetContent) {
        snippet =
          event.snippetContent.length > Constant.SNIPPET_CHARS_LIMIT
            ? event.snippetContent.substring(0, Constant.SNIPPET_CHARS_LIMIT)
            : event.snippetContent;
      }

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
      singleItem.eduVideoLink = event.eduVideoLink || event.blame.eduVideoLink || "";
      singleItem.source = event.securityProvider;
      singleItem.ruleId = event.ruleId || "";
      singleItem.realMatch = event.realMatch || ""; //Dont change it!!!
      singleItem.snippetLineNumber = event.blame.snippetLineNumber;
      singleItem.securityAlert = event;

      singleItem.language = event?.language ? event?.language : "";
      singleItem.branch = repo.defaultBranch;
      singleItem.filePath = event.filePath || "";
      singleItem.lockfile = event.lockfile;

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
export default PolicyDepConfusionPython;
