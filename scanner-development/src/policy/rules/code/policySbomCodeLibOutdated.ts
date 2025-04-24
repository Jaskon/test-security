import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import { SbomEvent, Version } from "../../../entitis/artifactoryTypes";
import { IssueOwner, Repo } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { ChangeReason, SeverityChange, severityReasons } from "../../../entitis/service/blameTypes";
import { getMonoRepoFilePath } from "../../../helper/commonUtils";
import { ExtendedSbomComponent } from "../../../helper/sbom/sbomHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import { PolicySbomCodeLicensesAggItem } from "./policySbomCodeLicenses";

const logger = loggerImport.getDebugLogger();

class PolicySbomCodeLibOutdated extends PolicyRulesBase {
  async eval(jsonData) {
    const sbomEvent: SbomEvent[] = jsonData.sbom;

    const diffAlowedFromArgs = this.getValueFromRuleArgs("daysCheck");
    if (isNaN(diffAlowedFromArgs)) {
      throw `diffAlowedFromArgs from args is not number, ${diffAlowedFromArgs.toString()}`;
    }

    const compareMajorVersion = this.getValueFromRuleArgs("compareMajorVersion");
    let compareMajorVersionCheck: boolean = compareMajorVersion[0].toLowerCase() === "Major version".toLowerCase();

    const typeFromArgs = this.getValueFromRuleArgs("type");
    if (typeFromArgs !== "direct" && typeFromArgs !== "indirect") {
      throw `typeFromArgs ${typeFromArgs} are not direct or indirect`;
    }
    const direct = typeFromArgs === "direct";

    const items = this.getKeyValueMapByRuleIdAndData(jsonData, diffAlowedFromArgs, compareMajorVersionCheck, sbomEvent, direct);

    const res = [];
    for (const itemInfo of items) {
      try {
        const lib: ExtendedSbomComponent = itemInfo.lib;
        const versionInfo: Version = itemInfo.versionInfo;

        let violationInfoTitle = `Library directly referenced in code is not up to date: ${lib.name}@${lib.additionalInsight.currentVer.version}, version ${lib.additionalInsight.latestVer.version} was available ${lib.additionalInsight.latestVer.timeInDays} days ago`;
        let second = `${lib.name} was deployed on date ${lib.additionalInsight.currentVer.timeStr}. Version ${lib.additionalInsight.currentVer.version} was published on date ${lib.additionalInsight.currentVer.timeStr}. The latest version is ${lib.additionalInsight.latestVer.version} which was published on date ${lib.additionalInsight.latestVer.timeStr}`;
        let fixLink = `https://www.google.com/search?q=alternative+to+${lib.name} library`;
        if (lib?.additionalInsight?.linkToFix != undefined) {
          fixLink = lib?.additionalInsight?.linkToFix;
        }

        let rec = `Please update library ${lib.name} to the latest version ${lib.additionalInsight.latestVer.version}`;

        if (!direct) {
          violationInfoTitle = `Library indirectly referenced in code is not up to date: ${lib.name}@${lib.additionalInsight.currentVer.version}`;
          rec = `Please identify which of your directly referenced libraries have references to Library ${lib.name}. Once identified please consider updating the directly referenced libraries`;
          fixLink = "";
        }

        const changeReasons = [];

        const aggregated = {
          aggregatedItems: itemInfo.singleItem,
          columns: "policySecurityScan",
          violationInfoTitle,
        };

        if (lib.blame.dependencyType === "direct") {
          const directReason = ChangeReason.copy(severityReasons.directDependency);
          changeReasons.push(directReason);
        } else if (lib.blame?.dependencyChain) {
          if (lib.blame.dependencyChain.length < 3) {
            const indirectReason = ChangeReason.copy(severityReasons.firstLevelIndirectDependency);
            changeReasons.push(indirectReason);
          } else {
            const deepIndirectReason = ChangeReason.copy(severityReasons.deepLevelIndirectDependency);
            changeReasons.push(deepIndirectReason);
          }
        }

        const oldUnmaintainedCodeReason = ChangeReason.copy(severityReasons.oldUnmaintainedCode);
        changeReasons.push(oldUnmaintainedCodeReason);

        let item = this.generateItemForReport(
          true,
          violationInfoTitle,
          second,
          violationInfoTitle,
          rec,
          "",
          "",
          [],
          "",
          true,
          fixLink,
          aggregated,
          [SourceToolType.SBOM],
          ["trivy", "trivy-sbom"],
          [],
          this.getCustomIssueId(lib?.purl),
          itemInfo.issueOwner,
          "",
          this.policyRuleMetadata.ruleId,
          [],
          "",
          [],
          this.policyRuleMetadata.severity,
          [],
          "",
          "",
          [],
          SeverityChange.NotApplicable,
          changeReasons,
          [],
        );

        if (lib?.blame?.triggerPackage) {
          item.scaTriggerPkg = `${lib.blame.triggerPackage.name}@${lib?.blame?.triggerPackage.version}`;
        }

        item.blameExists = !!lib.blame;
        item.graphExists = lib.blame?.graphExists || false;
        item.problematicPkg = `${lib.name}@${lib.version}`;

        item.libId = `${lib.pkgManager}|${lib.name}|${lib.version}`;
        res.push(item);
      } catch (err) {
        logger.error(
          `failed to add a single item for policy ${this.policyRuleMetadata.name} err: ${err}, lib: ${JSON.stringify(itemInfo)}`,
        );
      }
    }

    return res;
  }

  getKeyValueMapByRuleIdAndData(
    jsonData: any,
    diffAllowed: number,
    compareMajorVersionCheck: boolean,
    sbomEvents: SbomEvent[],
    direct: boolean,
  ) {
    let items = [];
    const notApprovedLibs = [];
    for (const sbomEvent of sbomEvents) {
      for (const lib of sbomEvent.sbomHelper.extendedSbom.components) {
        try {
          //Dont show again deprecated
          const deprecated = lib?.additionalInsight?.projectInfo?.deprecated;
          if (deprecated != undefined) {
            if (deprecated) {
              continue;
            }
          }

          //Check direct
          let alertDirect = false;
          if (lib?.blame?.dependencyType != undefined) {
            alertDirect = lib.blame.dependencyType.toLowerCase() === "direct";
          }
          if (direct != alertDirect) {
            continue;
          }

          //Find next major version
          let versionInfo: Version;
          if (!compareMajorVersionCheck) {
            versionInfo = lib.additionalInsight.nextVersionAfterCurrent;
          } else {
            if (lib.additionalInsight.currentVer == undefined || lib.additionalInsight.nextReleasesVer == undefined) {
              continue;
            }

            versionInfo = lib.additionalInsight.nextReleasesVer as Version;
          }

          //Check if the new version available in the word more then policy
          if (versionInfo == undefined) {
            continue;
          }
          //Just sanity check
          if (versionInfo.version === lib?.additionalInsight?.currentVer.version) {
            continue;
          }
          if (versionInfo.timeInDays < diffAllowed) {
            continue;
          }

          notApprovedLibs.push({ lib: lib, versionInfo: versionInfo });
        } catch (err) {
          logger.error(`failed process single lib in code lib outdated: ${JSON.stringify(lib.additionalInsight)} err: ${err}`);
        }
      }
    }

    const repo: Repo = jsonData.code_repo;
    const unique = new Set();
    for (const notApprovedLib of notApprovedLibs) {
      try {
        const lib: ExtendedSbomComponent = notApprovedLib.lib;
        const versionInfo: Version = notApprovedLib.versionInfo;
        const issueOwner: IssueOwner[] = [];

        if (lib.blame.commitDate && lib.blame.commiterEmail) {
          issueOwner.push({
            name: lib.blame.commiterName,
            email: lib.blame.commiterEmail,
          } as IssueOwner);
        }

        const singleItem: PolicySbomCodeLicensesAggItem = new PolicySbomCodeLicensesAggItem();
        singleItem.isOldEvent = lib.isOldEvent;

        let lineContent = lib.purl;
        let snippet = lib.purl;
        let startLine = -1;
        if (lib.blame) {
          if (lib.blame.lineContent) {
            lineContent = lib.blame.lineContent;
          }
          if (lib.blame.snippetContent) {
            snippet = lib.blame.snippetContent;
          }
          startLine = lib.blame.snippetLineNumber;
        }

        const fullPath = lib.blame.fileName ? lib.blame.fileName : lib.fileName;

        singleItem.fileName = fullPath;
        singleItem.filePath = lib.blame.fileName ? getMonoRepoFilePath(repo, lib.blame.fileName) : getMonoRepoFilePath(repo, lib.fileName);
        singleItem.fileUri = repo.fileLink + fullPath;
        singleItem.startLine = startLine;
        singleItem.endLine = -1;
        singleItem.match = lineContent;
        singleItem.snippet = snippet;
        singleItem.date = lib.blame.commitDate;
        singleItem.commitLink = `${repo.commitLink}/${lib.blame.commitSha}`;

        if (lib.blame.commiterName && lib.blame.commiterEmail) {
          singleItem.commitBy = `${lib.blame.commiterName || ""} ${lib.blame.commiterEmail || ""}`;
        } else if (lib.blame.commiterName) {
          singleItem.commitBy = lib.blame.commiterName;
        } else if (lib.blame.commiterEmail) {
          singleItem.commitBy = lib.blame.commiterEmail;
        } else {
          singleItem.commitBy = "";
        }
        singleItem.commiterName = lib.blame.commiterName || "";
        singleItem.commiterEmail = lib.blame.commiterEmail || "";
        singleItem.pushType = "";
        singleItem.title =
          lib.blame?.commitDescription?.length > 400 ? lib.blame?.commitDescription?.substring(0, 400) : lib.blame?.commitDescription;
        singleItem.mergedBy = "";
        singleItem.link = singleItem.commitLink;
        singleItem.reviewers = "";
        singleItem.fixes = lib.blame.fixes;
        singleItem.fromCommitHistory = false;
        singleItem.eduVideoLink = lib.blame.eduVideoLink;
        singleItem.libName = lib.additionalInsight.Name;
        singleItem.libVersion = lib.additionalInsight.Version;
        singleItem.realMatch = lib.purl; //Dont change it!!!

        if (!singleItem.realMatch) {
          logger.error(`failed add sbom for repo: ${repo.name}, no match, policy: ${this.policyRuleMetadata.name}`);
          continue;
        }

        //Keep it unique
        if (unique.has(lib.purl)) {
          continue;
        }
        unique.add(lib.purl);

        singleItem.setAggId();

        lib.notUpdated = true;

        items.push({
          singleItem: [singleItem],
          lib: lib,
          versionInfo: versionInfo,
          issueOwner: issueOwner,
        });
      } catch (err) {
        logger.error(`failed handle aggregation of single item for code lib outdated: ${JSON.stringify(notApprovedLib)} err: ${err}`);
      }
    }

    return items;
  }
}

export default PolicySbomCodeLibOutdated;
