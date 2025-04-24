import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import { SbomEvent } from "../../../entitis/artifactoryTypes";
import { IssueOwner, Repo } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { ChangeReason, SeverityChange, severityReasons } from "../../../entitis/service/blameTypes";
import { getMonoRepoFilePath } from "../../../helper/commonUtils";

import { ExtendedSbomComponent } from "../../../helper/sbom/sbomHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import { PolicySbomCodeLicensesAggItem } from "./policySbomCodeLicenses";

const logger = loggerImport.getDebugLogger();

class PolicySbomCodeLibNotPopular extends PolicyRulesBase {
  async eval(jsonData) {
    const interestedFromArgs = this.getValueFromRuleArgs("interested");
    const downloadsFromArgs = this.getValueFromRuleArgs("downloads");
    const forksFromArgs = this.getValueFromRuleArgs("forks");

    if (isNaN(interestedFromArgs)) {
      throw `interestedFromArgs from args is not number, ${interestedFromArgs.toString()}`;
    }
    if (isNaN(downloadsFromArgs)) {
      throw `downloadsFromArgs from args is not number, ${downloadsFromArgs.toString()}`;
    }
    if (isNaN(forksFromArgs)) {
      throw `forksFromArgs from args is not number, ${forksFromArgs.toString()}`;
    }

    const typeFromArgs = this.getValueFromRuleArgs("type");
    const direct = typeFromArgs === "direct";

    const sbomEvent: SbomEvent[] = jsonData.sbom;

    const items = this.getKeyValueMapByRuleIdAndData(jsonData, interestedFromArgs, downloadsFromArgs, forksFromArgs, sbomEvent, direct);

    const res = [];
    for (const itemInfo of items) {
      try {
        const lib: ExtendedSbomComponent = itemInfo.lib;

        let fixLink = `https://www.google.com/search?q=alternative+to+${lib.name} library`;

        const stars = lib.additionalInsight.projectInfo.StarsCount;
        const forks = lib.additionalInsight.projectInfo.ForksCount;
        const downloads = lib.additionalInsight.downloads;

        let violationInfoTitle = `Unpopular library directly referenced in code: ${lib.name}@${
          lib.version
        } (${stars} stars, ${forks} forks${downloads == undefined ? ")" : `, ${downloads} weekly downloads)`}`;
        if (!direct) {
          violationInfoTitle = `Unpopular library indirectly referenced in code: ${lib.name}@${
            lib.version
          } (${stars} stars, ${forks} forks${downloads == undefined ? ")" : `, ${downloads} weekly downloads)`}`;
          fixLink = "";
        }

        let secondTitle = `Your code contains direct references to library ${lib.name} which is not widely used`;
        let rec = `Please look at an alternative library for ${lib.name} that is more widely used`;
        if (!direct) {
          rec = `Please identify which of your directly referenced libraries have references to Library ${lib.name}. Once identified please consider updating the directly referenced libraries`;
          secondTitle = "";
          if (lib.blame) {
            if (lib.blame.dependencyChain) {
              secondTitle = `Your code contains indirect references to library ${
                lib.name
              } which is not widely used and was introduced to your app by the following dependency chain: ${lib.blame.dependencyChain
                .map(u => u.name)
                .join(" -> ")}`;
            }
          }
        }

        let additionalInfo = lib.extraInfo;

        additionalInfo.push({
          key: "Approved stars",
          value: interestedFromArgs.toString(),
        });

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

        const unpopularLibReason = ChangeReason.copy(severityReasons.UnpopularLib);
        changeReasons.push(unpopularLibReason);

        let item = this.generateItemForReport(
          true,
          violationInfoTitle,
          secondTitle,
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
          lib?.additionalInsight?.projectInfo?.Homepage,
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
    starsFromArgs: number,
    downloadsFromArgs: number,
    forksFromArgs: number,
    sbomEvents: SbomEvent[],
    direct: boolean,
  ) {
    let items = [];
    const notApprovedLibs = [];
    for (const sbomEvent of sbomEvents) {
      for (const lib of sbomEvent.sbomHelper.extendedSbom.components) {
        //Not match to policy
        let alertDirect = false;
        if (lib?.blame?.dependencyType != undefined) {
          alertDirect = lib.blame.dependencyType.toLowerCase() === "direct";
        }
        if (direct != alertDirect) {
          continue;
        }
        const stars = lib?.additionalInsight?.projectInfo?.StarsCount;
        const forks = lib?.additionalInsight?.projectInfo?.ForksCount;
        this.evaluateSbomPopularity(lib, starsFromArgs, forksFromArgs);
        if (stars == undefined) {
          continue;
        }
        if (stars >= starsFromArgs) {
          continue;
        }

        if (forks == undefined) {
          continue;
        }
        if (forks >= forksFromArgs) {
          continue;
        }
        const downloads = lib?.additionalInsight?.downloads;
        if (downloads != undefined) {
          if (downloads >= downloadsFromArgs) {
            continue;
          }
        }
        notApprovedLibs.push(lib);
      }
    }

    const repo: Repo = jsonData.code_repo;
    const unique = new Set();
    for (const notApprovedLib of notApprovedLibs) {
      try {
        const lib: ExtendedSbomComponent = notApprovedLib;
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
        singleItem.title;
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
        notApprovedLibs.push(lib);

        singleItem.setAggId();

        items.push({
          singleItem: [singleItem],
          lib: lib,
          issueOwner: issueOwner,
        });
      } catch (err) {
        logger.error(`failed handle aggregation of single item for code stars: ${JSON.stringify(notApprovedLib)} err: ${err}`);
      }
    }

    return items;
  }

  evaluateSbomPopularity(lib: ExtendedSbomComponent, minStars?: number, minForks?: number): void {
    if (
      minStars == undefined ||
      minForks == undefined ||
      lib?.additionalInsight?.projectInfo?.StarsCount === undefined ||
      lib?.additionalInsight?.projectInfo?.ForksCount === undefined
    ) {
      lib.notPopular = null;
      return;
    }
    lib.notPopular = lib.additionalInsight.projectInfo.StarsCount < minStars || lib.additionalInsight.projectInfo.ForksCount < minForks;
  }
}

export default PolicySbomCodeLibNotPopular;
