import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import { SbomEvent } from "../../../entitis/artifactoryTypes";
import { IssueOwner, Repo } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { ChangeReason, SeverityChange, severityReasons } from "../../../entitis/service/blameTypes";
import { ExtendedSbomComponent } from "../../../helper/sbom/sbomHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import { PolicySbomCodeLicensesAggItem } from "./policySbomCodeLicenses";

const logger = loggerImport.getDebugLogger();

class PolicySbomCodeLibDeprecated extends PolicyRulesBase {
  async eval(jsonData) {
    const sbomEvent: SbomEvent[] = jsonData.sbom;

    const typeFromArgs = this.getValueFromRuleArgs("type");
    const direct = typeFromArgs === "direct";

    const items = this.getKeyValueMapByRuleIdAndData(jsonData, sbomEvent, direct);

    const res = [];
    for (const itemInfo of items) {
      try {
        const lib: ExtendedSbomComponent = itemInfo.lib;

        let fixLink = `https://www.google.com/search?q=alternative+to+${lib.name} library`;

        let violationInfoTitle = `Deprecated library directly referenced in code: ${lib.name}@${lib.version}`;
        if (!direct) {
          fixLink = "";
          violationInfoTitle = `Deprecated library indirectly referenced in code: ${lib.name}@${lib.version}`;
        }

        let rec = `Please look at an alternative library for ${lib.name} that is well maintained`;
        let secondLink = `Your code contains direct references to library ${lib.name} which is deprecated`;
        if (!direct) {
          rec = `Please identify which of your directly referenced libraries have references to Library ${lib.name}. Once identified please consider updating the directly referenced libraries`;
          secondLink = "";
          if (lib.blame) {
            if (lib.blame.dependencyChain) {
              secondLink = `Your code contains indirect references to library ${
                lib.name
              } which is deprecated and was introduced to your app by the following dependency chain: ${lib.blame.dependencyChain
                .map(u => u.name)
                .join(" -> ")}`;
            }
          }
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
          secondLink,
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
          this.getCustomIssueId(lib.purl),
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
        item.blameExists = !!lib.blame;
        item.graphExists = lib.blame?.graphExists || false;
        item.problematicPkg = `${lib.name}@${lib.version}`;

        if (lib?.blame?.triggerPackage) {
          item.scaTriggerPkg = `${lib.blame.triggerPackage.name}@${lib?.blame?.triggerPackage.version}`;
        }
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

  getKeyValueMapByRuleIdAndData(jsonData: any, sbomEvents: SbomEvent[], direct: boolean) {
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
        const deprecated = lib?.additionalInsight?.projectInfo?.deprecated;
        if (deprecated != undefined) {
          if (deprecated) {
            notApprovedLibs.push(lib);
          }
        }
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

        singleItem.isSilent = false;
        singleItem.fileName = fullPath;
        singleItem.filePath = fullPath;
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
        (singleItem.title =
          lib.blame?.commitDescription?.length > 400 ? lib.blame?.commitDescription?.substring(0, 400) : lib.blame?.commitDescription),
          (singleItem.mergedBy = "");
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
        lib.isDeprecated = true;
        singleItem.setAggId();

        items.push({
          singleItem: [singleItem],
          lib: lib,
          issueOwner: issueOwner,
        });
      } catch (err) {
        logger.error(`failed handle aggregation of single item for code not maintained: ${JSON.stringify(notApprovedLib)} err: ${err}`);
      }
    }

    return items;
  }
}

export default PolicySbomCodeLibDeprecated;
