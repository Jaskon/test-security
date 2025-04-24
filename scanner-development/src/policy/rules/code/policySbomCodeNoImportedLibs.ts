import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import { SbomEvent } from "../../../entitis/artifactoryTypes";
import { Repo } from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { AggregatedInfoForExclusion, AggregatedNotUsedLibs } from "../../../entitis/service/exclusionTypes";
import { getMonoRepoFilePath } from "../../../helper/commonUtils";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import { ExtendedSbomComponent } from "../../../helper/sbom/sbomHelper";
import StringHelper from "../../../helper/stringHelper";
import loggerImport from "../../../logger";
import { DependencyType } from "../../../mongo/sbom/types";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class PolicySbomCodeNoImportedLibs extends PolicyRulesBase {
  async eval(jsonData) {
    try {
      const sbomEvent: SbomEvent[] = jsonData.sbom;

      const repo: Repo = jsonData.code_repo;
      if (!repo.realRepo) {
        return [];
      }

      const libs: ExtendedSbomComponent[] = sbomEvent.map(i => i.sbomHelper.extendedSbom.components).flat();

      const res = [];
      const aggItems: NotUsedLibsAggItem[] = [];
      const unique = new Set();
      for (const lib of libs) {
        try {
          if (!lib?.blame?.language) {
            continue;
          }
          if (lib.blame.language.toLowerCase() !== "typescript" && lib.blame.language.toLowerCase() !== "javascript") {
            continue;
          }

          //Handle only direct and Ignore imported pkg
          if (lib?.blame?.dependencyType !== DependencyType.Direct || lib?.scaValidator?.pkgImported == undefined) {
            lib.notImported = null;
            continue;
          }

          if (lib?.scaValidator?.pkgImported == true) {
            lib.notImported = false;
            continue;
          }

          const id = `${lib.name}@${lib.version}`;
          lib.notImported = true;
          if (unique.has(id)) {
            continue;
          }

          unique.add(id);

          const notUsedLibsAggItem: NotUsedLibsAggItem = new NotUsedLibsAggItem();
          notUsedLibsAggItem.nameAndVer = `${lib.name}@${lib.version}`;
          notUsedLibsAggItem.stars = lib?.additionalInsight?.projectInfo?.StarsCount
            ? lib?.additionalInsight?.projectInfo?.StarsCount.toString()
            : "";
          notUsedLibsAggItem.forks = lib?.additionalInsight?.projectInfo?.ForksCount
            ? lib?.additionalInsight?.projectInfo?.ForksCount.toString()
            : "";
          notUsedLibsAggItem.downloads = lib?.additionalInsight?.downloads ? lib?.additionalInsight?.downloads.toString() : "";
          if (lib.vulnerabilityCounts) {
            let str = [];
            for (const [severity, count] of Object.entries(lib.vulnerabilityCounts)) {
              str.push(`${severity}:${count}`);
            }
            notUsedLibsAggItem.vulBySeverity = str.join(", ");
          } else {
            notUsedLibsAggItem.vulBySeverity = "None";
          }

          // Additional data for resolved issues
          notUsedLibsAggItem.fileName = lib.blame.fileName;
          notUsedLibsAggItem.filePath = getMonoRepoFilePath(repo, lib.blame.fileName);
          notUsedLibsAggItem.match = lib.blame.lineContent;
          notUsedLibsAggItem.realMatch = lib.purl;
          if (!notUsedLibsAggItem.realMatch) {
            logger.error(`failed add sbom for repo: ${repo.name}, no match, policy: ${this.policyRuleMetadata.name}`);
            continue;
          }
          notUsedLibsAggItem.libName = lib.name;

          notUsedLibsAggItem.setAggId();
          aggItems.push(notUsedLibsAggItem);
        } catch (err) {
          logger.error(`failed to add a single item for policy ${this.policyRuleMetadata.name} err: ${err}`);
        }
      }

      if (aggItems.length == 0) {
        return [];
      }

      const violationInfoTitle = "";
      const aggregated = {
        aggregatedItems: aggItems,
        columns: "policySbomCodeNoImportedLibs",
        violationInfoTitle,
      };

      const withForksList = [];
      const withoutForksList = [];
      aggItems.forEach(i => {
        if (i.forks) {
          withForksList.push(i);
        } else {
          withoutForksList.push(i);
        }
      });

      aggregated.aggregatedItems = [...withForksList, ...withoutForksList];

      const mainTitle = "Dependency not used in code";
      // : `Dependency not used in code: (${true ? "COUNT_TEMPLATE" : aggItems.length} ${
      //     true ? "PLURAL_TEMPLATE" : aggItems.length > 1 ? "dependencies" : "dependency"
      //   })`;
      const description = `Repo ${repo.fullName} has ${true ? "COUNT_TEMPLATE" : aggItems.length} ${
        true ? "PLURAL_TEMPLATE" : aggItems.length > 1 ? "dependencies" : "dependency"
      } that are not utilized. In other words, no functions or variables of the ${
        true ? "PLURAL_TEMPLATE" : aggItems.length > 1 ? "dependencies" : "dependency"
      } are used.`;

      const issueOwners = this.getOwnersFromUsers(jsonData);

      let item = this.generateItemForReport(
        true,
        mainTitle,
        description,
        "",
        "It is best practise to remove dependencies that are not being used.",
        "",
        "",
        [],
        "",
        true,
        "",
        aggregated,
        [SourceToolType.SBOM],
        ["trivy", "trivy-sbom"],
        [],
        this.getGeneralIssueId(),
        issueOwners,
        "",
        this.policyRuleMetadata.ruleId,
      );

      res.push(item);

      return res;
    } catch (err) {
      logger.error(`Failed to run eval of policySbomCodeNoImportedLibs ${err}`);
    }
  }
}

export class NotUsedLibsAggItem extends AggregatedInfoForExclusion {
  nameAndVer: string;
  stars: string;
  downloads: string;
  forks: string;
  vulBySeverity: string;
  filePath?: string;
  fileName?: string;
  match?: string;
  realMatch?: string;
  libName?: string;

  getExclusionObj() {
    const i: AggregatedNotUsedLibs = new AggregatedNotUsedLibs();
    i.nameAndVer = this.nameAndVer;
    return i;
  }

  setAggId() {
    this.aggId = StringHelper.combineStrings(this.nameAndVer);
    this.hashAggId = StringHelper.hashMd5(this.aggId);
  }
}

export default PolicySbomCodeNoImportedLibs;
