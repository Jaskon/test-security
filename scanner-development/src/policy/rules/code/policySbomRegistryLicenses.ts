import { ImageInfo } from "../../../entitis/artifactoryTypes";
import { IssueOwner, Repo } from "../../../entitis/codeRepoTypes";
import { AggregatedInfoForExclusion, AggregatedSbomData } from "../../../entitis/service/exclusionTypes";
import { ExtendedSbomComponent } from "../../../helper/sbom/sbomHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import { Severity } from "../../../entitis/reportTypes";
import { SeverityChange } from "../../../entitis/service/blameTypes";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import StatesHelper from "../../../helper/statesHelper";
import StringHelper from "../../../helper/stringHelper";
import { DependencyType } from "../../../mongo/sbom/types";
import { SourceToolType } from "@oxappsec/ox-consolidated-categories";

const lowSeverityLic = ["MPL-2.0".toLowerCase()];

const logger = loggerImport.getDebugLogger();

class PolicySbomRegistryLicenses extends PolicyRulesBase {
  isEmptyLicApproved = false;

  async eval(jsonData) {
    return [];
  }

  getLicenseTokens(license: string) {
    let info = license.replaceAll("OR", "");
    info = info.replaceAll("AND", "");
    const tokens = info.split(" ");
    const t = [];
    tokens.forEach(i => t.push(i.trim()));
    return t.filter(i => i !== "");
  }

  isApproved(license: string, approvedList: string[], notApprovedList: string[]) {
    const licenseToLower = license.toLowerCase();
    const isLink = licenseToLower.includes("http");

    //Handle OR
    if (license.includes("OR")) {
      const tokens = this.getLicenseTokens(license);
      //Find one of the tokens
      let found = false;
      let notApproved = false;
      for (const token of tokens) {
        const tokenToLower = token.toLowerCase();
        if (
          approvedList.find(
            i =>
              i === tokenToLower ||
              i.startsWith(tokenToLower) ||
              tokenToLower.startsWith(i) ||
              i.endsWith(tokenToLower) ||
              tokenToLower.endsWith(i),
          ) != undefined
        ) {
          found = true;
          break;
        }

        //if link search inside it
        if (isLink) {
          if (approvedList.find(i => tokenToLower.includes(i)) != undefined) {
            found = true;
            break;
          }
        }

        if (notApprovedList.includes(tokenToLower)) {
          notApproved = true;
        }
      }
      //Due to OR first check if one of them found
      if (found) {
        return true;
      }
      if (notApproved) {
        return false;
      }
      //Handle AND
    } else if (license.includes("AND")) {
      let foundCounter = 0;
      const tokens = this.getLicenseTokens(license);
      //Find at least one match matches
      for (const token of tokens) {
        const tokenToLower = token.toLowerCase();
        if (notApprovedList.includes(tokenToLower)) {
          return false;
        }

        if (
          approvedList.find(
            i =>
              i === tokenToLower ||
              i.startsWith(tokenToLower) ||
              tokenToLower.startsWith(i) ||
              i.endsWith(tokenToLower) ||
              tokenToLower.endsWith(i),
          ) != undefined
        ) {
          foundCounter++;
        } else {
          //if link search inside it
          if (isLink) {
            if (approvedList.find(i => tokenToLower.includes(i)) != undefined) {
              foundCounter++;
            }
          }
        }
      }
      //In case of and all needs to be found
      return foundCounter === tokens.length;
    } else {
      //Single license
      if (notApprovedList.includes(licenseToLower)) {
        return false;
      } else if (
        approvedList.find(
          i =>
            i === licenseToLower ||
            i.startsWith(licenseToLower) ||
            licenseToLower.startsWith(i) ||
            i.endsWith(licenseToLower) ||
            licenseToLower.endsWith(i),
        ) != undefined
      ) {
        return true;
      } else {
        //if link search inside it
        if (isLink) {
          if (approvedList.find(i => licenseToLower.includes(i)) != undefined) {
            return true;
          }
        }
      }
    }

    //No license
    if (this.isEmptyLicApproved && (license == undefined || license === "")) {
      return true;
    }
    return false;
  }

  getKeyValueMapByRuleIdAndData(jsonData: any, approvedList: string[], imagesInfo: ImageInfo, notApprovedList: string[], direct: boolean) {
    let items = [];
    const notApprovedLibs = [];
    for (const sbomEvent of imagesInfo.sbomEvents) {
      for (const lib of sbomEvent.sbomHelper.extendedSbom.components) {
        //No support at the moment
        if (lib.pkgManager == "deb" || lib.pkgManager == "apk") {
          continue;
        }

        let alertDirect = false;
        if (lib?.blame?.dependencyType != undefined) {
          alertDirect = lib.blame.dependencyType.toLowerCase() === "direct";
          if (direct != alertDirect) {
            continue;
          }
        }

        const gcpLicenseCausingViolation: string[] = [];
        let oneWasApproved = false;
        for (const license of lib.licenses) {
          try {
            if (!license.expression) {
              continue;
            }

            if (!this.isApproved(license.expression, approvedList, notApprovedList)) {
              gcpLicenseCausingViolation.push(license.expression);
            } else {
              oneWasApproved = true;
            }
          } catch (err) {
            logger.error(`failed handle single item for artifact license obj: ${JSON.stringify(license)} err: ${err}`);
          }
        }
        let layerID: string = "";
        for (const property of lib.properties) {
          if (property.name.includes("LayerDiffID")) {
            layerID = property.value;
          }
        }
        if (!oneWasApproved) {
          gcpLicenseCausingViolation.forEach(license => notApprovedLibs.push({ lib: lib, license: license, layerID: layerID }));
        }
      }
    }

    const repo: Repo = jsonData.code_repo;
    const unique = new Set();
    for (const notApprovedLib of notApprovedLibs) {
      try {
        const lib: ExtendedSbomComponent = notApprovedLib.lib;
        const issueOwner: IssueOwner[] = [];

        if (lib.blame.commitDate && lib.blame.commiterEmail) {
          issueOwner.push({
            name: lib.blame.commiterName,
            email: lib.blame.commiterEmail,
          } as IssueOwner);
        }

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

        const singleItem: PolicySbomArtifactLicensesAggItem = new PolicySbomArtifactLicensesAggItem();
        singleItem.match = lineContent;
        singleItem.snippet = snippet;
        singleItem.date = lib.blame.commitDate;
        singleItem.title =
          lib.blame?.commitDescription?.length > 400 ? lib.blame?.commitDescription?.substring(0, 400) : lib.blame?.commitDescription;
        singleItem.libName = lib.additionalInsight.Name;
        singleItem.libVersion = lib.additionalInsight.Version;
        singleItem.realMatch = lib.purl || ""; //Dont change it!!!
        singleItem.imageCreatedAt = imagesInfo.image.imagePushedAt || "";
        singleItem.sha = imagesInfo.image.imageDigest || "";
        //singleItem.os = imagesInfo.image.os || "";
        singleItem.image = imagesInfo.image.name || "";
        singleItem.tag = imagesInfo.image.imageTags[0].at(0);
        singleItem.layer = notApprovedLib.layerID || "";

        if (!singleItem.realMatch) {
          logger.error(`failed add sbom for repo: ${repo.name}, no match, policy: ${this.policyRuleMetadata.name}`);
          continue;
        }

        singleItem.setAggId();

        //Keep it unique
        if (unique.has(lib.purl)) {
          continue;
        }
        unique.add(lib.purl);

        lib.licenseIssue = true;
        items.push({
          singleItem: [singleItem],
          lib: lib,
          issueOwner: issueOwner,
        });
      } catch (err) {
        logger.error(`failed handle aggregation of single item for artifact license: ${JSON.stringify(notApprovedLib)} err: ${err}`);
      }
    }

    return items;
  }
}

export class PolicySbomArtifactLicensesAggItem extends AggregatedInfoForExclusion {
  match: string;
  realMatch: string;
  snippet: string;
  date: string;
  pushType: string;
  title: string;

  //Additional info needed
  libName: string;
  libVersion: string;
  imageCreatedAt: string;
  sha: string;
  tag: string;
  image: string;
  layer: any;

  getExclusionObj() {
    const i: AggregatedSbomData = new AggregatedSbomData();
    i.realMatch = this.realMatch;
    return i;
  }
  setAggId() {
    this.aggId = StringHelper.combineStrings(this.realMatch);
    this.hashAggId = StringHelper.hashMd5(this.aggId);
  }
}

export default PolicySbomRegistryLicenses;
