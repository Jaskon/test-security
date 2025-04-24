import { Fix } from "sarif";
import { SbomEvent } from "../../../entitis/artifactoryTypes";
import { IssueOwner, Repo } from "../../../entitis/codeRepoTypes";
import { AggregatedInfoForExclusion, AggregatedSbomData } from "../../../entitis/service/exclusionTypes";
import { ExtendedSbomComponent } from "../../../helper/sbom/sbomHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";

import Constant from "../../../entitis/constant";
import { Severity } from "../../../entitis/reportTypes";
import { ChangeReason, SeverityChange, severityReasons } from "../../../entitis/service/blameTypes";
import { getMonoRepoFilePath } from "../../../helper/commonUtils";
import StringHelper from "../../../helper/stringHelper";
import { SourceToolType } from "@oxappsec/ox-consolidated-categories";

const lowSeverityLic = ["MPL-2.0".toLowerCase()];

const logger = loggerImport.getDebugLogger();

class PolicySbomCodeLicenses extends PolicyRulesBase {
  isEmptyLicApproved = false;

  async eval(jsonData) {
    let licenseTypeFromArgs: string[] = this.getValueFromRuleArgs("approvedLicenses");

    let notApprovedList: string[] = this.getValueFromRuleArgs("notApprovedLicenses");

    const typeFromArgs = this.getValueFromRuleArgs("type");
    const direct = typeFromArgs === "direct";

    const unique = new Set();
    for (const l of licenseTypeFromArgs) {
      const lower = l.toLowerCase();
      unique.add(lower);
      unique.add(`${lower} license`);
      if (l.includes(" ")) {
        unique.add(lower.replaceAll(" ", "-"));
      }
      if (l.includes("-")) {
        unique.add(lower.replaceAll("-", " "));
      }
    }

    const approvedList = Array.from(unique) as string[];
    approvedList.push("non-standard");
    approvedList.push("SEE LICENSE IN".toLowerCase());
    approvedList.push("Historical Permission Notice and Disclaimer (HPND)".toLowerCase());
    approvedList.push("License :: CC0 1.0 Universal (CC0 1.0) Public Domain Dedication".toLowerCase());
    approvedList.push("facebook permissive license");
    approvedList.push("UNKNOWN".toLowerCase());
    approvedList.push("EPL-1.0".toLowerCase());
    approvedList.push("EPL-2.0".toLowerCase());
    approvedList.push("Common Public License Version 1.0".toLowerCase());
    approvedList.push("The Go license".toLowerCase());
    approvedList.push("CDDL-1.1".toLowerCase());
    approvedList.push("CDDL License".toLowerCase());
    approvedList.push("Bouncy Castle Licence".toLowerCase());
    approvedList.push("Common Development and Distribution License (CDDL) v1.0".toLowerCase());

    notApprovedList = notApprovedList.map(element => {
      return element.toLowerCase();
    });

    this.isEmptyLicApproved = approvedList.some(i => i.toLowerCase() === "no license");

    const sbomEvent: SbomEvent[] = jsonData.sbom;

    const items = this.getKeyValueMapByRuleIdAndData(jsonData, approvedList, notApprovedList, sbomEvent, direct);

    const res = [];
    for (const itemInfo of items) {
      try {
        const lib: ExtendedSbomComponent = itemInfo.lib;

        const licenses = lib.licenses.length == 0 ? "No License" : lib.licenses.map(i => i.expression).join(", ");

        let licForViolation = licenses;

        //Overwrite this for UI
        if (licForViolation === "non-standard") {
          licForViolation = `Non standard license`;
        }

        let fixLink = `https://www.google.com/search?q=alternative+to+${lib.name} library`;

        let violationInfoTitle = `Library with unapproved license directly referenced in code: ${lib.name}@${lib.version} (${licForViolation})`;
        if (!direct) {
          violationInfoTitle = `Library with unapproved license indirectly referenced in code: ${lib.name}@${lib.version} (${licForViolation})`;
        }

        let recommendation = `Based on company policy please look at an alternative library for ${lib.name} utilizing a company approved license`;
        let secondLink = `Your code contains direct reference to ${lib.name} which has an unapproved license`;
        if (!direct) {
          recommendation = `Please identify which of your directly referenced libraries have references to Library ${lib.name}. Once identified please consider updating the directly referenced libraries`;
          fixLink = "";
          secondLink = "";
          if (lib.blame) {
            if (lib.blame.dependencyChain) {
              secondLink = `Your code contains indirect reference to ${
                lib.name
              } which has an unapproved license and was introduced to your app by the following dependency chain: ${lib.blame.dependencyChain
                .map(u => u.name)
                .join(" -> ")}`;
            }
          }
        }

        const latestVer: string = lib?.additionalInsight?.latestVer?.version;
        const latestVerLicenses: string[] = lib?.additionalInsight?.latestVer?.licenses;
        if (latestVerLicenses?.length && latestVer != undefined && direct) {
          if (lib.additionalInsight.Version !== latestVer && latestVerLicenses.join(", ") !== licenses) {
            let allApproved = true;
            for (const latestVerLicense of latestVerLicenses) {
              if (!this.isApproved(latestVerLicense, approvedList, notApprovedList)) {
                allApproved = false;
                break;
              }
            }
            if (allApproved) {
              recommendation = `Version ${lib.additionalInsight.Version} of ${
                lib.name
              } comes with a company approved license ${latestVerLicenses.join(", ")}. Please upgrade ${lib.name} to version ${
                lib?.additionalInsight?.latestVer?.version
              }.`;
              if (lib?.additionalInsight?.linkToFix != undefined) {
                fixLink = lib?.additionalInsight?.linkToFix;
              }
            }
          }
        }

        const changeReasons = [];

        const aggregated = {
          aggregatedItems: itemInfo.singleItem,
          columns: "policySecurityScan",
          violationInfoTitle,
        };

        let severity = this.policyRuleMetadata.severity;
        if (lowSeverityLic.includes(licForViolation.toLowerCase())) {
          severity = Severity.LOW;
        }

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

        const licReason = ChangeReason.copy(severityReasons.licIssue);
        changeReasons.push(licReason);

        let item = this.generateItemForReport(
          true,
          violationInfoTitle,
          secondLink,
          violationInfoTitle,
          recommendation,
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
          severity,
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
        item.libId = `${lib.pkgManager}|${lib.name}|${lib.version}`;
        item.problematicPkg = `${lib.name}@${lib.version}`;
        res.push(item);
      } catch (err) {
        logger.error(
          `failed to add a single item for policy ${this.policyRuleMetadata.name} err: ${err}, lib: ${JSON.stringify(itemInfo)}`,
        );
      }
    }

    return res;
  }

  getLicenseTokens(license) {
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

  getKeyValueMapByRuleIdAndData(
    jsonData: any,
    approvedList: string[],
    notApprovedList: string[],
    sbomEvents: SbomEvent[],
    direct: boolean,
  ) {
    let items = [];
    const changeReasons = [];
    const notApprovedLibs = [];
    for (const sbomEvent of sbomEvents) {
      for (const lib of sbomEvent.sbomHelper.extendedSbom.components) {
        //Not match to policy
        let alertDirect = false;
        if (lib?.blame?.dependencyType != undefined) {
          alertDirect = lib.blame.dependencyType === "direct";
        }
        if (direct != alertDirect) {
          continue;
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
            logger.error(`failed handle single item for code license obj: ${JSON.stringify(license)} err: ${err}`);
          }
        }

        if (!oneWasApproved) {
          gcpLicenseCausingViolation.forEach(license => notApprovedLibs.push({ lib: lib, license: license }));
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

        const singleItem: PolicySbomCodeLicensesAggItem = new PolicySbomCodeLicensesAggItem();
        singleItem.isOldEvent = lib.isOldEvent;

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
        singleItem.realMatch = lib.purl || ""; //Dont change it!!!

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
        logger.error(`failed handle aggregation of single item for code license: ${JSON.stringify(notApprovedLib)} err: ${err}`);
      }
    }

    return items;
  }
}

export class PolicySbomCodeLicensesAggItem extends AggregatedInfoForExclusion {
  fileName: string;
  fileUri: string;
  startLine: number;
  endLine: number;
  match: string;
  realMatch: string;
  filePath: string;
  snippet: string;
  date: string;
  commitLink: string;
  commitBy: string;
  commiterName: string;
  commiterEmail: string;
  pushType: string;
  title: string;
  mergedBy: string;
  link: string;
  reviewers: string;
  fixes: Fix[];
  fromCommitHistory: boolean;
  eduVideoLink: string;
  isOldEvent: boolean;

  //Additional info needed
  libName: string;
  libVersion: string;

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

export default PolicySbomCodeLicenses;
