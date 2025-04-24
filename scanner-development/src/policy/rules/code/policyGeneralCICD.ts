import { Fix } from "sarif";
import {
  CodeRepoTypes,
  getToolsNames,
  getUniqueInfoForAggregation,
  IssueOwner,
  Repo,
  repoType,
  SecurityAlertType,
  SecurityEvent,
} from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { ChangeReason } from "../../../entitis/service/blameTypes";
import { AggregatedCodeData, AggregatedInfoForExclusion } from "../../../entitis/service/exclusionTypes";
import { SCAVulnerability } from "../../../helper/policy/scaVulHelper";
import { getAllInfoForSeverity, getSeverityChanges } from "../../../helper/policy/severityHelper";
import StringHelper from "../../../helper/stringHelper";
import TimeHelper from "../../../helper/timeHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class policyGeneralCICD extends PolicyRulesBase {
  private commiters: IssueOwner[] = [];
  private timeHelper: TimeHelper = new TimeHelper("");

  async eval(jsonData) {
    try {
      const repo: Repo = jsonData.code_repo;

      let securityEvents: SecurityEvent[] = jsonData.securityEvents.filter(sec => sec.securityProvidersArr.includes("Checkov"));

      let genericSecurityEvents = securityEvents.filter(
        event => event.ruleId.includes("CKV_CIRCLECIPIPELINES_") || event.ruleId.includes("CKV_ARGO_"),
      );

      switch (repo.type.toLowerCase()) {
        case repoType.gitlab:
          securityEvents = securityEvents.filter(event => event.ruleId.includes("CKV_GITLABCI_"));
          break;

        case repoType.github:
          securityEvents = securityEvents.filter(
            event => (event.ruleId.includes("CKV_GHA_") && event.ruleId != "CKV_GHA_1") || event.ruleId.includes("CKV2_GHA_"),
          );
          break;

        case repoType.azureGit || repoType.azure:
          securityEvents = securityEvents.filter(event => event.ruleId.includes("CKV_AZUREPIPELINES_"));
          break;

        case repoType.bitbucket || repoType.bitbucketStash || "bitbucket-stash":
          securityEvents = securityEvents.filter(event => event.ruleId.includes("CKV_BITBUCKETPIPELINES_"));
          break;

        default:
          break;
      }

      securityEvents = [...securityEvents, ...genericSecurityEvents];
      if (securityEvents.length === 0) {
        return [];
      }

      const aggragatedInfo = this.getKeyValueMapByRuleIdAndData(jsonData, securityEvents);

      let res = [];
      for (const events of Object.values(aggragatedInfo) as any) {
        if (events.length == 0) {
          continue;
        }

        //Get the hights original severity alert
        let topLevelEventData = events.aggregated[0].securityAlert as SecurityEvent;

        this.commiters.push({
          name: topLevelEventData.blame.commiterName,
          email: topLevelEventData.blame.commiterEmail,
        });

        const aggregated = {
          aggregatedItems: this.sortEvents(events.aggregated),
          columns: "policySecurityScan",
        };

        //Set additional info for secrets
        let extraInfo = topLevelEventData.extraInfo;

        const aggregatedItems: PolicySecurityScanAggItem[] = events.aggregated;
        const issueOwners = this.getIssueOwners(jsonData, aggregatedItems);

        let mainTitle = topLevelEventData.blame.summaryTitle || topLevelEventData.violationInfo;

        const secondaryTitle = topLevelEventData.blame.title || topLevelEventData.title || "";
        const recommendation = topLevelEventData.blame.recommendation || topLevelEventData.recommendation;

        if (topLevelEventData.blame.eduVideoLink !== undefined && topLevelEventData.blame.eduVideoLink !== "") {
          extraInfo.push({
            key: "Recommended Video",
            value: topLevelEventData.blame.eduVideoLink,
          });
        }

        if (topLevelEventData.ruleId) {
          extraInfo.push({
            key: "Rule Name",
            value: `${topLevelEventData.ruleId}`,
          });
        }

        const securityItems: SecurityEvent[] = (events.aggregated as PolicySecurityScanAggItem[]).map(i => i.securityAlert);
        const cweList = this.getCWEList(topLevelEventData, securityItems);

        const resInfo = getAllInfoForSeverity(securityItems, repo.fullName);
        const uniqueSeverityChanges = resInfo.uniqueSeverityFromAllAlerts as ChangeReason[];
        const originalSeverity = resInfo.originalSeverity;
        const originalSeverityStr = resInfo.originalSeverityStr;
        const newSeverityForPolicy = resInfo.newSeverityForPolicy;

        let learnMore = topLevelEventData.moreInfoLink;

        const uniqueAgg = this.getCustomIssueId(getUniqueInfoForAggregation(topLevelEventData));
        //Keep this last before the generate item function

        let item = this.generateItemForReport(
          !repo.privateVisability ? false : true,
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
          [Constant.cicdPosture],
          getToolsNames(topLevelEventData.securityProviders, topLevelEventData.tools),
          extraInfo,
          uniqueAgg,
          issueOwners,
          learnMore,
          topLevelEventData.ruleId,
          this.generateCWElist(securityItems),
          topLevelEventData.snippetContent,
          cweList,
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

        res.push(item);
      }

      return res;
    } catch (e) {
      logger.error(`failed to eval policy, error: ${e}, policy: ${this.policyRuleMetadata.functionName}`);
    }
    return [];
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

  getKeyValueMapByRuleIdAndData(jsonData: any, securityEvents: SecurityEvent[]) {
    let aggregatedItems = {};

    const repo: Repo = jsonData.code_repo;

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
      if (event.securityAlertType === SecurityAlertType.iac || event.securityAlertType === SecurityAlertType.sast) {
        if (event?.autoFixResponse?.autofixable) {
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

export class PolicySecurityScanAggItem extends AggregatedInfoForExclusion {
  fileName: string;
  fileUri: string;
  startLine: number;
  endLine: number;
  match: string;
  realMatch: string;
  version: string;
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
  language: string;
  snippetLineNumber: number;
  securityAlert: SecurityEvent;
  isFixAvailable: boolean;
  isFixApplied: boolean;
  fixAppliedBy: string;
  installedVersion: string;
  pkgName: string;
  fixedVersion: string;
  branch: string;
  filePath: string;
  lockfile: string;

  triggerPkgName: string;
  triggerPkgVersion: string;
  triggerPkgUpgradeVersion: string;

  //Additional data need
  source: string;
  ruleId: string;

  //SCA
  sCAVulnerability: SCAVulnerability[] = [];

  //Artifacts
  dockerVer: string;
  imageCreatedAt: string;
  pkgCount: number;
  binariesCount: number;
  sha: string;
  os: string;
  image: string;
  tag: string;

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

export default policyGeneralCICD;
