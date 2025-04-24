import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();
import { Exclusion } from "../../entitis/service/exclusionTypes";
import { Issue } from "../../entitis/issuesTypes";
import { ExclusionService } from "../../helper/service/exclusion-service/api";
import { AggItem } from "../../mongo/schemas";
import { OxExclusionLevel, OxExclusionMode, OxExclusionScope, OxExclusionType } from "@oxappsec/ox-consolidated-exclusions";
import { PipeLineHelper } from "../../helper/pipelineHelper";

class RuleExclusions {
  uuid: string;
  orgName: string;
  issueExclusions: Exclusion[] = [];
  aggExclusions: Map<string, Exclusion[]> = new Map();
  applicationExclusions: Exclusion[] = [];
  globalExclusions: Exclusion[] = [];

  constructor(uuid: string, orgName: string, private readonly isPipelinescan: boolean) {
    this.uuid = uuid;
    this.orgName = orgName;
  }

  public async parseExclusions() {
    logger.info(`try set rule exclusions from DB`);

    const exclusionMode = this.isPipelinescan ? OxExclusionMode.pipelineScan : OxExclusionMode.fullScan;

    const exclusionsFromDB = await ExclusionService.Instance.getAlertExclusionsByMode(this.orgName, exclusionMode);

    const exclusionsSet = new Set<string>();
    for (const exclusionFromDB of exclusionsFromDB) {
      try {
        if (
          exclusionFromDB.exclusionType !== OxExclusionType.alert ||
          exclusionFromDB.oxIssueId === undefined ||
          exclusionFromDB.oxIssueId === null
        ) {
          continue;
        }
        const exclusion: Exclusion = new Exclusion();
        exclusion.exclusionMatch = exclusionFromDB.match;
        exclusion.exclusionScope = exclusionFromDB.exclusionScope;
        exclusion.repoId = exclusionFromDB.appId;
        exclusion.repoName = exclusionFromDB.appName;
        exclusion.policyId = exclusionFromDB.policyId;
        exclusion.exclusionMode = exclusionFromDB.exclusionMode;
        exclusion.exclusionId = exclusionFromDB.exclusionId;
        exclusion.exclusionType = exclusionFromDB.exclusionType;
        exclusion.isActive = exclusionFromDB.isActive;
        exclusion.issueId =
          exclusionMode === OxExclusionMode.fullScan
            ? exclusionFromDB.oxIssueId
            : PipeLineHelper.Instance.extractOriginalIssueId(exclusionFromDB.oxIssueId);
        if (exclusionFromDB.expiredAt) {
          exclusion.expiredAt = new Date(exclusionFromDB.expiredAt);
        }

        exclusion.validateExclusion();
        const exclusionStr = JSON.stringify(exclusion);
        if (exclusionsSet.has(exclusionStr)) continue;
        switch (exclusion.exclusionScope) {
          case OxExclusionScope.aggItem:
            const { policyId } = exclusion;
            const policyExclusions = this.aggExclusions.get(policyId);
            if (!policyExclusions) {
              this.aggExclusions.set(policyId, []);
            }
            const aggItemsSet = this.aggExclusions.get(policyId);
            aggItemsSet.push(exclusion);
            break;
          case OxExclusionScope.issue:
            exclusion.exclusionMatch.forEach(i => {
              this.issueExclusions.push(exclusion);
            });
            break;
          case OxExclusionScope.application:
            this.applicationExclusions.push(exclusion);
            break;
          case OxExclusionScope.global:
            this.globalExclusions.push(exclusion);
            break;
          default:
            const msg = `exclusion scope: ${exclusion.exclusionScope} is unknown`;
            logger.error(msg);
            throw msg;
        }

        exclusionsSet.add(exclusionStr);
      } catch (e) {
        logger.error(`failed to create exclusion: ${JSON.stringify(exclusionFromDB)}, orgId: ${this.orgName}. error: ${e}`);
      }
    }

    logger.info(`number of unique exclusions: ${exclusionsSet.size}`);
  }

  public isIssueExcluded(issueId: string, reducedSeverity: boolean) {
    try {
      const exclusion = this.issueExclusions.find(e => e.issueId === issueId);
      if (exclusion) {
        logger.info(`ISSUE EXCLUSION: exclude issue: ${issueId}, reducedSeverity: ${reducedSeverity}`);
      }
      return exclusion;
    } catch (e) {
      logger.error(`error in isIssueExcluded, issueId ${issueId}, reduced severity: ${reducedSeverity}, error: ${e}`);
    }

    return null;
  }

  public isAggItemExcluded(aggId: string, issuePId: string, issueId: string) {
    try {
      //Check based on policy id
      const isPolicyAggItems = this.aggExclusions.has(issuePId);
      if (!isPolicyAggItems) {
        return null;
      }
      const policyAggItems = this.aggExclusions.get(issuePId);
      const exclusion = policyAggItems.find(e => {
        if (e.issueId && e.issueId !== issueId) {
          //not the same issue
          return false;
        }
        return e.exclusionMatch.every(m => m.value === aggId);
      });
      if (exclusion) {
        logger.info(`AGG ITEM EXCLUSION: exclude issueId: ${issueId}, aggId: ${aggId}`);
      }
      return exclusion;
    } catch (e) {
      logger.error(`failed in isAggItemExcluded, aggId: ${aggId}, issueId: ${issueId}, error: ${e}`);
    }
    return null;
  }

  public isGlobalExcluded(aggItem: AggItem, issue: Issue) {
    try {
      const exclusion = this.globalExclusions.find(e => {
        const isAllMatched = e.exclusionMatch.every(match => {
          const val = match.level === OxExclusionLevel.issue ? issue[match.key] : aggItem[match.key];
          const isMatched = val === match.value;
          return isMatched;
        });
        if (isAllMatched) {
          logger.info(
            `GLOBAL EXCLUSION: exclusion: ${JSON.stringify(e)}, issueId: ${issue.issueId}, aggId: ${aggItem.aggId}, appId: ${
              issue.appId
            }, appName: ${issue.appName}, org: ${this.orgName}`,
          );
        }
        return isAllMatched;
      });

      return exclusion;
    } catch (e) {
      logger.error(`failed in isGlobalExcluded, aggItem: ${JSON.stringify(aggItem)} issueId: ${issue.issueId}, error :${e}`);
    }
    return null;
  }

  public isApplicationExcluded(aggItem: AggItem, issue: Issue) {
    try {
      const exclusion = this.applicationExclusions.find(e => {
        const isAllMatched = e.exclusionMatch.every(match => {
          const val = match.level === OxExclusionLevel.issue ? issue[match.key] : aggItem[match.key];
          const isMatched = val === match.value && issue.appId === e.repoId;
          return isMatched;
        });
        if (isAllMatched) {
          logger.info(
            `APPLICATION EXCLUSION: exclusion: ${JSON.stringify(e)}, issueId: ${issue.issueId}, aggId: ${aggItem.aggId}, appId: ${
              issue.appId
            }, appName: ${issue.appName},  org: ${this.orgName}`,
          );
        }

        return isAllMatched;
      });
      return exclusion;
    } catch (e) {
      logger.error(`failed in isApplicationExcluded, aggItem: ${JSON.stringify(aggItem)}, issueId: ${issue.issueId}, error: ${e}`);
    }
    return null;
  }
}

export default RuleExclusions;
