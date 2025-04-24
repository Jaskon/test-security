import { formatDistanceToNow } from "date-fns";
import _ from "lodash";
import { CloudSecurityEvent } from "../../../entitis/cloudTypes";
import {
  AffiliationType,
  AlertSeverity,
  CweObject,
  Dependency,
  IssueOwner,
  OrgRoles,
  PullRequest,
  Repo,
  repoResourceType,
  repoType,
  resourceType,
  SecurityEvent,
  User,
  UserRole,
} from "../../../entitis/codeRepoTypes";
import { ExtraInfo } from "../../../entitis/issuesTypes";
import { PolicyResListItem, Severity } from "../../../entitis/reportTypes";
import { ScaFixType } from "../../../entitis/service/alertrRcommendationTypes";
import { ChangeCategory, ChangeReason, LanguageInfo, SeverityChange, severityReasons } from "../../../entitis/service/blameTypes";
import { capitalizeFirstLetter } from "../../../helper/commonUtils";
import { PipeLineHelper } from "../../../helper/pipelineHelper";
import LanguageHelper from "../../../helper/policy/languageHelper";
import { SCAVulnerability } from "../../../helper/policy/scaVulHelper";
import {
  getPolicyInfo,
  getSeverityFromStr,
  setSeverityFromPolicy,
  SeverityOptions,
  shouldIncludeByPolicy,
} from "../../../helper/policy/severityHelper";
import { getInfoBasedOnCWE, getInfoBasedOnOscar, OscarInfo } from "../../../helper/policyExtraDataHelper";
import { VulnerabilityCount } from "../../../helper/sbom/sbomHelper";
import { ComplianceControl, Policy } from "../../../helper/service/policy-service/types";
import StatesHelper from "../../../helper/statesHelper";
import StringHelper from "../../../helper/stringHelper";
import loggerImport from "../../../logger";
import compliance_mapping_by_ruleid from "../../org/config/compliance_mapping_by_ruleid.json";
import cweToOscar from "../../org/config/cwe_to_oscar.json";
import secretMapping from "../../org/config/secretMapping.json";
import OrgPolicyParser from "../../org/ruleConfigParser";
import ResultsHandler from "../../reporting/ResultsHandler";
import { AppOwnerRole } from "../../reporting/types";
import { PolicySecurityScanAggItem } from "./policySecurityScan";

const logger = loggerImport.getDebugLogger();

abstract class PolicyRulesBase {
  halfYear = 86400000 * 360;

  uuid: string;
  orgName: string;
  policyRuleMetadata: Policy;
  orgPolicyParser: OrgPolicyParser;
  languageHelper: LanguageHelper;
  appId: string;
  repoId: string;
  repoName: string;
  resultsHandler: ResultsHandler;

  //policy
  severityOptions: SeverityOptions;
  policyWasSet = false;

  abstract eval(jsonData: any);

  async runEval(jsObj: any, resultsHandler: ResultsHandler) {
    let res = [];
    let violation = false;

    let appName = "";

    try {
      this.uuid = jsObj.uuid;
      this.orgName = jsObj.orgName;
      this.policyRuleMetadata = jsObj.policyRuleMetadata;
      this.orgPolicyParser = new OrgPolicyParser(jsObj.uuid);
      let resourcesData = jsObj.resourcesData;
      this.appId = resourcesData.code_repo.id;
      this.languageHelper = new LanguageHelper(this.uuid);
      this.resultsHandler = resultsHandler;

      const repo: Repo = resourcesData.code_repo;
      this.repoId = repo.repoId;
      this.repoName = repo.fullName;

      appName = resourcesData.code_repo.fullName;

      if (!this.uuid || !this.policyRuleMetadata || !resourcesData) {
        throw `cannot execute rule: ${this.policyRuleMetadata.name} app name: ${appName}, flow uid: ${jsObj.flowUid} due to missing data, resourcesData: ${resourcesData}`;
      }

      let ignoreAlertDueToImportance = false;
      if (resourcesData.code_repo != undefined) {
        ignoreAlertDueToImportance = resourcesData.code_repo.repoImportance.total == 0;
      }
      const noneRelevantRepo = resourcesData.code_repo.noneRelevantRepo;

      //Dont run git posture on mono repo child
      let shouldRunPolicy = true;

      const isMonoRepoChild = repo.monoRepoChild;
      if (isMonoRepoChild) {
        if (this.policyRuleMetadata.ignoreMonoRepoChild) {
          shouldRunPolicy = false;
        }
      }

      if (
        (process.env.SKIP_POSTURE_POLICIES && (this.policyRuleMetadata.catId == 25 || this.policyRuleMetadata.catId == 3)) ||
        (process.env.SKIP_OLD_SCA_POLICIES &&
          this.policyRuleMetadata.catId == 6 &&
          this.policyRuleMetadata.policyId != "oxPolicy_securityScan_120")
      ) {
        shouldRunPolicy = false;
      }

      if (!ignoreAlertDueToImportance && !noneRelevantRepo && shouldRunPolicy) {
        const timeBeforeRunningPolicy = new Date().getTime();

        res = await this.eval(resourcesData);

        const policyRunTime = (new Date().getTime() - timeBeforeRunningPolicy) / 1000;
        if (policyRunTime > 10) {
          logger.warn(
            `LONG time policy eval for app name: ${appName}, flow uid: ${jsObj.flowUid}, policy code file: ${this.policyRuleMetadata.functionName}, time in seconds: ${policyRunTime}`,
          );
        }
        violation = res.length > 0;
      } else {
        violation = false;
      }
    } catch (err) {
      const errInfo = `failed run rule: ${this.policyRuleMetadata.name}, app name: ${appName}`;
      logger.error(errInfo, err);
    }

    return {
      policy_id: this.policyRuleMetadata.policyId,
      name: this.policyRuleMetadata.name,
      categoryId: this.policyRuleMetadata.catId,
      violation: violation,
      total: res.length,
      list: res,
      description: this.policyRuleMetadata.description,
      severity: this.policyRuleMetadata.severity,
      exclusionCategory: jsObj.policyRuleMetadata.exclusionCategory,
    };
  }

  isSingleAggItemExcluded(aggId: string, issueId: string) {
    return this.resultsHandler.isSingleAggItemExcluded(aggId, this.policyRuleMetadata.policyId, issueId);
  }

  generateCWElist(securityEvents: SecurityEvent[]): string[] {
    const unique = new Set<string>();
    try {
      securityEvents.forEach(secEvent => {
        secEvent.cweList.forEach(cwe => {
          if (typeof cwe !== "string") {
            logger.warn(`generateCWElist, cwe is not string, cwe: ${JSON.stringify(secEvent)}, pol name: ${this.policyRuleMetadata.name}`);
          }
          unique.add(cwe);
        });
      });
    } catch (err) {
      logger.error(`failed set generateCWElist, err: ${err}, pol name: ${this.policyRuleMetadata.name}`, err);
    }
    return Array.from(unique);
  }

  getOscarIdForSecretEvent(securityEvents: SecurityEvent[]) {
    const res = [];

    try {
      securityEvents.forEach((i: SecurityEvent) => {
        let groupKey: string = i.secretGroup ? i.secretGroup : i.ruleId;
        if (secretMapping.groups.hasOwnProperty(groupKey)) {
          const item = secretMapping.groups[groupKey];
          if (item) {
            item.forEach(j => {
              res.push(j);
            });
          }
        }
      });
    } catch (err) {
      logger.error(`failed set getOscarIdForSecretEvent, err: ${err}, pol name: ${this.policyRuleMetadata.name}`);
    }
    return res;
  }

  getValueFromRuleArgs(val: string) {
    const res = this.policyRuleMetadata.args.find(i => i.name.toLowerCase() === val.toLowerCase());
    if (res === undefined) {
      return null;
    }
    return res.value;
  }

  isExistInStringArr(arr, string, item) {
    try {
      if (arr.length == 0) {
        return true;
      }
      if (string === "") {
        return false;
      }

      if (arr.find(i => i.toLowerCase() === "any")) return true;
      if (arr.some(i => i.toLowerCase() === string.toLowerCase())) return true;

      return false;
    } catch (err) {
      logger.error(
        `failed check is exist in array for rule: ${this.policyRuleMetadata.name}, str data: ${string}, item: ${JSON.stringify(
          item,
        )} err: ${err}`,
      );
      throw err;
    }
  }

  getUniqueSecurityProviders(items, provider: string) {
    try {
      const u = new Set();
      items.forEach(i => {
        const h = i as any;
        Array.from(h).forEach(j => {
          u.add(j);
        });
      });
      return Array.from(u) as string[];
    } catch (err) {
      logger.error(`failed get security providers err: ${err}`);
      return [provider];
    }
  }

  addSeverityBasedOnUserChanges() {
    try {
      return new ChangeReason(
        `Manual severity changed`,
        `The severity of the policy was changed through policies page`,
        0,
        ChangeCategory.Exploitable,
      );
    } catch (e) {
      logger.error(`Could not create severity factor due to change of the configured severity by the customer ${e}`);
    }
  }

  setScaFixType(topLevelEventData: SecurityEvent, policyName: string) {
    try {
      let scaFixType = ScaFixType.UNAVAILABLE;
      if (topLevelEventData.alertRecommendationResponse.ScaFixType) {
        scaFixType = topLevelEventData.alertRecommendationResponse.ScaFixType;
      }
      return scaFixType;
    } catch (e) {
      logger.error(`Could not set ScaFixType for policy: ${policyName}, err: ${e}`);
      return ScaFixType.UNKNOWN;
    }
  }

  //TODO: Remove when json will change
  generateItemForReport(
    overrightBP: boolean,
    mainTitle,
    seconderyTitle,
    info,
    recommendation,
    resource,
    resourceType,
    replaceInfo,
    additionalInfo,
    isRepo,
    fixLink,
    aggregatedInfo,
    sources: string[],
    tools: Tool[],
    extraInfo: ExtraInfo[],
    issueId: string,
    issueOwners: IssueOwner[] = [],
    moreInfoLink = "",
    ruleId = "",
    cwe = [],
    snippet = "",
    cweList: CweObject[] = [],
    severity: number = this.policyRuleMetadata.severity,
    dependencyChain: Dependency[] = [],
    publicExploitLink: string = "",
    originalToolSeverityPretty: string = Severity[this.policyRuleMetadata.severity],
    severityChangeReason: string[] = [],
    severityChange: SeverityChange = SeverityChange.NotApplicable,
    severityChangedReason: ChangeReason[] = [],
    scaVulnerabilitiesTable: SCAVulnerability[] = [],
    secEventsSev: VulnerabilityCount[] = [], // array of objects containing original severity of secEvents (from aggregated items)
    languageInfo: LanguageInfo = null,
    isFixApplied: boolean = false,
    fixAppliedBy: string = "",
    oscarDataPerSecrets: string[] = [],
    scaFixType: ScaFixType = ScaFixType.UNAVAILABLE,
    version: string = "",
  ) {
    const stringHelper: StringHelper = new StringHelper();
    let newSeverity;

    if (this.policyRuleMetadata.defaultSeverity != undefined) {
      const sevFactorForConfiguredSev = this.isConfiguredSeverity(
        this.policyRuleMetadata.severity,
        this.policyRuleMetadata.defaultSeverity,
      );
      if (sevFactorForConfiguredSev) {
        severityChangedReason.push(sevFactorForConfiguredSev);
      }
    }
    newSeverity = this.getSeverity(severity);
    const tempSev = setSeverityFromPolicy(originalToolSeverityPretty, newSeverity, this.policyRuleMetadata, severityChangedReason);
    if (tempSev) {
      newSeverity = tempSev;
    }
    if (StatesHelper.Instance.dontChangeSeverity) {
      newSeverity = this.policyRuleMetadata.severity;
    }

    //Handle case of secEventsSev is empty
    if (secEventsSev.length === 0) {
      secEventsSev = this.handleSecEventsSev(aggregatedInfo, newSeverity);
    }

    const oscarData = {
      oscar: [],
    };
    this.setOscar(extraInfo, oscarData, cwe, oscarDataPerSecrets);
    this.setCWE(cweList);

    //Handle original severity
    if (!originalToolSeverityPretty) {
      originalToolSeverityPretty = AlertSeverity[this.policyRuleMetadata.severity];
    }

    const originalToolSeverity = capitalizeFirstLetter(originalToolSeverityPretty);
    if (!originalToolSeverity) {
      logger.error(
        `something went wrong, empty original severity for: ${this.policyRuleMetadata.name}, severity: ${this.policyRuleMetadata.severity}, defaultSeverity: ${this.policyRuleMetadata.defaultSeverity}, originalToolSeverityPretty: ${originalToolSeverityPretty}`,
      );
    }

    //Set pipeline specific config
    let newIssuesPipelineOptionId = this.policyRuleMetadata.newIssuesPipelineOptionId;
    let oldIssuesPipelineOptionId = this.policyRuleMetadata.oldIssuesPipelineOptionId;
    if (StatesHelper.Instance.isPipelineScan) {
      const specificConfig = PipeLineHelper.Instance.getSpecificConfiguForPolicy(
        this.policyRuleMetadata,
        newSeverity,
        this.repoId,
        this.repoName,
      );
      if (specificConfig) {
        newIssuesPipelineOptionId = specificConfig.newIssuesPipelineOptionId;
        oldIssuesPipelineOptionId = specificConfig.oldIssuesPipelineOptionId;
      }
    }

    const alert: PolicyResListItem = {
      mainTitle: stringHelper.replaceAll(mainTitle, replaceInfo),
      secondTitle: stringHelper.replaceAll(seconderyTitle, replaceInfo),
      info: stringHelper.replaceAll(info, replaceInfo), // info shold
      recommendation: stringHelper.replaceAll(recommendation, replaceInfo),
      resource: stringHelper.replaceAll(resource, replaceInfo),
      isRepo: isRepo,
      severity: newSeverity,
      resource_type: stringHelper.replaceAll(resourceType, replaceInfo),
      fixLink: fixLink,
      policy_id: this.policyRuleMetadata.policyId,
      name: this.policyRuleMetadata.name,
      description: stringHelper.replaceAll(this.policyRuleMetadata.description, replaceInfo),
      violation: true,
      additionalInfo: additionalInfo,
      show_remediation: false,
      aggregatedInfo: aggregatedInfo,
      detailedDescription: this.policyRuleMetadata.detailedDescription,
      moreInfoLink: moreInfoLink,
      exclusionCategory: this.policyRuleMetadata.exclusionCategory,
      issueOwners,
      ruleId: ruleId,
      extraInfo,
      cwe,
      snippet,
      cweList,
      issueId,
      dependencyChain,
      publicExploitLink,
      originalToolSeverity,
      severityChangeReason: severityChangeReason,
      severityChange,
      severityChangedReason: severityChangedReason,
      scaVulnerabilitysTable: scaVulnerabilitiesTable,
      sources: sources,
      newIssuesPipelineOptionId: newIssuesPipelineOptionId,
      oldIssuesPipelineOptionId: oldIssuesPipelineOptionId,
      pipelineScanJobInfo: PipeLineHelper.Instance.pipelineScanJobInfo,
      countRule: this.policyRuleMetadata.countRule,
      fixes: undefined,
      overrightBP: overrightBP,
      directSCAVulnerability: undefined,
      noneDirectSCAVulnerability: undefined,
      allUniqueLibs: undefined,
      languageInfo,
      indirectSupported: false,
      scaTriggerPkg: undefined,
      libId: undefined,
      isFixApplied,
      fixAppliedBy,
      oscarData: oscarData.oscar,
      eventFromExternalTool: false,
      compliance: this.getCompliance(ruleId),
      tools,
      graphExists: undefined,
      blameExists: undefined,
      secEventsSev,
      additionalTabs: undefined,
      correlatedIssueId: undefined,
      correlatedRegistry: undefined,
      uniqueArtifacts: [],
      problematicPkg: undefined,
      dataRangeInDays: this.policyRuleMetadata.dataRangeInDays,
      scaFixType,
      oxRecommendationExists: false,
      commitInfoExists: false,
      ignoreResolve: this.policyRuleMetadata.ignoreResolve,
      triggerPkgForResolveIssues: undefined,
      uid: undefined,
      isSilent: false,
      version,
    };
    return alert;
  }

  getSeverity(severity: any) {
    try {
      const newSeverity = Math.floor(severity) in Severity ? Math.floor(severity) : this.policyRuleMetadata.severity;
      return newSeverity;
    } catch (err) {
      logger.error(`failed to generate severity: ${err}, pol: ${this.policyRuleMetadata.name}`);
    }
    const newSeverity = severity in Severity ? severity : this.policyRuleMetadata.severity;
    return newSeverity;
  }

  isConfiguredSeverity(severity: number, defaultSeverity: number) {
    try {
      if (severity - defaultSeverity > 0) {
        severityReasons.configuredSevIsHigher.reason = `The severity of the policy was changed through policies page from ${AlertSeverity[defaultSeverity]} to ${AlertSeverity[severity]}`;
        return severityReasons.configuredSevIsHigher;
      } else if (severity - defaultSeverity < 0) {
        severityReasons.configuredSevIsLower.reason = `The severity of the policy was changed through policies page from ${AlertSeverity[defaultSeverity]} to ${AlertSeverity[severity]}`;
        return severityReasons.configuredSevIsLower;
      }
    } catch (e) {
      logger.error(`Could not create severity factor due to change of the configured severity by the customer ${e}`);
    }
  }

  dateToDaysNow(dateString: string) {
    try {
      const date = Date.parse(dateString);
      const diff = Math.round((Date.now() - date) / (1000 * 3600 * 24));
      return diff;
    } catch (e) {
      logger.error(`Could not get date in days, err: ${e}`);
    }
  }

  handleSecEventsSev(aggregatedInfo, newSeverity: number) {
    try {
      let secEventsSev = [];

      let severity = newSeverity;

      //no agg items
      if (severity) {
        if (aggregatedInfo.length === 0) {
          {
            const originalSev: VulnerabilityCount = {
              severity: severity.toString(),
              count: 1,
            };
            secEventsSev.push(originalSev);
          }
        } else {
          const originalSev: VulnerabilityCount = {
            severity: severity.toString(),
            count: aggregatedInfo?.aggregatedItems?.length,
          };
          secEventsSev.push(originalSev);
        }
      }
      return secEventsSev;
    } catch (e) {
      logger.error(
        `Could not add secEventSev for functionName: ${this.policyRuleMetadata.functionName}, policy: ${this.policyRuleMetadata.name} error: ${e}`,
        e,
      );
    }
    return [];
  }

  getCompliance(ruleId: string) {
    try {
      const copy: ComplianceControl[] = this.policyRuleMetadata.compliance ? this.policyRuleMetadata.compliance : [];

      const complianceInfo: ComplianceControl[] = JSON.parse(JSON.stringify(copy));
      const unique = new Set();

      complianceInfo.forEach(i => {
        unique.add(`${i.standard}_${i.control}`);
      });

      try {
        if (ruleId) {
          const dataFromConfig = compliance_mapping_by_ruleid[ruleId];

          if (dataFromConfig) {
            dataFromConfig.forEach(item => {
              const key = `${item.standard}_${item.control}`;
              if (unique.has(key)) {
                return;
              }
              unique.add(key);

              const c: ComplianceControl = new ComplianceControl();
              c.control = item.control;
              c.standard = item.standard;
              c.category = item.category;
              c.description = item.description;
              c.controlLink = item.controlLink;
              complianceInfo.push(c);
            });
          }
        }
      } catch (err) {
        logger.error(
          `failed to set compliance from compliance_mapping_by_ruleid, rule name: ${this.policyRuleMetadata.name}, severity: ${this.policyRuleMetadata.severity}, err: ${err}`,
        );
      }

      return complianceInfo;
    } catch (err) {
      logger.error(
        `failed to set compliance, rule name: ${this.policyRuleMetadata.name}, severity: ${this.policyRuleMetadata.severity}, err: ${err}`,
      );
    }
    return [];
  }

  setCWE(CweList: CweObject[]) {
    try {
      if (!this.policyRuleMetadata.cwe) {
        return;
      }

      this.policyRuleMetadata.cwe.forEach(i => {
        const cweInfo: CweObject = getInfoBasedOnCWE(i);
        if (!cweInfo) {
          return;
        }
        const item: CweObject = new CweObject();
        item.description = cweInfo.description;
        item.name = cweInfo.name;
        item.shortName = cweInfo.name;
        item.url = cweInfo.url;
        CweList.push(item);
      });
    } catch (err) {
      logger.error(
        `failed to set cwe, rule name: ${this.policyRuleMetadata.name}, severity: ${this.policyRuleMetadata.severity}, err: ${err}`,
      );
    }
  }

  setOscar(extraInfo: ExtraInfo[], oscarData: any, cweListFromBlame: string[], oscarDataPerSecrets: string[]) {
    try {
      let oscarIdArray: string[] = [];
      if (this.policyRuleMetadata.oscarId && this.policyRuleMetadata.oscarId.length > 0) {
        oscarIdArray = JSON.parse(JSON.stringify(this.policyRuleMetadata.oscarId));
      } else if (oscarDataPerSecrets && oscarDataPerSecrets.length > 0) {
        oscarIdArray = oscarIdArray.concat(oscarDataPerSecrets);
      } else if (cweListFromBlame && cweListFromBlame.length > 0) {
        cweListFromBlame.forEach((cwe: string) => {
          const fallbackOscarIds = cweToOscar[cwe];
          if (!fallbackOscarIds) {
            return;
          }
          fallbackOscarIds.forEach((i: string) => {
            oscarIdArray.push(i);
          });
        });
      }

      const unique = new Set();
      oscarIdArray.forEach(i => {
        const oscarInfoOriginal: OscarInfo = getInfoBasedOnOscar(i);
        if (!oscarInfoOriginal) {
          return;
        }
        if (unique.has(oscarInfoOriginal.name)) {
          return;
        }
        unique.add(oscarInfoOriginal.name);

        //Copy
        const oscarInfo: OscarInfo = JSON.parse(JSON.stringify(oscarInfoOriginal));

        oscarInfo.name = `${oscarInfo.id}: ${oscarInfo.name}`;
        oscarData.oscar.push(oscarInfo);
      });
    } catch (err) {
      logger.error(
        `failed to set oscar, rule name: ${this.policyRuleMetadata.name}, severity: ${this.policyRuleMetadata.severity}, err: $`,
      );
    }
  }

  getFilesAfterFilter(pullRequest: PullRequest, extensionsFromArgs: string[]) {
    try {
      const res = pullRequest.uniqueFilesChanged.filter(i =>
        extensionsFromArgs.every(extension => i.toLowerCase().endsWith(extension.toLowerCase()) === false),
      );
      return res;
    } catch (err) {
      logger.error(`failed get files after filter err: ${err}`);
    }
    return [];
  }

  getOwnersFromUsers(jsonData) {
    const repo: Repo = jsonData.code_repo;

    try {
      if (!jsonData.code_repo.realRepo) {
        return [];
      }
      if (repo.type === repoType.awsCodeCommit) {
        return [];
      }
      const users = jsonData.code_repo.repoUsers as User[];
      users.sort((a, b) => (a.createdAt < b.createdAt ? 1 : -1));
      let res: IssueOwner[] = [];

      const veteranReviewers = jsonData.code_repo.mostVeretanUsers as string[];
      const owners = users.filter(u => u.role === UserRole.OWNER);
      if (owners.length > 0) {
        for (const vetReviewer of veteranReviewers) {
          const owner = owners.find(owner => owner.name === vetReviewer);
          if (owner && owner.name !== "") {
            res.push({
              name: owner.name,
              email: owner.email || "",
              username: owner.username || "",
            });
            break;
          }
        }
        if (res.length > 0) {
          return res;
        } else {
          if (owners[0].name !== "") {
            return [owners[0]].map(u => {
              return {
                name: u.name,
                email: u.email || "",
                username: u.username || "",
              };
            });
          }
        }
      }
      const maintainers = users.filter(u => u.role === UserRole.MAINTAINER);
      if (maintainers.length > 0) {
        for (const veteran of veteranReviewers) {
          const maintainer = maintainers.find(maintainer => maintainer.name === veteran);
          if (maintainer && veteran !== "") {
            res.push({
              name: veteran,
              email: maintainer.email || "",
              username: maintainer.username || "",
            });
            break;
          }
        }
        if (res.length > 0) {
          return res;
        } else {
          if (maintainers[0].name !== "") {
            return [maintainers[0]].map(u => {
              return {
                name: u.name,
                email: u.email || "",
                username: u.username || "",
              };
            });
          }
        }
      }
      const developers = users.filter(u => u.role === UserRole.DEVELOPER);
      if (developers.length > 0) {
        for (const veteran of veteranReviewers) {
          const developer = developers.find(developer => developer.name === veteran);
          if (developer && veteran !== "") {
            res.push({
              name: veteran,
              email: developer.email || "",
              username: developer.username || "",
            });
            break;
          }
        }
        if (res.length > 0) {
          return res;
        } else {
          if (developers[0].name !== "") {
            return [developers[0]].map(u => {
              return {
                name: u.name,
                email: u.email || "",
                username: u.username || "",
              };
            });
          }
        }
      }

      if (res.length == 0) {
        if (repo) {
          return [
            {
              name: repo.ownerName || "",
              email: repo.ownerEmail || "",
              username: repo.ownerName || "",
            },
          ];
        }
      }

      return res;
    } catch (e) {
      logger.error(`failed to get owners from users, error :${e}`);
    }

    if (!repo) {
      return [];
    }

    return [
      {
        name: repo.ownerName || "",
        email: repo.ownerEmail || "",
        username: repo.ownerName || "",
      },
    ];
  }

  getOwnersFromAppCreator(jsonData) {
    try {
      if (!jsonData.code_repo.realRepo) {
        return [];
      }
      const res: IssueOwner[] = [];
      const { ownerName, ownerEmail } = jsonData.code_repo;
      if (ownerName && ownerName !== "") {
        res.push({ name: ownerName, email: ownerEmail });
      }

      return res;
    } catch (e) {
      logger.error(`failed to get app creator, error: ${e}`);
    }
    return [];
  }

  setPolicyInfo() {
    if (this.policyWasSet) {
      return;
    }
    this.policyWasSet = true;

    let arg = this.policyRuleMetadata.displayIssueSeverity;
    this.severityOptions = getPolicyInfo(arg);

    //Debug
    //logger.info(`policy name: ${this.policyRuleMetadata.name} set severity: ${JSON.stringify(this.severityOptions)}, from policy: ${arg}`);
  }

  shouldIncludeByPolicyEx(alertSeverity: AlertSeverity) {
    this.setPolicyInfo();
    const res = shouldIncludeByPolicy(alertSeverity, this.severityOptions);
    return res;
  }

  getUserJson(bypassedUser: any, gitType: string, users: User[]) {
    try {
      switch (gitType) {
        case repoType.github:
          return users.filter(i => i.name === bypassedUser.login)[0];

        case repoType.gitlab:
          return bypassedUser;
      }
    } catch (err) {
      logger.error(`failed getting user: ${bypassedUser} object, err: ${err}`);
    }
  }

  checkOutsideCollaborator(user: any, gitType: string, commonUserPrefixSuffix: any) {
    try {
      switch (gitType) {
        case repoType.github:
          if (user.affiliation.has(AffiliationType.outside)) {
            const partOfCommon = commonUserPrefixSuffix.find(i => user.username.startsWith(i) || user.username.endsWith(i));
            if (!partOfCommon) {
              return true;
            }
          }
          break;

        case repoType.gitlab:
          if (user.orgRole.has(OrgRoles.COLLABORATORS)) return true;
      }

      return false;
    } catch (err) {
      logger.error(`failed checking if user: ${user} is outside collaborator, err: ${err}`);
    }
  }

  getOwnersFromAppOwnersConfig(jsonData) {
    try {
      const res: IssueOwner[] = [];
      const repo = jsonData.code_repo as Repo;
      if (repo.type === repoType.awsCodeCommit) {
        return [];
      }
      const veteranReviewers = jsonData.code_repo.mostVeretanUsers as string[];
      const { appOwners } = repo;
      if (appOwners) {
        if (appOwners.length === 0) return [];
        const devOwners = appOwners.filter(owner => owner.roles.includes(AppOwnerRole.Dev));
        if (devOwners.length > 0) {
          for (const veteran of veteranReviewers) {
            const devOwner = devOwners.find(devOwner => devOwner.name === veteran);
            if (devOwner && veteran !== "") {
              res.push({ name: veteran, email: devOwner.email || "" });
            }
            break;
          }
          if (res.length > 0) {
            return res;
          } else {
            return devOwners.map(u => {
              if (u.name !== "") return { name: u.name, email: u.email || "" };
            });
          }
        }
        const secOwners = appOwners.filter(owner => owner.roles.includes(AppOwnerRole.Security));

        if (secOwners.length > 0) {
          for (const veteran of veteranReviewers) {
            const secOwner = secOwners.find(secOwner => secOwner.name === veteran);
            if (secOwner && veteran !== "") {
              res.push({ name: veteran, email: secOwner.email || "" });
              break;
            }
          }
          if (res.length > 0) {
            return res;
          } else {
            return secOwners.map(u => {
              if (u.name !== "") return { name: u.name, email: u.email || "" };
            });
          }
        }

        return res;
      }
    } catch (e) {
      logger.error(`failed to get issue owners, error: ${e}`);
    }
    return [];
  }

  getUserActivityBasedPretty(length: number, time: Date) {
    try {
      const res = `${length} ${length == 1 ? "operation" : "operations"}, last: ${formatDistanceToNow(time, {
        addSuffix: true,
      })}`;

      return res;
    } catch (err) {
      logger.error(`failed get user activity based on logs, error: ${err}`);
    }
    return "";
  }

  getAdminWithMaxOperations(users: User[], adminRole: string, isRepo = false) {
    try {
      if (!users) {
        return;
      }

      const usersThatNotOutside = users.filter(i => !i.affiliation.has(AffiliationType.outside));

      let allAdminUsers;

      if (isRepo) {
        allAdminUsers = usersThatNotOutside.filter(u => (Array.from(u.repoRolesRaw) as string[]).find(i => i?.toLowerCase() === adminRole));
      } else {
        allAdminUsers = usersThatNotOutside.filter(u => (Array.from(u.orgRole) as string[]).find(i => i?.toLowerCase() === adminRole));
      }

      if (allAdminUsers.length == 0) {
        return;
      }

      const usersWithAdminOperation = allAdminUsers.filter(u => u.adminOperation > 0);
      if (usersWithAdminOperation.length > 0) {
        const sortedAdmins = usersWithAdminOperation.sort((a, b) => b.adminOperation - a.adminOperation);
        return sortedAdmins[0];
      }

      const usersWithDevOperation = allAdminUsers.filter(u => u.devOperation > 0);
      if (usersWithDevOperation.length > 0) {
        const sortedAdmins = usersWithDevOperation.sort((a, b) => b.devOperation - a.devOperation);
        return sortedAdmins[0];
      }

      return allAdminUsers[0];
    } catch (err) {
      logger.error(`failed get admin with max operations, on policy: ${this.policyRuleMetadata.functionName} error: ${err}`);
    }
  }

  getAdminWithMaxDevOperations(users: User[], adminRole: string, isRepo = false) {
    try {
      if (!users) {
        return;
      }

      const usersThatNotOutside = users.filter(i => !i.affiliation.has(AffiliationType.outside));

      let allAdminUsers;

      if (isRepo) {
        allAdminUsers = usersThatNotOutside.filter(u => (Array.from(u.repoRolesRaw) as string[]).find(i => i.toLowerCase() === adminRole));
      } else {
        allAdminUsers = usersThatNotOutside.filter(u => (Array.from(u.orgRole) as string[]).find(i => i.toLowerCase() === adminRole));
      }

      if (allAdminUsers.length == 0) {
        return;
      }

      const usersWithDevOperation = allAdminUsers.filter(u => u.devOperation > 0);
      if (usersWithDevOperation.length > 0) {
        const sortedAdmins = usersWithDevOperation.sort((a, b) => b.devOperation - a.devOperation);
        return sortedAdmins[0];
      }

      const usersWithAdminOperation = allAdminUsers.filter(u => u.adminOperation > 0);
      if (usersWithAdminOperation.length > 0) {
        const sortedAdmins = usersWithAdminOperation.sort((a, b) => b.adminOperation - a.adminOperation);
        return sortedAdmins[0];
      }

      return allAdminUsers[0];
    } catch (err) {
      logger.error(`failed get admin with max dev operations, on policy: ${this.policyRuleMetadata.functionName} error: ${err}`);
    }
  }

  getUserWithMaxOperations(users: User[]) {
    try {
      if (!users) {
        return;
      }

      const usersThatNotOutside = users.filter(i => !i.affiliation.has(AffiliationType.outside));

      const sortedUsers = usersThatNotOutside.sort((a, b) => b.devOperation - a.devOperation);
      return sortedUsers[0];
    } catch (err) {
      logger.error(`failed get admin with max operations, on policy: ${this.policyRuleMetadata.functionName} error: ${err}`);
    }
  }

  getOriginalSev(secEvents: SecurityEvent[] | CloudSecurityEvent[]) {
    try {
      const originalSev = {};
      let sevArr: any[] = [];
      if (secEvents.length === 0) {
        return [];
      }
      for (const event of secEvents) {
        if (event.isSilent) {
          continue;
        }
        let severity = event.originalSeverityStr?.toLowerCase();
        if (!severity) {
          severity = this?.policyRuleMetadata?.severity?.toString();
        }
        if (severity == undefined) {
          continue;
        }
        originalSev[severity] = (originalSev[severity] || 0) + 1;
      }
      sevArr = Object.entries(originalSev).map(([severity, count]) => ({
        severity: getSeverityFromStr(severity).toString(),
        count,
      }));
      return sevArr;
    } catch (err) {
      logger.error(`failed get mapping of original severity, on policy: ${this.policyRuleMetadata.functionName} error: ${err}`);
    }
    return [];
  }
  //All the policy's that not have aggregated items will use it
  getGeneralIssueId() {
    return StringHelper.combineStrings(this.appId, this.policyRuleMetadata.policyId);
  }

  //Most of the policy that have aggregated items will use it
  getCustomIssueId(unique: string) {
    return StringHelper.combineStrings(this.appId, this.policyRuleMetadata.policyId, unique);
  }

  handlePermissionsDisplay(permissions) {
    if (permissions[0] === "push" && permissions.includes("triage")) {
      return ["Triage", "Write"].join(", ");
    }
    const res = permissions.map(p => p.charAt(0).toUpperCase() + p.slice(1));
    return res[0];
  }

  adminPercentageFromTotal(partialValue, totalValue) {
    return (100 * partialValue) / totalValue;
  }

  limitPercentage(minAdminsPercentage, totalUsers) {
    return (minAdminsPercentage / 100) * totalUsers;
  }

  isPossibleBot = (user: User, botStrings: string[]) => {
    try {
      const hasSubString = botStrings?.find(sub => {
        return user.name.toLowerCase().includes(sub);
      });

      return hasSubString ? true : false;
    } catch (e) {
      logger.error(`isPossibleBot error: ${e}`, e);
    }
    return false;
  };

  publicOrPrivate(repo: Repo) {
    return repo.privateVisability ? "private" : "public";
  }

  arrangeForPII(aggEvents, fallBack?) {
    try {
      const sorted = [];

      const groupedByFileName = _.groupBy(aggEvents, "fileName");

      for (const events of Object.values(groupedByFileName)) {
        sorted.push(events[0]);
      }

      for (const events of Object.values(groupedByFileName)) {
        sorted.push(...events.slice(1));
      }
      return sorted;
    } catch (e) {
      logger.error(`failed to sortByCountByFile`, e);
    }
    if (fallBack) {
      return fallBack(aggEvents);
    } else {
      return aggEvents;
    }
  }

  handlePiiSevExtraInfo(uniqueSeverityChanges: ChangeReason[], events: PolicySecurityScanAggItem[]) {
    try {
      const piiSeverityFactors = uniqueSeverityChanges.filter(
        sf =>
          sf.shortName === severityReasons.piiInCode.shortName ||
          sf.shortName === severityReasons.piiInPrivateRepo.shortName ||
          sf.shortName === severityReasons.piiInPublicRepo.shortName ||
          sf.shortName === severityReasons.piiInCodeHistory.shortName,
      );

      piiSeverityFactors.map(sf => this.handleSingleSevExtraInfo(sf, events));
    } catch (e) {
      logger.error(`failed to handlePiiSevExtraInfo policy: ${this.policyRuleMetadata.name}`, e);
    }
  }

  handleSingleSevExtraInfo(severityReason: ChangeReason, events: PolicySecurityScanAggItem[]) {
    try {
      if (severityReason) {
        let count = 0;
        severityReason.extraInfo = [];

        for (const aggItem of events) {
          const lastPartLength = Math.max(Math.ceil(aggItem.match.length / 3), Math.min(8, aggItem.match.length - 1), 0);
          const reducted = aggItem.match.substring(0, aggItem.match.length - lastPartLength) + "*".repeat(lastPartLength);

          severityReason.extraInfo.push({
            key: "Snippet",
            link: aggItem.link,
            snippet: {
              fileName: aggItem.fileName,
              text: reducted,
              language: aggItem.language,
              snippetLineNumber: aggItem.startLine,
            },
          });
          count++;

          if (count >= 10) {
            break;
          }
        }
      }
    } catch (e) {
      logger.error(`failed to handleSingleSevExtraInfo policy: ${this.policyRuleMetadata.name}`, e);
    }
  }
}

export default PolicyRulesBase;

export type Tool =
  | "UNKNOWN"
  | "NONE"
  | "trivy-sbom"
  | "min-permissions"
  | "snyk"
  | "aws"
  | "syft"
  | "aws-cloud"
  | "grype"
  | "wiz-cspm"
  | "prisma-cspm"
  | "check-marx-sca"
  | "check-marx-sast"
  | "circleci"
  | "snyk-open-source"
  | "snyk-container"
  | "semgrep"
  | "semgrep-enterprise"
  | "semgrep CLI"
  | "jenkins"
  | "gitleaks"
  | "checkov"
  | "coverity"
  | "spectral"
  | "trivy"
  | "gitlab-ci/cd"
  | "Snyk CLI"
  | "docker-file-scan"
  | "dependabot"
  | "gitlab-sec-issues"
  | "gitlab-dependency-scanning"
  | "gitlab-secret"
  | "gitlab-security-center"
  | "github-security-center"
  | "klocwork"
  | "orca"
  | "prisma-artifacts"
  | "snyk-code"
  | "sonar-qube"
  | "sona-type"
  | "azure-pipelines"
  | "vera-code"
  | "wiz"
  | "black-duck"
  | "dep-confusion"
  | "dep-jacking"
  | "dep-confusion-alert"
  | "depJaking"
  | "docker-scan"
  | "snyk-license"
  | "snyk-iac"
  | "droneci"
  | "gitHub-actions"
  | "prowler-cspm"
  | "azure-webhooks"
  | "bitbucket-webhooks"
  | "hcl"
  | "fortify"
  | "intercept"
  | "solace"
  | "kong"
  | "generic"
  | "black-duck-license"
  | repoResourceType
  | resourceType;
