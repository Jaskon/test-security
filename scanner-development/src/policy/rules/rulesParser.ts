import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();

import fs from "fs";
import CollectorManager from "../../dal/collectorManager";
import { AlertSeverity, Repo, SecurityAlertType } from "../../entitis/codeRepoTypes";
import { Constant } from "../../entitis/constant";
import { OrgPolicy } from "../../entitis/orgPolicyTypes";
import FileHelper from "../../helper/IO/fileHlper";
import { ConfigForSpecificPolicy, PipeLineHelper } from "../../helper/pipelineHelper";
import { getPolicyInfo, SeverityOptions, shouldIncludeByPolicy } from "../../helper/policy/severityHelper";
import GraphQlHelper from "../../helper/service/graphQlHelper";
import { PolicyService } from "../../helper/service/policy-service/api";
import { PipelineOptionId, Policy } from "../../helper/service/policy-service/types";
import StatesHelper from "../../helper/statesHelper";
import MongoConnect from "../../mongo/mongoConnect";

class RulesParser {
  uuid: string;
  dir: string;
  orgPolicy: OrgPolicy;
  orgName: string;
  mongoConnect: MongoConnect;
  graphQlHelper: GraphQlHelper;
  collectorManager: CollectorManager;
  ignoreBusinessPriorityPolicies = new Set();

  private disabledPolicies: Policy[] = [];
  private policyRules: Policy[] = [];

  constructor(uuid: string, orgPolicy: OrgPolicy, orgName: string, mongoConnect: MongoConnect, collectorManager: CollectorManager) {
    this.uuid = uuid;

    this.dir = __dirname + "/config/";
    this.orgPolicy = orgPolicy;
    this.orgName = orgName;
    this.mongoConnect = mongoConnect;
    this.collectorManager = collectorManager;
    this.graphQlHelper = new GraphQlHelper(this.uuid, this.orgName);
  }

  async init(isDemo: boolean, isPipelineMode: boolean = false) {
    await this.graphQlHelper.init();
    await this.fetchRules(isDemo, isPipelineMode);
  }

  getRules() {
    return this.policyRules;
  }

  getDisabledPolicies() {
    return this.disabledPolicies;
  }

  getDisablePolicyBasedOnSeverity(policyId: string, policyName: string, newSeverityNumber: number) {
    const newSeverity = AlertSeverity[newSeverityNumber];
    try {
      const currentPolicy = this.policyRules.find(i => i.policyId === policyId || i.name === policyName);
      if (!currentPolicy) {
        logger.info(`cannot find current policyName: ${policyName}, severity: ${newSeverity}`);
        return;
      }

      if (currentPolicy.displayIssueSeverity != undefined) {
        let arg = currentPolicy.displayIssueSeverity;
        const severityOptions: SeverityOptions = getPolicyInfo(arg);
        const res = shouldIncludeByPolicy(newSeverityNumber, severityOptions);
        if (res) {
          return;
        }
        return currentPolicy;
      }

      const allPolicyRelated = this.disabledPolicies.filter(
        i => i.categoryId === currentPolicy.categoryId && i.functionName === currentPolicy.functionName,
      );
      if (allPolicyRelated.length == 0) {
        return;
      }

      let p;
      for (const pol of allPolicyRelated) {
        for (const arg of pol.args) {
          if (arg.name.toLowerCase() !== "alertseverity") {
            continue;
          }
          if (!Array.isArray(arg.value)) {
            continue;
          }
          if (arg.value[0].toLowerCase() === newSeverity.toLowerCase()) {
            p = pol;
            break;
          }
        }
        if (p) {
          break;
        }
      }
      return p;
    } catch (err) {
      logger.info(`finish get policy based on severity, policyName: ${policyName}, severity: ${newSeverity}, err: ${err}`);
    }
  }

  getChangedPolicyBasedOnSeverity(policyId: string, policyName: string, newSeverityNumber: number) {
    const newSeverity = AlertSeverity[newSeverityNumber];
    try {
      const currentPolicy = this.policyRules.find(i => i.policyId === policyId || i.name === policyName);
      if (!currentPolicy) {
        logger.info(`cannot find current policyName: ${policyName}, severity: ${newSeverity}`);
        return;
      }

      const allPolicyRelated = this.policyRules.filter(
        i => i.categoryId === currentPolicy.categoryId && i.functionName === currentPolicy.functionName,
      );
      if (allPolicyRelated.length == 0) {
        return;
      }

      let p;
      for (const pol of allPolicyRelated) {
        for (const arg of pol.args) {
          if (arg.name.toLowerCase() !== "alertseverity") {
            continue;
          }
          if (!Array.isArray(arg.value)) {
            continue;
          }
          if (arg.value[0].toLowerCase() === newSeverity.toLowerCase()) {
            p = pol;
            break;
          }
        }
        if (p) {
          break;
        }
      }
      return p;
    } catch (err) {
      logger.info(`finish get changed policy based on severity, policyName: ${policyName}, severity: ${newSeverity}, err: ${err}`);
    }
  }

  processPolicyRulesForPipeLine(repo: Repo, policyRules: Policy[]) {
    const rules: Policy[] = [];

    for (const policyRule of policyRules) {
      let rule = this.createAndVerifyRule(policyRule, repo.repoId, repo.fullName);
      if (rule == null) {
        continue;
      }
      if (!policyRule.selected) {
        logger.info(
          `policy name: ${policyRule.name}, id: ${policyRule.ruleId} added for ${repo.fullName}, execType: ${policyRule.execType}, enable: ${policyRule.selected}`,
        );
      }
      rules.push(rule);
    }
    PipeLineHelper.Instance.printPolicySpecificConfig();
    return rules;
  }

  async fetchRules(isDemo: boolean, isPipelineMode: boolean): Promise<Policy[]> {
    try {
      if (isPipelineMode && process.env.DEBUG === undefined) {
        const appPolicies = PipeLineHelper.Instance.rootAppPolicies;

        for (const policyRule of appPolicies) {
          let rule = this.createAndVerifyRule(policyRule, PipeLineHelper.Instance.repoId, PipeLineHelper.Instance.repoName);
          if (rule == null) {
            continue;
          }

          if (this.isPolicyIgnoreBusinessPriority(rule)) {
            this.ignoreBusinessPriorityPolicies.add(rule.policyId);
          }
          if (!policyRule.selected) {
            logger.info(
              `skipping policy name: ${policyRule.name} id: ${policyRule.ruleId}, added, execType: ${policyRule.execType}, enable: ${policyRule.selected}`,
            );
            continue;
          }

          logger.info(
            `adding policy name: ${policyRule.name} id: ${policyRule.ruleId}, added, execType: ${policyRule.execType}, enable: ${policyRule.selected}, severity: ${policyRule.severity}, defaultS: ${policyRule.defaultSeverity}`,
          );
          this.policyRules.push(rule);
        }
        PipeLineHelper.Instance.printPolicySpecificConfig();
        return;
      }

      if (!process.env.DEBUG) {
        logger.info(`try get all policy rules`);

        const policyListFromDB = await PolicyService.Instance.getSelectedPolicies(this.orgName);
        const disablePoliciesFromDB: Policy[] = await this.graphQlHelper.invokeDisablePoliciesForActiveProfileQueryRequest();

        //From DB
        for (const policyRule of policyListFromDB) {
          let rule = this.createAndVerifyRule(policyRule);
          if (rule == null) {
            logger.error(
              `failed load policy name: ${policyRule.name} id: ${policyRule.ruleId}, added, execType: ${policyRule.execType}, enable: ${policyRule.selected}, createAndVerifyRule failed`,
            );
            continue;
          }

          if (this.isPolicyIgnoreBusinessPriority(rule)) {
            this.ignoreBusinessPriorityPolicies.add(rule.policyId);
          }

          if (!policyRule.selected) {
            logger.info(
              `skipping policy name: ${policyRule.name} id: ${policyRule.ruleId}, added, execType: ${policyRule.execType}, enable: ${policyRule.selected}`,
            );
            continue;
          }

          logger.info(
            `adding policy name: ${policyRule.name} id: ${policyRule.ruleId}, added, execType: ${policyRule.execType}, enable: ${policyRule.selected}, severity: ${policyRule.severity}, defaultS: ${policyRule.defaultSeverity}`,
          );
          this.policyRules.push(rule);
        }

        //Add for specific org
        if (
          StatesHelper.Instance.orgName.toLowerCase() !== "org_w8bmCRRdcj6HnQGL".toLowerCase() ||
          StatesHelper.Instance.orgName.toLowerCase() !== "org_ZyE4SHkTEFk3z5aX".toLowerCase()
        ) {
          const fileHelpe: FileHelper = new FileHelper(this.uuid);
          let policyFiles = await fileHelpe.getFiles(this.dir);
          const p = policyFiles.find(i => i.name.includes("policyRuntimeApplicationSecretsScanning.json"));
          if (p) {
            const polItem = this.getRuleFormFile(p.name);
            if (polItem != null) {
              logger.info(`try policy name: ${polItem.name} was added from disk`);
              let rule = this.createAndVerifyRule(polItem);
              if (rule != null) {
                this.policyRules.push(rule);
                logger.info(`add policy name: ${polItem.name} was added from disk`);
              }
            }
          }
        }

        // from DB - disable policies
        for (const policyRule of disablePoliciesFromDB) {
          let rule = this.createAndVerifyRule(policyRule);
          if (rule == null) {
            continue;
          }
          this.disabledPolicies.push(rule);
        }

        //Demo files from disk
        const demoFiles = await this.getDemoFiles(isDemo);
        for (const policyFile of demoFiles) {
          const polItem = this.getRuleFormFile(policyFile.name);
          if (polItem == null) {
            continue;
          }
          let rule = this.createAndVerifyRule(polItem);
          if (rule == null) {
            continue;
          }

          logger.info(`policy name: ${rule.name} was added from disk`);
          this.policyRules.push(rule);
        }
      }

      if (this.policyRules.length > 0 || this.disabledPolicies.length > 0) {
        this.setSpecificPolicyConfig();
        logger.info(
          `finish to create all policy rules, policy rules count: ${this.policyRules.length}, disabled policies: ${this.disabledPolicies.length}`,
        );
        return;
      }

      //Parse policy from disk- if we fail fetchbpolicies from policy service
      const fileHelpe: FileHelper = new FileHelper(this.uuid);
      let policyFiles = await fileHelpe.getFiles(this.dir);
      const demoFiles = await this.getDemoFiles(isDemo);
      policyFiles = [...policyFiles, ...demoFiles];

      const polListFromDisk: Policy[] = [];

      for (const policyFile of policyFiles) {
        const polItem = this.getRuleFormFile(policyFile.name);
        if (polItem != null) {
          polListFromDisk.push(polItem);
          logger.info(`policy name: ${polItem.name} was added from disk`);
        }
      }
      //Create rule item and verify its content
      for (const policyRule of polListFromDisk) {
        let rule = this.createAndVerifyRule(policyRule);

        if (rule == null) {
          continue;
        }

        if (this.isPolicyIgnoreBusinessPriority(rule)) {
          this.ignoreBusinessPriorityPolicies.add(rule.policyId);
        }

        this.policyRules.push(rule);
      }

      this.removeDisabledPolicy();
      this.setSpecificPolicyConfig();

      logger.info(
        `finish create all policy rules, policy rules count: ${this.policyRules.length}, disable: ${this.disabledPolicies.length}`,
      );
    } catch (err) {
      const errInfo = `failed get all policy rules`;
      logger.error(errInfo, err);
    } finally {
      if (this.policyRules.length == 0) {
        throw "0 policy files created, stopping scan from running";
      }
    }
  }

  isPolicyIgnoreBusinessPriority(rule) {
    try {
      const ignoreBPArg = rule.args.find(i => i.name === "ignoreBusinessPriority");
      if (ignoreBPArg) {
        return ignoreBPArg.value;
      }
    } catch (err) {
      logger.error(`failed to get if rule: ${rule.policyId} need to ignore business priority. err: ${err}`);
    }
    return false;
  }

  async getDemoFiles(isDemo: boolean) {
    if (isDemo) {
      const fileHelpe: FileHelper = new FileHelper(this.uuid);
      let policyFilesDemo = await fileHelpe.getFiles(__dirname + "/demo");
      policyFilesDemo = policyFilesDemo.filter(i => i.name.includes(".json"));
      return policyFilesDemo;
    }
    return [];
  }

  removeDisabledPolicy() {
    let enabledPolicy: Policy[] = [];
    for (const policyRule of this.policyRules) {
      if (!policyRule.selected) {
        this.disabledPolicies.push(policyRule);
        logger.info(`policy name: ${policyRule.name} disable`);
        continue;
      }

      enabledPolicy.push(policyRule);
    }
    this.policyRules = enabledPolicy;
  }

  getPolicyById(policyId: string) {
    const policy = this.policyRules.find(p => p.policyId === policyId);
    if (!policy) {
      logger.error(`failed to get next policy by severity for policy id: ${policyId}`);
      return;
    }
    return policy;
  }

  setSpecificPolicyConfig() {
    const isScaLowEnabled = true;
    //   this.policyRules.find(i => (i.categoryId?.toLowerCase() === "sca" || i.catId === 6) && i.severity == 1) != undefined;
    StatesHelper.Instance.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.sca]] = isScaLowEnabled;

    const isSastLowEnabled = true;
    //this.policyRules.find(i => (i.categoryId?.toLowerCase() === "sast" || i.catId === 4) && i.severity == 1) != undefined;
    StatesHelper.Instance.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.sast]] = isSastLowEnabled;

    const isCspmLowEnabled = true;
    //this.policyRules.find(i => (i.categoryId?.toLowerCase() === "cspm" || i.catId === 15) && i.severity == 1) != undefined;
    StatesHelper.Instance.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.cspm]] = isCspmLowEnabled;

    //romanzit improve this
    const isSecretLowEnabled = true;
    StatesHelper.Instance.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.secrets]] = isSecretLowEnabled;

    const isIacLowEnabled = true;
    //this.policyRules.find(i => (i.categoryId?.toLowerCase() === "iac" || i.catId === 8) && i.severity == 1) != undefined;
    //StatesHelper.Instance.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.iac]] = isIacLowEnabled;
    StatesHelper.Instance.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.iac]] = isIacLowEnabled;

    logger.info(
      `policy specific config isCspmLowEnabled: ${isCspmLowEnabled}, isScaLowEnabled: ${isScaLowEnabled}, isSastLowEnabled: ${isSastLowEnabled}, isSecretLowEnabled: ${isSecretLowEnabled}, isIacLowEnabled: ${isIacLowEnabled}`,
    );
  }

  getOrganizedPolicyRulesBySeverity(severity: number): Policy[] {
    return this.policyRules.filter(i => i.severity == severity);
  }

  private getRuleFormFile(path: string) {
    try {
      logger.debug(`try get policy rule from path: ${path}`);

      const info = fs.readFileSync(path, "utf8");
      const policyRule = <Policy>JSON.parse(info);
      return policyRule;
    } catch (err) {
      logger.error(`failed to get rule from file path: ${path}, err: ${err}`);
    }
    return null;
  }

  //This function extend the policy from the admin with the configuration data that we define for this policy
  //we do this here one time to avoid asking for this data again and again later stages
  private createAndVerifyRule(policyRule: Policy, repoId: string = "", repoName: string = ""): Policy {
    try {
      if (policyRule.policyId === undefined) {
        return null;
      }

      if (!policyRule.functionName) {
        return null;
      }
      if (!policyRule.args) {
        return null;
      }

      //Pipeline scan
      if (StatesHelper.Instance.isPipelineScan && repoId && repoName) {
        let shouldRunSecret =
          policyRule.policyId === Constant.secretHistoryInfoSeverity ||
          policyRule.policyId === Constant.secretHistoryLowSeverity ||
          policyRule.policyId === Constant.secretHistoryMidSeverity ||
          policyRule.policyId === Constant.secretHistoryHighSeverity ||
          policyRule.policyId === Constant.secretHistoryCriticalSeverity ||
          policyRule.policyId === Constant.secretHistoryAppoxSeverity ||
          policyRule.policyId === Constant.secretInfoSeverity ||
          policyRule.policyId === Constant.secretLowSeverity ||
          policyRule.policyId === Constant.secretMidSeverity ||
          policyRule.policyId === Constant.secretHighSeverity ||
          policyRule.policyId === Constant.secretCriticalSeverity ||
          policyRule.policyId === Constant.secretAppoxSeverity;

        let shouldRunIac =
          policyRule.policyId === Constant.iacInfoSeverity ||
          policyRule.policyId === Constant.iactLowSeverity ||
          policyRule.policyId === Constant.iacMidSeverity ||
          policyRule.policyId === Constant.iacHighSeverity ||
          policyRule.policyId === Constant.iacCriticalSeverity ||
          policyRule.policyId === Constant.iacAppoxSeverity;

        let shouldRunSast =
          policyRule.policyId === Constant.sastInfoSeverity ||
          policyRule.policyId === Constant.sasttLowSeverity ||
          policyRule.policyId === Constant.sastMidSeverity ||
          policyRule.policyId === Constant.sastHighSeverity ||
          policyRule.policyId === Constant.sastCriticalSeverity ||
          policyRule.policyId === Constant.sastAppoxSeverity;

        if (
          //sca
          policyRule.policyId === Constant.scaInfoSeverity ||
          policyRule.policyId === Constant.scaLowSeverity ||
          policyRule.policyId === Constant.scaMidSeverity ||
          policyRule.policyId === Constant.scaHighSeverity ||
          policyRule.policyId === Constant.scaCriticalSeverity ||
          policyRule.policyId === Constant.scaAppoxlSeverity ||
          //dockerSCA
          policyRule.policyId === Constant.scaDockerInfoSeverity ||
          policyRule.policyId === Constant.scaDockerLowSeverity ||
          policyRule.policyId === Constant.scaDockerMidSeverity ||
          policyRule.policyId === Constant.scaDockerHighSeverity ||
          policyRule.policyId === Constant.scaDockerCriticalSeverity ||
          policyRule.policyId === Constant.scaDockerAppoxlSeverity ||
          //cicd
          policyRule.policyId === Constant.generalCICDInfoSeverity ||
          policyRule.policyId === Constant.generalCICDLowSeverity ||
          policyRule.policyId === Constant.generalCICDMidSeverity ||
          policyRule.policyId === Constant.generalCICDHighSeverity ||
          policyRule.policyId === Constant.generalCICDCriticalSeverity ||
          policyRule.policyId === Constant.generalCICDAppoxSeverity ||
          //secrets
          shouldRunSecret ||
          //iac
          shouldRunIac ||
          //sast
          shouldRunSast
        ) {
          try {
            let configForSpecificPolicy: ConfigForSpecificPolicy = PipeLineHelper.Instance.configForSpecificPolicy.find(
              i => i.repoId === repoId,
            );
            if (!configForSpecificPolicy) {
              configForSpecificPolicy = new ConfigForSpecificPolicy();
              configForSpecificPolicy.repoId = repoId;
              configForSpecificPolicy.repoName = repoName;
              PipeLineHelper.Instance.configForSpecificPolicy.push(configForSpecificPolicy);
            }
            configForSpecificPolicy.hackPolicyForPipelineScan[policyRule.policyId] = policyRule;

            logger.info(
              `hack for policy in pipeline mode, policy: ${policyRule.name}, id: ${policyRule.policyId} saved on only for configuration`,
            );
          } catch (err) {
            logger.error(
              `failed set hack policy for pipeline scan for policy: ${policyRule.policyId}, name: ${policyRule.name}, err: ${err}`,
            );
          }
          return null;
        }
      }
      if (
        policyRule.newIssuesPipelineOptionId === PipelineOptionId.Disable &&
        policyRule.oldIssuesPipelineOptionId === PipelineOptionId.Disable
      ) {
        logger.info(`policy: ${policyRule.policyId}, name: ${policyRule.name} new and old mode are disabled, skipping policy`);
        return null;
      }

      let noneCodeRepoResurce = false;

      for (const resource of policyRule.resources) {
        if (resource.global) {
          noneCodeRepoResurce = true;
        }
        if (!resource.global) {
          resource.global = false;
        }
        if (policyRule.functionName === "policyDemo") {
          noneCodeRepoResurce = true;
        }
        if (resource.type !== "code_repo" && resource.type !== "external") {
          noneCodeRepoResurce = true;
        }
        if (resource.name === "webhooks") {
          noneCodeRepoResurce = true;
        }
      }

      //numberOfVersionsToSkip fro sbom policy
      if (policyRule.args) {
        policyRule.args.forEach(i => {
          if (i.name.toLowerCase() === "numberOfVersionsToSkip".toLowerCase()) {
            StatesHelper.Instance.numberOfVersionsToSkip = i.value as number;
            logger.info(`set numberOfVersionsToSkip value for sbom policy to: ${i.value}`);
          }
          if (i.name.toLowerCase() === "includeForkedPublicRepos".toLowerCase()) {
            StatesHelper.Instance.includeForkedPublicRepos = i.value as boolean;
            logger.info(`set numberOfVersionsToSkip value for sbom policy to: ${i.value}`);
          }
          if (i.name.toLowerCase() === "licenseFileNames".toLowerCase()) {
            const identifier = policyRule.args.find(a => a.name === "fileDisplayName");
            if (identifier && i.value) {
              StatesHelper.Instance.filesToRead.set(identifier.value, i.value);
            } else {
              // exclude this policy from this logic, it does not have 'fileDisplayName' by design
              if (policyRule.policyId !== "oxPolicy_publicRepo_1") {
                logger.error(
                  `issue in licenseFileNames in: ${policyRule.name}, one of the fields is empty, identifier.value: ${identifier?.value}, i.value: ${i?.value}`,
                );
              }
            }
          }
        });
      }

      //Specific policy to execute at end of scan
      if (
        policyRule.policyId.toLowerCase().includes("publicrepo") ||
        policyRule.policyId.toLowerCase().includes("nosast") ||
        policyRule.policyId.toLowerCase().includes("nosca") ||
        policyRule.policyId.toLowerCase().includes("nocicd") ||
        policyRule.policyId.toLowerCase().includes("openwiki") ||
        policyRule.policyId === "oxPolicy_runtimeMonitor_1"
      ) {
        noneCodeRepoResurce = true;
      }

      if (policyRule.policyId.toLowerCase().includes("editablewiki")) {
        StatesHelper.Instance.openWikiEnable = true;
      }

      //Set this specific data for performance boost in case of github
      if (policyRule.policyId.toLowerCase().includes("commitReviewCount".toLowerCase())) {
        const item = policyRule.args.find(i => i.name.toLowerCase() === "minConsideration".toLowerCase());
        if (!item) {
          logger.error(`cannot find minConsideration arg in commit without reviews`);
        } else {
          if (isNaN(item.value)) {
            logger.error(`found minConsideration arg in commit without reviews but its not a number: ${item.value}`);
          } else {
            StatesHelper.Instance.policyForQueryPullsByDays = item.value * 30;
            logger.info(`found minConsideration arg in commit without reviews and set to: ${item.value}`);
          }
        }
      }

      policyRule.execType = noneCodeRepoResurce ? Constant.execType.endScan : Constant.execType.duringScan;

      return policyRule;
    } catch (err) {
      logger.error(`failed create rule: ${policyRule.ruleId}, err: ${err}`);
    }
    return null;
  }
}

export default RulesParser;
