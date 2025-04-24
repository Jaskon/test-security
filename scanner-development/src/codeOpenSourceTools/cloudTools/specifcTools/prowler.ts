import { join } from "path";
import { CloudResourcesToRun, CloudSecurityEvent } from "../../../entitis/cloudTypes";
import { addSeverityCloudChangedReason, AlertSeverity } from "../../../entitis/codeRepoTypes";
import { Token } from "../../../entitis/collectorEntitisTypes";
import { ExtraInfo } from "../../../entitis/issuesTypes";
import { severityReasons } from "../../../entitis/service/blameTypes";
import { ToolConfig } from "../../../entitis/tool/secuirtyToolsConfig";
import isCloudSecretEnabledForOrg from "../../../helper/featureFlags/isCloudSecretEnabled";
import Iqueue from "../../../helper/queue/Iqueue";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import OrgPolicyParser from "../../../policy/org/ruleConfigParser";
import { Tool } from "../../../policy/rules/code/policyRulesBase";
import CloudSecurityTool from "../cloudSecurityTools";
import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import { prowlerServices } from "../../../appmgr/__mocks__/prowler/constants";
import { isDevelopment } from "../../../helper/envUtils";
const crypto = require("crypto");

const fs = require("fs");
const readline = require("readline");

const logger = loggerImport.getDebugLogger();

class Prowler extends CloudSecurityTool {
  folderToProwlerConfig = `${__dirname}/specificToolsConfig/prowler`;
  useDefaultConfig = true;
  timerID = null;
  secretScanningEnabled = false;

  testsToExludeByService: Record<string, string[]> = {
    ecr: ["ecr_repositories_scan_images_on_push_enabled"],
    iam: [
      "iam_password_policy_number",
      "iam_password_policy_minimum_length_14",
      "iam_password_policy_expires_passwords_within_90_days_or_less",
      "iam_password_policy_symbol",
      "iam_password_policy_reuse_24",
      "iam_password_policy_lowercase",
      "iam_password_policy_uppercase",
      "iam_role_cross_service_confused_deputy_prevention",
    ],
    sqs: ["sqs_queues_not_publicly_accessible"],
  };

  // old implementation of prowler
  testsToExculde: string[] = [
    "iam_password_policy_number",
    "iam_password_policy_minimum_length_14",
    "iam_password_policy_expires_passwords_within_90_days_or_less",
    "iam_password_policy_symbol",
    "iam_password_policy_reuse_24",
    "iam_password_policy_lowercase",
    "iam_password_policy_uppercase",
    "iam_role_cross_service_confused_deputy_prevention",
    "ecr_repositories_scan_images_on_push_enabled",
    "sqs_queues_not_publicly_accessible",
  ];

  // new implementaion of prowler
  secretTests = [
    "autoscaling_find_secrets_ec2_launch_configuration",
    "awslambda_function_no_secrets_in_code",
    "awslambda_function_no_secrets_in_variables",
    "cloudformation_stack_outputs_find_secrets",
    "ec2_instance_secrets_user_data",
    "cloudwatch_log_group_no_secrets_in_logs",
    "ecs_task_definitions_no_environment_secrets",
  ];

  uniqueResourceWhichWasSendToScan = {};

  constructor(uuid: string, orgPolicyParser: OrgPolicyParser, toolConfig: ToolConfig, queue: Iqueue, orgName: string, token: Token) {
    super(uuid, orgPolicyParser, toolConfig, queue, orgName, token);
  }

  async createSecurityEvents(cloudResourcesToExecuteObj: any) {
    this.secretScanningEnabled = await isCloudSecretEnabledForOrg.isOn(this.orgName);

    const cloudPolicyToExecute: CloudResourcesToRun = cloudResourcesToExecuteObj as CloudResourcesToRun;
    let securityEventList: CloudSecurityEvent[] = [];

    try {
      if (!fs.existsSync(cloudPolicyToExecute.fileForResults)) {
        logger.warn(`Failed to located file ${cloudPolicyToExecute.fileForResults}`);
        StatesHelper.Instance.globalApisFails.add("prowler-cspm" as Tool);
        return [];
      }

      this.copyToolResults({
        cloudResourceName: cloudPolicyToExecute.name,
        dir: cloudPolicyToExecute.fileForResults,
      });

      const rawdata: string = fs.readFileSync(cloudPolicyToExecute.fileForResults, "utf-8");
      if (!rawdata) {
        logger.error(`Unable to read file ${cloudPolicyToExecute.fileForResults}`);
        StatesHelper.Instance.globalApisFails.add("prowler-cspm" as Tool);
        return [];
      }

      const prowlerInfo = JSON.parse(rawdata);

      for await (const item of prowlerInfo) {
        const isSecretPolicy = this.secretTests.includes(item.CheckID);
        const risk: string = item.Risk !== "" ? item.Risk : item.CheckTitle;

        const oxwrapper = item?.oxwrapper;
        const resourceId = item.ResourceId;
        if (resourceId === "") {
          logger.warn(`prowler resoruce ID is empty for ${risk}`);
          continue;
        }

        const title = oxwrapper && oxwrapper?.title ? oxwrapper.title : item.CheckTitle;
        const severity = oxwrapper && oxwrapper?.severity ? oxwrapper.severity : item.Severity;
        const description = oxwrapper && oxwrapper?.description ? oxwrapper.description : item.Description;
        const recommendation = oxwrapper && oxwrapper?.recommendation ? oxwrapper.recommendation : item.Remediation.Recommendation.Text;
        try {
          let securityEvent = new CloudSecurityEvent(
            "AWS",
            SourceToolType["Cloud Security"],
            "",
            new Date().toLocaleString(),
            description,
            title,
            severity,
            "",
            "medium",
            recommendation,
            true,
            item.CheckID,
            item.Remediation.Recommendation.Url,
            item.AccountId,
            "", // missing CAFEPIC
            item.Region,
            item.ServiceName,
            item.ResourceId,
            "",
            "",
            this.secretTests.includes(cloudPolicyToExecute.id), // ResourceId
            item.Status.toLowerCase() === "fail" ? true : false,
            "prowler-cspm" as Tool,
          );

          try {
            if (oxwrapper?.severityFactors) {
              oxwrapper.severityFactors.forEach((sfKey: string) => {
                if (severityReasons.hasOwnProperty(sfKey)) {
                  addSeverityCloudChangedReason(severityReasons[sfKey], securityEvent);
                }
              });
            }
          } catch (err) {}

          if (oxwrapper?.cwe) {
            securityEvent.cweList = oxwrapper.cwe;
          }

          const lambda: string = item.ResourceId;

          if (isSecretPolicy) {
            //not supported yet - pasha asked to disable this
            if (!this.secretScanningEnabled && !isDevelopment()) {
              continue;
            }

            // This file is case sensitive, make sure not to use anything with lowercase()
            const extraDatFile = `${cloudPolicyToExecute.folderRes}RAW_SECRETS/${item.CheckID}-${lambda}-${item.Region}-variables.txt`;
            if (fs.existsSync(extraDatFile)) {
              logger.info(`try add prowler extra data for file: ${extraDatFile}, info: ${JSON.stringify(item)}`);
              this.fileHelper.copyFileSync(extraDatFile, StatesHelper.Instance.pathToProlwerSecretsFolder);

              const extraData = await this.getExtraDataContent(securityEvent, extraDatFile, cloudPolicyToExecute, "", item);
              if (extraData.length > 0) {
                securityEventList = [...securityEventList, ...extraData];
                logger.info(
                  `[useProwlerWithServices] Added ${extraData.length} secrets for ${item.CheckID}-${lambda}-${item.Region}-variables.txt`,
                );
              } else {
                logger.error(`[useProwlerWithServices] Couldnt find secrets for ${extraDatFile}`);
                securityEventList.push(securityEvent);

                //Delete after reading
                this.fileHelper.deleteFile(extraDatFile);
              }
            } else {
              logger.warn(`[useProwlerWithServices] Couldnt find secrets file ${extraDatFile}`);
            }
          } else {
            securityEventList.push(securityEvent);
          }
        } catch (err) {
          logger.error(`failed to create single security event for prowler resource type ${cloudPolicyToExecute.name},err ${err}`);
        }
      }

      logger.info(
        `${this.toolConfig.name} Info after filter ${securityEventList.length}, service: ${cloudPolicyToExecute.serviceStr}, testName: ${cloudPolicyToExecute.name}`,
      );

      //Delete after reading
      this.fileHelper.deleteFile(cloudPolicyToExecute.fileForResults);

      return securityEventList;
    } catch (err) {
      const errInfo = `failed to parse results for tool prowler resource type ${cloudPolicyToExecute.name}, err ${err} NEW`;
      StatesHelper.Instance.globalApisFails.add("prowler-cspm" as Tool);
      logger.error(errInfo);
    }
    return [];
  }

  async getExtraDataContent(
    securityEvent: CloudSecurityEvent,
    path: string,
    cloudResourcesToRun: CloudResourcesToRun,
    severityFromConfig: string,
    itemInfo: any,
  ) {
    try {
      const cloudSecurityEvents: CloudSecurityEvent[] = [];

      const fileStream = fs.createReadStream(path);
      const lines = readline.createInterface({
        input: fileStream,
        crlfDelay: Infinity,
      });
      let rawdata = "";
      for await (const line of lines) {
        rawdata += line;
      }

      let prowlerResourcesRes = JSON.parse(rawdata);
      const unique = new Set();
      const entry: string = Object.keys(prowlerResourcesRes)[0];
      const arrayOfResults = prowlerResourcesRes[entry];
      for (const value of arrayOfResults) {
        const keyItem = value as any;
        try {
          const prefixPath = `${cloudResourcesToRun.folderRes}RAW_SECRETS/`;

          let fileWithTheSecrets = "";

          if (fs.existsSync(`${prefixPath}${keyItem.filename}`)) {
            fileWithTheSecrets = `${prefixPath}${keyItem.filename}${keyItem.filename}`;
          } else if (fs.existsSync(`${prefixPath}${keyItem.filename.split("/").pop()}`)) {
            fileWithTheSecrets = `${prefixPath}${keyItem.filename.split("/").pop()}`;
          } else {
            logger.error(`failed to find file ${keyItem.filename} in ${prefixPath}`);
            continue;
          }

          const secretData = await this.fileHelper.getContentByLine(fileWithTheSecrets, keyItem.line_number);
          if (secretData === "") {
            logger.warn(`failed to get prowler secret data for path: ${fileWithTheSecrets}, line: ${keyItem.line_number}`);
            continue;
          }
          const uniqueData = `${securityEvent.resource}_${secretData}`;
          if (unique.has(uniqueData)) {
            logger.warn(`Data exists ${uniqueData}`);
            continue;
          }

          //Dont use critical for secrets as original severity
          if (!severityFromConfig) {
            if (securityEvent.severity === AlertSeverity.Critical) {
              securityEvent.setSeverity(AlertSeverity[AlertSeverity.Medium]);
            }
          }

          const item: CloudSecurityEvent = new CloudSecurityEvent(
            securityEvent.cloudEnv,
            securityEvent.securityProvider,
            securityEvent.link,
            securityEvent.createdAt,
            securityEvent.violationInfo,
            securityEvent.title,
            securityEvent.severityStr,
            securityEvent.additionalInfo,
            securityEvent.confidenceStr,
            securityEvent.recommendation,
            securityEvent.oxTool,
            securityEvent.ruleId,
            securityEvent.moreInfoLink,
            securityEvent.accountName,
            securityEvent.category,
            securityEvent.region,
            securityEvent.cloudService,
            securityEvent.resource,
            secretData.trim(),
            keyItem.type,
            securityEvent.secret,
            securityEvent.isViolation,
            "prowler-cspm" as Tool,
          );
          item.tools = securityEvent.tools;

          const extraCloudInfo: ExtraInfo[] = [];
          try {
            if (itemInfo.AssessmentStartTime) {
              extraCloudInfo.push({
                key: "Assessment start time",
                value: itemInfo.AssessmentStartTime,
              });
            }
            if (itemInfo.ResourceId && itemInfo.ServiceName) {
              extraCloudInfo.push({
                key: itemInfo.ServiceName,
                value: itemInfo.ResourceId,
              });
            }
            if (itemInfo.Region) {
              extraCloudInfo.push({
                key: "Region",
                value: itemInfo.Region,
              });
            }
            if (itemInfo.ResourceTags) {
              for (const [name, entry] of Object.entries(itemInfo.ResourceTags)) {
                extraCloudInfo.push({
                  key: name,
                  value: entry as any,
                });
              }
            }
          } catch (err) {
            logger.error(`failed to create sf for ${this.toolConfig.name} secret, err: ${err}`);
          }

          if (itemInfo.ServiceName === "lambda") {
            addSeverityCloudChangedReason(severityReasons.Lambda, item, extraCloudInfo);
          }

          item.realMatch = crypto.createHash("md5").update(secretData).digest("hex");
          item.accountId = securityEvent.accountName;
          cloudSecurityEvents.push(item);
          unique.add(uniqueData);
        } catch (err) {
          logger.error(`failed to add prowler key item: ${entry}, err: ${err}`);
        }
      }
      return cloudSecurityEvents;
    } catch (err) {
      logger.error(`failed to get extra data from file: ${path}, err: ${err}`);
    }
    return [];
  }

  async getToolResourceToRun() {
    const sharedDir = process.env.OX_SHARED_DATA == undefined ? "/var/shared-data" : process.env.OX_SHARED_DATA;
    StatesHelper.Instance.pathToProlwerSecretsFolder = `${sharedDir}/${this.orgName}/scan_${this.uuid.replaceAll("-", "_")}/prowlerSecrets`;
    this.fileHelper.createDir(StatesHelper.Instance.pathToProlwerSecretsFolder);

    logger.info(
      `outputResDir for prowler: ${this.outputResDir}, prowler secret folder: ${StatesHelper.Instance.pathToProlwerSecretsFolder}`,
    );

    let cloudResourcesToExecuteList: CloudResourcesToRun[] = [];
    try {
      if (StatesHelper.Instance.useProwlerWithServices) {
        // new implementation for Prowler
        await this.getToolResourceToRunByServices(cloudResourcesToExecuteList);
      } else {
        await this.getToolResourceToRunByChecks(cloudResourcesToExecuteList);
      }

      logger.info(`prowler cloudResourcesToExecuteList: ${cloudResourcesToExecuteList.length}`);
      return cloudResourcesToExecuteList;
    } catch (err) {
      logger.error(`failed excute getToolResourceToRun error - ${err}`);
      return [];
    }
  }

  async getToolResourceToRunByChecks(cloudResourcesToExecuteList: CloudResourcesToRun[]) {
    try {
      // const pathForJsonIssues = join(__dirname, "../../config/cloudSecurityEventsConfig.json");
      // jsonParser.getInstance().doParse(pathForJsonIssues, "prowler");
      const path = join(__dirname, "../../../appmgr/__mocks__/prowler/prowlerChecks.txt");

      if (!fs.existsSync(path)) {
        logger.error(`cannot find prowler policy default list from ${path}`);
        return [];
      }

      const cateogryFileStream = fs.createReadStream(path, {
        encoding: "UTF-8",
      });
      const catLines = readline.createInterface({
        input: cateogryFileStream,
        crlfDelay: Infinity,
      });

      for await (const line of catLines) {
        const cleanData = line.replace(/\x1b\[\d+m/g, "");
        const firstPosOfBracket = cleanData.indexOf("[");

        const secondPosOfBracket = cleanData.indexOf("]", firstPosOfBracket);
        if (secondPosOfBracket === -1 || firstPosOfBracket === -1) {
          continue;
        }
        const check = cleanData.substring(firstPosOfBracket + 1, secondPosOfBracket);
        if (this.testsToExculde.includes(check.toLowerCase())) {
          logger.info(`Test ${check.toLowerCase()} is excluded`);
          continue;
        }
        let firstDash = cleanData.indexOf("-");
        let checkIfAnotherDash = cleanData.indexOf("-", firstDash + 1);
        if (firstDash < checkIfAnotherDash) firstDash = checkIfAnotherDash;
        const bracketAfterDash = cleanData.indexOf("[", firstDash);
        if (firstDash === -1 || bracketAfterDash === -1) {
          continue;
        }
        let policyCategory = cleanData.substring(firstDash + 1, bracketAfterDash);
        policyCategory = policyCategory.replace(/\s+/g, "");
        if (policyCategory.indexOf("-") !== -1) {
          policyCategory = policyCategory.substring(policyCategory.indexOf("-") + 1, policyCategory.length);
        }
        const policyName = cleanData.substring(secondPosOfBracket + 1, firstDash);
        const resource = new CloudResourcesToRun(check, policyName, policyCategory, cleanData, "prowler", this.outputResDir);
        cloudResourcesToExecuteList.push(resource);
      }
    } catch (error) {
      logger.error(`failed excute getToolResourceToRunByChecks error - ${error}`);
      return;
    }
  }

  async getToolResourceToRunByServices(cloudResourcesToExecuteList: CloudResourcesToRun[]) {
    try {
      for (const service of prowlerServices) {
        const excludeChecks = this.testsToExludeByService[service] ?? [];
        const resource = new CloudResourcesToRun(service, "", service, "", "prowler", this.outputResDir, undefined, excludeChecks);
        cloudResourcesToExecuteList.push(resource);
      }
    } catch (error) {
      logger.error(`[useProwlerWithServices] failed excute getToolResourceToRunByServices error - ${error}`);
      return;
    }
  }
}

export default Prowler;
