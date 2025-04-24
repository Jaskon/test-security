import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import { existsSync, readFileSync } from "node:fs";
import { basename, join } from "node:path";
import { ArtifactoryResourceToRun } from "../../../entitis/artifactoryTypes";
import { ArtifactorySecEventType, guessArtifactSystem } from "../../../entitis/ArtifactTypes";
import { addSeverityChangedReason, AlertSeverity, SecurityAlertType, SecurityEvent } from "../../../entitis/codeRepoTypes";
import { Token } from "../../../entitis/collectorEntitisTypes";
import { Constant, OXtools } from "../../../entitis/constant";
import { ExtraInfo } from "../../../entitis/issuesTypes";
import { LATERAL_MOVEMENT_GROUPS, secretTagMapping, severityReasons } from "../../../entitis/service/blameTypes";
import { ToolConfig } from "../../../entitis/tool/secuirtyToolsConfig";
import { copyToolInfo } from "../../../helper/commonUtils";
import { isDevelopment } from "../../../helper/envUtils";
import Iqueue from "../../../helper/queue/Iqueue";
import StatesHelper from "../../../helper/statesHelper";
import { StringHelper } from "../../../helper/stringHelper";
import { ToolsExecutionStats } from "../../../helper/toolExecutionStats";
import loggerImport from "../../../logger";
import OrgPolicyParser from "../../../policy/org/ruleConfigParser";
import ArtifactorySecurityTool from "../artifactorySecurityTools";

const logger = loggerImport.getDebugLogger();

class Gitleaks extends ArtifactorySecurityTool {
  constructor(uuid: string, orgPolicyParser: OrgPolicyParser, toolConfig: ToolConfig, queue: Iqueue, orgName: string, token: Token) {
    super(uuid, orgPolicyParser, toolConfig, queue, orgName, token);
  }

  async createSecurityEvents(resource: ArtifactoryResourceToRun) {
    const securityEventList: SecurityEvent[] = [];
    let path;
    let alertNumber = 0;
    let alertNumberTotal = 0;
    let ignoredAlerts = 0;
    let piiAlerts = 0;
    let gitleaksSecrets;

    try {
      path = `${resource.dirWhereToPutRes}/${this.toolConfig.fileNameOutput}`;

      if (process.env.DEBUG != undefined && !process.env.DOCKER_DEBUG) {
        path = join(__dirname, "../../../appmgr/__mocks__/Gitleaks/gitleaks.json");
      }

      if (!existsSync(path)) {
        logger.warn(`${this.toolConfig.name} path: ${path} not exist, imageName: ${resource.imageDetail.name}`);
        return [];
      }
      copyToolInfo(resource.imageDetail.name, path, this.toolConfig.name, this.uuid);

      const rawdata = readFileSync(path, "utf-8");
      if (!rawdata) {
        logger.warn(`${this.toolConfig.name} path: ${path} is empty, imageName: ${resource.imageDetail.name}`);
        return [];
      }

      gitleaksSecrets = JSON.parse(rawdata);

      logger.info(`${this.toolConfig.name} Info before filter: ${gitleaksSecrets ? gitleaksSecrets.length : 0}, path: ${path}`);

      if (gitleaksSecrets) {
        alertNumberTotal = gitleaksSecrets.length;
      }

      for (const secret of gitleaksSecrets) {
        try {
          let filePath = secret.File;
          const i = filePath.lastIndexOf("/artifact/");
          if (i != -1) {
            filePath = filePath.substring(i + "/artifact/".length, filePath.length);
            const j = filePath.indexOf("/");
            if (j != -1) {
              filePath.substring(j + "/".length, filePath.length);
            }
          }
          const fileName = basename(filePath);

          let severity = this.toolSeverity.getSeverityToolBaseOnRuleId(secret.RuleID, "");
          if (!severity) {
            severity = this.toolConfig.defaultSeverity;
          }

          const securityEvent = new SecurityEvent(
            SourceToolType["Container Security"],
            true,
            "",
            new Date().toLocaleString(),
            "",
            "",
            "",
            secret.Description,
            "",
            fileName,
            severity,
            `Rule name: ${secret.RuleID}`,
            secret.StartLine,
            AlertSeverity[AlertSeverity.High],
            SecurityAlertType.container,
            "",
            secret.Match,
            secret.Match,
            secret.EndLine,
            true,
            false,
            "",
            "",
            "",
            "",
            secret.RuleID,
            "",
            "",
            "",
            "",
            "",
            "gitleaks",
          );

          const artifacts = {
            system: guessArtifactSystem(resource.imageDetail.name),
            subType: ArtifactorySecEventType.Docker,
            repoFullName: resource.imageDetail.repositoryName,
            imageCreatedAt: resource.imageDetail.imagePushedAt,
            dockerVer: "",
            hasPackageManager: false,
            os: "",
            osVersion: "",
            sha: resource.imageDetail.imageDigestWithoutPrefix,
            binariesCount: 0,
            pkgCount: 0,
            dockerFileInRunTime: resource.imageDetail.name,
            registry: resource.imageDetail.location,
            tag: resource.imageDetail.imageTags.join(", "),
            linkToRegistry: resource.imageDetail.link,
            linkToTask: "",
            baseImage: "",
            baseImageSha: "",
            baseImageRegistry: resource.imageDetail.location,
            baseImageOsVersion: "",
            registryName: resource.imageDetail.cloudEnv,
          };
          securityEvent.artifacts = artifacts;

          securityEvent.secretWithoutObfuscation = securityEvent.realMatch;
          securityEvent.realMatch = StringHelper.hashMd5(securityEvent.lineContent);
          securityEvent.securitySubTypeAlertType = SecurityAlertType.secrets;
          securityEvent.lineContent = securityEvent.lineContent.trim().replace(/\s+/g, " ");
          securityEvent.filePath = filePath;

          //Artifact data
          securityEvent.artifactFilePath = filePath;
          securityEvent.artifactFileLine = secret.StartLine;
          securityEvent.matchFromArtifact = securityEvent.lineContent;
          securityEvent.imageId = resource.imageDetail.imageId;

          if (isDevelopment() && StatesHelper.Instance.orgName === "org_uYqRKTN36zqJTPN9") {
            securityEvent.imageId = resource.imageDetail.name;
          }

          addSeverityChangedReason(severityReasons.appContainerVull, securityEvent, undefined);

          const lineContent = securityEvent.lineContent;
          try {
            if (secret.Tags) {
              //No filter of events
              for (const tag of secret.Tags) {
                try {
                  if (tag === "silent") {
                    securityEvent.isSilent = true;
                  } else if (tag === "pii") {
                    securityEvent.isPII = true;
                    piiAlerts++;
                  } else {
                    let extraInfo: ExtraInfo[] = [];
                    const lastPartLength = Math.max(Math.ceil(lineContent.length / 3), Math.min(8, lineContent.length - 1), 0);
                    const reducted = lineContent.substring(0, lineContent.length - lastPartLength) + "*".repeat(lastPartLength);
                    extraInfo.push({
                      key: "Snippet",
                      link: securityEvent.link,
                      snippet: {
                        fileName: fileName,
                        text: reducted,
                        language: "",
                        snippetLineNumber: secret.StartLine,
                      },
                    });

                    if (secretTagMapping.hasOwnProperty(tag)) {
                      addSeverityChangedReason(secretTagMapping[tag], securityEvent, undefined, extraInfo);
                      if (LATERAL_MOVEMENT_GROUPS.includes(tag)) {
                        addSeverityChangedReason(severityReasons.lateralMovement, securityEvent, undefined);
                      }
                    }
                  }
                } catch (err) {
                  logger.error(
                    `set single tag: ${tag} in ${this.toolConfig.name} in single event, for path: ${path}, imageName: ${resource.imageDetail.name}, err: ${err}`,
                  );
                }
              }

              //Possible filter some of the events (pii events)
              let removed = false;
              for (const tag of secret.Tags) {
                if (tag === "pii") {
                  const key = `${resource.imageDetail.name}_${securityEvent.ruleId}`;

                  // static counter used to show total in policy - keep for now
                  StatesHelper.Instance.piiEventsCounter[key] = StatesHelper.Instance.piiEventsCounter[key] + 1 || 1;

                  if (StatesHelper.Instance.piiEventsCounter[key] > Constant.piiCollectLimit) {
                    removed = true;
                    break;
                  }
                }
              }
              if (removed) {
                ignoredAlerts++;
                continue;
              }
            }
          } catch (err) {
            logger.error(
              `set all tags in ${this.toolConfig.name} in single event, for path: ${path}, imageName: ${resource.imageDetail.name}, err: ${err}`,
            );
          }

          alertNumber++;
          if (alertNumber > 10000) {
            break;
          }

          securityEventList.push(securityEvent);
        } catch (err) {
          logger.error(
            `failed to parse results for tool ${this.toolConfig.name} in single event, for path: ${path}, imageName: ${resource.imageDetail.name}, ignoredAlerts: ${ignoredAlerts}, err: ${err}`,
          );
        }
      }
    } catch (err) {
      logger.error(
        `failed to parse results for tool ${this.toolConfig.name} in all event, for path: ${path}, imageName: ${resource.imageDetail.name}, err: ${err}`,
      );
    }

    if (alertNumber > 10000) {
      logger.warn(
        `${this.toolConfig.name} Info after filter ${securityEventList.length}, for artifact path: ${path}, piiAlerts: ${piiAlerts}, alertNumber in total: ${alertNumberTotal}`,
      );
    } else {
      logger.info(
        `${this.toolConfig.name} Info after filter ${securityEventList.length}, piiAlerts: ${piiAlerts},for artifact path: ${path}`,
      );
    }

    ToolsExecutionStats.addExecutionStateOfAlertsNumber(
      this.requestId,
      resource.imageDetail.repositoryName,
      resource.imageDetail.imageId,
      "artifact",
      this.toolConfig.name,
      path,
      alertNumberTotal,
      securityEventList.length,
    );

    return securityEventList;
  }
}

export default Gitleaks;
