import path from "path";
import { ContainerSecurityType } from "../../../entitis/artifactoryTypes";
import { ArtifactorySecEvent, ArtifactorySecEventSystem } from "../../../entitis/ArtifactTypes";
import {
  CodeRepoTypes,
  CweObject,
  getToolsNames,
  getUniqueInfoForAggregation,
  IssueOwner,
  Repo,
  SecurityAlertType,
  SecurityEvent,
} from "../../../entitis/codeRepoTypes";
import Constant from "../../../entitis/constant";
import { AdditionalTab, ExtraInfo } from "../../../entitis/issuesTypes";
import { ChangeReason, getDependencyType, severityReasons } from "../../../entitis/service/blameTypes";
import { replaceAll } from "../../../helper/generalUtils";
import { PipeLineHelper } from "../../../helper/pipelineHelper";
import { getFixVersionsFromSecEvent } from "../../../helper/policy/scaVersionHelper";
import { adjustTitle, getScaVul, SCAVulnerability } from "../../../helper/policy/scaVulHelper";
import { getAllInfoForSeverity, getSeverityChanges } from "../../../helper/policy/severityHelper";
import StatesHelper from "../../../helper/statesHelper";
import TimeHelper from "../../../helper/timeHelper";
import { getObfuscatedPassForContainer } from "../../../helper/tools/passwordHelper";
import loggerImport from "../../../logger";
import { DependencyType } from "../../../mongo/sbom/types";
import PolicyRulesBase from "./policyRulesBase";
import { PolicySecurityScanAggItem } from "./policySecurityScan";
import cweMapping from "../../../policy/org/config/cwe.json";

const logger = loggerImport.getDebugLogger();

const registryMap = new Map();
registryMap.set(ArtifactorySecEventSystem.AA, "AA");
registryMap.set(ArtifactorySecEventSystem.AZURE_CONTAINER_REGISTRY, "ACR");
registryMap.set(ArtifactorySecEventSystem.CA, "CA");
registryMap.set(ArtifactorySecEventSystem.DOCKER_HUB, "DH");
registryMap.set(ArtifactorySecEventSystem.ECR, "ECR");
registryMap.set(ArtifactorySecEventSystem.GCP_ARTIFACTS, "GAR");
registryMap.set(ArtifactorySecEventSystem.GCP_CONTAINER, "GCR");
registryMap.set(ArtifactorySecEventSystem.GITHUB_REGISTRY, "GHCR");
registryMap.set(ArtifactorySecEventSystem.GITLAB_REGISTRY, "GLCR");
registryMap.set(ArtifactorySecEventSystem.Generic, "Generic");
registryMap.set(ArtifactorySecEventSystem.JFROG_REGISTRY, "JFrog");
registryMap.set(ArtifactorySecEventSystem.Harbor, "Harbor");
registryMap.set(ArtifactorySecEventSystem.NEXUS_CONTAINER_REGISTRY, "NCR");
registryMap.set(ArtifactorySecEventSystem.NPM, "NPM");

class PolicySecurityScanSCA extends PolicyRulesBase {
  private commiters: IssueOwner[] = [];
  private timeHelper: TimeHelper = new TimeHelper("");

  async eval(jsonData) {
    const scanTypeFromArgs = this.getValueFromRuleArgs("scanType");

    if (Array.isArray(scanTypeFromArgs)) {
      throw `scanType is array and not string type, ${scanTypeFromArgs.toString()}`;
    }
    if (!scanTypeFromArgs) {
      throw `scanType is not exist string type, ${scanTypeFromArgs}`;
    }

    //Dont run this policy on pipeline scan if no configuration for this policy was defined
    if (StatesHelper.Instance.isPipelineScan) {
      if (PipeLineHelper.Instance.configForSpecificPolicy.length == 0) {
        throw `configForSpecificPolicy is empty`;
      }
    }

    let securityEvents: SecurityEvent[] = jsonData.securityEvents;
    const repo: Repo = jsonData.code_repo;

    //for demo
    if (StatesHelper.Instance.isDemo) {
      if (!repo.realRepo) {
        return [];
      }
    }

    let isSca = false;
    let isArtifactSca = false;
    let isArtifactIac = false;
    let isScaOnDockerFile = false;

    let isArtifactScaBaseImage = this.policyRuleMetadata.policyId === "oxPolicy_securityScan_222";
    let isArtifactScaApplication = this.policyRuleMetadata.policyId === "oxPolicy_securityScan_221";
    let isArtifactScaPossibleBaseImage = this.policyRuleMetadata.policyId === "oxPolicy_securityScan_220";
    let isArtifactScaUserInstructions = this.policyRuleMetadata.policyId === "oxPolicy_securityScan__421";
    let isArtifactSecrets = this.policyRuleMetadata.policyId === "oxPolicy_artifacts_securityScanSecret_1";
    let isPiiPolicy = this.policyRuleMetadata.policyId === "oxPolicy_policyPiiContainer_1";
    if (scanTypeFromArgs.toLowerCase() === "sca") {
      securityEvents = securityEvents.filter(
        i => i.securityAlertType == SecurityAlertType.sca && i.securitySubTypeAlertType !== SecurityAlertType.dockerFileVul,
      );
      isSca = true;
    } else if (scanTypeFromArgs.toLowerCase() === "ArtifactsSCA".toLowerCase()) {
      securityEvents = securityEvents.filter(
        i => i.securityAlertType === SecurityAlertType.container && i.securitySubTypeAlertType === SecurityAlertType.sca,
      );
      if (isArtifactScaPossibleBaseImage) {
        securityEvents = securityEvents.filter(i => i.containerScanType === ContainerSecurityType.possibleOsOnly);
      } else if (isArtifactScaBaseImage) {
        securityEvents = securityEvents.filter(i => i.containerScanType === ContainerSecurityType.baseOnly);
      } else if (isArtifactScaUserInstructions) {
        securityEvents = securityEvents.filter(i => i.containerScanType === ContainerSecurityType.instructionsOnly);
      } else if (isArtifactScaApplication) {
        securityEvents = securityEvents.filter(i => i.containerScanType === ContainerSecurityType.appOnly || !i.containerScanType);
      } else {
        logger.error(`not appOnly or baseOnly, number of alerts for: ${repo.fullName}, count: ${securityEvents.length}`);
      }
      isArtifactSca = true;
    } else if (scanTypeFromArgs.toLowerCase() === "ArtifactsIAC".toLowerCase()) {
      securityEvents = securityEvents.filter(
        i => i.securityAlertType == SecurityAlertType.container && i.securitySubTypeAlertType === SecurityAlertType.iac,
      );
      isArtifactIac = true;
    } else if (scanTypeFromArgs.toLowerCase() === "ArtifactsSecrets".toLowerCase()) {
      securityEvents = securityEvents.filter(
        i => i.securityAlertType == SecurityAlertType.container && i.securitySubTypeAlertType === SecurityAlertType.secrets,
      );
      isArtifactSecrets = true;
    } else if (scanTypeFromArgs.toLowerCase() === "deployment") {
      securityEvents = securityEvents.filter(
        i => i.securityAlertType === SecurityAlertType.sca && i.securitySubTypeAlertType === SecurityAlertType.dockerFileVul,
      );
      isScaOnDockerFile = true;
    } else {
      //We handle only this 2 types in the policy
      return [];
    }

    if (isPiiPolicy) {
      securityEvents = securityEvents.filter(i => i.isPII);
    } else {
      securityEvents = securityEvents.filter(i => !i.isPII);
    }

    if (securityEvents.length === 0) {
      return [];
    }

    const aggregatedInfo = this.getKeyValueMapByRuleIdAndData(
      jsonData,
      securityEvents,
      isSca,
      isArtifactScaBaseImage,
      isArtifactScaApplication,
      isArtifactScaPossibleBaseImage,
      isArtifactIac,
      isScaOnDockerFile,
      isArtifactSecrets,
      isArtifactScaUserInstructions,
    );

    let res = [];
    for (const events of Object.values(aggregatedInfo) as any) {
      try {
        if (events.aggregated.length == 0) {
          continue;
        }

        //Get the hights original severity alert
        const aggItems = events.aggregated as PolicySecurityScanAggItem[];
        let topLevelEventData = events.aggregated[0].securityAlert as SecurityEvent;

        //Try to find graph on some other item - can happen due to issues on other service that provide this data
        if (topLevelEventData.graphNodesCount == 0) {
          const withG: PolicySecurityScanAggItem = aggItems.find(i => i.securityAlert?.graphNodesCount > 0);
          if (withG) {
            topLevelEventData = withG.securityAlert;
          }
        }

        if (!this.shouldIncludeByPolicyEx(topLevelEventData.severity)) {
          continue;
        }

        this.commiters.push({
          name: topLevelEventData.blame.commiterName,
          email: topLevelEventData.blame.commiterEmail,
        });

        //Set additional info for secrets
        let extraInfo = [];
        const aggregatedItems: PolicySecurityScanAggItem[] = events.aggregated;
        const issueOwners = this.getIssueOwners(jsonData, aggregatedItems);

        const importedLibsChecked = {
          val: true,
        };

        const allSecEvents = aggregatedItems.map(i => i.securityAlert);
        const scaVul = getScaVul(allSecEvents, repo.fullName);
        const directSCAVulnerability = scaVul.directSCAVulnerability;
        const noneDirectSCAVulnerability = scaVul.noneDirectSCAVulnerability;
        const SCAVulnerability = [...directSCAVulnerability, ...noneDirectSCAVulnerability];

        const doesPkgImportedChecked = scaVul.doesPkgImportedChecked;
        if (!doesPkgImportedChecked) {
          importedLibsChecked.val = false;
        }

        let triggerPkgName = topLevelEventData.pkgName;
        let triggerPkgVersion = topLevelEventData.installedVersion;
        let triggerPkgManager = topLevelEventData.pkgManager;
        let triggerPkgExist = false;
        if (topLevelEventData?.blame?.triggerPackage?.name) {
          triggerPkgName = topLevelEventData.blame.triggerPackage.name;
          if (topLevelEventData?.blame?.triggerPackage?.version) {
            triggerPkgVersion = topLevelEventData.blame.triggerPackage.version;
            triggerPkgExist = true;
          } else {
            triggerPkgVersion = "";
          }
        }

        const resInfo = getAllInfoForSeverity(allSecEvents, repo.fullName);
        const uniqueSeverityChanges = resInfo.uniqueSeverityFromAllAlerts as ChangeReason[];
        const originalSeverity = resInfo.originalSeverity;
        const originalSeverityStr = resInfo.originalSeverityStr;
        const newSeverityForPolicy = resInfo.newSeverityForPolicy;

        const unusedPkg = uniqueSeverityChanges.find(i => i.reason === severityReasons.packageNotImported.reason) != undefined;

        const allSecAlerts: SecurityEvent[] = SCAVulnerability.map(i => i.alert);
        let mainTitle = topLevelEventData.blame.summaryTitle || topLevelEventData.violationInfo;
        let secondaryTitle = topLevelEventData.additionalInfo;
        const indirectLibsChecked = {
          val: true,
        };

        const violationInfoTitle = "";
        const aggregated = {
          aggregatedItems: this.sortEvents(events.aggregated),
          columns: isSca || isScaOnDockerFile ? "policySecurityScanSCA" : "policySecurityContainerScan",
          violationInfoTitle,
        };
        const aggItemsInfo = this.getUniqueAggSCAalerts(aggregated.aggregatedItems);

        //Handle additional tabs
        const uniqueArtifactFileInfo = new Set();
        const additionalTabs = [];

        if (isArtifactSecrets || isArtifactScaApplication || isArtifactIac) {
          try {
            let additionalTabArtifactFiles: AdditionalTab = new AdditionalTab();
            additionalTabArtifactFiles.type = "artifactFiles";
            aggregatedItems.forEach(i => {
              if (!i?.securityAlert?.artifactFilePath && i?.securityAlert?.matchFromArtifact) {
                return;
              }
              if (isArtifactSecrets) {
                if (!i.securityAlert.artifactFilePath) {
                  return;
                }
              }

              if (i?.securityAlert?.artifactFilePath?.includes("artifactdownload.tar")) {
                return;
              }

              const p: PolicySecurityScanAggItem = new PolicySecurityScanAggItem();
              p.fileName = i.securityAlert.artifactFilePath;
              p.match = i.securityAlert.matchFromArtifact;
              p.isOldEvent = i.securityAlert.isOldEvent;
              if (isArtifactSecrets) {
                p.match = getObfuscatedPassForContainer(i.securityAlert.matchFromArtifact);
              }
              p.snippetLineNumber = i.securityAlert.artifactFileLine == -1 ? undefined : i.securityAlert.artifactFileLine;
              const u = `${p.fileName}_${p.match}_${p.snippetLineNumber}`;
              if (uniqueArtifactFileInfo.has(u)) {
                return;
              }

              uniqueArtifactFileInfo.add(u);
              additionalTabArtifactFiles.aggItems.push(p);
            });

            if (additionalTabArtifactFiles.aggItems.length > 0) {
              if (isPiiPolicy) {
                additionalTabArtifactFiles.aggItems = this.arrangeForPII(additionalTabArtifactFiles.aggItems);
              }
              additionalTabs.push(additionalTabArtifactFiles);
            }
          } catch (err) {
            logger.error(`failed to add additionalTabArtifactFiles to policy: ${this.policyRuleMetadata.name}, err: ${err}`);
          }
        }

        // commits tab for pii pol
        if (isPiiPolicy) {
          let additionalTabCommits: AdditionalTab = new AdditionalTab();
          additionalTabCommits.type = "policySecurityScanSCA";
          aggregatedItems.forEach(i => {
            if (i.commitBy) {
              additionalTabCommits.aggItems.push(i);
            }
          });
          if (additionalTabCommits.aggItems.length > 0) {
            additionalTabs.push(additionalTabCommits);
          }
        }

        //Artifacts
        const uniqueArtifactCommitInfo = new Set();
        const corelateIssueInfo = allSecAlerts.find(i => i.corelateIssue);
        if (corelateIssueInfo && !isPiiPolicy) {
          if (corelateIssueInfo?.blame?.commiterName) {
            //This is a hack we do to additional tabs on top of the agg item key
            const additionalTab: AdditionalTab = new AdditionalTab();
            additionalTab.type = "policySecurityScanSCA";

            if (allSecEvents.length > 1) {
              aggregatedItems.forEach(i => {
                if (i.commitBy) {
                  const u = `${i.fileName}_${i.commitBy}_${i.match}_${i.startLine}`;
                  if (uniqueArtifactCommitInfo.has(u)) {
                    return;
                  }
                  additionalTab.aggItems.push(i);
                  uniqueArtifactCommitInfo.add(u);
                }
              });
            }
            additionalTabs.push(additionalTab);
          }
        }

        mainTitle = this.getIssueInfoPretty(
          allSecAlerts,
          SCAVulnerability,
          mainTitle,
          triggerPkgName,
          triggerPkgVersion,
          triggerPkgExist,
          indirectLibsChecked,
          unusedPkg,
          isSca,
          isArtifactScaBaseImage,
          isArtifactScaApplication,
          isArtifactScaPossibleBaseImage,
          isArtifactIac,
          isScaOnDockerFile,
          isArtifactSecrets,
          isArtifactScaUserInstructions,
        );

        secondaryTitle = this.getDescriptionInfoPretty(
          allSecAlerts,
          topLevelEventData,
          SCAVulnerability,
          triggerPkgName,
          triggerPkgVersion,
          triggerPkgExist,
          indirectLibsChecked.val,
          unusedPkg,
          isArtifactScaBaseImage,
          isArtifactScaApplication,
          aggItemsInfo.length,
          isArtifactScaPossibleBaseImage,
          isArtifactIac,
          isScaOnDockerFile,
          isArtifactSecrets,
          mainTitle,
          isArtifactScaUserInstructions,
        );

        const atLeastOneWithRec = allSecEvents.find(i => i?.alertRecommendationResponse?.recommendation);
        let recommendation = this.getRecommendationInfoPretty(
          atLeastOneWithRec ? atLeastOneWithRec : topLevelEventData,
          SCAVulnerability,
          allSecAlerts,
          isArtifactScaBaseImage,
          isScaOnDockerFile,
          isArtifactSecrets,
          isArtifactScaPossibleBaseImage,
        );

        if (!recommendation) {
          recommendation = "There are no recommended upgrades currently.";
        }
        secondaryTitle = replaceAll(secondaryTitle, "~", "\\~");
        recommendation = replaceAll(recommendation, "~", "\\~");

        let cweList: CweObject[] = this.getCWEList(topLevelEventData, SCAVulnerability);

        let learnMore = topLevelEventData?.blame?.versionsPageUrl;
        const direct = allSecAlerts.find(i => getDependencyType(i?.blame?.dependencyType) === DependencyType.Direct);
        if (direct) {
          if (direct?.blame?.versionsPageUrl) {
            learnMore = direct?.blame?.versionsPageUrl;
          }
        }

        let uniqueProviders = this.getUniqueSecurityProviders(
          SCAVulnerability.map(i => i.alert.securityProviders),
          topLevelEventData.securityProvider,
        );

        if (isArtifactSca || isArtifactIac) {
          const cweWithName = [];
          cweList.forEach(i => {
            if (i.description) {
              cweWithName.push(i);
            }
          });
          cweList = cweWithName;
        }

        aggregated.aggregatedItems = aggItemsInfo;

        this.addExtraInfo(
          topLevelEventData,
          extraInfo,
          isArtifactSca,
          isSca,
          isArtifactScaBaseImage,
          isArtifactScaApplication,
          isArtifactScaPossibleBaseImage,
          isArtifactIac,
          isScaOnDockerFile,
          isArtifactSecrets,
          isArtifactScaUserInstructions,
        );

        const scaFixType = this.setScaFixType(topLevelEventData, this.policyRuleMetadata.functionName);

        const uniqueArtifacts = new Set();

        let issueId;
        //Container
        if ((isArtifactSca || isArtifactIac || isArtifactSecrets) && topLevelEventData.oxTool) {
          const uniqueInfoAgg = getUniqueInfoForAggregation(topLevelEventData);
          issueId = `${topLevelEventData.imageId}_${this.policyRuleMetadata.policyId}_${uniqueInfoAgg}`;
          aggItemsInfo.forEach(i => {
            uniqueArtifacts.add(i.securityAlert.imageId);
          });
        }
        //Repo
        else {
          issueId = this.getCustomIssueId(getUniqueInfoForAggregation(topLevelEventData));
        }

        if (isPiiPolicy) {
          this.handlePiiSevExtraInfo(uniqueSeverityChanges, events.aggregated);
        }

        let item = this.generateItemForReport(
          isArtifactSecrets ? false : true,
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
          uniqueProviders,
          getToolsNames(topLevelEventData.securityProviders, topLevelEventData.tools),
          extraInfo,
          issueId,
          issueOwners,
          learnMore,
          topLevelEventData.ruleId,
          this.generateCWElist(allSecEvents),
          topLevelEventData.snippetContent,
          cweList,
          newSeverityForPolicy,
          topLevelEventData.blame.dependencyChain,
          topLevelEventData.blame.publicExploitLink,
          originalSeverityStr,
          [],
          getSeverityChanges(originalSeverity, newSeverityForPolicy),
          uniqueSeverityChanges,
          isArtifactIac ? [] : SCAVulnerability,
          this.getOriginalSev(allSecEvents),
          topLevelEventData?.blame?.runtime?.languageInfo,
          false,
          "",
          this.getOscarIdForSecretEvent(allSecEvents),
          scaFixType,
        );

        item.oxRecommendationExists = topLevelEventData?.alertRecommendationResponse?.recommendation ? true : false;
        item.commitInfoExists = topLevelEventData?.blame?.commitSha ? true : false;
        item.uniqueArtifacts = Array.from(uniqueArtifacts);
        item.version = topLevelEventData.version;

        try {
          if (isSca || isArtifactScaApplication || isScaOnDockerFile || isArtifactScaUserInstructions) {
            item.triggerPkgForResolveIssues = `${triggerPkgName}@${triggerPkgVersion}`;
          }
          if (isArtifactScaBaseImage) {
            const artifactorySecEvent: ArtifactorySecEvent = allSecAlerts[0]?.artifacts;
            if (artifactorySecEvent) {
              item.triggerPkgForResolveIssues = `${artifactorySecEvent.baseImage}@${artifactorySecEvent.baseImageOsVersion}`;
            }
          }
          if (isArtifactScaPossibleBaseImage) {
            const artifactorySecEvent: ArtifactorySecEvent = allSecAlerts[0]?.artifacts;
            if (artifactorySecEvent) {
              item.triggerPkgForResolveIssues = `${artifactorySecEvent.os}@${artifactorySecEvent.osVersion}`;
            }
          }
        } catch (err) {
          logger.error(`failed to set triggerPkgForResolveIssues for single item to policy: ${this.policyRuleMetadata.name}, err: ${err}`);
        }

        if (isSca || isArtifactSca || isScaOnDockerFile) {
          const vulNodes = new Set<string>();

          if (isArtifactScaApplication || isSca) {
            item.blameExists = !!topLevelEventData.blame;
            item.graphExists = topLevelEventData.blame?.graphExists || false;
            item.indirectSupported = importedLibsChecked.val;
            if (triggerPkgName && triggerPkgVersion && triggerPkgExist) {
              item.scaTriggerPkg = `${triggerPkgName}@${triggerPkgVersion}`;
              vulNodes.add(`${triggerPkgName}@${triggerPkgVersion}`);
              item.libId = `${triggerPkgManager}|${triggerPkgName}|${triggerPkgVersion}`;
            }
          } else if (triggerPkgName && triggerPkgVersion && triggerPkgExist) {
            item.scaTriggerPkg = `${triggerPkgName}@${triggerPkgVersion}`;
          }

          item.eventFromExternalTool = allSecAlerts.filter(i => !i.oxTool).length > 0;

          allSecAlerts.forEach(i => {
            vulNodes.add(`${i.pkgName}@${i.installedVersion}`);
          });

          item.directSCAVulnerability = directSCAVulnerability;
          item.noneDirectSCAVulnerability = noneDirectSCAVulnerability;
          item.allUniqueLibs = Array.from(vulNodes);
        }

        //Set silent
        let isActive = allSecAlerts.find(i => !i.isSilent);
        if (!isActive) {
          item.isSilent = true;
        }

        item.additionalTabs = additionalTabs.length == 0 ? undefined : additionalTabs;

        if (corelateIssueInfo) {
          item.correlatedIssueId = corelateIssueInfo.corelateIssue;
        }
        item.correlatedRegistry = topLevelEventData?.artifacts?.registryName;

        res.push(item);
      } catch (err) {
        logger.error(`failed to add single item to policy: ${this.policyRuleMetadata.name}, err: ${err}`);
      }
    }

    return res;
  }

  getUniqueAggSCAalerts(aggItems: PolicySecurityScanAggItem[]) {
    const newAggItems: PolicySecurityScanAggItem[] = [];
    const uniqueSet = new Set();
    aggItems.forEach(i => {
      try {
        let key = `${getUniqueInfoForAggregation(i.securityAlert)}_${i.securityAlert.fileName}`;
        if (i.securityAlert.securityAlertType === SecurityAlertType.container) {
          key = `${i.image}`;
        }
        if (uniqueSet.has(key)) {
          return;
        }
        uniqueSet.add(key);
        newAggItems.push(i);
      } catch (err) {
        logger.error(`failed get single unique agg SCA alert, err: ${err}`);
      }
    });

    if (newAggItems.length == 0) {
      return aggItems;
    }
    return newAggItems;
  }

  addExtraInfo(
    topLevelEventData: SecurityEvent,
    extraInfo: ExtraInfo[],
    isArtifact: boolean,
    isSca: boolean,
    isArtifactScaBaseImage: boolean,
    isArtifactScaApplication: boolean,
    isArtifactScaPossibleBaseImage: boolean,
    isArtifactIac: boolean,
    isScaOnDockerFile: boolean,
    isArtifactSecrets: boolean,
    isArtifactScaUserInstructions: boolean,
  ) {
    if (topLevelEventData.eduVideoLink !== undefined) {
      extraInfo.push({
        key: "Recommended Video",
        value: topLevelEventData.eduVideoLink,
      });
    } else if (topLevelEventData.blame.eduVideoLink !== undefined) {
      extraInfo.push({
        key: "Recommended Video",
        value: topLevelEventData.blame.eduVideoLink,
      });
    }
    if (topLevelEventData.ruleId && !isArtifactScaBaseImage && !isArtifactScaPossibleBaseImage && !isScaOnDockerFile) {
      extraInfo.push({ key: "Rule Id", value: topLevelEventData.ruleId });
    }
    if (isArtifact) {
      extraInfo.push({ key: "Container type", value: "Docker" });
    }
  }

  getIssueInfoPretty(
    allSecAlerts: SecurityEvent[],
    SCAVulnerability: SCAVulnerability[],
    mainTitle: string,
    triggerPkgName: string,
    triggerPkgVersion: string,
    triggerPkgExist: boolean,
    indirectSupportedInfo: any,
    unusedPkg: boolean,
    isSca: boolean,
    isArtifactScaBaseImage: boolean,
    isArtifactScaBaseApplication: boolean,
    isArtifactScaPossibleBaseImage: boolean,
    isArtifactIac: boolean,
    isScaOnDockerFile: boolean,
    isArtifactSecrets: boolean,
    isArtifactScaUserInstructions: boolean,
  ) {
    try {
      const singleSecAlert: SecurityEvent = SCAVulnerability[0].alert;

      if (isArtifactSecrets) {
        let secretStatus;
        const artifactorySecEvent: ArtifactorySecEvent = allSecAlerts[0].artifacts;

        let dockerFileName = artifactorySecEvent.dockerFileInRunTime;
        let registryNameShort;
        try {
          if (artifactorySecEvent?.registryName === ArtifactorySecEventSystem.ECR) {
            dockerFileName = path.basename(artifactorySecEvent.dockerFileInRunTime);
          }
          registryNameShort = registryMap.get(artifactorySecEvent.registryName);
          if (registryNameShort === ArtifactorySecEventSystem.Generic) {
            registryNameShort = "";
          }
        } catch (err) {
          logger.error(`failed getting DockerFile base name: ${artifactorySecEvent.dockerFileInRunTime}, err: ${err}`);
        }

        if (singleSecAlert.secretChecked) {
          if (singleSecAlert.validSecret) {
            secretStatus = "active";
          } else {
            secretStatus = "inactive";
          }
        }

        const title = `${
          secretStatus ? secretStatus[0].toUpperCase() + secretStatus.slice(1) + " " : ""
        }${mainTitle} was found in the '${dockerFileName}' image${registryNameShort ? ` (${registryNameShort})` : ``}`;
        return title;
      }

      const cvssAlerts: SecurityEvent[] = allSecAlerts.filter(i => i?.blame?.cvssScore && i?.blame?.cve);
      const cvssAlertsSorted: SecurityEvent[] = cvssAlerts.sort((a, b) => Number(b.blame.cvssScore) - Number(a.blame.cvssScore));

      if (isScaOnDockerFile) {
        const vulCount = SCAVulnerability.length > 1 ? `${SCAVulnerability.length} vulnerabilities` : `1 vulnerability`;
        const fileName = singleSecAlert.fileName;
        let title = `${singleSecAlert.blame.triggerPackage.name}@${singleSecAlert.blame.triggerPackage.version} is a base image defined in ${fileName} having ${vulCount}`; //singleSecAlert
        if (!singleSecAlert.blame.triggerPackage.version) {
          title = `${singleSecAlert.blame.triggerPackage.name} is a base image defined in ${fileName} having ${vulCount}`; //singleSecAlert
        }
        if (cvssAlertsSorted.length > 0) {
          const cve = cvssAlertsSorted[0].blame.cve;
          let importInfo;
          if (cvssAlertsSorted[0].blame.exploitType) {
            const exploitType = cvssAlertsSorted[0].blame.exploitType;
            importInfo = `${cve} (CVSS:${cvssAlertsSorted[0].blame.cvssScore}, ${exploitType})`;
          } else {
            importInfo = `${cve} (CVSS:${cvssAlertsSorted[0].blame.cvssScore})`;
          }
          title = `${title}. Top risk: ${importInfo}`;
        }
        return title;
      }

      if (isArtifactScaBaseImage || isArtifactScaPossibleBaseImage || isArtifactScaUserInstructions) {
        const artifactorySecEvent: ArtifactorySecEvent = allSecAlerts[0].artifacts;

        let registryNameShort;
        let dockerFileName = artifactorySecEvent.dockerFileInRunTime;
        try {
          if (artifactorySecEvent?.registryName === ArtifactorySecEventSystem.ECR) {
            dockerFileName = path.basename(artifactorySecEvent.dockerFileInRunTime);
          }
          registryNameShort = registryMap.get(artifactorySecEvent.registryName);
          if (registryNameShort === ArtifactorySecEventSystem.Generic) {
            registryNameShort = "";
          }
        } catch (err) {
          logger.error(`failed getting DockerFile base name: ${artifactorySecEvent.dockerFileInRunTime}, err: ${err}`);
        }

        let title;
        //Base image
        if (isArtifactScaBaseImage) {
          let baseImage = `${artifactorySecEvent.baseImage}@${artifactorySecEvent.baseImageOsVersion}`;
          if (!artifactorySecEvent.baseImageOsVersion) {
            baseImage = `${artifactorySecEvent.baseImage}`;
          }

          //In case 3 party they not always report the container that the base in stalled on
          const isOriginalImageNotExist = allSecAlerts[0].securityProvider === "Snyk Container";
          if (isOriginalImageNotExist) {
            title = `${baseImage} is the base image${registryNameShort ? ` (${registryNameShort})` : ``} having ${
              SCAVulnerability.length
            } ${SCAVulnerability.length > 1 ? "vulnerabilities" : "vulnerability"}`;
          } else {
            title = `${baseImage} is the base image of the '${dockerFileName}' image ${
              registryNameShort ? `(${registryNameShort})` : ``
            } having ${SCAVulnerability.length} ${SCAVulnerability.length > 1 ? "vulnerabilities" : "vulnerability"}`;
          }
        }

        //Possible os
        if (isArtifactScaPossibleBaseImage) {
          const osOnly = SCAVulnerability.filter(i => i.alert.containerScanType === ContainerSecurityType.possibleOsOnly);

          if (!artifactorySecEvent.os) {
            logger.info(
              `no OS or version provided for alert, image: ${dockerFileName}, cluster: ${registryNameShort}, osVulnerabilites: ${osOnly}, allVulnerabilites: ${SCAVulnerability.length}`,
            );
            return;
          }

          //Have 1 layer
          let t = `${artifactorySecEvent.os}@${artifactorySecEvent.osVersion}`;
          if (!artifactorySecEvent.osVersion) {
            t = `${artifactorySecEvent.os}`;
          }
          if (osOnly.length === SCAVulnerability.length) {
            title = `${t} is the OS of '${dockerFileName}' image ${registryNameShort ? `(${registryNameShort})` : ``} having ${
              osOnly.length
            } ${osOnly.length > 1 || osOnly.length == 0 ? "vulnerabilities" : "vulnerability"}`;
          }
          //Have additional layes
          else {
            const additionalVul = SCAVulnerability.length - osOnly.length;
            title = `${t} is the OS of '${dockerFileName}' image ${registryNameShort ? `(${registryNameShort})` : ``} having ${
              osOnly.length
            } ${
              osOnly.length > 1 || osOnly.length == 0 ? "vulnerabilities" : "vulnerability"
            }. OS additions introduced another ${additionalVul} ${additionalVul > 1 ? "vulnerabilities" : "vulnerability"}`;
          }
        }

        if (isArtifactScaUserInstructions) {
          title = `${singleSecAlert.pkgName}@${
            singleSecAlert.installedVersion
          } is a user instruction introduced dependency in '${dockerFileName}' image ${
            registryNameShort ? `(${registryNameShort})` : ``
          } having ${SCAVulnerability.length} ${SCAVulnerability.length > 1 ? "vulnerabilities" : "vulnerability"}`;
        }

        if (cvssAlertsSorted.length > 0) {
          const cve = cvssAlertsSorted[0].blame.cve;
          let importInfo;
          if (cvssAlertsSorted[0].blame.exploitType) {
            const exploitType = cvssAlertsSorted[0].blame.exploitType;
            importInfo = `${cve} (CVSS:${cvssAlertsSorted[0].blame.cvssScore}, ${exploitType})`;
          } else {
            importInfo = `${cve} (CVSS:${cvssAlertsSorted[0].blame.cvssScore})`;
          }
          title = `${title}. Top risk: ${importInfo}`;
        }

        //No cvss alert with score
        else {
          try {
            if (SCAVulnerability.length > 0) {
              const cvssAlertsSorted: SCAVulnerability[] = SCAVulnerability.sort(
                (a, b) => Number(b.originalSeverityNumber) - Number(a.originalSeverityNumber),
              );
              if (cvssAlertsSorted[0].cve) {
                title = `${title}. ${cvssAlertsSorted[0].cve} is the most severe vulnerability`;
              }
            } else {
              logger.warn(`no cvss for triggerPkgName: ${triggerPkgName}, triggerPkgVersion: ${triggerPkgVersion}`);
            }
          } catch (err) {
            logger.error(`failed calc cvss, err: ${err}`);
          }
        }
        return title;
      }

      //Iac
      if (isArtifactIac) {
        const artifactorySecEvent: ArtifactorySecEvent = allSecAlerts[0].artifacts;

        let registryNameShort;
        let dockerFileName = artifactorySecEvent.dockerFileInRunTime;
        try {
          if (artifactorySecEvent?.registryName === ArtifactorySecEventSystem.ECR) {
            dockerFileName = path.basename(artifactorySecEvent.dockerFileInRunTime);
          }
          registryNameShort = registryMap.get(artifactorySecEvent.registryName);
          if (registryNameShort === ArtifactorySecEventSystem.Generic) {
            registryNameShort = "";
          }
        } catch (err) {
          logger.error(`failed getting DockerFile base name: ${artifactorySecEvent.dockerFileInRunTime}, err: ${err}`);
        }

        let title = `${mainTitle} in '${dockerFileName}' image ${registryNameShort ? `(${registryNameShort}) ` : ``}`;
        return title;
      }

      triggerPkgName = adjustTitle(triggerPkgName);

      //https://oxsecurity.atlassian.net/wiki/spaces/OXDEV/pages/310411426/SCA+Consolidation+Second+Phase
      //Direct or Development
      const directNumber = allSecAlerts.filter(i => getDependencyType(i?.blame?.dependencyType) === DependencyType.Direct);
      const indirectNumber = allSecAlerts.filter(i => getDependencyType(i?.blame?.dependencyType) === DependencyType.Indirect);
      const devNumber = allSecAlerts.filter(i => getDependencyType(i?.blame?.dependencyType) === DependencyType.Development);

      const isDirect = (directNumber.length > 0 || indirectNumber.length > 0) && triggerPkgExist;

      //First title
      let direction;
      let title: string;
      if (isDirect) {
        direction = " direct";
      } else if (devNumber.length > 0) {
        direction = " development";
      } else {
        direction = " indirect";
        indirectSupportedInfo.val = false;
        StatesHelper.Instance.scanInfoStats.pkgIndirectCount++;
        //for debug
        // logger.info(
        //   `blame set direct, for triggerPkgName: ${triggerPkgName}, triggerPkgVersion: ${triggerPkgVersion}, triggerPkgExist: ${triggerPkgExist}, directNumber: ${directNumber.length}, indirectNumber: ${indirectNumber.length}, devNumber: ${devNumber.length}`,
        // );

        //In case its not ox we may not have this data
        if (!isSca) {
          direction = "";
        }

        if ((triggerPkgExist && singleSecAlert.blame.graphExists) || singleSecAlert?.blame?.checkedForDirectIndirect) {
          //manage to check direct/indirect
        } else {
          direction = "";
        }
      }

      //Overwrite in case we have issue
      if (singleSecAlert.blame.graphExists == undefined || singleSecAlert.blame.graphExists == false) {
        indirectSupportedInfo.val = false;
      }

      const indirectSupported = indirectSupportedInfo.val;
      const lan = singleSecAlert.blame.language || singleSecAlert.language;

      const directTotalNum = directNumber.length;
      const indirectTotalNum = indirectNumber.length;
      let dockerFileName;
      let registryNameShort;
      const artifactorySecEvent: ArtifactorySecEvent = allSecAlerts[0].artifacts;

      try {
        if (isArtifactScaBaseApplication) {
          dockerFileName = allSecAlerts[0].artifacts.dockerFileInRunTime;
          if (allSecAlerts[0].artifacts.registryName === ArtifactorySecEventSystem.ECR) {
            dockerFileName = path.basename(artifactorySecEvent.dockerFileInRunTime);
          }
          registryNameShort = registryMap.get(artifactorySecEvent.registryName);
          if (registryNameShort === ArtifactorySecEventSystem.Generic) {
            registryNameShort = "";
          }
        }
      } catch (err) {
        logger.error(`failed getting DockerFile base name: ${allSecAlerts[0].artifacts.dockerFileInRunTime}, err: ${err}`);
      }

      if (directTotalNum > 0 && indirectTotalNum > 0) {
        title = `${triggerPkgName}@${triggerPkgVersion} is a ${lan}${direction} dependency${
          isArtifactScaBaseApplication && registryNameShort ? ` in '${dockerFileName}' image (${registryNameShort})` : ``
        } having ${directTotalNum} direct and ${indirectTotalNum} indirect vulnerabilities.`;
      } else if (directTotalNum > 0) {
        title = `${triggerPkgName}@${triggerPkgVersion} is a ${lan}${direction} dependency${
          isArtifactScaBaseApplication && registryNameShort ? ` in '${dockerFileName}' image (${registryNameShort})` : ``
        } having ${directTotalNum} ${
          indirectSupported
            ? `direct ${directTotalNum > 1 ? "vulnerabilities" : "vulnerability"} and no indirect vulnerabilities.`
            : `${directTotalNum > 1 ? "vulnerabilities" : "vulnerability"}.`
        }`;
      } else if (indirectTotalNum > 0) {
        title = `${triggerPkgName}@${triggerPkgVersion} is a ${lan}${direction} dependency${
          isArtifactScaBaseApplication && registryNameShort ? ` in '${dockerFileName}' image (${registryNameShort})` : ``
        } having ${indirectTotalNum} ${
          indirectSupported
            ? `indirect ${indirectTotalNum > 1 ? "vulnerabilities" : "vulnerability"} and no direct vulnerabilities.`
            : `${indirectTotalNum > 1 ? "vulnerabilities" : "vulnerability"}.`
        }`;
      }
      if (!title) {
        title = `${triggerPkgName}@${triggerPkgVersion}`;
        if (lan && direction) {
          title = `${title} is a ${lan}${direction}`;
        } else if (lan) {
          title = `${title} is a ${lan}`;
        } else if (direction) {
          title = `${title} ${direction}`;
        }
        title = `${title}${
          isArtifactScaBaseApplication && registryNameShort
            ? ` dependency in '${dockerFileName}' image (${registryNameShort}) having`
            : " dependency having"
        } ${SCAVulnerability.length} ${SCAVulnerability.length > 1 ? "vulnerabilities" : "vulnerability"}.`;
      }

      //The dependency is not imported into the code.
      const notImported = SCAVulnerability.find(i => i?.alert?.scaValidatorTypesResponse?.pkgImported === false) || unusedPkg;
      if (notImported) {
        title = `${title} The dependency is not imported into the code.`;
      }
      //The dependency is imported into the code.
      else {
        if (cvssAlertsSorted.length > 0) {
          const cve = cvssAlertsSorted[0].blame.cve;
          let importInfo;
          if (cvssAlertsSorted[0].blame.exploitType) {
            const exploitType = cvssAlertsSorted[0].blame.exploitType;
            importInfo = `${cve} (CVSS:${cvssAlertsSorted[0].blame.cvssScore}, ${exploitType})`;
          } else {
            importInfo = `${cve} (CVSS:${cvssAlertsSorted[0].blame.cvssScore})`;
          }
          if (isArtifactScaBaseApplication) {
            title = `${title} Top risk: ${importInfo}`;
          } else {
            title = `${title} ${importInfo} is the most severe vulnerability.`;
          }
        }
        //No cvss alert with score
        else {
          try {
            if (SCAVulnerability.length > 0) {
              const cvssAlertsSorted: SCAVulnerability[] = SCAVulnerability.sort(
                (a, b) => Number(b.originalSeverityNumber) - Number(a.originalSeverityNumber),
              );
              if (cvssAlertsSorted[0].cve) {
                title = `${title} Top risk: ${cvssAlertsSorted[0].cve} is the most severe vulnerability.`;
              }
            } else {
              logger.warn(`no cvss for triggerPkgName: ${triggerPkgName}, triggerPkgVersion: ${triggerPkgVersion}`);
            }
          } catch (err) {
            logger.error(`failed calc cvss`, err);
          }
        }
      }
      return title;
    } catch (err) {
      logger.error(`failed get issue title info new sca pretty`, err);
    }
    return mainTitle;
  }

  getSeverityPrettyImages(allSecAlerts: SecurityEvent[]) {
    let c = {};
    allSecAlerts.forEach(i => {
      if (c[i.originalSeverityStr]) {
        c[i.originalSeverityStr] = c[i.originalSeverityStr] + 1;
      } else {
        c[i.originalSeverityStr] = 1;
      }
    });
    let str = ``;
    for (const [key, val] of Object.entries(c)) {
      str = `${str}&bull; ${key} : ${val}<br>`;
    }
    return str;
  }

  getDescriptionInfoPretty(
    allSecAlerts: SecurityEvent[],
    securityEvent: SecurityEvent,
    SCAVulnerability: SCAVulnerability[],
    triggerPkgName: string,
    triggerPkgVersion: string,
    triggerPkgExist: boolean,
    indirectSupported: boolean,
    unusedPkg: boolean,
    isArtifactScaBaseImage: boolean,
    isArtifactScaBaseApplication: boolean,
    aggItemsCount: number,
    isArtifactScaPossibleBaseImage: boolean,
    isArtifactIac: boolean,
    isScaOnDockerFile: boolean,
    isArtifactSecrets: boolean,
    mainTitle: string,
    isArtifactScaUserInstructions: boolean,
  ) {
    try {
      const singleSecAlert: SecurityEvent = SCAVulnerability[0].alert;
      let res;

      if (securityEvent.artifacts) {
        const artifactorySecEvent: ArtifactorySecEvent = securityEvent.artifacts;
        try {
          let dockerFileName = "";
          if (artifactorySecEvent.registryName === ArtifactorySecEventSystem.ECR) {
            dockerFileName = path.basename(artifactorySecEvent.dockerFileInRunTime);
            mainTitle = mainTitle.replace(dockerFileName, artifactorySecEvent.dockerFileInRunTime);
          }
        } catch (err) {
          logger.error(
            `failed replacing DockerFile base name with full path for description: ${artifactorySecEvent.dockerFileInRunTime}, err: ${err}`,
          );
        }
      }

      if (
        securityEvent.securityAlertType === SecurityAlertType.container &&
        securityEvent.securitySubTypeAlertType === SecurityAlertType.secrets &&
        securityEvent.isPII
      ) {
        let secondaryTitle = `${mainTitle}.`;
        try {
          const key = `${securityEvent.artifacts.dockerFileInRunTime}_${securityEvent.ruleId}`;
          const total = StatesHelper.Instance.piiEventsCounter[key];
          const remaining = total - Constant.piiCollectLimit;
          if (remaining > 0) {
            secondaryTitle += `<br>
There are ${remaining} more occurences of this violation.`;
          }
        } catch (e) {
          logger.error(`failed to get total pii events from counter for ${securityEvent.artifacts.dockerFileInRunTime}`);
        }

        return secondaryTitle;
      }

      if (isArtifactSecrets) {
        let secretStatus = "";
        if (securityEvent.secretChecked && securityEvent.validSecret) {
          secretStatus = "active";
        }
        if (securityEvent.secretChecked && !securityEvent.validSecret) {
          secretStatus = "inactive";
        }

        if (secretStatus == "active") {
          return `${mainTitle}. The secret is considered live or active by the system it is meant to connect to.
          <br/>${securityEvent.title}`;
        } else if (secretStatus == "inactive") {
          return `${mainTitle}. The secret is disabled or revoked by the system it is meant to connect to.
          <br/>${securityEvent.title}`;
        } else {
          return `${mainTitle}.<br/>
          ${securityEvent.title}`;
        }
      }

      if (isArtifactScaBaseImage || isArtifactScaPossibleBaseImage || isArtifactScaUserInstructions) {
        const artifactorySecEvent: ArtifactorySecEvent = allSecAlerts[0].artifacts;

        let registryName = artifactorySecEvent.registryName;
        if (registryName === ArtifactorySecEventSystem.Generic) {
          registryName = "";
        }

        //Base image
        if (isArtifactScaBaseImage) {
          const osOnly = SCAVulnerability.filter(i => i.alert.LayerOrder === 1);
          let baseNameVer = `${artifactorySecEvent.baseImage}\\@${artifactorySecEvent.baseImageOsVersion}`;
          if (!artifactorySecEvent.baseImageOsVersion) {
            baseNameVer = `${artifactorySecEvent.baseImage}`;
          }

          let osNameVer;
          if (artifactorySecEvent.os) {
            osNameVer = `${artifactorySecEvent.os}`;
          }
          if (artifactorySecEvent.os && artifactorySecEvent.osVersion) {
            osNameVer = `${artifactorySecEvent.os}\\@${artifactorySecEvent.osVersion}`;
          }

          const isOriginalImageNotExist = allSecAlerts[0].securityProvider === "Snyk Container";

          if (baseNameVer === osNameVer) {
            res = `${baseNameVer} is the base image${
              !isOriginalImageNotExist ? ` created for the '${artifactorySecEvent.dockerFileInRunTime}' image` : ""
            }${registryName ? ` stored in ${registryName}` : ""}.`;
            res = `${res}<br><br>${allSecAlerts.length === 1 ? "There is" : "There are a total of"} ${allSecAlerts.length} ${
              allSecAlerts.length > 1 ? "vulnerabilities" : "vulnerability"
            }.`;
          } else {
            res = `${baseNameVer} is the base image${
              !isOriginalImageNotExist ? ` created for the '${artifactorySecEvent.dockerFileInRunTime}' image` : ""
            }${registryName ? ` stored in ${registryName}` : ""}. ${
              osNameVer ? `${osNameVer} is the operating system present in the base image.` : ``
            }`;
            res = `${res}<br><br>${allSecAlerts.length === 1 ? "There is" : "There are a total of"} ${allSecAlerts.length} ${
              allSecAlerts.length > 1 ? "vulnerabilities" : "vulnerability"
            }.`;

            //Add os data if exist
            if (osNameVer) {
              res = `${res} Operating System ${osNameVer} has ${osOnly.length} ${
                osOnly.length > 1 || osOnly.length == 0 ? "vulnerabilities" : "vulnerability"
              }.`;
            }

            if (osOnly.length > 0) {
              const diff = allSecAlerts.length - osOnly.length;
              if (diff == 1) {
                res = `${res}, there is ${diff} more vulnerability in the ${baseNameVer} image.`;
              } else {
                res = `${res}, there are ${diff} more vulnerabilities in the ${baseNameVer} image.`;
              }
            }
          }
        }

        //Possible os
        if (isArtifactScaPossibleBaseImage) {
          const osOnly = SCAVulnerability.filter(i => i.alert.containerScanType === ContainerSecurityType.possibleOsOnly);
          //Have 1 layer
          if (osOnly.length === SCAVulnerability.length) {
            res = `${artifactorySecEvent.os}\\@${artifactorySecEvent.osVersion} is the operating system used in ${artifactorySecEvent.dockerFileInRunTime}.`;
            res = `${res}<br><br>${allSecAlerts.length === 1 ? "There is" : "There are a total of"} ${allSecAlerts.length} ${
              allSecAlerts.length > 1 ? "vulnerabilities" : "vulnerability"
            }.`;
          }
          //Have additional layes
          else {
            res = `${artifactorySecEvent.os}\\@${artifactorySecEvent.osVersion} is the operating system used in ${artifactorySecEvent.dockerFileInRunTime}. Additional OS modules were also added to the container.`;
            res = `${res}<br><br>${allSecAlerts.length === 1 ? "There is" : "There are a total of"} ${allSecAlerts.length} ${
              allSecAlerts.length > 1 ? "vulnerabilities" : "vulnerability"
            }. ${artifactorySecEvent.os}\\@${artifactorySecEvent.osVersion} has ${osOnly.length} ${
              osOnly.length > 1 ? "vulnerabilities" : "vulnerability"
            }. The additional OS modules increase the number of known vulnerabilities by ${allSecAlerts.length - osOnly.length}.`;
          }
        }

        //User instructions
        if (isArtifactScaUserInstructions) {
          const title = `${singleSecAlert.pkgName}\\@${
            singleSecAlert.installedVersion
          } dependency added by a DockerFile user instruction to the '${artifactorySecEvent.dockerFileInRunTime}' image${
            registryName ? ` stored in ${artifactorySecEvent.registryName}` : ""
          }.<br>`;
          res = `${title}${allSecAlerts.length === 1 ? "There is" : "There are a total of"} ${allSecAlerts.length} ${
            allSecAlerts.length > 1 ? "vulnerabilities" : "vulnerability"
          }.`;
        }

        const breakDown = this.getSeverityPrettyImages(allSecAlerts);
        if (breakDown) {
          res = `${res}<br><br>The severities of the CVEs are as follows:<br>${breakDown}`;
        }

        const allVulLibs = new Set();
        allSecAlerts.forEach(i => {
          try {
            const key = `${i.pkgName}\\@${i.installedVersion}`;
            allVulLibs.add(key);
          } catch (err) {
            logger.error(`failed add single item to libs, sec alert: ${JSON.stringify(i)} err: ${err}`);
          }
        });
        if (allVulLibs.size > 0) {
          res = `${res}<br>
          The following ${allVulLibs.size > 1 ? `${allVulLibs.size} dependencies have` : "dependency has"} vulnerabilities: ${Array.from(
            allVulLibs,
          )
            .slice(0, 20)
            .join(", ")}${allVulLibs.size > 20 ? `...+ ${allVulLibs.size - 20} more` : ""}`;
        }

        if (singleSecAlert.dockerInstructions) {
          if (isArtifactScaBaseImage) {
            //do nothing
          } else {
            res = `${res}<br><br>Docker instruction: ${singleSecAlert.dockerInstructions}`;
          }
        }

        return res;
      }

      if (isArtifactIac) {
        // A misconfiguration was found in the  image stored in Amazon Elastic Container Registry.
        let registryName = singleSecAlert?.artifacts?.registryName;

        if (singleSecAlert?.artifacts?.dockerFileInRunTime) {
          const title = `A misconfiguration was found in the '${singleSecAlert.artifacts.dockerFileInRunTime}' image${
            registryName ? ` stored in ${registryName}` : ""
          }.<br>`;
          res = `${title}<br>${singleSecAlert.additionalInfo}`;
          return res;
        }
        return singleSecAlert.additionalInfo;
      }

      if (isScaOnDockerFile) {
        let dockerImage = `${singleSecAlert.blame.triggerPackage.name}\\@${singleSecAlert.blame.triggerPackage.version}`;
        if (!singleSecAlert.blame.triggerPackage.version) {
          dockerImage = `${singleSecAlert.blame.triggerPackage.name}`;
        }
        let description = `${dockerImage} is the base image used in ${singleSecAlert.fileName}.`;

        const allVulLibs = new Set();
        allSecAlerts.forEach(i => {
          try {
            const key = `${i.pkgName}\\@${i.installedVersion}`;
            allVulLibs.add(key);
          } catch (err) {
            logger.error(`failed add single item to libs, sec alert: ${JSON.stringify(i)} err: ${err}`);
          }
        });

        if (allSecAlerts.length > 0) {
          description += `<br><br> ${
            allSecAlerts.length > 1 ? `There are a total of ${allSecAlerts.length} vulnerabilities` : "There is 1 vulnerability"
          } in ${dockerImage}.`;
        }

        const breakDown = this.getSeverityPrettyImages(allSecAlerts);
        if (breakDown) {
          description += `<br><br>The severities of the CVEs are as follows:<br>${breakDown}`;
        }

        if (allVulLibs.size > 0) {
          description += `<br>
          The following ${allVulLibs.size > 1 ? `${allVulLibs.size} dependencies have` : "dependency has"} vulnerabilities: ${Array.from(
            allVulLibs,
          )
            .slice(0, 20)
            .join(", ")}${allVulLibs.size > 20 ? `...+ ${allVulLibs.size - 20} more` : ""}`;
        }

        if (singleSecAlert.dockerInstructions) {
          res = `${res}<br><br>Docker instruction: ${singleSecAlert.dockerInstructions}`;
        }

        return description;
      }

      //https://oxsecurity.atlassian.net/wiki/spaces/OXDEV/pages/310411426/SCA+Consolidation+Second+Phase
      //First title
      let firstTitle: string;
      //Direct
      const directNumber = allSecAlerts.filter(i => getDependencyType(i?.blame?.dependencyType) === DependencyType.Direct);
      const indirectNumber = allSecAlerts.filter(i => getDependencyType(i?.blame?.dependencyType) === DependencyType.Indirect);
      const devNumber = allSecAlerts.filter(i => getDependencyType(i?.blame?.dependencyType) === DependencyType.Development);

      let isDirect = directNumber.length > 0;
      if (!isDirect) {
        isDirect = (directNumber.length > 0 || indirectNumber.length > 0) && triggerPkgExist;
      }

      triggerPkgVersion = triggerPkgVersion.replace("~", "\\~");
      const artifactorySecEvent: ArtifactorySecEvent = allSecAlerts[0].artifacts;
      let registryName;
      if (artifactorySecEvent) {
        registryName = artifactorySecEvent.registryName;
        if (registryName === ArtifactorySecEventSystem.Generic) {
          registryName = "";
        }
      }

      if (isDirect) {
        // cryptography@3.1.1 is a Python package that was added as a direct dependency to the 'bank-backend' image stored in Google Container Registry. This issue was detected on X version(s) of the 'bank-backend' image.
        firstTitle = `${triggerPkgName}\\@${triggerPkgVersion} is a ${
          singleSecAlert.language
        } package that was added as a direct dependency${
          isArtifactScaBaseApplication
            ? ` to the  '${artifactorySecEvent.dockerFileInRunTime}' image${
                registryName ? ` stored in ${registryName}` : ""
              }. This issue was detected on ${aggItemsCount} ${aggItemsCount > 1 ? "versions" : "version"} of the '${
                artifactorySecEvent.dockerFileInRunTime
              }' image`
            : ""
        }.`;
      }
      //Development
      else if (devNumber.length > 0) {
        firstTitle = `${triggerPkgName}\\@${triggerPkgVersion} is a ${
          singleSecAlert.language
        } package that was added as a development dependency${
          isArtifactScaBaseApplication
            ? ` to the '${artifactorySecEvent.dockerFileInRunTime}' image${
                registryName ? ` stored in ${registryName}` : ""
              }. This issue was detected on ${aggItemsCount} ${aggItemsCount > 1 ? "versions" : "version"} of the '${
                artifactorySecEvent.dockerFileInRunTime
              }' image`
            : ""
        }. It is used in development and should not be promoted to production.`;
      } else {
        let checkedIndirect = false;
        if ((triggerPkgExist && singleSecAlert.blame.graphExists) || singleSecAlert?.blame?.checkedForDirectIndirect) {
          checkedIndirect = true;
        }
        if (checkedIndirect) {
          if (singleSecAlert.language) {
            firstTitle = `${triggerPkgName}\\@${triggerPkgVersion} is a ${
              singleSecAlert.language
            } package that was added as an indirect dependency${
              isArtifactScaBaseApplication
                ? ` to the '${artifactorySecEvent.dockerFileInRunTime}' image${
                    registryName ? `stored in ${registryName}` : ""
                  }. This issue was detected on ${aggItemsCount} ${aggItemsCount > 1 ? "versions" : "version"} of the '${
                    artifactorySecEvent.dockerFileInRunTime
                  }' image`
                : ""
            }.`;
          } else {
            firstTitle = `${triggerPkgName}\\@${triggerPkgVersion}${
              isArtifactScaBaseApplication
                ? ` ${aggItemsCount > 1 ? `is used in ${aggItemsCount} containers` : `used in ${aggItemsCount} container`}`
                : ""
            }.`;
          }
        } else {
          if (singleSecAlert.language) {
            firstTitle = `${triggerPkgName}\\@${triggerPkgVersion} is a ${singleSecAlert.language} package dependency${
              isArtifactScaBaseApplication
                ? ` ${aggItemsCount > 1 ? `is used in ${aggItemsCount} containers` : `used in ${aggItemsCount} container`}`
                : ""
            }.`;
          } else {
            firstTitle = `${triggerPkgName}\\@${triggerPkgVersion}${
              isArtifactScaBaseApplication
                ? ` ${aggItemsCount > 1 ? `is used in ${aggItemsCount} containers` : `used in ${aggItemsCount} container`}`
                : ""
            }.`;
          }
        }
      }
      res = `${firstTitle}`;

      //Second title
      let secondTitle;
      const directTotalNum = directNumber.length;
      const indirectTotalNum = indirectNumber.length;
      if (directTotalNum > 0 && indirectTotalNum > 0) {
        secondTitle = `${directTotalNum} direct and ${indirectTotalNum} indirect vulnerabilities`;
      } else if (directTotalNum > 0) {
        secondTitle = `${directTotalNum} ${
          indirectSupported
            ? `direct ${directTotalNum > 1 ? "vulnerabilities" : "vulnerability"} and no indirect vulnerabilities`
            : `${directTotalNum > 1 ? "vulnerabilities" : "vulnerability"}`
        }`;
      } else if (indirectTotalNum > 0) {
        secondTitle = `${indirectTotalNum} ${
          indirectSupported
            ? `indirect ${indirectTotalNum > 1 ? "vulnerabilities" : "vulnerability"} and no direct vulnerabilities`
            : `${indirectTotalNum > 1 ? "vulnerabilities" : "vulnerability"}`
        }`;
      }
      if (secondTitle) {
        res = `${res} It contains:<br><br>&bull; ${secondTitle}`;
      }

      const notImported = SCAVulnerability.find(i => i?.alert?.scaValidatorTypesResponse?.pkgImported === false) || unusedPkg;
      let forthTitle;
      if (!notImported) {
        const publicExploits = allSecAlerts.filter(i => i?.blame?.hasPublicExploit);
        if (publicExploits.length > 0) {
          forthTitle = `${publicExploits.length} ${
            publicExploits.length > 1 ? "vulnerabilities with" : "vulnerability with"
          }  publicly available exploits`;
        }
      }
      if (forthTitle) {
        res = `${res}<br>&bull; ${forthTitle}`; //newline between them
      }

      let totalNumberOfIndirectDep = ``;
      const withNodes = allSecAlerts.filter(i => i.graphNodesCount > 0);
      if (withNodes.length > 0) {
        const n = singleSecAlert?.blame?.triggerPackage?.dependencyAmount || withNodes[0].graphNodesCount - 1;
        totalNumberOfIndirectDep = `${n == 0 ? "No" : `${n}`} indirect dependencies`; //newline
        res = `${res}<br>&bull; ${totalNumberOfIndirectDep}`; //newline between them
      }

      if (securityEvent.blame.dependencyType === DependencyType.Development) {
        //Do nothing
      } else if (notImported) {
        res = `${res}<br>&bull; NOT imported into your code`;
      } else if (!notImported) {
        //Do nothing
      }

      if (devNumber.length > 0) {
        res = `${res}<br>&bull; Used for development only`; //newline between them
      }

      res = `${res}<br><br>${allSecAlerts.length === 1 ? "There is" : "There are a total of"} ${allSecAlerts.length} ${
        allSecAlerts.length > 1 ? "vulnerabilities" : "vulnerability"
      }.`;

      const breakDown = this.getSeverityPrettyImages(allSecAlerts);
      if (breakDown) {
        res = `${res}<br><br>The severities of the CVEs are as follows:<br>${breakDown}`;
      }

      const allVulLibs = new Set();
      allSecAlerts.forEach(i => {
        try {
          const key = `${i.pkgName}\\@${i.installedVersion}`;
          allVulLibs.add(key);
        } catch (err) {
          logger.error(`failed add single item to libs, sec alert: ${JSON.stringify(i)} err: ${err}`);
        }
      });
      if (allVulLibs.size > 0) {
        res = `${res}<br>
          The following ${allVulLibs.size > 1 ? `${allVulLibs.size} dependencies have` : "dependency has"} vulnerabilities: ${Array.from(
          allVulLibs,
        )
          .slice(0, 20)
          .join(", ")}${allVulLibs.size > 20 ? `...+ ${allVulLibs.size - 20} more` : ""}`;
      }

      if (singleSecAlert.dockerInstructions) {
        res = `${res}<br><br>Docker instruction: ${singleSecAlert.dockerInstructions}`;
      }

      return res;
    } catch (err) {
      logger.error(`failed get description info pretty in: ${this.policyRuleMetadata.name}`, err);
    }
    return securityEvent.title;
  }

  getRecommendationInfoPretty(
    securityEvent: SecurityEvent,
    SCAVulnerability: SCAVulnerability[],
    allSecAlerts: SecurityEvent[],
    isArtifactScaBaseImage: Boolean,
    isScaOnDockerFile: Boolean,
    isArtifactSecrets: boolean,
    isArtifactScaPossibleBaseImage: boolean,
  ) {
    try {
      if (this.policyRuleMetadata.policyId === "oxPolicy_policyPiiContainer_1") {
        return `Add OX to your repos pipeline to detect and block PII from being exposed in your code.

Educate developers on the potential ramifications of embedding PII directly within code and provide guidelines for safer alternatives, such as using environment variables or secure storage solutions. Strengthen code review processes and ensure adherence to data protection principles, emphasizing the importance of keeping PII out of the codebase.  <br><br>
Following code changes, make sure you remove this container image and replace it with a code which is clean of Pii`;
      }

      if (securityEvent?.alertRecommendationResponse?.recommendation) {
        return securityEvent?.alertRecommendationResponse?.recommendation;
      }

      if (isArtifactSecrets) {
        let extraInfo = securityEvent.extraInfo;
        const artifactorySecEvent: ArtifactorySecEvent = allSecAlerts[0].artifacts;

        let secretStatus = "";
        if (securityEvent.secretChecked && securityEvent.validSecret) {
          secretStatus = "active";
        }
        if (securityEvent.secretChecked && !securityEvent.validSecret) {
          secretStatus = "inactive";
        }

        // if (securityEvent.secretChecked) {
        if (secretStatus === "active") {
          securityEvent.recommendation = `This is an **active** ${securityEvent.violationInfo} in the ${artifactorySecEvent.dockerFileInRunTime} image that needs to be removed. Please do the following:\n
              1. Revoke/Disable the found ${securityEvent.violationInfo}.
              2. Generate a new ${securityEvent.violationInfo}.
              3. Store the new ${securityEvent.violationInfo} in an environment variable or secret manager.
              4. Change the code to utilize the new ${securityEvent.violationInfo} via the method chosen above.
              5. Remove all mentions of the found ${securityEvent.violationInfo} from the image.
              \nWARNING: The found ${securityEvent.violationInfo} will still be visible in the Git History. Ensure it is revoked/disabled.`;
        } else {
          securityEvent.recommendation = `${secretStatus === "inactive" ? "This is an **inactive** " : "The "}${
            securityEvent.violationInfo
          } in the ${artifactorySecEvent.dockerFileInRunTime} image${
            secretStatus === "inactive" ? " that " : " "
          }needs to be removed. Please do the following:\n
              1. Moving forward, store secrets in an environment variable or secret manager.
              2. Change the code to access secrets using the method chosen above.
              3. Remove all mentions of the found ${securityEvent.violationInfo} from the image.
              \nWARNING: The found ${securityEvent.violationInfo} will still be visible in the Git History. Ensure it is revoked/disabled.`;
        }

        if (secretStatus) {
          extraInfo.push({
            key: "Secret status",
            value: secretStatus,
          });
        }
      }

      if (isScaOnDockerFile) {
        if (securityEvent?.alertRecommendationResponse?.recommendation) {
          return securityEvent?.alertRecommendationResponse?.recommendation;
        }
      }

      if (isArtifactScaBaseImage) {
        if (securityEvent?.alertRecommendationResponse?.recommendation) {
          return securityEvent?.alertRecommendationResponse?.recommendation;
        }
      }

      if (SCAVulnerability.length > 0) {
        if (isArtifactScaBaseImage || isArtifactScaPossibleBaseImage) {
          const keyValUnique = {};
          SCAVulnerability.forEach(i => {
            const key = `${i.alert.pkgName}\\@${i.alert.installedVersion}`;
            if (keyValUnique[key]) {
              keyValUnique[key].push(i.alert);
            } else {
              keyValUnique[key] = [i.alert];
            }
          });
          let solvedIssues = 0;
          let final = ``;
          let lines = 0;
          for (const [name, entry] of Object.entries(keyValUnique)) {
            try {
              const allEvents = entry as SecurityEvent[];
              const singleIssue = allEvents[0];
              const ignoreMinorMajorVer = true;
              const res = getFixVersionsFromSecEvent(allEvents[0], allEvents, ignoreMinorMajorVer);

              if (res.fixVer) {
                const i = `&bull; ${singleIssue.pkgName}\\@${res.fixVer} (${res.isMajor ? "major" : "minor"} upgrade) resolves ${
                  res.numberIssuesFixed
                } of ${allEvents.length} ${allEvents.length > 1 ? "CVEs" : "CVE"} in ${name}`;
                if (!final) {
                  if (i) {
                    final = i;
                  }
                } else {
                  if (i && lines < 30) {
                    final = `${final}<br>${i}`;
                    lines++;
                  }
                }
                solvedIssues += res.numberIssuesFixed;
              }
            } catch (err) {
              logger.error(`failed get recommendation for os lib, err: ${err}`);
            }
          }

          let finalStr;
          if (solvedIssues > 0) {
            finalStr = `The recommended upgrades below will solve ${solvedIssues} of ${allSecAlerts.length} vulnerabilities:<br><br>${final}`;
          }
          return finalStr;
        }

        const ignoreMinorMajorVer = true;
        const res = getFixVersionsFromSecEvent(securityEvent, allSecAlerts, ignoreMinorMajorVer);
        if (res.numberIssuesFixed > 0) {
          const installedVerName = `${securityEvent.pkgName}\\@${securityEvent.installedVersion}`;
          const i = `&bull; ${securityEvent.pkgName}\\@${res.fixVer} (${res.isMajor ? "major" : "minor"} upgrade) resolves ${
            res.numberIssuesFixed
          } of ${allSecAlerts.length} ${allSecAlerts.length > 1 ? "CVEs" : "CVE"} in ${installedVerName}`;
          if (i) {
            return i;
          }
        } else {
          if (SCAVulnerability[0].alert?.alertRecommendationResponse?.recommendation) {
            return SCAVulnerability[0].alert.alertRecommendationResponse.recommendation;
          }
          if (SCAVulnerability[0].alert?.recommendation) {
            return SCAVulnerability[0].alert?.recommendation;
          }
          return "";
        }
      }
    } catch (err) {
      logger.error(`failed get recommendation info pretty, err: ${err}`);
    }
    return securityEvent.recommendation;
  }

  getCWEList(securityEvent: SecurityEvent, SCAVulnerability: SCAVulnerability[]) {
    let r = [];
    try {
      const exist = new Set();
      SCAVulnerability.forEach(i => {
        if (!i.alert.cweList) {
          return;
        }
        i.alert.cweList.forEach(j => {
          if (exist.has(j)) {
            return;
          }
          exist.add(j);
          r.push(j);
        });
      });
    } catch (err) {
      logger.error(`failed get CWE list, err: ${err}`, err);
    }
    if (r.length == 0) {
      r = securityEvent.cweList;
    }
    const cweObjectList = [];
    for (const cwe of r) {
      if (cweMapping.hasOwnProperty(cwe)) {
        cweObjectList.push(cweMapping[cwe]);
      }
    }
    return cweObjectList;
  }

  getKeyValueMapByRuleIdAndData(
    jsonData: any,
    securityEvents: SecurityEvent[],
    isSca: boolean,
    isArtifactScaBaseImage: boolean,
    isArtifactScaBaseApplication: boolean,
    isArtifactScaPossibleBaseImage: boolean,
    isArtifactIac: boolean,
    isScaOnDockerFile: boolean,
    isArtifactSecrets: boolean,
    isArtifactScaUserInstructions: boolean,
  ) {
    let aggregatedItems = {};

    const repo: Repo = jsonData.code_repo;

    for (const event of securityEvents) {
      try {
        if (isSca || isScaOnDockerFile) {
          if (!event.fileName) {
            logger.error(`failed to add event to security event provider: ${event.securityProvider} due to file name empty`);
            continue;
          }
        }
        if (
          isArtifactScaBaseImage ||
          isArtifactScaBaseApplication ||
          isArtifactScaPossibleBaseImage ||
          isArtifactScaUserInstructions ||
          isArtifactIac ||
          isArtifactSecrets
        ) {
          if (!event?.artifacts?.dockerFileInRunTime) {
            logger.error(`failed to add event to security event, provider: ${event.securityProvider}, due to dockerFileInRunTime`);
            continue;
          }
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
        if (event?.blame?.commitDescription) {
          titleInfo =
            event.blame.commitDescription.length > 1000 ? event.blame.commitDescription.substring(0, 1000) : event.blame.commitDescription;
        }

        const singleItem: PolicySecurityScanAggItem = new PolicySecurityScanAggItem();
        singleItem.isOldEvent = event.isOldEvent;

        //Set fix available
        let isFixAvailable = false;
        if (isSca || isScaOnDockerFile) {
          if (event?.alertRecommendationResponse?.autofixable && (event.blame.graphExists || event.blame.language)) {
            isFixAvailable = true;
          }
        }
        if (StatesHelper.Instance.isContainerEnable) {
          if (isArtifactScaBaseApplication) {
            if (event?.alertRecommendationResponse?.autofixable && event.blame.graphExists) {
              isFixAvailable = true;
            }
          }
          if (isArtifactScaBaseImage) {
            if (event?.alertRecommendationResponse?.autofixable) {
              isFixAvailable = true;
            }
          }
        }

        //Set fix applied
        let isFixApplied = false;

        let lineContent = "";
        let snippet = "";
        if (event.lineContent) {
          lineContent =
            event.lineContent.length > Constant.MATCH_CHARS_LIMIT
              ? event.lineContent.substring(0, Constant.MATCH_CHARS_LIMIT)
              : event.lineContent;
          snippet =
            event.snippetContent.length > Constant.SNIPPET_CHARS_LIMIT
              ? event.snippetContent.substring(0, Constant.SNIPPET_CHARS_LIMIT)
              : event.snippetContent;
        }

        singleItem.isSilent = event.isSilent || false;
        singleItem.fileName = event.fileName || "";
        singleItem.version = event.branch || "";
        singleItem.graphExists = event.blame?.graphExists || false;
        singleItem.blameExists = !!event.blame;
        singleItem.fileUri = event.link;
        singleItem.linkToExternalProduct = event.linkToExternalProduct;
        singleItem.startLine = event.startLineNumber != undefined && event.startLineNumber != -1 ? event.startLineNumber : undefined;
        singleItem.endLine = event.endLineNumber;
        singleItem.match = lineContent || "";
        singleItem.uid = event?.uid || "";
        singleItem.snippet = snippet || "";
        if (isArtifactSecrets) {
          singleItem.match = getObfuscatedPassForContainer(lineContent);
          singleItem.snippet = getObfuscatedPassForContainer(snippet);
        }
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
        singleItem.pkgName = event.pkgName;
        singleItem.fixedVersion = event.fixedVersion;
        singleItem.installedVersion = event.installedVersion;
        singleItem.language = event?.blame?.language ? event?.blame?.language : "";
        singleItem.branch = repo.defaultBranch;
        singleItem.filePath = event.filePath || "";
        singleItem.lockfile = event?.lockfile?.includes("oxLockDir") ? "" : event.lockfile;
        if (event.alertRecommendationResponse.triggerPkgName) {
          singleItem.triggerPkgName = event.alertRecommendationResponse.triggerPkgName;
          singleItem.triggerPkgVersion = event.alertRecommendationResponse.triggerPkgVersion;
          singleItem.triggerPkgUpgradeVersion = event.alertRecommendationResponse.upgradeVersion;
        }

        if (
          isArtifactScaBaseImage ||
          isArtifactScaBaseApplication ||
          isArtifactScaPossibleBaseImage ||
          isArtifactIac ||
          isArtifactSecrets ||
          isArtifactScaUserInstructions
        ) {
          singleItem.additionalToolData = event?.artifacts?.additionalInfo || "";
          singleItem.dockerVer = event?.artifacts?.dockerVer || "";
          singleItem.imageCreatedAt = event?.artifacts?.imageCreatedAt || "";
          if (singleItem.imageCreatedAt) {
            if (singleItem.imageCreatedAt.toLowerCase() != "n/a") {
              try {
                singleItem.imageCreatedAt = new Date(singleItem.imageCreatedAt).toLocaleString();
              } catch (err) {}
            } else {
              singleItem.imageCreatedAt = "";
            }
          }

          singleItem.pkgCount = event?.artifacts?.pkgCount || 0;
          singleItem.binariesCount = event?.artifacts?.binariesCount || 0;
          singleItem.sha = event?.artifacts?.sha || "";
          singleItem.os = event?.artifacts?.os || "";
          if (singleItem.os) {
            if (event?.artifacts?.osVersion) {
              singleItem.os = `${singleItem.os}@${event?.artifacts?.osVersion}`;
            }
          }

          if (event?.artifacts?.baseImage && event.containerScanType === ContainerSecurityType.baseOnly) {
            {
              singleItem.baseImage = `${event?.artifacts?.baseImage}`;
              if (event?.artifacts?.baseImageOsVersion) {
                singleItem.baseImage = `${event?.artifacts?.baseImage}@${event?.artifacts?.baseImageOsVersion}`;
              }
            }
          }

          singleItem.image = event.artifacts.dockerFileInRunTime;
          singleItem.imageLink = event.artifacts.linkToRegistry || "";
          singleItem.registryName = event.artifacts.registryName || "";
          singleItem.tag = event?.artifacts?.tag || "";
          singleItem.layer = event?.LayerId || "";

          //Set for exclusion
          singleItem.realMatch = singleItem.image;
        }

        singleItem.dependencyType = event.blame.dependencyType;
        singleItem.dependencyChain = event?.blame?.dependencyChain;
        if (!singleItem.realMatch) {
          logger.error(`failed add ${event.securityProvider} for repo: ${repo.name}, no match, policy: ${this.policyRuleMetadata.name}`);
          continue;
        }

        singleItem.issueOwner = event.issueOwner;
        singleItem.setAggId();

        let unique = getUniqueInfoForAggregation(event);

        if (aggregatedItems.hasOwnProperty(unique)) {
          let info = aggregatedItems[unique];
          info.aggregated.push(singleItem);
          if (event.fileName) {
            info.uniqueFiles.add(event.fileName);
          }
        } else {
          const info = {
            aggregated: [],
            uniqueFiles: new Set(),
          };
          if (event.fileName) {
            info.uniqueFiles.add(event.fileName);
          }
          info.aggregated.push(singleItem);
          aggregatedItems[unique] = info;
        }
      } catch (err) {
        logger.info(`failed to add single agg item: ${this.policyRuleMetadata.name}, err: ${err}`);
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
      if (issueOwners.length === 0) {
        for (const singleItem of aggregatedItems) {
          if (singleItem.issueOwner) {
            issueOwners.push({
              name: singleItem.issueOwner,
              email: "",
            });
            break;
          }
        }
      }
      return issueOwners;
    } catch (e) {
      logger.error(`failed to get issue owners, error; ${e}`);
    }
    return [];
  }
}

export default PolicySecurityScanSCA;
