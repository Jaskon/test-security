import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import fs from "fs";
import { join } from "path";
import { ArtifactoryResourceToRun, ComplianceJson, ContainerSecurityType, Sbom, SbomEvent } from "../../../entitis/artifactoryTypes";
import { ArtifactorySecEventType, guessArtifactSystem } from "../../../entitis/ArtifactTypes";
import { addSeverityChangedReason, AlertSeverity, CweObject, SecurityAlertType, SecurityEvent } from "../../../entitis/codeRepoTypes";
import { Token } from "../../../entitis/collectorEntitisTypes";
import { severityReasons } from "../../../entitis/service/blameTypes";
import { ToolConfig } from "../../../entitis/tool/secuirtyToolsConfig";
import { copyToolInfo, getPkgManagerPretty } from "../../../helper/commonUtils";
import jsonParser from "../../../helper/jsonParser";
import Iqueue from "../../../helper/queue/Iqueue";
import { extractPkgManagerFromPurl } from "../../../helper/sbom/sbomHelper";
import { ToolsExecutionStats } from "../../../helper/toolExecutionStats";
import loggerImport from "../../../logger";
import OrgPolicyParser from "../../../policy/org/ruleConfigParser";
import ArtifactorySecurityTool from "../artifactorySecurityTools";
import spdx = require("spdx-correct");

const logger = loggerImport.getDebugLogger();

class TrivyContainers extends ArtifactorySecurityTool {
  constructor(uuid: string, orgPolicyParser: OrgPolicyParser, toolConfig: ToolConfig, queue: Iqueue, orgName: string, token: Token) {
    super(uuid, orgPolicyParser, toolConfig, queue, orgName, token);
  }

  async createSbomEvents(resource: ArtifactoryResourceToRun): Promise<SbomEvent> {
    let pathToSBOM = `${resource.dirWhereToPutRes}/trivySbom.json`;

    if (process.env.LOCAL_SBOM) {
      pathToSBOM = join(
        __dirname,
        "/Users/eyal/Downloads/2023-05-14T18_14_49.990Z/ox-security/telemetry-2e9717b1-1373-4dde-967f-2021bd4a39e4/security-report/scala-steward/Trivy/trivySbom.json",
        // "../../../appmgr/__mocks__/TrivySbom/compliance.json"
      );
    }
    let rawdata = "";

    try {
      if (!fs.existsSync(pathToSBOM)) {
        logger.warn(`${this.toolConfig.name} path: ${pathToSBOM} does not exist, docker name: ${resource.imageDetail.name}`);
        return null;
      }
      copyToolInfo(resource.imageDetail.name, pathToSBOM, "trivySBOM", this.uuid);

      rawdata = fs.readFileSync(pathToSBOM, "utf-8");
      if (!rawdata) {
        return null;
      }

      const trivySBOM = JSON.parse(rawdata) as Sbom;

      // filter out cjs items
      trivySBOM.components = trivySBOM.components.filter(
        comp => !comp["bom-ref"].startsWith("pkg:npm/") || !comp["bom-ref"].includes("-cjs@"),
      );

      trivySBOM.components.forEach(component => {
        // Fix for trivy Java/Javascript names split without group
        if (component.group) {
          const separator = component["bom-ref"].startsWith("pkg:npm/") ? "/" : ":";
          component.name = `${component.group}${separator}${component.name}`;
        }
        // Fix for trivy changing license structure
        component.licenses = (component.licenses || []).map(license => {
          const name = license.expression || (license as any).license.name;
          return { expression: spdx(name) || name };
        });
      });

      const sbomEvent = new SbomEvent(trivySBOM, "trivy");
      logger.info(
        `${this.toolConfig.name}, SBOM alerts after filter ${sbomEvent.sbomHelper.extendedSbom.components.length} path ${pathToSBOM}`,
      );

      ToolsExecutionStats.addExecutionStateOfAlertsNumber(
        this.requestId,
        resource.imageDetail.name,
        resource.imageDetail?.imageId,
        "artifact",
        this.toolConfig.name,
        pathToSBOM,
        sbomEvent.sbomHelper.extendedSbom.components.length,
        sbomEvent.sbomHelper.extendedSbom.components.length,
      );

      return sbomEvent;
    } catch (err) {
      logger.error(
        `failed to parse results for tool ${this.toolConfig.name} for image: ${resource.imageDetail.name}, err: ${err}, rawdata: ${rawdata}`,
      );
      return null;
    }
  }

  async createSecurityEvents(resource: ArtifactoryResourceToRun) {
    let path = `${resource.dirWhereToPutRes}/${this.toolConfig.fileNameOutput}`;
    let pathToSBOM = `${resource.dirWhereToPutRes}/trivySbom.json`;

    if (process.env.LOCAL_SBOM) {
      pathToSBOM = join(
        __dirname,
        //"/Users/eyal/Downloads/2023-05-14T18_14_49.990Z/ox-security/telemetry-2e9717b1-1373-4dde-967f-2021bd4a39e4/security-report/scala-steward/Trivy/trivySbom.json",
        "../../../appmgr/__mocks__/TrivySbom/trivySbom.json",
      );
    }
    let totalVulsFromTool = 0;

    // if (process.env.DEBUG != undefined) {
    //   path = join(__dirname, "../../../appmgr/__mocks__/TrivySbom/trivyVuln.json");
    // }

    //For Debug
    const libNameVerForLogs = {};
    let possibleOsCount = 0;
    let baseImageCount = 0;
    let layerOneOnly = 0;

    try {
      const securityEventList: SecurityEvent[] = [];

      if (!fs.existsSync(path)) {
        logger.warn(`${this.toolConfig.name} path: ${path} not exist, imageName: ${resource.imageDetail.name}`);
        return [];
      }

      if (!fs.existsSync(pathToSBOM)) {
        logger.warn(`${this.toolConfig.name} path: ${pathToSBOM} does not exist, docker name: ${resource.imageDetail.name}`);
        return [];
      }
      copyToolInfo(resource.imageDetail.name, path, "trivySCA", this.uuid);
      const rawdata = fs.readFileSync(path, "utf-8");
      if (!rawdata) {
        logger.warn(`${this.toolConfig.name} path: ${path} is empty, imageName: ${resource.imageDetail.name}`);
        return [];
      }

      const sbomRawdata = fs.readFileSync(pathToSBOM, "utf-8");
      if (!sbomRawdata) {
        return [];
      }

      resource.scannedImage = true;

      const trivySBOM = JSON.parse(sbomRawdata) as Sbom;

      let trivyInfoJs: any = JSON.parse(rawdata.substr(rawdata.indexOf("{")));

      //OS data
      let osName = "";
      let baseVersion = "";
      let osVersion = "";
      if (trivyInfoJs?.Metadata?.OS) {
        osName = trivyInfoJs?.Metadata?.OS.Family;
        osVersion = trivyInfoJs?.Metadata?.OS.Name;
        resource.imageDetail.os = osName;
        resource.imageDetail.osVersion = osVersion;
      }

      let layers: string[] = [];
      if (trivyInfoJs?.Metadata?.DiffIDs) {
        layers = trivyInfoJs?.Metadata?.DiffIDs;
      }

      const layerToDockerInstructions = {};
      try {
        if (trivyInfoJs?.Metadata?.ImageConfig?.history) {
          const dockerInstructions = trivyInfoJs?.Metadata?.ImageConfig?.history;
          const onlyFullInstructions = dockerInstructions.filter(i => !i.empty_layer);
          if (layers.length !== onlyFullInstructions.length) {
            logger.error(
              `${this.toolConfig.name} layers size: ${layers.length} and onlyFullInstructions: ${onlyFullInstructions.length} are not the same, imageName: ${resource.imageDetail.name}`,
            );
          } else {
            let i = 0;
            layers.forEach(layer => {
              layerToDockerInstructions[layer] = onlyFullInstructions[i];
              i++;
            });
          }
        }
      } catch (err) {
        logger.error(
          `failed set layerToDockerInstructions for: ${this.toolConfig.name} in image: ${resource.imageDetail.name}, err: ${err}`,
        );
      }

      if (!trivyInfoJs?.Results?.length) {
        logger.warn(`${this.toolConfig.name} res are empty`);
        return [];
      }

      let cannotFindUserIns = 0;

      for (const trivyRes of trivyInfoJs.Results) {
        if (!trivyRes?.Vulnerabilities?.length) {
          continue;
        }

        const fileName = trivyRes.Target;
        let baseImage = "";
        let baseImageSha = "";

        for (const trivyVulnerability of trivyRes.Vulnerabilities) {
          try {
            const oxwrapper = trivyVulnerability?.oxwrapper;
            let pkgName = trivyVulnerability.PkgName;
            totalVulsFromTool++;

            let snippet = "";
            let recommendation = `The currently used vulnerable version of ${pkgName} is ${trivyVulnerability.InstalledVersion}. To remediate the vulnerability, you should upgrade ${pkgName} to version ${trivyVulnerability.FixedVersion} or later.`;
            if (trivyVulnerability.FixedVersion === undefined) {
              recommendation = `The currently used vulnerable version of ${pkgName} is ${trivyVulnerability.InstalledVersion}. Currently, no fixed version is available. You should reconsider the usage of this library, or sanitize your code surrounding library usage to reduce the risk.`;
            }

            const moreInfoLink = this.getAdditionalInfoUrlForTrivy(trivyVulnerability);

            const securityEvent = new SecurityEvent(
              SourceToolType["Container Security"],
              true,
              trivyVulnerability.PrimaryURL,
              new Date().toLocaleString(),
              "",
              "",
              "",
              trivyVulnerability.VulnerabilityID + " - " + trivyVulnerability.Title,
              trivyVulnerability.Description,
              fileName,
              trivyVulnerability.Severity,
              `Rule name: ${trivyVulnerability.VulnerabilityID}, Link for more info: ${moreInfoLink}`,
              -1,
              AlertSeverity[AlertSeverity.High],
              SecurityAlertType.container,
              recommendation,
              trivyVulnerability.PkgID,
              snippet,
              -1,
              true,
              false,
              "",
              "",
              "",
              "",
              trivyVulnerability.VulnerabilityID,
              moreInfoLink,
              "",
              "",
              "",
              "",
              "trivy",
            );

            try {
              if (oxwrapper?.severityFactors) {
                oxwrapper.severityFactors.forEach((sfKey: string) => {
                  if (severityReasons.hasOwnProperty(sfKey)) {
                    addSeverityChangedReason(severityReasons[sfKey], securityEvent, undefined, []);
                  }
                });
              }
            } catch (err) {
              logger.error(`trivyContainer, failed addSeverityChangedReason, err: ${err}`);
            }

            const purl = trivySBOM.components.find(
              c => c.name === trivyVulnerability.PkgName && c.version === trivyVulnerability.InstalledVersion,
            )?.purl;
            securityEvent.pkgManager = purl ? extractPkgManagerFromPurl(purl) : trivyRes.Type;
            if (trivyVulnerability.PkgName.includes(":")) {
              securityEvent.groupId = trivyVulnerability.PkgName.split(":")[0];
            }
            if (trivyVulnerability?.CweIDs) {
              if (Array.isArray(trivyVulnerability.CweIDs)) {
                securityEvent.blame.cwe = trivyVulnerability.CweIDs;
              }
            }

            securityEvent.lockfile = securityEvent.filePath;
            securityEvent.blame.cve = trivyVulnerability.VulnerabilityID;
            if (securityEvent.blame.cve) {
              securityEvent.cves.push(securityEvent.blame.cve);
            }
            securityEvent.pkgName = pkgName;
            securityEvent.fixedVersion = trivyVulnerability.FixedVersion;
            securityEvent.securitySubTypeAlertType = SecurityAlertType.sca;

            if (trivyVulnerability.CweIDs) {
              if (trivyVulnerability.CweIDs.length > 0) {
                securityEvent.blame.cwe.push(trivyVulnerability.CweIDs[0]);
                const cweObject = new CweObject();
                cweObject.name = trivyVulnerability.CweIDs[0];
                securityEvent.blame.cweList.push(cweObject);
              }
            }
            if (trivyVulnerability.CVSS) {
              if (Object.values(trivyVulnerability.CVSS).length > 0) {
                const item = Object.values(trivyVulnerability.CVSS)[0] as any;
                if (item.V3Score) {
                  securityEvent.blame.cvssScore = item.V3Score;
                }
              }
            }
            securityEvent.blame.cveDescription = trivyVulnerability.Description;
            securityEvent.installedVersion = trivyVulnerability.InstalledVersion;
            securityEvent.realMatch = trivyVulnerability.PkgID;
            if (!securityEvent.realMatch) {
              securityEvent.realMatch = `${securityEvent.pkgName}@${securityEvent.installedVersion}`;
              securityEvent.lineContent = `${securityEvent.pkgName}@${securityEvent.installedVersion}`;
            }

            securityEvent.setLayeridIssue(trivyVulnerability?.Layer?.DiffID, layers);
            securityEvent.setIsOsTypeLib(trivyRes.Class);

            //Set image id on security event
            securityEvent.imageId = resource.imageDetail.imageId;

            if (trivyVulnerability?.Layer?.DiffID) {
              const layerInfo = layerToDockerInstructions[trivyVulnerability?.Layer?.DiffID];
              if (layerInfo) {
                securityEvent.dockerInstructions = layerInfo.created_by;
                securityEvent.dockerInstructionsCreation = layerInfo.created;
              } else {
                logger.error(
                  `checkType: ${this.toolConfig.name}, failed find layer id for path: ${path}, imageName: ${resource.imageDetail.name}`,
                );
              }
            } else {
              cannotFindUserIns++;
            }

            const layerId = trivyVulnerability?.Layer?.DiffID;
            if (!layerId) {
              logger.error(
                `layerId is empty for ${securityEvent.pkgName}@${securityEvent.installedVersion}, tool: ${this.toolConfig.name}, path: ${path}, imageName: ${resource.imageDetail.name}`,
              );
            }

            //Flow in case we have base image info
            if (layerId && resource.imageDetail.baseImage) {
              baseImage = resource.imageDetail.baseImage.repo;
              baseImageSha = resource.imageDetail.baseImage.digest;
              baseVersion = resource.imageDetail.baseImage.tag;
              if (resource.imageDetail.baseImage.layers.has(layerId)) {
                securityEvent.containerScanType = ContainerSecurityType.baseOnly;
              } else {
                //Base image available and we didnt found the lib inside it and its an os lib
                if (securityEvent.isOsLib) {
                  securityEvent.containerScanType = ContainerSecurityType.instructionsOnly;
                }
                //Base image available and we didnt found the lib inside it and its NOT os lib
                else {
                  securityEvent.containerScanType = ContainerSecurityType.appOnly;
                }
              }
            }
            //Second flow when we dont have the base image
            else {
              if (securityEvent.isOsLib) {
                securityEvent.containerScanType = ContainerSecurityType.possibleOsOnly;
              } else {
                securityEvent.containerScanType = ContainerSecurityType.appOnly;
              }
            }

            //Stats
            if (securityEvent.containerScanType === ContainerSecurityType.appOnly) {
              addSeverityChangedReason(severityReasons.appContainerVull, securityEvent, undefined);
              let len = trivyRes.Target;
              if (!len.includes("/")) {
                securityEvent.language = getPkgManagerPretty(trivyRes.Target);
              }
              //For logs set type as key as we may have a lot of libs so use only type
              if (libNameVerForLogs[ContainerSecurityType.appOnly]) {
                libNameVerForLogs[ContainerSecurityType.appOnly] = libNameVerForLogs[ContainerSecurityType.appOnly] + 1;
              } else {
                libNameVerForLogs[ContainerSecurityType.appOnly] = 1;
              }
            }
            if (securityEvent.containerScanType === ContainerSecurityType.baseOnly) {
              addSeverityChangedReason(severityReasons.baseContainerVull, securityEvent, undefined);
              //For logs set as base image name and version as key
              baseImageCount++;
              const key = `${baseImage}@${baseVersion}`;
              const item = libNameVerForLogs[key];
              if (item) {
                item.baseOnly = item.baseOnly + 1;
              } else {
                libNameVerForLogs[key] = {
                  possibleOsOnly: 0,
                  baseOnly: 1,
                };
              }
            }
            if (securityEvent.containerScanType === ContainerSecurityType.possibleOsOnly) {
              addSeverityChangedReason(severityReasons.osVull, securityEvent, undefined);
              baseImage = trivyRes.Target;
              baseImageSha = securityEvent.LayerId;
              possibleOsCount++;
              //For logs set as osName and version as key
              const key = `${osName}@${osVersion}`;
              const item = libNameVerForLogs[key];
              if (item) {
                item.possibleOsOnly = item.possibleOsOnly + 1;
              } else {
                libNameVerForLogs[key] = {
                  possibleOsOnly: 1,
                  baseOnly: 0,
                };
              }
            }
            if (securityEvent.containerScanType === ContainerSecurityType.instructionsOnly) {
              addSeverityChangedReason(severityReasons.userInstructionsContainerVull, securityEvent, undefined);
              //For logs set type as key as we may have a lot of libs so use only type
              if (libNameVerForLogs[ContainerSecurityType.instructionsOnly]) {
                libNameVerForLogs[ContainerSecurityType.instructionsOnly] = libNameVerForLogs[ContainerSecurityType.instructionsOnly] + 1;
              } else {
                libNameVerForLogs[ContainerSecurityType.instructionsOnly] = 1;
              }
            }

            if (securityEvent.LayerOrder == 1) {
              layerOneOnly++;
            }

            const artifacts = {
              system: guessArtifactSystem(resource.imageDetail.name),
              subType: ArtifactorySecEventType.Docker,
              repoFullName: resource.imageDetail.repositoryName,
              imageCreatedAt: resource.imageDetail.imagePushedAt,
              dockerVer: trivyInfoJs.Metadata.ImageConfig.docker_version,
              hasPackageManager: false,
              os: osName,
              osVersion: osVersion,
              sha: resource.imageDetail.imageDigestWithoutPrefix,
              binariesCount: 0,
              pkgCount: 0,
              dockerFileInRunTime: resource.imageDetail.name,
              registry: resource.imageDetail.location,
              tag: resource.imageDetail.imageTags.join(", "),
              linkToRegistry: resource.imageDetail.link,
              linkToTask: "",
              baseImage: baseImage,
              baseImageSha: baseImageSha,
              baseImageRegistry: resource.imageDetail.location,
              baseImageOsVersion: baseVersion,
              baseImageTags: resource.imageDetail.baseImage?.tags,
              registryName: resource.imageDetail.cloudEnv,
            };
            securityEvent.artifacts = artifacts;
            securityEvent.artifactFilePath = trivyVulnerability.PkgPath;

            securityEventList.push(securityEvent);
          } catch (err) {
            logger.error(
              `checkType: ${this.toolConfig.name}, failed add trivy for path: ${path}, imageName: ${resource.imageDetail.name}, err: ${err}`,
            );
          }
        }
      }

      ToolsExecutionStats.addExecutionStateOfAlertsNumber(
        this.requestId,
        resource.imageDetail.repositoryName,
        resource.imageDetail.imageId,
        "artifact",
        this.toolConfig.name,
        pathToSBOM,
        totalVulsFromTool,
        securityEventList.length,
      );

      logger.info(
        `${this.toolConfig.name} Info after filter ${securityEventList.length}, layerOneOnlyCount: ${layerOneOnly}, imageName: ${
          resource.imageDetail.name
        }, image split info: ${JSON.stringify(libNameVerForLogs)} cannotFindUserIns: ${cannotFindUserIns}, path: ${path}`,
      );

      return securityEventList;
    } catch (err) {
      logger.error(
        `failed to parse results for tool ${this.toolConfig.name} for path: ${path}, imageName: ${resource.imageDetail.name}, err: ${err}`,
      );
      return [];
    }
  }

  async createComplianceAlerts(resource: ArtifactoryResourceToRun): Promise<SecurityEvent[]> {
    let pathToCompliance;
    try {
      pathToCompliance = `${resource.dirWhereToPutRes}/compliance.json`;
      if (process.env.DEBUG != undefined) {
        pathToCompliance = join(__dirname, "../../../appmgr/__mocks__/TrivySbom/compliance.json");
      } else {
        pathToCompliance = `${resource.dirWhereToPutRes}/compliance.json`;
      }

      let rawdata = "";
      if (!fs.existsSync(pathToCompliance)) {
        logger.warn(`${this.toolConfig.name} path: ${pathToCompliance} does not exist, image: ${resource?.imageDetail?.name}`);
        return [];
      }

      rawdata = fs.readFileSync(pathToCompliance, "utf-8");
      if (!rawdata) {
        return [];
      }

      let totalVulsFromTool = 0;

      const jsonCompliance = JSON.parse(rawdata) as ComplianceJson;
      let pathForJsonIssues = join(__dirname, "../../config/TrivyComplianceIssues.json");
      jsonParser.getInstance().doParse(pathForJsonIssues, "trivy");

      if (!jsonCompliance.Results) {
        return [];
      }

      let secAlert: SecurityEvent[] = [];
      for (const complianceVoliation of jsonCompliance.Results) {
        if (!complianceVoliation.Misconfigurations) {
          continue;
        }

        for (const misconfigs of complianceVoliation.Misconfigurations) {
          try {
            const manaulConfig = jsonParser.getInstance().getIdObject(misconfigs.AVDID, "trivy");
            totalVulsFromTool++;
            if (manaulConfig?.Skip) {
              logger.info(`Confgirued to skip ${manaulConfig.id}`);
              continue;
            }

            const fileName = complianceVoliation.Target.substring(complianceVoliation.Target.lastIndexOf("/") + 1);
            const lineNumber = misconfigs.CauseMetadata.StartLine === undefined ? -1 : misconfigs.CauseMetadata.StartLine;

            let securityEvent = new SecurityEvent(
              SourceToolType["Container Security"],
              true,
              misconfigs.PrimaryURL,
              new Date().toLocaleString(),
              "",
              "",
              "",
              manaulConfig !== undefined && manaulConfig.summaryTitle ? manaulConfig.summaryTitle : misconfigs.Title,
              manaulConfig !== undefined && manaulConfig["How to fix"] ? manaulConfig["How to fix"] : misconfigs.Message,
              fileName,
              manaulConfig !== undefined && manaulConfig.severity ? manaulConfig.severity : misconfigs.Severity,
              manaulConfig !== undefined && manaulConfig["Why does it matter?"]
                ? manaulConfig["Why does it matter?"]
                : misconfigs.Description,
              lineNumber,
              AlertSeverity[AlertSeverity.High],
              SecurityAlertType.container,
              manaulConfig !== undefined && manaulConfig["How to fix"] ? manaulConfig["How to fix"] : misconfigs.Message,
              misconfigs.CauseMetadata.Code.Lines !== null ? misconfigs.CauseMetadata.Code.Lines[0].Content : "",
              misconfigs.CauseMetadata.Code.Lines !== null ? misconfigs.CauseMetadata.Code.Lines[0].Content : "",
              misconfigs.CauseMetadata.EndLine === undefined ? 0 : misconfigs.CauseMetadata.EndLine,
              true,
              false,
              "",
              "",
              "",
              "",
              misconfigs.AVDID,
              misconfigs.References[0],
              "",
              "",
              "",
              complianceVoliation.Target.substring(0, complianceVoliation.Target.lastIndexOf("/")),
              "trivy",
            );

            if (manaulConfig !== undefined && manaulConfig["eduVideoLink"]) {
              securityEvent.setEduLink(manaulConfig["eduVideoLink"]);
            }
            securityEvent.realMatch = misconfigs.ID;
            securityEvent.securitySubTypeAlertType = SecurityAlertType.iac;

            const artifacts = {
              system: guessArtifactSystem(resource.imageDetail.name),
              subType: ArtifactorySecEventType.Docker,
              repoFullName: resource.imageDetail.repositoryName,
              imageCreatedAt: resource.imageDetail.imagePushedAt,
              dockerVer: "",
              hasPackageManager: false,
              os: jsonCompliance?.Metadata?.OS?.Name,
              osVersion: jsonCompliance?.Metadata?.OS?.Family,
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

            addSeverityChangedReason(severityReasons.appContainerVull, securityEvent, undefined);

            securityEvent.artifactFilePath = fileName;
            securityEvent.artifactFileLine = lineNumber;
            securityEvent.matchFromArtifact = securityEvent.lineContent ? securityEvent.lineContent : undefined;
            securityEvent.imageId = resource.imageDetail.imageId;

            secAlert.push(securityEvent);
          } catch (err) {
            logger.error(`failed to create compliance sec event ${err}, misconfigs: ${JSON.stringify(misconfigs)}`);
          }
        }
      }

      ToolsExecutionStats.addExecutionStateOfAlertsNumber(
        this.requestId,
        resource.imageDetail.repositoryName,
        resource.imageDetail.imageId,
        "artifact",
        this.toolConfig.name,
        pathToCompliance,
        totalVulsFromTool,
        secAlert.length,
      );

      logger.info(
        `${this.toolConfig.name}, found ${secAlert.length} compliance alerts, image: ${resource?.imageDetail?.name}, path: ${pathToCompliance}`,
      );
      return secAlert;
    } catch (err) {
      logger.error(`failed to run createComplianceAlerts, image: ${resource?.imageDetail?.name}, path: ${pathToCompliance}, err: ${err}`);
    }
    return [];
  }

  getAdditionalInfoUrlForTrivy(trivyVulnerability) {
    try {
      //CVE exist
      const cve = trivyVulnerability?.VulnerabilityID;
      if (cve) {
        if (trivyVulnerability.References) {
          const nvdLink = trivyVulnerability.References.find(url => url.includes("nvd.nist"));
          if (nvdLink != undefined) {
            return nvdLink;
          }
        }
        if (cve.toLowerCase().startsWith("cve")) {
          return `https://nvd.nist.gov/vuln/detail/${cve}`;
        }
        if (cve.toLowerCase().startsWith("ghsa")) {
          return `https://github.com/advisories/${cve}`;
        }
      }

      //CVE not exist
      if (trivyVulnerability.References == undefined) {
        return trivyVulnerability.PrimaryURL;
      }

      const nvdLink = trivyVulnerability.References.find(url => url.includes("nvd.nist"));
      if (nvdLink != undefined) {
        return nvdLink;
      }
      const mitreLink = trivyVulnerability.References.find(url => url.includes("cve.mitre"));
      if (mitreLink != undefined) {
        return mitreLink;
      }
    } catch (err) {
      logger.error(`uuid: ${this.uuid}, failed to get additional info link for trivy, err: ${err}`);
    }
    return trivyVulnerability.PrimaryURL;
  }
}

export default TrivyContainers;
