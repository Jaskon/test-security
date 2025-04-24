import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import { Sbom, SbomEvent } from "../../../entitis/artifactoryTypes";
import { addSeverityChangedReason, AlertSeverity, Repo, repoType, SecurityAlertType, SecurityEvent } from "../../../entitis/codeRepoTypes";
import { Token } from "../../../entitis/collectorEntitisTypes";
import { OXtools } from "../../../entitis/constant";
import { severityReasons } from "../../../entitis/service/blameTypes";
import { ToolConfig } from "../../../entitis/tool/secuirtyToolsConfig";
import { handleFileNameReplace } from "../../../helper/commonUtils";
import Iqueue from "../../../helper/queue/Iqueue";
import { extractPkgManagerFromPurl } from "../../../helper/sbom/sbomHelper";
import StatesHelper from "../../../helper/statesHelper";
import { ToolsExecutionStats } from "../../../helper/toolExecutionStats";
import loggerImport from "../../../logger";
import { CveToolsService } from "../../../mongo/cve-tools.service";
import OrgPolicyParser from "../../../policy/org/ruleConfigParser";
import CodeSecurityTool from "../codeSecurityTools";
import spdx = require("spdx-correct");

const logger = loggerImport.getDebugLogger();

const fs = require("fs");

export class Trivy extends CodeSecurityTool {
  constructor(uuid: string, orgPolicyParser: OrgPolicyParser, toolConfig: ToolConfig, queue: Iqueue, orgName: string, token: Token) {
    super(uuid, orgPolicyParser, toolConfig, queue, orgName, token);
  }

  async createSecurityEvents(repo: Repo) {
    if (process.env["TOOLS_TRIVY-SCA"] !== "enabled") {
      return [];
    }
    try {
      let securityEventList: SecurityEvent[] = [];

      const path = `${repo.securityResDir}/${this.toolConfig.fileNameOutput}`;
      const sbomPath = `${repo.securityResDir}/trivySbom.json`;

      if (!fs.existsSync(path)) {
        logger.warn(`trivy path: ${path} not exist`);
        StatesHelper.Instance.addFailedTool("trivy", repo.id); // roman ?
        return [];
      }
      if (!fs.existsSync(sbomPath)) {
        logger.warn(`${this.toolConfig.name} path: ${sbomPath} not exist, repo: ${repo.fullName}`);
        StatesHelper.Instance.addFailedTool("trivy-sbom", repo.id); // roman ?
        return null;
      }

      this.copyToolResults({ repoName: repo.name, dir: path });

      const rawdata = fs.readFileSync(path, "utf-8");
      if (!rawdata) {
        logger.info(`${this.toolConfig.name} path: ${path} content empty`);
        StatesHelper.Instance.addFailedTool("trivy", repo.id);
        return [];
      }
      const sbomRawdata = fs.readFileSync(sbomPath, "utf-8");
      if (!sbomRawdata) {
        logger.warn(`${this.toolConfig.name} path: ${sbomPath} content empty, repo: ${repo.fullName}`);
        StatesHelper.Instance.addFailedTool("trivy-sbom", repo.id);
        return null;
      }
      const trivySbom = JSON.parse(sbomRawdata) as Sbom;
      let trivyInfoJs = JSON.parse(rawdata.substr(rawdata.indexOf("{")));
      // logger.info(`trivy rawdata json: ${JSON.stringify(trivyInfoJs)}`);
      // const trivyInfoJs = fs.readFileSync("c:\\test\\a.txt", "utf-8");

      if (trivyInfoJs.Results == undefined) {
        // StatesHelper.Instance.addFailedTool("trivy", repo.id); // roman ?
        logger.warn(`trivy Results are empty, repo: ${repo.fullName}, res: ${JSON.stringify(trivyInfoJs)}`);
        return [];
      }

      let totalVulsFromTool = 0;
      for (const trivyRes of trivyInfoJs.Results) {
        if (trivyRes.Vulnerabilities == undefined) {
          // StatesHelper.Instance.addFailedTool("trivy", repo.id); // roman ?
          continue;
        }

        if (trivyRes.Type === "pom") {
          trivyRes.Type = "maven";
        }

        logger.info(`${this.toolConfig.name} Info before filter ${trivyRes.Vulnerabilities.length} repo ${repo.fullName}`);
        this.addGlobalStats(this.toolConfig.defaultType, this.toolConfig.name, trivyRes.Vulnerabilities.length, repo);

        let fileName = trivyRes.Target;

        for (const trivyVulnerability of trivyRes.Vulnerabilities) {
          try {
            const oxwrapper = trivyVulnerability?.oxwrapper;
            totalVulsFromTool++;

            let pkgName = trivyVulnerability.PkgName;

            const startLineNumber = trivyVulnerability?._OX?.startLineNumber ?? -1;
            const endLineNumber = trivyVulnerability?._OX?.endLineNumber ?? -1;

            let lineContent = "";
            let snippet = "";
            let link = null;
            let replaceInfo = repo.getRepoPathForToolCommand();

            fileName = handleFileNameReplace(fileName, replaceInfo);

            if (startLineNumber > 0) {
              if (repo.type === repoType.awsCodeCommit) {
                link = repo.fileLink + fileName + repo.linkFilePreffix + startLineNumber + "-" + startLineNumber;
              } else {
                link = repo.fileLink + fileName + repo.linkFilePreffix + startLineNumber;
              }
            } else {
              link = repo.fileLink + fileName + repo.linkFilePreffix;
            }

            let recommendation = `The currently used vulnerable version of ${pkgName} is ${trivyVulnerability.InstalledVersion}. To remediate the vulnerability, you should upgrade ${pkgName} to version ${trivyVulnerability.FixedVersion} or later.`;
            if (trivyVulnerability.FixedVersion === undefined) {
              recommendation = `The currently used vulnerable version of ${pkgName} is ${trivyVulnerability.InstalledVersion}. Currently, no fixed version is available. You should reconsider the usage of this library, or sanitize your code surrounding library usage to reduce the risk.`;
            }

            const moreInfoLink = this.getAdditionalInfoUrlForTrivy(trivyVulnerability);

            let securityEvent = new SecurityEvent(
              SourceToolType["Open Source Security"],
              true,
              link,
              new Date().toLocaleString(),
              "",
              "",
              "",
              trivyVulnerability.VulnerabilityID + " - " + trivyVulnerability.Title,
              trivyVulnerability.Description,
              fileName,
              trivyVulnerability.Severity,
              `Rule name: ${trivyVulnerability.VulnerabilityID}, Link for more info: ${moreInfoLink}`,
              startLineNumber,
              AlertSeverity[AlertSeverity.High],
              SecurityAlertType.sca,
              recommendation,
              lineContent,
              snippet,
              endLineNumber,
              true,
              false,
              "",
              "",
              "",
              "",
              trivyVulnerability.VulnerabilityID,
              moreInfoLink,
              repo.parentRepoOfMonoRepo == null ? repo.cloneDir : repo.parentRepoOfMonoRepo.cloneDir,
              repo.fullName,
              repo.insideFolder,
              repo.monoRepoChild ? repo.name.substring(1) + "/" + fileName : fileName,
              OXtools.trivyCode,
            );

            try {
              if (oxwrapper?.severityFactors) {
                oxwrapper.severityFactors.forEach((sfKey: string) => {
                  if (severityReasons.hasOwnProperty(sfKey)) {
                    addSeverityChangedReason(severityReasons[sfKey], securityEvent, repo, []);
                  }
                });
              }
            } catch (err) {
              logger.error(`trivy, failed addSeverityChangedReason: ${repo.name}, err: ${err}`);
            }

            securityEvent.version = repo.defaultBranch;
            securityEvent.privateVisability = repo.privateVisability;
            securityEvent.lineContent = securityEvent.lineContent.trim().replace(/\s+/g, " ");
            const purl = trivySbom?.components?.find(
              c => c.name === trivyVulnerability.PkgName && c.version === trivyVulnerability.InstalledVersion,
            )?.purl;
            securityEvent.pkgManager = purl ? extractPkgManagerFromPurl(purl) : trivyRes.Type;
            if (trivyVulnerability.PkgName.includes(":")) {
              securityEvent.groupId = trivyVulnerability.PkgName.split(":")[0];
            }

            if (trivyVulnerability?.CweIDs) {
              if (Array.isArray(trivyVulnerability.CweIDs)) {
                securityEvent.cweList = trivyVulnerability.CweIDs ?? [];
              } else if (typeof trivyVulnerability.CweIDs === "string") {
                securityEvent.cweList = [trivyVulnerability.CweIDs];
              }
            }

            if (securityEvent.filePath.endsWith("go.mod")) {
              securityEvent.lockfile = securityEvent.filePath.replace("go.mod", "go.sum");
            } else {
              securityEvent.lockfile = securityEvent.filePath;
            }

            securityEvent.blame.cve = trivyVulnerability.VulnerabilityID;
            if (securityEvent.blame.cve) {
              securityEvent.cves.push(securityEvent.blame.cve);
            }
            securityEvent.pkgName = pkgName;
            securityEvent.fixedVersion = trivyVulnerability.FixedVersion;
            securityEvent.installedVersion = trivyVulnerability.InstalledVersion;
            securityEvent.realMatch = `${trivyVulnerability.PkgName}@${trivyVulnerability.InstalledVersion}`;
            securityEvent.originalFilName = fileName;

            if (securityEvent.installedVersion.startsWith("*")) {
              logger.error(
                `failed add ${this.toolConfig.name} for repo: ${repo.name}, installedVersion: ${securityEvent.installedVersion} include incorrect char`,
              );
            }

            if (!securityEvent.realMatch) {
              logger.error(`failed add ${this.toolConfig.name} for repo: ${repo.name}, no match`);
              continue;
            }

            securityEventList.push(securityEvent);
          } catch (err) {
            logger.error(`checkType: trivy, failed add trivy for repo: ${repo.name}, err: ${err}`);
            // StatesHelper.Instance.addFailedTool("trivy", repo.id);
          }
        }
      }

      ToolsExecutionStats.addExecutionStateOfAlertsNumber(
        this.requestId,
        repo.fullName,
        repo.id,
        "repo",
        this.toolConfig.name,
        sbomPath,
        totalVulsFromTool,
        securityEventList.length,
      );

      logger.info(`${this.toolConfig.name} Info after filter ${securityEventList.length} repo: ${repo.name}`);

      if (securityEventList.length > 15000) {
        logger.info(`${this.toolConfig.name} losing alerts due to cap, original count: ${securityEventList.length}`);
        securityEventList = securityEventList.slice(0, 15000);
      }

      this.printStatsForSecEvents(securityEventList, repo);
      securityEventList.forEach(secEvent => CveToolsService.instance.addToCveTools(secEvent.repoFullName, secEvent));

      return securityEventList;
    } catch (err) {
      logger.error(`failed to parse results for tool trivy for repo: ${repo.name}, err: ${err}`);
      StatesHelper.Instance.addFailedTool("trivy", repo.id);
      return [];
    }
  }

  async createSbomEvents(repo: Repo): Promise<SbomEvent | null> {
    if (process.env["TOOLS_TRIVY-SBOM"] !== "enabled") {
      return null;
    }
    let rawdata = "";

    try {
      let path = `${repo.securityResDir}/trivySbom.json`;
      if (process.env.LOCAL_SBOM) {
        // path = "./src/appmgr/__mocks__/repoSbom/sbom.json";
        path =
          "/Users/eyal/Downloads/2023-05-14T18_14_49.990Z/ox-security/telemetry-2e9717b1-1373-4dde-967f-2021bd4a39e4/security-report/scala-steward/Trivy/trivySbom.json";
      }

      if (!fs.existsSync(path)) {
        logger.warn(`${this.toolConfig.name} sbom path: ${path} not exist, repo: ${repo.fullName}`);
        StatesHelper.Instance.addFailedTool("trivy-sbom", repo.id); // roman ?
        return null;
      }

      rawdata = fs.readFileSync(path, "utf-8");
      if (!rawdata) {
        StatesHelper.Instance.addFailedTool("trivy-sbom", repo.id); // roman ?
        logger.warn(`${this.toolConfig.name} sbom path: ${path} content empty, repo: ${repo.fullName}`);
        return null;
      }
      this.copyToolResults({ repoName: repo.name, dir: path });

      const report = JSON.parse(rawdata) as Sbom;

      if (report.components == null) {
        StatesHelper.Instance.addFailedTool("trivy", repo.id); // roman ?
        logger.warn(`${this.toolConfig.name} sbom components empty, repo: ${repo.fullName}`);
        return null;
      }

      // filter out OX gen pom item
      report.components = report.components.filter(
        comp =>
          // (comp.type === SbomComponentType.Library || comp.type == SbomComponentType.Os) &&
          comp.name !== "org.oxsecurity:oxsecurity",
      );
      // filter out cjs items
      report.components = report.components.filter(comp => !comp["bom-ref"].startsWith("pkg:npm/") || !comp["bom-ref"].includes("-cjs@"));

      report.components.forEach(component => {
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

      const sbomEvent = new SbomEvent(report, "trivy");
      logger.info(
        `${this.toolConfig.name} sbom Info before filter ${sbomEvent.sbomHelper.extendedSbom.components.length} repo ${repo.fullName}`,
      );

      return sbomEvent;
    } catch (err) {
      logger.error(`failed to parse results for ${this.toolConfig.name} sbom for repo: ${repo.name}, err: ${err}, rawdata: ${rawdata}`);
      StatesHelper.Instance.addFailedTool("trivy", repo.id); // roman
    }
    return null;
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
