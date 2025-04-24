import memoryDB from "@oxappsec/ox-memory-db";
import axios from "axios";
import { parse, stringify } from "flatted";
import { ApplicationManager } from "../../appmgr/AppManager";
import { ArtifactorySecEventSystem, ArtifactorySecEventType, guessArtifactSystem } from "../../entitis/ArtifactTypes";
import { ContainerSecurityType } from "../../entitis/artifactoryTypes";
import { SecurityAlertType, SecurityEvent, addSeverityChangedReason } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { severityReasons } from "../../entitis/service/blameTypes";
import { flatNestedJson, getPkgManagerPretty, sleep } from "../../helper/commonUtils";
import { replaceAll } from "../../helper/generalUtils";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ArtifactoryBase from "../base/artifactoryBase";
import { isDevelopment, isLocalDevelopment } from "../../helper/envUtils";
import StatesHelper from "../../helper/statesHelper";
import PromisePool from "@supercharge/promise-pool";
import { Tool } from "../../policy/rules/code/policyRulesBase";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import { S3Service } from "../../helper/aws/s3Service";

const logger = loggerImport.getDebugLogger();

const THREE_MONTH_DAYS = 90;

let olderThan3MonthAlertsCount = 0;

export class PrismaStaticHelper {
  private static _instance: PrismaStaticHelper;
  public static get Instance() {
    return this._instance || (this._instance = new this());
  }
}

class Prisma extends ExternalSecurityProviderBase {
  host: string;
  private_token: string;
  appMgr: ApplicationManager;
  api: any;
  name: string;
  internalToken: any;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.host = token.host;
    this.private_token = token.password;
    this.appMgr = new ApplicationManager(this.uuid);
  }

  async initLib() {
    this.internalToken = null;

    const url = this.token.host;
    const username = this.token.userName;
    const password = this.token.password;

    const request = {
      username: username,
      password: password,
    };

    const authUrl = `${url}/api/v1/authenticate`;

    const requestAxios = (await axios.post(authUrl, request, {
      headers: {
        ContentType: `application/json`,
      },
    })) as any;

    if (requestAxios.status != 200) {
      StatesHelper.Instance.globalApisFails.add("prisma-artifacts");
      const err = `${this.token.name} failed invoke post request to prisma to get token, response http err: ${requestAxios.status}`;
      logger.error(err);
    }

    this.internalToken = requestAxios.data.token;
  }

  readCSVFile(file: string) {
    const lines = file.split("\r\n");
    // const lines = file.split("\r\n").slice(0, 10); for debug

    let isTitles = true;
    let titles;
    const events = [];

    for (const line of lines) {
      if (isTitles) {
        titles = line.split(",");
        isTitles = false;
        continue;
      }
      const event = {};
      const values = line.split(",");
      titles.forEach((title, index) => {
        event[title] = values[index];
      });
      events.push(event);
    }
    return events;
  }

  isOlderThan3Month(scanTime: string) {
    const shouldRun = StatesHelper.Instance.orgName === "org_f0AdAbSkUFpaznEc";
    if (!shouldRun) {
      return false;
    }
    const nowDate = new Date();
    const scanTimeDate = new Date(scanTime);

    let dif = nowDate.getTime() - scanTimeDate.getTime();
    let daysDiff = Math.round(dif / (1000 * 3600 * 24));
    return daysDiff > THREE_MONTH_DAYS;
  }

  async getEventsFromS3() {
    try {
      const orgId = "orgId";
      const fileName = "fileNmae";
      const { rawContent, lastModified } = await S3Service.getFileAndLastModified(
        S3Service.getClient({ region: process.env.INTERCEPT_CONFIG_AWS_REGION || "eu-west-1" }),
        {
          Bucket: process.env.INTERCEPT_CONFIG_BUCKET || "ox-download-bucket-test-k8s",
          Key: `OutputFiles/org_US3qDZlQqt1VzoxB/prisma.csv`,
        },
      );

      const events = this.readCSVFile(rawContent);
    } catch (err) {
      logger.error(`getEventsFromS3: failed get prisma events from s3, err: ${err}`);
    }
  }

  async securityEvents() {
    try {
      //API - https://pan.dev/prisma-cloud/api/cwpp/get-containers/

      // //Retrieves registry image scan reports.
      //const registry = await this.getSecurityEventsFromApi("registry");

      // //This endpoint maps to the Running hosts table in Monitor > Vulnerabilities > Hosts > Running hosts in the Console UI.
      // const hosts = await (
      //   await this.getSecurityEventsFromApi("hosts")
      // ).filter(i => i.hostname.includes("debian") && i.cloudMetadata.accountID === "Non-onboarded cloud accounts");

      if (StatesHelper.Instance.isRepsol || StatesHelper.Instance.orgName === "org_US3qDZlQqt1VzoxB") {
        const res = await this.getEventsFromS3();
        return res;
      }

      const hosts = await this.doApi("hosts");
      const hostScans = this.fromPrismaArtifactsToOxScanResultsForHost(hosts);

      // //This endpoint maps to the table in Monitor > Vulnerabilities > Hosts > VM images in the Prisma Cloud Compute.
      //const vms = await this.getSecurityEventsFromApi("vms");

      //Retrieves container scan reports.
      const containersRes = await this.doApi("containers");
      const containersScans = this.fromPrismaArtifactsToOxScanResultsForContainers(containersRes);

      //Note that the compliance issues in an image might be different (fewer) than those in a running instance of the image (a container).
      //Retrieves image scan reports.
      const imagesRes = await this.doApi("images");
      const imagesScans = this.fromPrismaArtifactsToOxScanResultsForImage(imagesRes);

      const res = [];
      if (hostScans) {
        hostScans.forEach(i => {
          res.push(i);
        });
      }
      if (containersScans) {
        containersScans.forEach(i => {
          res.push(i);
        });
      }
      if (imagesScans) {
        imagesScans.forEach(i => {
          res.push(i);
        });
      }
      logger.info(`${this.token.name} scans api, total: ${res.length}, total alerts older than 3 month: ${olderThan3MonthAlertsCount}`);

      return res;
    } catch (err) {
      logger.error(`${this.token.name} failed to get all security events for prisma, err: ${err}`);
      StatesHelper.Instance.globalApisFails.add(this.token.name.toLocaleLowerCase() as Tool);
    }

    return [];
  }

  async doApi(scanUrlItem: string) {
    const url = this.token.host;

    try {
      let apiRes = [];
      let offset = 0;
      while (true) {
        await sleep(1000);

        const scanUrl = `${url}/api/v1/${scanUrlItem}?limit=50&offset=${offset}`;

        const config = {
          headers: {
            authorization: `Bearer ${this.internalToken}`,
          },
        };

        try {
          const response = (await axios.get(scanUrl, config)) as any;

          if (response.data == null) {
            break;
          }

          apiRes.push(response.data);

          if (response.data.length < 50) {
            break;
          }

          offset += 50;
        } catch (err) {
          logger.error(`${this.token.name} failed to get single security events for prisma, err: ${err}`);
          break;
        }
      }

      apiRes = apiRes.flat();
      logger.info(`${this.token.name}, sec events count: ${apiRes.length}, source: ${scanUrlItem}`);

      return apiRes;
    } catch (err) {
      logger.error(`${this.token.name} failed to get all security events for prisma, err: ${err}`);
    }
    return [];
  }

  fromPrismaArtifactsToOxScanResultsForContainers(prismaApiAlerts) {
    const securityEventList = [];
    const uniqueRepos = new Set();

    const allUniqueRepos = {};

    for (const securityIssueEx of prismaApiAlerts) {
      try {
        let count = undefined;

        const possibaleRepoNameLable = securityIssueEx?.info?.labels?.find(i => i.includes("com.azure.dev.image.build.repository.name:"));
        let repoFullName = "";
        if (possibaleRepoNameLable) {
          repoFullName = possibaleRepoNameLable.replace("com.azure.dev.image.build.repository.name:", "");
        }

        if (!repoFullName) {
          repoFullName = securityIssueEx.info.imageName;
          const index = repoFullName.indexOf("/");
          if (index != -1) {
            repoFullName = repoFullName.substring(index + 1);
          }
        }
        if (repoFullName) {
          const index = repoFullName.indexOf(":");
          repoFullName = repoFullName.substring(0, index);
        }

        const splitInfo = securityIssueEx.info.imageName.split(":");
        let tag;
        let name = securityIssueEx.info.imageName;
        if (splitInfo.length > 1) {
          tag = splitInfo[1];
          name = splitInfo[0];
        }
        const registry = securityIssueEx.info.imageName.substring(0, securityIssueEx.info.imageName.indexOf("/"));

        allUniqueRepos[repoFullName] = securityIssueEx;

        const imageCreatedAt = securityIssueEx.info.startTime;
        const dockerVer = securityIssueEx.info.installedProducts.docker;
        const hasPackageManager = securityIssueEx.info.installedProducts.hasPackageManager
          ? securityIssueEx.info.installedProducts.hasPackageManager
          : false;
        const os = securityIssueEx.info.installedProducts.osDistro ? securityIssueEx.info.installedProducts.osDistro : "";
        const binariesCount = undefined;
        const pkgCount = count;
        let dockerFile = securityIssueEx.info.imageName;
        const sha = securityIssueEx.info.imageID.replace("sha256:", "");

        uniqueRepos.add(repoFullName);

        const artifacts = {
          system: ArtifactorySecEventSystem.Generic,
          subType: ArtifactorySecEventType.Docker,
          repoFullName: repoFullName,
          imageCreatedAt: imageCreatedAt,
          dockerVer: dockerVer,
          hasPackageManager: hasPackageManager,
          os: os,
          binariesCount: binariesCount,
          pkgCount: pkgCount,
          sha: sha,
          dockerFileInRunTime: "",
          registry: "",
          tag: "",
          linkToRegistry: "",
          linkToTask: "",
        };

        artifacts.dockerFileInRunTime = name;
        artifacts.registry = registry;
        artifacts.tag = tag;

        artifacts.system = guessArtifactSystem(artifacts.registry);

        //Container pkg(SCA) alerts
        if (securityIssueEx.info.vulnerabilities != null) {
          for (const securityIssue of securityIssueEx.vulnerabilities) {
            try {
              const securityEvent = this.getSca(securityIssueEx, securityIssue);

              //None violated, just scanned resources
              if (securityIssueEx.pass) {
                continue;
              }

              if (!securityEvent) {
                continue;
              }

              //Attach the artifacts
              securityEvent.artifacts = artifacts;
              securityEventList.push(securityEvent);
            } catch (err) {
              logger.error(`${this.token.name} failed to single security event from vulnerabilities for prisma containers, err: ${err}`);
            }
          }
        }

        if (securityIssueEx.info.complianceIssues != null && securityIssueEx.info.complianceIssues.length > 0) {
          for (const securityIssue of securityIssueEx.info.complianceIssues) {
            try {
              const securityEvent = this.getIac(securityIssueEx.info, securityIssue, dockerFile);
              if (!securityEvent) {
                continue;
              }
              securityEvent.artifacts = artifacts;
              securityEventList.push(securityEvent);
            } catch (err) {
              logger.error(`${this.token.name} failed to single security event from compliance for prisma containers, err: ${err}`);
            }
          }
        }
      } catch (err) {
        logger.error(`${this.token.name} failed to single security event from general for prisma, err: ${err}`);
      }
    }

    logger.info(
      `${this.token.name} security alerts count: ${securityEventList.length}, all repos from image: ${Object.keys(allUniqueRepos).join(
        ", ",
      )}`,
    );

    return securityEventList;
  }

  fromPrismaArtifactsToOxScanResultsForHost(prismaApiAlerts) {
    const securityEventList = [];

    for (const securityIssueEx of prismaApiAlerts) {
      try {
        const repoName = securityIssueEx.hostname;
        const imageName = securityIssueEx.cloudMetadata.name;
        const accountId = securityIssueEx.cloudMetadata.accountID;
        const registry = securityIssueEx.cloudMetadata.provider;
        const region = securityIssueEx.cloudMetadata.region;
        const imageCreatedAt = securityIssueEx.firstScanTime;
        const dockerVer = "";
        const hasPackageManager = false;
        const os = securityIssueEx.osDistro ? securityIssueEx.osDistro : "";
        const pkgCount = securityIssueEx.packages.length;
        let dockerFile = repoName;

        const artifacts = {
          system: guessArtifactSystem(registry),
          subType: ArtifactorySecEventType.Docker,
          repoFullName: repoName,
          imageCreatedAt: imageCreatedAt,
          dockerVer: dockerVer,
          hasPackageManager: hasPackageManager,
          os: os,
          binariesCount: 0,
          pkgCount: pkgCount,
          sha: "",
          dockerFileInRunTime: imageName,
          registry: registry,
          tag: "",
          linkToRegistry: "",
          linkToTask: "",
          baseImage: imageName,
          baseImageSha: "",
          baseImageRegistry: "",
          baseImageOsVersion: `${securityIssueEx.osDistroRelease}-${securityIssueEx.osDistroVersion}`,
          registryName: registry,
          runningOnHost: repoName,
          region: region,
          accountId: accountId,
        };

        artifacts.registry = securityIssueEx.hostname;

        let addInfo;
        try {
          let data = flatNestedJson(securityIssueEx.cloudMetadata);
          if (!data) {
            data = {};
          }
          const additionalInfoRes = {};
          for (const [name, entry] of Object.entries(data)) {
            try {
              const k = name as any;
              if (!entry || !k) {
                continue;
              }
              let newK = k.replace(new RegExp("[0-9]", "g"), "");
              newK = replaceAll(newK, "  ", " ");
              newK = replaceAll(newK, "_", " ");
              newK = replaceAll(newK, "-", " ");

              if (Array.isArray(entry)) {
                const arr = entry as any;
                if (arr.length == 0) {
                  continue;
                }
              }
              if (newK.endsWith(" ")) {
                newK = newK.slice(0, newK.length - 1);
              }

              if (Object.getPrototypeOf(entry) === Object.prototype) {
                continue;
              }
              additionalInfoRes[newK] = entry;
            } catch (err) {
              /**no need for log */
            }
          }
          addInfo = JSON.stringify(additionalInfoRes);
        } catch (err) {
          logger.error(`${this.token.name} failed get additional info for prisma, err: ${err}`);
        }

        //Container pkg(SCA) alerts
        if (securityIssueEx.vulnerabilities != null) {
          for (const securityIssue of securityIssueEx.vulnerabilities) {
            try {
              //Ignore the rest if its not image for zerto - add FF
              if (securityIssue.type !== "image") {
                continue;
              }

              const securityEvent = this.getSca(securityIssueEx, securityIssue);

              if (!securityEvent) {
                continue;
              }

              securityEvent.securitySubTypeAlertType = SecurityAlertType.cloudRunTime;

              //Attach the artifacts
              securityEvent.artifacts = artifacts;
              securityEvent.artifacts.additionalInfo = addInfo;
              securityEventList.push(securityEvent);
            } catch (err) {
              logger.error(`${this.token.name} failed to single security event from vulnerabilities for prisma hosts, err: ${err}`);
            }
          }
        }

        if (securityIssueEx.complianceIssues != null && securityIssueEx.complianceIssues.length > 0) {
          for (const securityIssue of securityIssueEx.complianceIssues) {
            try {
              //Ignore the rest if its not image for zerto - add FF
              if (securityIssue.type !== "image") {
                continue;
              }

              const securityEvent = this.getIac(securityIssueEx, securityIssue, dockerFile);
              if (!securityEvent) {
                continue;
              }
              securityEvent.artifacts = artifacts;
              securityEvent.artifacts.additionalInfo = addInfo;
              securityEventList.push(securityEvent);
            } catch (err) {
              logger.error(`${this.token.name} failed to single security event from compliance for prisma hosts, err: ${err}`);
            }
          }
        }
      } catch (err) {
        logger.error(`${this.token.name} failed to single security event from general for prisma, err: ${err}`);
      }
    }

    logger.info(`${this.token.name} security alerts count: ${securityEventList.length}`);

    return securityEventList;
  }

  fromPrismaArtifactsToOxScanResultsForImage(prismaApiAlerts) {
    const securityEventList = [];
    const uniqueRepos = new Set();

    const allUniqueRepos = {};

    for (const securityIssueEx of prismaApiAlerts) {
      try {
        let count = 0;
        securityIssueEx.packages.forEach(i => (count += i.pkgs.length));

        const possibaleRepoNameLable = securityIssueEx?.labels?.find(i => i.includes("com.azure.dev.image.build.repository.name:"));
        let repoFullName = "";
        if (possibaleRepoNameLable) {
          repoFullName = possibaleRepoNameLable.replace("com.azure.dev.image.build.repository.name:", "");
        }

        if (!repoFullName) {
          repoFullName = securityIssueEx.repoTag.repo;
          const index = repoFullName.indexOf("/");
          if (index != -1) {
            repoFullName = repoFullName.substring(index + 1);
          }
        }

        allUniqueRepos[repoFullName] = securityIssueEx;

        let imageCreatedAt = securityIssueEx.image.created;
        if (imageCreatedAt) {
          if (imageCreatedAt === "0001-01-01T00:00:00Z") {
            imageCreatedAt = securityIssueEx.pushTime;
          }
          if (imageCreatedAt === "0001-01-01T00:00:00Z") {
            imageCreatedAt = "";
          }
        }
        const dockerVer = securityIssueEx.installedProducts.docker;
        const hasPackageManager = securityIssueEx.installedProducts.hasPackageManager;
        const os = securityIssueEx.osDistro;
        const binariesCount = securityIssueEx.binaries.length;
        const pkgCount = count;
        let dockerFile = securityIssueEx.repoTag.registry;

        let sha = securityIssueEx.topLayer.replace("sha256:", "");
        if (securityIssueEx.repoDigests && securityIssueEx.repoDigests.length > 0) {
          sha = securityIssueEx.repoDigests[0].split("@sha256:")[1];
        }
        const registryName = securityIssueEx.repoTag.registry;

        uniqueRepos.add(repoFullName);

        for (const instance of securityIssueEx.instances) {
          const additionalInfo = {};
          try {
            if (securityIssueEx.scanTime) {
              additionalInfo["prisma scan time"] = securityIssueEx.scanTime;
            }
            if (instance.host) {
              additionalInfo["host"] = instance.host;
            }
            if (instance.registry) {
              additionalInfo["registry"] = instance.registry;
            }
            if (instance.repo) {
              additionalInfo["repo"] = instance.repo;
            }
            if (securityIssueEx.vulnerabilitiesCount) {
              additionalInfo["vulnerabilities count"] = securityIssueEx.vulnerabilitiesCount;
            }
            if (securityIssueEx.layers) {
              additionalInfo["layers"] = securityIssueEx.layers.length;
            }
            if (securityIssueEx.topLayer) {
              additionalInfo["image top layer sha256"] = securityIssueEx.topLayer.replace("sha256:", "");
            }
            if (securityIssueEx.startupBinaries) {
              additionalInfo["startup binaries"] = securityIssueEx.startupBinaries.map(i => i.name).join(",  ");
            }
            if (securityIssueEx.history) {
              const str = securityIssueEx.history.map(i => i.instruction).join("\\n");
              additionalInfo["docker instruction"] = str;
            }
            const pkgType = new Set();
            if (securityIssueEx.packages) {
              securityIssueEx.packages.forEach(p => {
                if (p.pkgsType === "package") {
                  pkgType.add(securityIssueEx.distro);
                  additionalInfo[`${securityIssueEx.distro} packages`] = p.pkgs.map(i => `${i.name}@${i.version}`).join(",  ");
                } else {
                  pkgType.add(p.pkgsType);
                  additionalInfo[`${p.pkgsType} packages`] = p.pkgs.map(i => `${i.name}@${i.version}`).join(",  ");
                }
              });
            }
            if (pkgType.size > 0) {
              additionalInfo["package types"] = Array.from(pkgType).join(", ");
            }
          } catch (err) {
            logger.error(`failed to set ${this.token.name} additional info for single image, err: ${err}`);
          }

          const artifacts = {
            system: ArtifactorySecEventSystem.Generic,
            subType: ArtifactorySecEventType.Docker,
            repoFullName: repoFullName,
            imageCreatedAt: imageCreatedAt ? imageCreatedAt : instance.modified,
            dockerVer: dockerVer,
            hasPackageManager: hasPackageManager,
            os: os,
            binariesCount: binariesCount,
            pkgCount: pkgCount,
            sha: sha,
            dockerFileInRunTime: "",
            registry: "",
            tag: "",
            linkToRegistry: "",
            linkToTask: "",
            registryName: registryName,
            scanTime: securityIssueEx.scanTime,
            baseImageOsVersion: `${securityIssueEx.osDistroVersion}`,
            additionalInfo: additionalInfo ? JSON.stringify(additionalInfo) : "",
          };

          artifacts.dockerFileInRunTime = instance.image.replace(`:${instance.tag}`, "").trim();
          artifacts.registry = instance.registry;
          artifacts.tag = instance.tag;

          artifacts.system = guessArtifactSystem(artifacts.registry);

          if (securityIssueEx.instances.length == 0) {
            logger.error(
              `${this.token.name} found 0 instance for prisma alerts, repo: ${repoFullName}, instance count: ${securityIssueEx.instances.length}`,
            );
            continue;
          }

          //Container pkg(SCA) alerts
          if (securityIssueEx.vulnerabilities != null) {
            for (const securityIssue of securityIssueEx.vulnerabilities) {
              try {
                const securityEvent = this.getSca(securityIssueEx, securityIssue);

                //None violated, just scanned resources
                if (securityIssueEx.pass) {
                  continue;
                }

                if (!securityEvent) {
                  continue;
                }

                //Attach the artifacts
                securityEvent.artifacts = artifacts;
                if (securityIssueEx.repoTag != null && securityIssueEx.repoTag.repo) {
                  securityEvent.issueOwner = securityIssueEx.repoTag?.repo;
                }
                securityEventList.push(securityEvent);
              } catch (err) {
                logger.error(`${this.token.name} failed to single security event from vulnerabilities for prisma images, err: ${err}`);
              }
            }
          }

          if (securityIssueEx.complianceIssues != null && securityIssueEx.complianceIssues.length > 0) {
            for (const securityIssue of securityIssueEx.complianceIssues) {
              try {
                const securityEvent = this.getIac(securityIssueEx, securityIssue, dockerFile);
                if (!securityEvent) {
                  continue;
                }
                securityEvent.artifacts = artifacts;
                if (securityIssueEx.repoTag != null && securityIssueEx.repoTag.repo) {
                  securityEvent.issueOwner = securityIssueEx.repoTag?.repo;
                }
                securityEventList.push(securityEvent);
              } catch (err) {
                logger.error(`${this.token.name} failed to single security event from compliance for prisma images, err: ${err}`);
              }
            }
          }
        }
      } catch (err) {
        logger.error(`${this.token.name} failed to single security event from general for prisma, err: ${err}`);
      }
    }

    logger.info(
      `${this.token.name} security alerts count: ${securityEventList.length}, all repos from image: ${Object.keys(allUniqueRepos).join(
        ", ",
      )}`,
    );

    return securityEventList;
  }

  getSca(securityIssueEx, securityIssue) {
    let pkgName = securityIssue.packageName;

    let fix = "";
    if (securityIssue.status.includes("fixed in")) {
      fix = securityIssue.status.replace("fixed in", "").trim();
    } else {
      fix = "";
    }

    const creationTime = securityIssueEx.scanTime;

    if (this.isOlderThan3Month(creationTime)) {
      olderThan3MonthAlertsCount++;
      return;
    }

    let recommendation = `The currently used vulnerable version of ${pkgName} is ${securityIssue.packageVersion}. To remediate the vulnerability, you should upgrade ${pkgName} to version ${fix} or later.`;
    if (fix === "") {
      recommendation = `The currently used vulnerable version of ${pkgName} is ${securityIssue.packageVersion}. Currently, no fixed version is available. You should reconsider the usage of this library, or sanitize your code surrounding library usage to reduce the risk.`;
    }

    let securityEvent = new SecurityEvent(
      "Prisma Artifacts",
      true,
      "",
      creationTime,
      "",
      "",
      "",
      securityIssue.description === "" ? `${securityIssue.cve} detected based in ${pkgName} pkg` : securityIssue.description,
      securityIssue.description,
      "",
      securityIssue.severity,
      `cve: ${securityIssue.cve}, cvss: ${securityIssue.cvss}`,
      -1,
      securityIssue.severity,
      SecurityAlertType.container,
      recommendation,
      `${pkgName} ${securityIssue.packageVersion}`,
      "",
      -1,
      false,
      false,
      "",
      "",
      "",
      "",
      securityIssue.cve,
      securityIssue.link,
      "",
      "prisma artifacts",
      "",
      "",
      "prisma-artifacts",
    );
    securityEvent.securitySubTypeAlertType = SecurityAlertType.sca;
    securityEvent.skipEnrichment = true;

    let pkgManager = "";
    let isOsLib = false;
    if (securityIssueEx?.packages) {
      securityIssueEx.packages.forEach(type => {
        type.pkgs.forEach(p => {
          if (p.name === pkgName) {
            if (type.pkgsType === "package") {
              pkgManager = securityIssueEx.distro;
              isOsLib = true;
            } else {
              pkgManager = type.pkgsType;
            }
          }
        });
      });
    }

    securityEvent.realMatch = `${pkgName}_${securityIssue.packageVersion}`;
    securityEvent.blame.cve = securityIssue.cve;
    if (securityEvent.blame.cve) {
      securityEvent.cves.push(securityEvent.blame.cve);
    }

    if (securityIssue.cvss) {
      securityEvent.blame.cvssScore = securityIssue.cvss;
    }
    securityEvent.pkgName = pkgName;
    securityEvent.fixedVersion = fix;
    securityEvent.installedVersion = securityIssue.packageVersion;
    securityEvent.pkgManager = pkgManager;
    if (securityIssue.discovered) {
      securityEvent.blame.publishedExploitDate = securityIssue.discovered;
    }
    securityEvent.blame.attackVector = Object.keys(securityIssue.riskFactors).find(i => i.includes("network")) ? "NETWORK" : undefined;
    securityEvent.blame.hasPublicExploit = Object.keys(securityIssue.riskFactors).find(i => i.includes("POC")) != undefined ? true : false;
    if (securityEvent.blame.hasPublicExploit) {
      addSeverityChangedReason(severityReasons.hasPublicExpolit, securityEvent, undefined);
    } else {
      addSeverityChangedReason(severityReasons.noPublicExpolit, securityEvent, undefined);
    }

    if (isOsLib) {
      securityEvent.isOsLib = true;
      securityEvent.containerScanType = ContainerSecurityType.possibleOsOnly;
      addSeverityChangedReason(severityReasons.osVull, securityEvent, undefined);
    } else {
      securityEvent.blame.language = getPkgManagerPretty(pkgManager);
      if (!securityEvent.blame.language) {
        securityEvent.blame.language = getPkgManagerPretty(securityEvent.pkgName);
        if (securityEvent.blame.language) {
          securityEvent.pkgManager = securityEvent.blame.language;
        }
      }
      securityEvent.containerScanType = ContainerSecurityType.appOnly;
    }

    return securityEvent;
  }

  getIac(securityIssueEx, securityIssue, dockerFile) {
    let recommendation = securityIssue.description;

    let ruleId = securityIssue.title;
    if (ruleId.includes("(")) {
      ruleId = securityIssue.title.substring(securityIssue.title.indexOf("(") + 1, securityIssue.title.indexOf(")")).trim();
    }

    const creationTime = securityIssueEx.startTime;

    if (this.isOlderThan3Month(creationTime)) {
      olderThan3MonthAlertsCount++;
      return;
    }

    let securityEvent = new SecurityEvent(
      "Prisma Artifacts",
      true,
      "",
      creationTime,
      "",
      "",
      "",
      securityIssue.title,
      securityIssue.title,
      dockerFile,
      securityIssue.severity,
      ``,
      999,
      securityIssue.severity,
      SecurityAlertType.container,
      recommendation,
      ``,
      "",
      -1,
      false,
      false,
      "",
      "",
      "",
      "",
      ruleId,
      "",
      "",
      "prisma artifacts",
      "",
      dockerFile,
      "prisma-artifacts",
    );

    securityEvent.securitySubTypeAlertType = SecurityAlertType.iac;
    securityEvent.realMatch = securityIssue.id;
    securityEvent.skipEnrichment = true;

    return securityEvent;
  }
}

export default Prisma;
