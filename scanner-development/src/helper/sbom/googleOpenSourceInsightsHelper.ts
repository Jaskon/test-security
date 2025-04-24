import { Job, Queue } from "bull";
import { chunk } from "lodash";
import { mkdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import { v4 } from "uuid";
import { AsyncTracker } from "../../async-tracker.service";
import { GoogleLicenseInsight, SbomEvent, SbomLicense, Version } from "../../entitis/artifactoryTypes";
import { Repo } from "../../entitis/codeRepoTypes";
import { ExtraInfo } from "../../entitis/issuesTypes";
import loggerImport from "../../logger";
import { replaceAll } from "../generalUtils";
import StatesHelper from "../statesHelper";
import { ExtendedSbomComponent } from "./sbomHelper";
const logger = loggerImport.getDebugLogger();

export class GoogleOpenSourceInsightsHelper {
  private finalResultsFromGcp: Record<string, GoogleLicenseInsight> = {};

  constructor(
    private readonly openSourceInfoQueue: Queue<OpenSourceInfoJob>,
    private readonly orgName: string,
    private readonly uuid: string,
  ) {}

  async setApplicationSbomData(repo: Repo, sbomData: SbomEvent[]) {
    let totalUniqueLibs = 0;
    let libsWithNoLic = 0;
    try {
      if (sbomData == undefined) {
        logger.info("skipping enrich sbom libs for single app. sbomData is empty");
        return;
      }

      const uniqueSbomComponentMap = new Map<string, ExtendedSbomComponent>();
      const allLibsFlatten = sbomData;

      const allUniqueLibs: ExtendedSbomComponent[] = this.getAllUniqueLibsArray(allLibsFlatten);
      const simplifiedLibs = allUniqueLibs.map(lib => ({
        libName: lib.name,
        libVersion: lib.version,
        packageManager: lib.pkgManager,
        licenses: lib.licenses?.length ? lib.licenses.map(l => l.expression).filter(Boolean) : undefined,
      }));

      if (!simplifiedLibs.length) {
        logger.info(`No libraries found`);
        return;
      }

      let results: GoogleLicenseInsight[];

      if (process.env.DEBUG) {
        results = await this.getOpenSourceInfoResultDebug(simplifiedLibs);
      } else {
        const chunks = chunk(simplifiedLibs, 500);
        logger.info(`Divided ${simplifiedLibs.length} libraries into ${chunks.length} parts`);
        const partials = await Promise.all(
          chunks.map(part =>
            AsyncTracker.runWithAsyncTracker(() =>
              this.getOpenSourceInfoResult(part, repo).catch(err => {
                logger.error("Failed to get some libraries from open source", err);
                return [];
              }),
            ),
          ),
        );
        results = partials.flat();
      }

      logger.info(`Got application sbom data, res count: ${results.length} results`);

      let missingLicense = 0;
      let missingCopyright = 0;
      for (const result of results) {
        StatesHelper.Instance.sbomTotal++;
        if (!result.copyrightInfo?.length) {
          result.copyrightInfo = ["N/A"];
          StatesHelper.Instance.sbomMissingCopyright++;
          missingCopyright++;
        }
        if (!result.copyWriteInfoLink) {
          StatesHelper.Instance.sbomMissingLicense++;
          missingLicense++;
        }
        result.nextReleasesVer = result.nextReleasesVer?.[StatesHelper.Instance.numberOfVersionsToSkip - 1];
        this.calculateTimeInDays(result.currentVer);
        this.calculateTimeInDays(result.latestVer);
        this.calculateTimeInDays(result.nextReleasesVer as Version);
        this.calculateTimeInDays(result.nextVersionAfterCurrent);
        const key = `${result.Name}_${result.Version}`;
        this.finalResultsFromGcp[key] = result;
      }

      this.attachAllEventsExtended(allLibsFlatten, uniqueSbomComponentMap);
      this.attachAllEvents(allLibsFlatten);

      const missingLicensePerecentage = Math.round((missingLicense / results.length) * 100);
      const missingCopyrightPerecentage = Math.round((missingCopyright / results.length) * 100);
      logger.info(
        `finish handle gcp from external service, totalUniqueLibs: ${totalUniqueLibs}, libsWithNoLic: ${libsWithNoLic}, missing license ${missingLicense} (${missingLicensePerecentage}%), missing copyright ${missingCopyright} (${missingCopyrightPerecentage}%)`,
      );
    } catch (err) {
      logger.error(`failed set all application sbom, err: ${err}`);
    } finally {
      //clean memory
      this.finalResultsFromGcp = {};
    }
  }

  private async getOpenSourceInfoResult(libs: LibraryEssential[], repo: Repo): Promise<GoogleLicenseInsight[]> {
    let prefix = repo.openSourceInfoDir;
    if (!prefix) {
      const globalDir = process.env.OX_GLOBAL_DATA == undefined ? "/var/shared-data" : process.env.OX_GLOBAL_DATA;
      prefix = `${globalDir}/${this.orgName}/scan_${replaceAll(this.uuid, "-", "_")}/openSourceInfo`;
    }

    const directoryForOpenSourceInfo = `${prefix}/${v4()}`;

    await mkdir(directoryForOpenSourceInfo, { recursive: true });
    const inputFilePath = `${directoryForOpenSourceInfo}/input.json`;
    const outputFilePath = `${directoryForOpenSourceInfo}/output.json`;
    const doneFilePath = `${outputFilePath}.done`;

    await writeFile(inputFilePath, JSON.stringify(libs));
    const queueJob = await this.sendMessageToQueue({
      orgId: StatesHelper.Instance.orgName,
      scanId: StatesHelper.Instance.uuid,
      inputFilePath,
      outputFilePath,
    });

    const startProcessTime = Date.now();
    await this.waitForDone(queueJob, doneFilePath, repo.id);
    logger.info(`finished waiting for open source info (${Date.now() - startProcessTime}ms)`);
    const output = await readFile(outputFilePath, { encoding: "utf-8" });
    try {
      await rm(directoryForOpenSourceInfo, { recursive: true, force: true });
    } catch (err) {
      logger.error("Could not remove openSourceInfo files", err);
    }
    return JSON.parse(output);
  }

  private async getOpenSourceInfoResultDebug(libs: LibraryEssential[]): Promise<GoogleLicenseInsight[]> {
    const mockResults: GoogleLicenseInsight[] = require("./openSourceInfo.mock.json");
    for (const lib of libs) {
      const randomResult = mockResults[randomIntFromInterval(0, libs.length - 1)];
      randomResult.Name = lib.libName;
      randomResult.Version = lib.libVersion;
    }
    return mockResults;
  }

  private calculateTimeInDays(version?: Version): void {
    if (!version?.timeStr) {
      return;
    }
    version.timeInMili = Date.now() - new Date(version.timeStr).getTime();
    version.timeInDays = Math.ceil(Math.abs(version.timeInMili) / (1000 * 60 * 60 * 24));
  }

  /**
   * polling for result for 5 minutes (150 times * 2 seconds)
   */
  private async waitForDone(job: Job, doneFilePath: string, appName: string): Promise<void> {
    const startTime = Date.now();
    logger.info("starting to wait for job completion sbom data");
    for (let i = 0; i < 150; i++) {
      // Wait 2 seconds
      await new Promise(resolver => setTimeout(resolver, 2000));

      if (await job.isCompleted()) {
        logger.info(`Job completed (${Date.now() - startTime}ms)`);
      } else {
        continue;
      }
      // Check if done file is present
      if (await stat(doneFilePath)) {
        const doneFile = await readFile(doneFilePath, { encoding: "utf-8" });
        const doneResult: OpenSourceInfoDone = JSON.parse(doneFile);
        if (doneResult.success) {
          for (const warn of doneResult.warnings) {
            StatesHelper.Instance.openSourceWarnings[warn] = (StatesHelper.Instance.openSourceWarnings[warn] || 0) + 1;
            logger.warn(warn);
          }
          return;
        } else {
          StatesHelper.Instance.scanInfoStats.failedOpenSource++;
          StatesHelper.Instance.scanInfoStats.failedOpenSourceRepoNames.push(appName);
          throw new Error(doneResult.error);
        }
      } else {
        StatesHelper.Instance.scanInfoStats.failedOpenSource++;
        StatesHelper.Instance.scanInfoStats.failedOpenSourceRepoNames.push(appName);
        throw new Error("Job missing done file");
      }
    }
    StatesHelper.Instance.scanInfoStats.timeoutOpenSource++;
    StatesHelper.Instance.scanInfoStats.timeoutOpenSourceRepoNames.push(appName);
    throw new Error(`Job waiting timeout (${Date.now() - startTime}ms)`);
  }

  private async sendMessageToQueue(job: OpenSourceInfoJob): Promise<Job<OpenSourceInfoJob>> {
    if (process.env.DEBUG) {
      job = {
        ...job,
        inputFilePath: job.inputFilePath.replace(process.env.OX_SHARED_DATA, "/shared"),
        outputFilePath: job.outputFilePath.replace(process.env.OX_SHARED_DATA, "/shared"),
      };
    }
    const queueJob = await this.openSourceInfoQueue.add(job);
    AsyncTracker.setValue("ox-open-source-info-job-id", queueJob.id);
    return queueJob;
  }

  private attachAllEventsExtended(sbomEvents: SbomEvent[], uniqueComponentMap: Map<string, ExtendedSbomComponent>) {
    try {
      logger.info(`try to attach all google insights extended findings, count: ${Object.keys(this.finalResultsFromGcp).length}`);
      let attached = 0;
      let totalEventsToAttach = 0;
      const notFoundByGoogle = [];

      for (const sbomEven of sbomEvents) {
        totalEventsToAttach += sbomEven.sbomHelper.extendedSbom.components.length;
        for (const component of sbomEven.sbomHelper.extendedSbom.components) {
          try {
            const key = `${component.name}_${component.version}`;
            if (key == undefined || key === "") {
              logger.error(`failed attach single extended sbom to events key: ${key} is not correct format`);
              continue;
            }
            if (!this.finalResultsFromGcp[key]) {
              notFoundByGoogle.push(`purl: ${component.purl}, key:${key}`);
              continue;
            }

            const item: GoogleLicenseInsight = this.finalResultsFromGcp[key];
            component.additionalInsight = item;
            if (!component.licenses) {
              component.licenses = [];
            }
            component.extraInfo = this.generatePolicyAdditionalInfo(component);
            component.copyRight = item.copyrightInfo ? item.copyrightInfo : [];

            let noneStandard = false;
            //Try get from GCP
            if (item.Licenses != undefined) {
              const s = new Set(component.licenses.map(i => i.expression));
              item.Licenses.forEach(i => {
                if (!i) {
                  return;
                }
                if (i.toLowerCase() === "non-standard") {
                  noneStandard = true;
                } else {
                  s.add(i);
                }
              });
              component.licenses = Array.from(s).map(i => ({ expression: i } as SbomLicense));
            }
            //If empty try get from api
            if (component.licenses.length == 0) {
              if (item?.currentVer?.licenses != undefined) {
                item?.currentVer?.licenses.forEach(i => component.licenses.push({ expression: i } as SbomLicense));
              }
            }
            //If not found at all and GCP return non-standard add it
            if (component.licenses.length == 0 && noneStandard) {
              component.licenses.push({
                expression: "non-standard",
              } as SbomLicense);
            }

            uniqueComponentMap.set(key, component);
            attached++;
          } catch (err) {
            logger.error(`failed set all unique extended libs: ${err}, component: ${JSON.stringify(component)}`);
          }
        }
      }

      const libsNotFound = notFoundByGoogle.join(", ");
      logger.info(
        `finish to attach all google insights extended findings count: ${
          Object.keys(this.finalResultsFromGcp).length
        }, total needed to attached: ${totalEventsToAttach}, actually attached: ${attached}, not attached: ${
          notFoundByGoogle.length
        }, data: ${libsNotFound}`,
      );
    } catch (err) {
      logger.error(`failed attach all extended sbom to events, err: ${err}`);
    }
  }

  private attachAllEvents(sbomEvents: SbomEvent[]) {
    try {
      logger.info(`try to attach all google insights findings, count: ${Object.keys(this.finalResultsFromGcp).length}`);
      let attached = 0;
      let totalEventsToAttach = 0;
      const notFoundByGoogle = new Set();

      for (const sbomEven of sbomEvents) {
        totalEventsToAttach += sbomEven.sbom.components.length;
        for (const component of sbomEven.sbom.components) {
          try {
            const key = `${component.name}_${component.version}`;
            if (key == undefined || key === "") {
              logger.error(`failed attach single sbom to events key: ${key} is not correct format`);
              continue;
            }
            if (this.finalResultsFromGcp[key] == undefined) {
              notFoundByGoogle.add(component.purl);
              continue;
            }

            const item: GoogleLicenseInsight = this.finalResultsFromGcp[key];
            if (component.licenses == undefined) {
              component.licenses = [];
            }
            component.copyRight = item.copyrightInfo ? item.copyrightInfo : [];

            let noneStandard = false;
            //Try get from GCP
            if (item.Licenses != undefined) {
              const s = new Set(component.licenses.map(i => i.expression));
              item.Licenses.forEach(i => {
                if (!i) {
                  return;
                }
                if (i.toLowerCase() === "non-standard") {
                  noneStandard = true;
                } else {
                  s.add(i);
                }
              });
              component.licenses = Array.from(s).map(i => ({ expression: i } as SbomLicense));
            }
            //If empty try get from api
            if (component.licenses.length == 0) {
              if (item?.currentVer?.licenses != undefined) {
                item?.currentVer?.licenses.forEach(i => component.licenses.push({ expression: i } as SbomLicense));
              }
            }
            //If not found at all and GCP return non-standard add it
            if (component.licenses.length == 0 && noneStandard) {
              component.licenses.push({
                expression: "non-standard",
              } as SbomLicense);
            }

            attached++;
          } catch (err) {
            logger.error(`failed single unique libs, err: ${err}`, err);
          }
        }
      }
      logger.info(
        `finish to attach all google insights findings count: ${
          Object.keys(this.finalResultsFromGcp).length
        }, total needed to attached: ${totalEventsToAttach}, actually attached: ${attached}, not found: ${notFoundByGoogle.size}`,
      );
    } catch (err) {
      logger.error(`failed attach all sbom to events err: ${err}`);
    }
  }

  private getAllUniqueLibsArray(sbomEvents: SbomEvent[]) {
    logger.info(`try set all unique libs array for sbom event, count: ${sbomEvents.length}`);

    const unique = new Set();
    let skipped = 0;
    let askedOnce = 0;
    let uniqueLibs: ExtendedSbomComponent[] = [];

    for (const sbomEven of sbomEvents) {
      try {
        for (const component of sbomEven.sbomHelper.extendedSbom.components) {
          try {
            if (component.askedOnce) {
              askedOnce++;
              continue;
            }
            if (component.type === "application") {
              continue;
            }

            const key = component["bom-ref"];
            if (key == undefined || key === "") {
              logger.error(`no bom-ref for: ${component.name}, ver: ${component.version}, type: ${component.type}`);
              continue;
            }
            if (component.version == undefined || component.version === "") {
              //Debug
              //logger.warn(`no version for: ${component.name}, ver: ${component.version}, type: ${component.type}`);
              continue;
            }

            if (unique.has(key)) {
              skipped++;
              continue;
            }
            unique.add(key);
            StatesHelper.Instance.allLibsCount++;
            uniqueLibs.push(component);
          } catch (err) {
            logger.error(`failed set sing unique libs:${component.name}, ver: ${component.version}, err ${err}`);
          }
        }
      } catch (err) {
        logger.error(`failed set all unique lib array, err: ${err}`);
      }
    }

    logger.info(`finish set all unique libs total count: ${unique.size}, askedOnce: ${askedOnce}, skipped: ${skipped}`);
    return uniqueLibs;
  }

  static capitalizeFirstLetter(string) {
    string = string.toLowerCase();
    return string.charAt(0).toUpperCase() + string.slice(1);
  }

  private generatePolicyAdditionalInfo(lib: ExtendedSbomComponent): ExtraInfo[] {
    const additionalInfo = [];

    additionalInfo.push({
      key: "Library",
      value: `${lib.name} - ${lib.version}`,
    });

    let license = lib.licenses.length == 0 ? "No License" : lib.licenses.map(i => i.expression).join(", ");
    if (license === "non-standard") {
      if (lib.additionalInsight.currentVer.licenses.length > 0) {
        license = `Non standard license - ${lib.additionalInsight.currentVer.licenses.join(", ")}`;
      } else {
        license = `Non standard license`;
      }
    }

    if (lib?.additionalInsight?.projectInfo?.deprecatedRecommendation != undefined) {
      additionalInfo.push({
        key: "Author comment",
        value: lib?.additionalInsight?.projectInfo?.deprecatedRecommendation,
      });
    }

    additionalInfo.push({
      key: "License",
      value: license,
    });

    if (lib?.pkgManager != undefined) {
      additionalInfo.push({
        key: "Package manager",
        value: `${lib?.pkgManager}`,
      });
    }

    if (lib?.additionalInsight?.projectInfo?.disabled != undefined) {
      if (lib?.additionalInsight?.projectInfo?.disabled) {
        additionalInfo.push({
          key: "Git Status",
          value: `Disabled`,
        });
      }
    }

    if (lib?.additionalInsight?.currentVer?.sha != undefined) {
      additionalInfo.push({
        key: "SHA",
        value: `${lib?.additionalInsight?.currentVer?.sha}`,
      });
    }

    if (lib?.additionalInsight?.latestVer?.version != undefined) {
      additionalInfo.push({
        key: "Latest version",
        value: `${lib?.additionalInsight?.latestVer?.version}`,
      });
    }

    if (lib?.additionalInsight?.totalCountOfVers != undefined) {
      if (lib?.additionalInsight?.totalCountOfVers != -1) {
        additionalInfo.push({
          key: "Total available versions",
          value: `${lib?.additionalInsight?.totalCountOfVers}`,
        });
      }
    }

    if (lib?.additionalInsight?.projectInfo?.Description != undefined) {
      additionalInfo.push({
        key: "Description",
        value: `${lib?.additionalInsight?.projectInfo?.Description}`,
      });
    }

    if (lib?.additionalInsight?.currentVer?.timeStr != undefined) {
      additionalInfo.push({
        key: "Created",
        value: `${lib?.additionalInsight?.currentVer?.timeStr} (${lib?.additionalInsight?.currentVer?.timeInDays} days ago)`,
      });
    }

    if (lib?.additionalInsight?.latestVer?.timeStr != undefined) {
      additionalInfo.push({
        key: "Latest version published",
        value: `${lib?.additionalInsight?.latestVer?.timeStr} (${lib?.additionalInsight?.latestVer?.timeInDays} days ago)`,
      });
    }

    if (lib?.additionalInsight?.projectInfo?.contributors != undefined) {
      additionalInfo.push({
        key: "Contributors",
        value: `${lib?.additionalInsight?.projectInfo?.contributors}`,
      });
    }

    if (lib?.additionalInsight?.downloads != undefined) {
      additionalInfo.push({
        key: "Downloads",
        value: `${lib?.additionalInsight?.downloads}`,
      });
    }

    if (lib?.additionalInsight?.maintainers != undefined) {
      if (lib?.additionalInsight?.maintainers.length > 0) {
        additionalInfo.push({
          key: "Maintainers",
          value: `${lib?.additionalInsight?.maintainers.length}`,
        });
      }
    }

    if (lib?.additionalInsight?.projectInfo?.ForksCount != undefined) {
      additionalInfo.push({
        key: "Forks",
        value: `${lib?.additionalInsight?.projectInfo?.ForksCount}`,
      });
    }
    if (lib?.additionalInsight?.projectInfo?.StarsCount != undefined) {
      additionalInfo.push({
        key: "Stars",
        value: `${lib?.additionalInsight?.projectInfo?.StarsCount}`,
      });
    }
    if (lib?.additionalInsight?.projectInfo?.OpenIssuesCount != undefined) {
      additionalInfo.push({
        key: "Open issues",
        value: `${lib?.additionalInsight?.projectInfo?.OpenIssuesCount}`,
      });
    }

    if (lib?.additionalInsight?.projectInfo?.linters != undefined) {
      if (lib?.additionalInsight?.projectInfo?.linters.length > 0) {
        additionalInfo.push({
          key: "Linters",
          value: `${lib?.additionalInsight?.projectInfo?.linters.join(", ")}`,
        });
      }
    }

    if (lib?.additionalInsight?.currentVer?.main != undefined) {
      additionalInfo.push({
        key: "Entry point file",
        value: `${lib?.additionalInsight?.currentVer?.main}`,
      });
    }

    if (lib?.additionalInsight?.projectInfo?.Type != undefined) {
      additionalInfo.push({
        key: "Source",
        value: GoogleOpenSourceInsightsHelper.capitalizeFirstLetter(`${lib?.additionalInsight?.projectInfo?.Type}`),
      });
    }

    if (lib?.additionalInsight?.publisher != undefined) {
      additionalInfo.push({
        key: "Publisher",
        value: `${lib?.additionalInsight?.publisher.name} (${lib?.additionalInsight?.publisher.email})`,
      });
    }

    if (lib?.additionalInsight?.linkToActualSite != undefined) {
      additionalInfo.push({
        key: lib?.pkgManager == undefined ? "Package" : lib?.pkgManager,
        value: `${lib?.additionalInsight?.linkToActualSite}`,
      });
    }

    let githubLink = "";
    lib?.additionalInsight?.Links?.forEach(i => {
      if (!githubLink && i.URL.includes("github.com") && i.URL.includes("issues")) {
        githubLink = i.URL.replace("/issues/", "");
        githubLink = i.URL.replace("/issues", "");
      }
      additionalInfo.push({
        key: i.Label,
        value: i.URL,
      });
    });

    if (githubLink) {
      additionalInfo.push({
        key: "Github",
        value: githubLink,
      });
    }

    lib?.additionalInsight?.Advisories?.forEach(i =>
      additionalInfo.push({
        key: i.Source,
        value: i.SourceID,
      }),
    );

    return additionalInfo;
  }
}

interface OpenSourceInfoJob {
  orgId: string;
  scanId: string;
  inputFilePath: string;
  outputFilePath: string;
}

interface LibraryEssential {
  libName: string;
  libVersion: string;
  packageManager: string;
}

interface OpenSourceInfoDone {
  success: boolean;
  error?: string;
  warnings: string[];
}

function randomIntFromInterval(min, max) {
  // min and max included
  return Math.floor(Math.random() * (max - min + 1) + min);
}
