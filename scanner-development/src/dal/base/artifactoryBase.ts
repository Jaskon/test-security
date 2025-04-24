import { PromisePool } from "@supercharge/promise-pool/dist/promise-pool";
import ms from "ms";
import { readFile, stat } from "node:fs/promises";
import { AsyncTracker } from "../../async-tracker.service";
import ArtifactoryToolsCreator from "../../codeOpenSourceTools/artifactoryTools/artifactoryToolsCreator";
import ArtifactoryToolsManager from "../../codeOpenSourceTools/artifactoryTools/artifactoryToolsManager";
import ArtifactoryDownloadCreator from "../../codeOpenSourceTools/artifactoryToolsDownload/artifactoryDownloadCreator";
import ArtifactoryDownloadManager from "../../codeOpenSourceTools/artifactoryToolsDownload/artifactoryDownloadManager";
import { ArtifactoryDownloadToRun, ArtifactoryResourceToRun, ImageInfo, SbomEvent } from "../../entitis/artifactoryTypes";
import { ArtifactorySecEvent, ArtifactorySecEventType, guessArtifactSystem } from "../../entitis/ArtifactTypes";
import { ImageDetail } from "../../entitis/cloudTypes";
import { addSeverityChangedReason, SecurityEvent, setSecEventFromDelta } from "../../entitis/codeRepoTypes";
import { ResourceType, Token } from "../../entitis/collectorEntitisTypes";
import { ExtraInfo } from "../../entitis/issuesTypes";
import { Resource } from "../../entitis/orgPolicyTypes";
import { severityReasons } from "../../entitis/service/blameTypes";
import { CacheResolver } from "../../helper/cache/cache.resolver";
import { CacheIdentifier } from "../../helper/cache/cache.service";
import { Cache } from "../../helper/cache/cache.types";
import { PerformanceTelemetry } from "../../helper/decorators/PerformanceTelemetry";
import { isDevelopment, isLocalDevelopment } from "../../helper/envUtils";
import MemoryMonitorHelper from "../../helper/IO/memoryMonitorHelper";
import { ARTIFACT_HEAVY_SIZE_THRESHOLD_BYTES } from "../../helper/repository-matching/artifacts-constants";
import { DockerApi } from "../../helper/repository-matching/docker-api";
import { ImageAnalysis, RepositoryMatcher } from "../../helper/repository-matching/RepositoryMatcher";
import { GoogleOpenSourceInsightsHelper } from "../../helper/sbom/googleOpenSourceInsightsHelper";
import AlertRecommendationHelper from "../../helper/service/alertRecommendationHelper";
import BlameHelper from "../../helper/service/blameHelper";
import LightBlameHelper from "../../helper/service/lightBlameHelper";
import { SettingsService } from "../../helper/service/scan-settings-service/service/settings-service";
import SecretValidationHelper from "../../helper/service/secretValidationHelper";
import StatesHelper from "../../helper/statesHelper";
import { ToolsExecutionStats } from "../../helper/toolExecutionStats";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";
import CollectorBase from "./collectorBase";
const logger = loggerImport.getDebugLogger();

export class ImageScanInfo {
  secAlertsFromCash: SecurityEvent[] = [];
  sbomAlertsFromCash: SbomEvent[] = [];
  artifactoryToolsManager: ArtifactoryToolsManager;
  imageObj: ImageInfo;
  resource: ArtifactoryResourceToRun;
  identifier: CacheIdentifier;
}

abstract class ArtifactoryBase extends CollectorBase {
  callObj: RulesManager;
  cacheResovler: CacheResolver;
  newAccessToken: string;
  foundImages: ImageInfo[] = [];

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, ResourceType[ResourceType.artifactory], policyConfiguration, jsonApplicationDiscoveryOverview);
  }

  abstract initLib();

  async getNewRefreshToken(): Promise<string | undefined> {
    return;
  }

  needToRefreshToken(): boolean {
    return false;
  }

  async collect(resources: Resource[], callObj: RulesManager): Promise<boolean[]> {
    logger.info(`[${this.token.name}] try set artifacts repos, url: ${this.token.host}`);

    this.cacheResovler = new CacheResolver(this.orgName, callObj.mongoConnect);
    this.callObj = callObj;

    try {
      if (StatesHelper.Instance.isPipelineScan) {
        logger.info(`[${this.token.name}] not setting artifacts repos, url: ${this.token.host} due to isPipelineScan`);
        return;
      }
      if (process.env.DISABLE_CONTAINERS) {
        logger.info(`[${this.token.name}] ignoring due to DISABLE_CONTAINERS from env`);
        return;
      }
      const isEnable = process.env[`TOOLS_TRIVY-CONTAINER`] === "enabled";
      if (!isEnable) {
        logger.info(`[${this.token.name}] not setting artifacts repos, url: ${this.token.host} due to disable tool`);
        return;
      }

      const startTime = new Date().getTime();

      this.initSelectedRepos(callObj);

      //init
      await this.initLib();
      this.blameHelper = new BlameHelper(this.callObj.blameQueue, this.uuid, this.orgName);
      this.lightBlameHelper = new LightBlameHelper(this.callObj.blameQueue, this.uuid, this.orgName);
      this.secretValidationHelper = new SecretValidationHelper(this.callObj.secretValidationQueue, this.uuid, this.orgName);
      this.alertRecommendationHelper = new AlertRecommendationHelper(this.callObj.alertRecommendationQueue, this.uuid, this.orgName);
      this.googleOpenSourceInsightsHelper = new GoogleOpenSourceInsightsHelper(this.callObj.openSourceInfoQueue, this.orgName, this.uuid);

      logger.info(`[${this.token.name}] start promisees poll to collect all ${resources.length} resources`);

      let artifactoryObj = {};
      artifactoryObj["resourceType"] = ResourceType[ResourceType.artifactory];

      const apisProms = resources.map(resource => this.addFirstLevelItemToArtifactsObj(artifactoryObj, resource));
      await Promise.all(apisProms);

      await callObj.applicationsManager.updateAppManagerWithImageItems(this.foundImages);
      this.foundImages = []; //Clean memory

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "after finish container scanning");

      const elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));
      logger.info(
        `[${this.token.name}] promisees poll finish collect all resource for artifacts, execution time in minutes: ${elapsedTime}`,
      );

      StatesHelper.Instance.scanInfoStats.artifactTime = elapsedTime;
    } catch (err) {
      logger.error(`[${this.token.name}] failed collect all resources for artifacts`, err);
    }

    return [];
  }

  async addFirstLevelItemToArtifactsObj(artifactObj: any, resource: Resource) {
    let data = [];

    try {
      if (this.funcNames.has(resource.name)) {
        data = await this[resource.name]();
        artifactObj[resource.name] = data;
      }

      return true;
    } catch (err) {
      logger.error(`[${this.token.name}] failed collect resources: ${resource.name}`, err);
    }
    return false;
  }

  async runSecurityToolsOnArtifacts(images: ImageInfo[]) {
    const imageIrrelevantTimeInMonths = SettingsService.Instance.irrelevantImageTimeInMonths();
    const MONTH_IN_MILLISECONDS = 1000 * 60 * 60 * 24 * 30;
    if (isLocalDevelopment()) {
      if (!process.env.SCAN_ARTIFACT_LOCALY) {
        return;
      }
    }

    const imagesScanInfo: ImageScanInfo[] = [];
    logger.info(
      `[${this.token.name}] start to run tools scan on: ${images.length} images, using concurrent of: ${StatesHelper.Instance.concurrentRepoScans}`,
    );

    const startTime = new Date().getTime();

    //Filters for debug
    if (isLocalDevelopment()) {
      if (StatesHelper.Instance.orgName === "org_e08aBbdBBkUVlSC0") {
        images = images.filter(i => i.image.name === "policy");
      }
      if (StatesHelper.Instance.orgName === "org_US3qDZlQqt1VzoxB") {
        images = [images[1]];
      }
    }

    if (isDevelopment()) {
      if (StatesHelper.Instance.orgName === "org_16U6jxMKWdXjVaAJ") {
        images = images.filter(
          i => i.image.name.includes("policy-service") || i.image.name.includes("scanner") || i.image.name.includes("cloner-service"),
        );
        logger.info(`[${this.token.name}] start to run tools scan on: ${images.length} for debug`);
      }
    }

    StatesHelper.Instance.scanInfoStats.totalImages += images.length;
    await this.callObj.resultsHandler.updateScanInfoStateWithDBupdate();

    let progressIndex = 0;
    let progressDiff = 0;
    let failedScannedArtifacts = 0;

    const missingHashes = new Set();
    const uniqueHashes = new Set();
    const uniqueImagesByHash: ImageInfo[] = [];
    const duplicateImagesByHash: ImageInfo[] = [];
    const duplicateImagesByHashSet = new Set();

    images.forEach(i => {
      if (!i.image.imageDigestWithoutPrefix) {
        missingHashes.add(i.image.name);
        return;
      }

      if (uniqueHashes.has(i.image.imageDigestWithoutPrefix)) {
        duplicateImagesByHash.push(i);
        duplicateImagesByHashSet.add(`${i.image.name}_${i.image.imageDigestWithoutPrefix}`);
        return;
      }
      uniqueHashes.add(i.image.imageDigestWithoutPrefix);
      uniqueImagesByHash.push(i);
    });

    //Update with duplicate images as we dont going to scan them again
    if (duplicateImagesByHashSet.size > 0) {
      StatesHelper.Instance.artifactScanCountProgress += duplicateImagesByHashSet.size;
      await this.callObj.resultsHandler.updateScanInfoStateWithDBupdate();
    }

    await PromisePool.for(uniqueImagesByHash)
      .withConcurrency(StatesHelper.Instance.concurrentRepoScans)
      .process(async (image: ImageInfo) => {
        await AsyncTracker.runWithAsyncTracker(async () => {
          AsyncTracker.setValue("ox-image-name", image.image.name);
          AsyncTracker.setValue("ox-image-id", image.image.imageDigest);
          try {
            if (Date.now() - new Date(image.image.imagePushedAt || 0).getTime() > imageIrrelevantTimeInMonths * MONTH_IN_MILLISECONDS) {
              logger.info(`[${this.token.name}] not scanning image cause too old (limitInMonths: ${imageIrrelevantTimeInMonths})`, {
                debug: image.image.imagePushedAt,
              });
              return;
            }
            const scanRes = await this.runArtifactoryToolsOnImage(this.callObj, image, this.token);

            progressIndex++;
            if (progressIndex % 2 == 0 || progressIndex == 1) {
              StatesHelper.Instance.artifactScanCountProgress++;
              await this.callObj.resultsHandler.updateScanInfoStateWithDBupdate();
              progressDiff++;
            }
            if (scanRes) {
              imagesScanInfo.push(scanRes);
            } else {
              failedScannedArtifacts++;
              StatesHelper.Instance.failedArtifactsScan.add(image.image.imageId);
            }
          } catch (err) {
            failedScannedArtifacts++;
            logger.error(`[${this.token.name}] failed to run ${image.image.name} error`, err);
          }
        });
      });

    logger.info(
      `[${this.token.name}] finish to run tools scan on: ${imagesScanInfo.length} images, uniqueImagesByHash: ${
        uniqueImagesByHash.length
      }, from total of: ${images.length}, missingHashes: ${missingHashes.size}, duplicateImagesByHashSet: ${
        duplicateImagesByHashSet.size
      }, missingHashesInfo: ${Array.from(missingHashes).join(", ")}, duplicateImagesByHashSet: ${Array.from(duplicateImagesByHashSet).join(
        ", ",
      )}`,
    );

    progressIndex = 0;

    const alertsInfo: Record<string, number> = {
      totalAlerts: 0,
      totalAlertsSecEvents: 0,
      totalAlertsSbom: 0,
      fromCash: 0,
      noneCash: 0,
      totalImages: 0,
    };

    await PromisePool.for(imagesScanInfo)
      .withConcurrency(StatesHelper.Instance.concurrentRepoScans)
      .process(async (imageScanInfo: ImageScanInfo) => {
        await AsyncTracker.runWithAsyncTracker(async () => {
          AsyncTracker.setValue("ox-image-name", imageScanInfo.imageObj.image.name);
          AsyncTracker.setValue("ox-image-id", imageScanInfo.imageObj.image.imageDigest);
          try {
            await this.parseAndSetResFromTools(imageScanInfo, alertsInfo);

            //Update alerts and data in case there are duplicate images which we didnt scan
            const duplicateImages = duplicateImagesByHash.filter(
              i => i.image.imageDigestWithoutPrefix === imageScanInfo.imageObj.image.imageDigestWithoutPrefix,
            );

            if (duplicateImages.length > 0) {
              duplicateImages.forEach(i => {
                this.setInfoForDuplicateImageByHash(i, imageScanInfo, alertsInfo);
              });
            }

            progressIndex++;
            if (progressIndex % 2 == 0 && StatesHelper.Instance.scanInfoStats.totalImages > 1) {
              StatesHelper.Instance.artifactScanCountProgress++;
              await this.callObj.resultsHandler.updateScanInfoStateWithDBupdate();
              progressDiff++;
            }
          } catch (err) {
            logger.error(`[${this.token.name}] failed to run ${imageScanInfo.imageObj.image.name}`, err);
          }
        });
      });

    const diff = images.length - progressDiff;
    if (diff > 0) {
      StatesHelper.Instance.artifactScanCountProgress += diff;
      await this.callObj.resultsHandler.updateScanInfoStateWithDBupdate();
    }

    imagesScanInfo.forEach(image => {
      if (!image.resource) {
        return;
      }
      if (!image.resource.scannedImage) {
        failedScannedArtifacts++;
        StatesHelper.Instance.failedArtifactsScan.add(image.imageObj.image.imageId);
      }
    });

    const elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));

    logger.info(
      `[${this.token.name}] finish to run scan on: ${imagesScanInfo.length} images, from total of: ${
        images.length
      }, alertsInfo: ${JSON.stringify(
        alertsInfo,
      )}, elapsedTime: ${elapsedTime}, failedScannedArtifacts: ${failedScannedArtifacts},  uniqueImagesByHash: ${
        uniqueImagesByHash.length
      }, from total of: ${images.length}, missingHashes: ${missingHashes.size}, duplicateImagesByHashSet: ${
        duplicateImagesByHashSet.size
      }, missingHashesInfo: ${Array.from(missingHashes).join(", ")}, duplicateImagesByHashSet: ${Array.from(duplicateImagesByHashSet).join(
        ", ",
      )}`,
    );

    StatesHelper.Instance.scanInfoStats.imageScanTimeInMinutes = elapsedTime.toString();
  }

  async getFromCache(
    imageObj: ImageInfo,
    imageScanInfo: ImageScanInfo,
    secAlerts: SecurityEvent[],
    sbomAlerts: SbomEvent[],
    identifier: CacheIdentifier,
  ) {
    imageObj.isDelta = true;
    const cacheStartTime = Date.now();
    let cacheFinishTime = 0;

    [secAlerts, sbomAlerts] = await Promise.all([
      this.cacheResovler.getFromCache<SecurityEvent>(identifier, Cache.SecurityEvents),
      this.cacheResovler.getSbomCache(identifier),
    ]);
    cacheFinishTime = Date.now() - cacheStartTime;

    secAlerts.forEach(i => {
      setSecEventFromDelta(undefined, i);
    });

    imageScanInfo.secAlertsFromCash = secAlerts;
    imageScanInfo.sbomAlertsFromCash = sbomAlerts;

    ToolsExecutionStats.addExecutionStateOfCache(
      imageObj.image.name,
      imageObj.image.imageDigest,
      "artifact",
      cacheFinishTime,
      Cache.SecurityEvents,
    );

    logger.info(
      `[${this.token.name}] retrieve sec alerts from cache for image: ${imageObj.image.name}, secAlertsFromCash: ${
        imageScanInfo.secAlertsFromCash.length
      }, sbomAlertsFromCash: ${imageScanInfo.sbomAlertsFromCash.length}, (${ms(cacheFinishTime)})`,
    );
  }

  @PerformanceTelemetry()
  async runArtifactoryToolsOnImage(callObj: RulesManager, imageObj: ImageInfo, token: Token) {
    let startTime = Date.now();

    try {
      const resourceToDownload = new ArtifactoryDownloadToRun(this.uuid, this.orgName, imageObj.image);

      const identifier: CacheIdentifier = { id: imageObj.image.imageDigest, idKey: "imageCacheId", name: imageObj.image.name };

      let secAlerts: SecurityEvent[] = [];
      let sbomAlerts: SbomEvent[] = [];

      const imageScanInfo: ImageScanInfo = new ImageScanInfo();
      imageScanInfo.imageObj = imageObj;
      imageScanInfo.identifier = identifier;

      // Don't retrieve from cache on full scan
      const cachedArtifact = StatesHelper.Instance.isFullScan
        ? []
        : await this.cacheResovler.getFromCache<{ imageId: string }>(identifier, Cache.Artifacts);

      if (cachedArtifact.length) {
        await this.getFromCache(imageObj, imageScanInfo, secAlerts, sbomAlerts, identifier);
        return imageScanInfo;
      } else {
        //First download the artifacts
        logger.info(
          `[${this.token.name}] try run download artifactory tools on image: ${imageObj.image.name}, to: ${resourceToDownload.artifactoryResultsDir}`,
        );

        //Check if token needs to be refreshed specific for GAR and GCR
        const needToRefresh = this.needToRefreshToken();
        if (needToRefresh) {
          this.newAccessToken = await this.getNewRefreshToken();
        }
        // if newAccessToken is available then assign it
        if (this.newAccessToken) {
          imageObj.image.accessToken = this.newAccessToken;
        }

        const toolsCreatorDownload = new ArtifactoryDownloadCreator(
          this.uuid,
          this.orgPolicyParser,
          this.orgName,
          this.securityToolsQueue,
          token,
        );
        toolsCreatorDownload.setTools();

        const artifactoryDownloadCollector = new ArtifactoryDownloadManager(
          this.uuid,
          this.orgPolicyParser,
          this.orgName,
          resourceToDownload,
          this.securityToolsQueue,
          toolsCreatorDownload,
          callObj.toolProgressBase,
        );
        const downloadStartTime = Date.now();

        await artifactoryDownloadCollector.sendScanRequest();
        //Failed to execute tool for download do fallback from cash
        if (artifactoryDownloadCollector.failedTools.size > 0) {
          await this.getFromCache(imageObj, imageScanInfo, secAlerts, sbomAlerts, identifier);
          return imageScanInfo;
        }

        await artifactoryDownloadCollector.waitForAlerts();

        //This is shared data dir
        const resource = new ArtifactoryResourceToRun(this.uuid, this.orgName, imageObj.image);
        resource.netShareDownloadArtifactPathForScan = `${resourceToDownload.artifactoryResultsDir}/artifactdownload.tar`;
        try {
          const stats = await stat(resource.netShareDownloadArtifactPathForScan);
          imageObj.image.isHeavy = stats.size > ARTIFACT_HEAVY_SIZE_THRESHOLD_BYTES;
        } catch (error) {
          if (!isLocalDevelopment()) {
            await this.getFromCache(imageObj, imageScanInfo, secAlerts, sbomAlerts, identifier);
            return imageScanInfo;
          }
        }

        logger.info(
          `[${this.token.name}] finish run download artifactory tool on image: ${imageObj.image.name}, to: ${
            resourceToDownload.artifactoryResultsDir
          } (${ms(Date.now() - downloadStartTime || 0)})`,
        );

        //Use token for this image only
        const toolsCreator = new ArtifactoryToolsCreator(this.uuid, this.orgPolicyParser, this.orgName, this.securityToolsQueue, token);
        toolsCreator.setTools();

        if (StatesHelper.Instance.isContainerEnable) {
          try {
            //only send the req;
            imageScanInfo.resource = resource;
            await RepositoryMatcher.instance.analyseImage(resource);
          } catch (err) {
            logger.error(`failed to get base image, image: ${imageObj.image.name}`, err);
          }
        }

        //Execute security tools
        const toolsStartTime = Date.now();
        const artifactoryToolsCollector = new ArtifactoryToolsManager(
          this.uuid,
          this.orgPolicyParser,
          this.orgName,
          resource,
          this.securityToolsQueue,
          toolsCreator,
          callObj.toolProgressBase,
        );
        await artifactoryToolsCollector.sendScanRequest();
        if (artifactoryToolsCollector.failedTools.size > 0) {
          await this.getFromCache(imageObj, imageScanInfo, secAlerts, sbomAlerts, identifier);
          return imageScanInfo;
        }

        //Only wait for res, parsing will be done at the end
        await artifactoryToolsCollector.waitForAlerts();
        if (artifactoryToolsCollector.failedTools.size > 0) {
          await this.getFromCache(imageObj, imageScanInfo, secAlerts, sbomAlerts, identifier);
          return imageScanInfo;
        }

        imageScanInfo.artifactoryToolsManager = artifactoryToolsCollector;

        logger.info(
          `[${this.token.name}] finish run tools on image: ${imageObj.image.name} (${ms(
            Date.now() - toolsStartTime,
          )}), total time with download: (${ms(Date.now() - startTime)})`,
        );
      }

      return imageScanInfo;
    } catch (err) {
      logger.error(
        `[${this.token.name}] failed to run artifactory from cloud for image: ${imageObj.image.name} (${ms(Date.now() - startTime)})`,
        err,
        { "ox-image-total": Date.now() - startTime },
      );
    }
  }

  @PerformanceTelemetry()
  async parseAndSetResFromTools(imageScanInfo: ImageScanInfo, alertsInfo: Record<string, number>) {
    const imageObj: ImageInfo = imageScanInfo.imageObj;

    try {
      const startTime = new Date().getTime();
      const artifactoryToolsCollector: ArtifactoryToolsManager = imageScanInfo.artifactoryToolsManager;
      const resource: ArtifactoryResourceToRun = imageScanInfo.resource;
      const identifier: CacheIdentifier = imageScanInfo.identifier;
      let secAlerts: SecurityEvent[] = imageScanInfo.secAlertsFromCash;
      let sbomAlerts: SbomEvent[] = imageScanInfo.sbomAlertsFromCash;

      alertsInfo.totalImages++;

      //Tools was executed and its not delta
      if (!imageObj.isDelta) {
        if (StatesHelper.Instance.isContainerEnable) {
          try {
            alertsInfo.noneCash++;

            //Parse now results
            const fsAnalisysFile = await RepositoryMatcher.instance.getAnalyzedImage(resource);
            if (fsAnalisysFile) {
              const resultContent = await readFile(fsAnalisysFile, "utf-8");
              const imageAnalysis: ImageAnalysis = JSON.parse(resultContent);
              imageObj.image.baseImage = await DockerApi.instance.getBaseImage(imageAnalysis.diffIds);
            } else {
              logger.info(`[${this.token.name}] no analyses file found for ${imageObj.image.name}`);
            }

            //Security alerts
            secAlerts = await artifactoryToolsCollector.collectAlertsWithoutWait();

            //Compliance alerts
            const complianceAlerts = await artifactoryToolsCollector.collectComplianceAlerts();
            complianceAlerts.forEach(i => {
              secAlerts.push(i);
            });
          } catch (err) {
            logger.error(`[${this.token.name}] failed to get base image, image: ${imageObj.image.name}`, err);
          }
        }

        //Sbom
        sbomAlerts = await artifactoryToolsCollector.collectSbom();

        //Run blame and other service to enrich sec alerts and sbom data before cash
        await this.setArtifactSecurityEventForFakeApp(secAlerts, sbomAlerts, imageScanInfo);

        //Cash
        if (secAlerts.length) {
          await this.cacheResovler.setForCache<SecurityEvent>(identifier, secAlerts, Cache.SecurityEvents);
        }
        for (const sbom of sbomAlerts) {
          await this.cacheResovler.setSbomCache(identifier, sbom);
        }

        //Delete when done working on the repo
        await this.fileHelper.deleteAllFilesInRootDir(resource.dirWhereToPutRes);
        this.fileHelper.deleteFile(resource.netShareDownloadArtifactPathForScan);

        logger.info(
          `[${this.token.name}] artifact scan res for image ${imageObj.image.name}, secAlerts: ${secAlerts.length}, sbom: ${sbomAlerts.length}`,
        );
      } else {
        alertsInfo.fromCash++;
      }

      await this.cacheResovler.setForCache(identifier, [{ imageId: identifier.id, scanId: this.uuid }], Cache.Artifacts);

      const artifacts = this.extractArtifactsFromSbomEvents(imageObj.image, sbomAlerts);

      imageObj.sbomEvents = sbomAlerts;

      if (StatesHelper.Instance.isContainerEnable) {
        imageObj.securityEvents = secAlerts;
      }

      secAlerts.forEach(secAlert => {
        if (!secAlert.artifacts) {
          secAlert.artifacts = artifacts;
        }

        if (imageObj.image.imageRunningInCloud || StatesHelper.Instance.isDemo) {
          const extraInfo: ExtraInfo[] = [];
          if (StatesHelper.Instance.isDemo && extraInfo.length == 0) {
            if (imageObj.image.cloudEnv) {
              extraInfo.push({
                key: "Cloud Platform",
                value: imageObj.image.cloudEnv,
              });
            }
            extraInfo.push({
              key: "Machine Type",
              value: "Compute",
            });
            extraInfo.push({
              key: "Instance",
              value: "514122851622",
            });
            extraInfo.push({
              key: "Location",
              value: "europe-west1-d",
            });
          }
          addSeverityChangedReason(severityReasons.runningInCloud, secAlert, undefined, extraInfo);
        }
      });

      const sbomCount = sbomAlerts.reduce((count, sbom) => count + sbom.sbom.components.length, 0);
      const telemetryData: Record<string, unknown> = {
        "ox-image-sbom-components": sbomCount,
        "ox-image-alerts-container": secAlerts.length,
      };
      logger.info(
        `[Telemetry] Image ${imageObj.image.name} stats: sbom: ${telemetryData["ox-image-sbom-components"]}, alerts: ${telemetryData["ox-image-alerts-container"]}`,
        telemetryData,
      );

      alertsInfo.totalAlertsSecEvents += secAlerts.length;
      alertsInfo.totalAlertsSbom += sbomCount;
      alertsInfo.totalAlerts += secAlerts.length + sbomCount;

      const elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));
      logger.info(
        `[${this.token.name}] finish collect artifactory sec tools, elapsed time: ${elapsedTime} on image: ${imageObj.image.name}, sbom alerts: ${sbomAlerts.length}, security events: ${imageObj.securityEvents.length}`,
      );
    } catch (err) {
      logger.error(`[${this.token.name}] failed to run artifactory from cloud for image: ${imageObj.image.name}`, err);
    }
  }

  async setInfoForDuplicateImageByHash(duplicateImage: ImageInfo, imageScanInfo: ImageScanInfo, alertsInfo: Record<string, number>) {
    const imageObj: ImageInfo = imageScanInfo.imageObj;

    try {
      const startTime = new Date().getTime();
      const artifactoryToolsCollector: ArtifactoryToolsManager = imageScanInfo.artifactoryToolsManager;

      logger.info(
        `[${this.token.name}] start collect artifactory sec tools on duplicate image: ${duplicateImage.image.name}, original image: ${imageObj.image.name}, sbom alerts: ${duplicateImage.sbomEvents.length}, security events: ${imageObj.securityEvents.length}`,
      );

      alertsInfo.totalImages++;

      imageObj.securityEvents.forEach(i => {
        const copy = JSON.parse(JSON.stringify(i));
        duplicateImage.securityEvents.push(copy);
      });
      imageObj.sbomEvents.forEach(i => {
        const copy = JSON.parse(JSON.stringify(i));
        duplicateImage.sbomEvents.push(copy);
      });

      //Tools was executed and its not delta
      if (artifactoryToolsCollector) {
        alertsInfo.noneCash++;
      } else {
        alertsInfo.fromCash++;
      }

      const artifacts = this.extractArtifactsFromSbomEvents(duplicateImage.image, duplicateImage.sbomEvents);
      duplicateImage.securityEvents.forEach(secAlert => {
        secAlert.artifacts = artifacts;
      });

      const sbomCount = duplicateImage.sbomEvents.reduce((count, sbom) => count + sbom.sbom.components.length, 0);

      alertsInfo.totalAlertsSecEvents += duplicateImage.securityEvents.length;
      alertsInfo.totalAlertsSbom += sbomCount;
      alertsInfo.totalAlerts += duplicateImage.securityEvents.length + sbomCount;

      const elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));
      logger.info(
        `[${this.token.name}] finish collect artifactory sec tools, elapsed time: ${elapsedTime} on duplicate image: ${duplicateImage.image.name},  original image: ${imageObj.image.name}, sbom alerts: ${duplicateImage.sbomEvents.length}, security events: ${imageObj.securityEvents.length}`,
      );
    } catch (err) {
      logger.error(
        `[${this.token.name}] failed to run artifactory from cloud for duplicate image: ${duplicateImage.image.name},  original image: ${imageObj.image.name}`,
        err,
      );
    }
  }

  extractArtifactsFromSbomEvents(imageDetails: ImageDetail, sbomEvents: SbomEvent[]): ArtifactorySecEvent {
    let pkgCount: number = 0;
    if (sbomEvents.length != 0) {
      pkgCount = sbomEvents[0].sbom.components.length;
    }
    const isPackageManger: boolean = pkgCount == 0 ? false : true;

    return {
      system: guessArtifactSystem(imageDetails.name),
      subType: ArtifactorySecEventType.Docker, // fill file type (zip tar txt etc..)
      repoFullName: imageDetails.repositoryName,
      imageCreatedAt: imageDetails.imagePushedAt,
      binariesCount: 1,
      pkgCount: pkgCount,
      hasPackageManager: isPackageManger,
      dockerVer: "",
      os: "",
      sha: imageDetails.imageDigestWithoutPrefix,
      dockerFileInRunTime: imageDetails.name,
      registry: imageDetails.name,
      tag: imageDetails.imageTags.join(", "),
      linkToRegistry: imageDetails.link,
      linkToTask: "",
      registryName: imageDetails.cloudEnv,
    };
  }

  getAdditionalInfoUrlForTrivyDebug(trivyVulnerability) {
    try {
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
      logger.error(
        `[${this.token.name}] uuid: ${this.uuid}, failed to get additional info link for trivy, info: ${JSON.stringify(
          trivyVulnerability,
          null,
          4,
        )}`,
        err,
      );
    }

    return trivyVulnerability.PrimaryURL;
  }
}

export default ArtifactoryBase;
