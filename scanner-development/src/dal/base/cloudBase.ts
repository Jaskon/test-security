import PromisePool from "@supercharge/promise-pool/dist";
import ms from "ms";
import { readFile, stat } from "node:fs/promises";
import { AsyncTracker } from "../../async-tracker.service";
import ArtifactoryToolsCreator from "../../codeOpenSourceTools/artifactoryTools/artifactoryToolsCreator";
import ArtifactoryToolsManager from "../../codeOpenSourceTools/artifactoryTools/artifactoryToolsManager";
import ArtifactoryDownloadCreator from "../../codeOpenSourceTools/artifactoryToolsDownload/artifactoryDownloadCreator";
import ArtifactoryDownloadManager from "../../codeOpenSourceTools/artifactoryToolsDownload/artifactoryDownloadManager";
import CloudToolsCreator from "../../codeOpenSourceTools/cloudTools/cloudToolsCreator";
import CloudToolsManager from "../../codeOpenSourceTools/cloudTools/cloudToolsManager";
import getAwsKeys from "../../codeOpenSourceTools/cloudTools/specifcTools/AWSCredentialsProvider";
import { ArtifactoryDownloadToRun, ArtifactoryResourceToRun, ImageInfo, SbomEvent } from "../../entitis/artifactoryTypes";
import { ArtifactorySecEvent, ArtifactorySecEventType, guessArtifactSystem } from "../../entitis/ArtifactTypes";
import { CloudResourcesToRun, CloudSecurityEvent, CloudTypes, ImageDetail } from "../../entitis/cloudTypes";
import {
  addSeverityChangedReason,
  AlertSeverity,
  SecurityAlertType,
  SecurityEvent,
  setSecEventFromDelta,
} from "../../entitis/codeRepoTypes";
import { AWSCredReturnType, ResourceType, Token } from "../../entitis/collectorEntitisTypes";
import Constant from "../../entitis/constant";
import { ExtraInfo } from "../../entitis/issuesTypes";
import { Resource } from "../../entitis/orgPolicyTypes";
import { CacheResolver } from "../../helper/cache/cache.resolver";
import { CacheIdentifier } from "../../helper/cache/cache.service";
import { Cache } from "../../helper/cache/cache.types";
import { getFakeCredentials } from "../../helper/connectorsSpecific/awsFakeK8Connector";
import { PerformanceTelemetry } from "../../helper/decorators/PerformanceTelemetry";
import { isDevelopment, isLocalDevelopment } from "../../helper/envUtils";
import MemoryMonitorHelper from "../../helper/IO/memoryMonitorHelper";
import { ARTIFACT_HEAVY_SIZE_THRESHOLD_BYTES } from "../../helper/repository-matching/artifacts-constants";
import { DockerApi } from "../../helper/repository-matching/docker-api";
import { ImageAnalysis, RepositoryMatcher } from "../../helper/repository-matching/RepositoryMatcher";
import { GoogleOpenSourceInsightsHelper } from "../../helper/sbom/googleOpenSourceInsightsHelper";
import AlertRecommendationHelper from "../../helper/service/alertRecommendationHelper";
import AWSinfoHelper from "../../helper/service/awsInfoHelper";
import BlameHelper from "../../helper/service/blameHelper";
import CloudGraphHelper from "../../helper/service/cloudGraphHelper";
import SecretValidationHelper from "../../helper/service/secretValidationHelper";
import StatesHelper from "../../helper/statesHelper";
import { millisToMinutesAndSeconds, ScanPhaseTime, sendScannerPhaseTimeTelemetry } from "../../helper/telemetry-utils";
import loggerImport from "../../logger";
import { severityReasons } from "../../package-index";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";
import { ImageScanInfo } from "./artifactoryBase";
import CollectorBase from "./collectorBase";
const Timeout = require("await-timeout");
const logger = loggerImport.getDebugLogger();

abstract class CloudBase extends CollectorBase {
  totalFinish: number = 0;
  accountTokens: Function[] = [];
  accountTokensEx: AWSCredReturnType[] = [];
  imagesObj: ImageInfo[] = [];
  cacheResovler: CacheResolver;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, ResourceType[ResourceType.cloud], policyConfiguration, jsonApplicationDiscoveryOverview);
  }

  initLib() {}
  async handleOxCrawlerAPI(): Promise<any> {}
  setImages(imagesInfoPerAccount: any) {}

  async oxCloudInit() {
    logger.info(`[${this.token.name}] try init lib for: ${this.token.name} for ox`);

    // Testing K8s locally
    if (isLocalDevelopment()) {
      this.accountTokensEx = getFakeCredentials();
    } else {
      this.accountTokensEx = await this.token.getAWSCredAccountsEx(this.uuid, this.orgName);
    }

    // Save keys for additional services like IAC Verification
    getAwsKeys().registerKeys(this.accountTokensEx);

    logger.info(`[${this.token.name}] finish init lib for: ${this.token.name} for ox, account count: ${this.accountTokensEx.length}`);
  }

  async getResourcesToRunByOx(toolsCreator: CloudToolsCreator) {
    try {
      const proms = toolsCreator.securityTools.map(i => i.getToolResourceToRun());
      const allResources = await Promise.all(proms);
      let resourcesToRun = allResources.flat();

      if (!StatesHelper.Instance.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.cspm]]) {
        resourcesToRun = resourcesToRun.filter(i => i.severity != AlertSeverity.Low);
      }

      return resourcesToRun;
    } catch (err) {
      logger.error(`[${this.token.name}] failed to get resources to run by ox for cloud`, err);
    }
    return [];
  }

  async collect(resources: Resource[], rulesManager: RulesManager): Promise<boolean[]> {
    try {
      if (StatesHelper.Instance.isSofi) {
        return [];
      }

      const startTime = new Date().getTime();
      this.cacheResovler = new CacheResolver(this.orgName, rulesManager.mongoConnect);

      await this.oxCloudInit();

      if (process.env.IAC_VERIFICATION_TESTING) {
        return [];
      }

      //Init helpers
      await this.initLib();
      this.blameHelper = new BlameHelper(rulesManager.blameQueue, this.uuid, this.orgName);
      this.secretValidationHelper = new SecretValidationHelper(rulesManager.secretValidationQueue, this.uuid, this.orgName);
      this.alertRecommendationHelper = new AlertRecommendationHelper(rulesManager.alertRecommendationQueue, this.uuid, this.orgName);
      this.googleOpenSourceInsightsHelper = new GoogleOpenSourceInsightsHelper(rulesManager.openSourceInfoQueue, this.orgName, this.uuid);

      logger.info(
        `[${this.token.name}] promisees poll start for: ${this.token.name}, url: ${this.token.host}, tokens: ${this.accountTokensEx.length}`,
      );

      //Start count time for prowler
      const startTimeProwler = new Date().getTime();

      //Execute by prowler and other ox tools
      const awsInfo = new AWSinfoHelper(rulesManager.awsCrawlerQueue, this.uuid, this.orgName);
      const cloudGraph = new CloudGraphHelper(rulesManager.cloudGraphQueue, this.uuid, this.orgName, rulesManager.applicationsManager);
      const proms = this.accountTokensEx.map(async tokenGetter => {
        const token = await (await tokenGetter(false)).getToken();
        return this.runCloudServices(rulesManager, awsInfo, cloudGraph, token);
      });

      //Set 3 steps for progress bar,
      if (StatesHelper.Instance.cloudScanTotalCount == 0) {
        StatesHelper.Instance.cloudScanTotalCount += 3;
        await rulesManager.resultsHandler.updateScanInfoStateWithDBupdate();
      }

      if (this.accountTokensEx.length === 0) {
        if (this.token.name.toLowerCase() === "prowler") {
          StatesHelper.Instance.globalApisFails.add("prowler-cspm");
        } // TO DO dvir and roman add microsoft once implemented
      }

      await Promise.all(proms);

      await MemoryMonitorHelper.Instance.printSnapshot(
        this.orgName,
        this.uuid,
        `${this.token.name} after runSingleCloudSecurityResourceEvalByOx`,
      );

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `${this.token.name} after setInfoAWS`);

      StatesHelper.Instance.cloudScanCountProgress++;
      await rulesManager.resultsHandler.updateScanInfoStateWithDBupdate();

      //For collecting all the rest of resources
      //like security events from other vendors
      await this.runSingleCloudSecurityResourceEval(rulesManager, resources);

      await MemoryMonitorHelper.Instance.printSnapshot(
        this.orgName,
        this.uuid,
        `${this.token.name} after runSingleCloudSecurityResourceEval`,
      );

      StatesHelper.Instance.cloudScanCountProgress++;
      await rulesManager.resultsHandler.updateScanInfoStateWithDBupdate();

      //Finish count time for prowler
      const elapsedTimeForProwler = Math.floor((new Date().getTime() - startTimeProwler) / (1000 * 60));

      StatesHelper.Instance.scanInfoStats.prowlerTime = `${elapsedTimeForProwler} minutes, ${new Date().toTimeString()}`;
      await sendScannerPhaseTimeTelemetry(ScanPhaseTime.ScanCloudProwlerPhaseTime, this.orgName, this.uuid, Number(elapsedTimeForProwler));

      logger.info(
        `[${this.token.name}] promisees poll finish for: ${this.token.name}, url: ${this.token.host}, execution time in minutes: ${elapsedTimeForProwler}`,
      );

      if (this.token.name === Constant.oxCloudConnectorName) {
        await this.handleOxCrawler(rulesManager);
      }
      StatesHelper.Instance.cloudScanCountProgress++;
      await rulesManager.resultsHandler.updateScanInfoStateWithDBupdate();

      //Set some timeline info
      const totalElapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));
      StatesHelper.Instance.scanInfoStats.totalCloudScanTime = `${totalElapsedTime} minutes, ${new Date().toTimeString()}`;

      await sendScannerPhaseTimeTelemetry(ScanPhaseTime.ScanCloudPhaseTime, this.orgName, this.uuid, totalElapsedTime);

      logger.info(
        `[${this.token.name}] promisees poll finish for: ${this.token.name} ox crawler, url: ${this.token.host}, execution time in minutes: ${totalElapsedTime}`,
      );
    } catch (err) {
      const errInfo = `[${this.token.name}] failed collect all resources for cloud, err: ${err}`;
      logger.error(errInfo, err);
    }

    return [];
  }

  runCloudServices(rulesManager: RulesManager, awsInfo: AWSinfoHelper, cloudGraph: CloudGraphHelper, token) {
    const p1 = awsInfo.setInfoAWS(token);
    const p2 = cloudGraph.setCloudGraph(token);
    const p3 = this.runSingleCloudSecurityResourceEvalByOx(rulesManager, token);
    return Promise.all([p1, p2, p3]);
  }

  async handleOxCrawler(callObj: RulesManager) {
    try {
      const startTime = new Date().getTime();

      logger.info(`[${this.token.name}] starting to wait for cloud crawlers`);
      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `[${this.token.name}] before handleOxCrawler`);

      const resCrawlerByOx = await this.handleOxCrawlerAPI();

      this.setImages(resCrawlerByOx);
      callObj.applicationsManager.updateAppManagerWithDiscoverdCloudItems(resCrawlerByOx);

      //Run tools on images from cloud registry
      await this.collectAndAddScanResultsForImages(callObj);

      await callObj.applicationsManager.updateAppManagerWithImageItems(this.imagesObj);

      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);
      await sendScannerPhaseTimeTelemetry(ScanPhaseTime.ScanCloudPhaseTime, this.orgName, this.uuid, Number(elapsedTime));

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, `[${this.token.name}] after handleOxCrawler`);

      logger.info(`[${this.token.name}] finish to wait for cloud crawlers, execution time in minutes: ${elapsedTime}`);
    } catch (err) {
      logger.error(`[${this.token.name}] failed collect crawlers resources for cloud`, err);
    }
  }

  async collectAndAddScanResultsForImages(callObj: RulesManager) {
    try {
      if (!StatesHelper.Instance.isContainerEnable) {
        logger.info(`[${this.token.name}] container scan is not enabled, skipping`);
        return;
      }
      if (process.env.DISABLE_CONTAINERS) {
        logger.info(`[${this.token.name}] ignoring ecr due to DISABLE_CONTAINERS from env`);
        return;
      }
      const isEnable = process.env[`TOOLS_TRIVY-CONTAINER`] === "enabled";
      if (!isEnable) {
        logger.info(`[${this.token.name}] not setting artifacts repos, url: ${this.token.host} due to disable tool`);
        return;
      }

      callObj.toolProgressBase.updateLastProgressTime("default", "cloud");

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "before container scanning");

      const startTime = new Date().getTime();
      logger.info(`[${this.token.name}] run artifactory tools on image count: ${this.imagesObj.length} from cloud base`);

      const properToken = await this.fetchTokenWithECRPermissions();
      const imagesScanInfo: ImageScanInfo[] = [];

      StatesHelper.Instance.scanInfoStats.totalImages += this.imagesObj.length;
      await callObj.resultsHandler.updateScanInfoStateWithDBupdate();

      let progressIndex = 0;
      let progressDiff = 0;
      let failedScannedArtifacts = 0;

      if (isDevelopment()) {
        if (StatesHelper.Instance.orgName === "org_16U6jxMKWdXjVaAJ") {
          this.imagesObj = this.imagesObj.filter(
            i => i.image.name.includes("policy-service") || i.image.name.includes("scanner") || i.image.name.includes("cloner-service"),
          );
          logger.info(`[${this.token.name}] start to run tools scan on: ${this.imagesObj.length} for debug`);
        }
      }

      await PromisePool.for(this.imagesObj)
        .withConcurrency(StatesHelper.Instance.concurrentRepoScans)
        .process(async (image: ImageInfo) => {
          await AsyncTracker.runWithAsyncTracker(async () => {
            AsyncTracker.setValue("ox-image-name", image.image.name);
            AsyncTracker.setValue("ox-image-id", image.image.imageDigest);
            try {
              const getECRToken = this.token.getEcrCredentials(image.image.registryId, image.image.region);
              // If getECRToken is available use it else use properToken
              const scanRes = await this.collectAndAddScanResultsForSingleImages(callObj, image, getECRToken || properToken);

              progressIndex++;
              if (progressIndex % 2 == 0 || progressIndex == 1) {
                StatesHelper.Instance.artifactScanCountProgress++;
                await callObj.resultsHandler.updateScanInfoStateWithDBupdate();
                progressDiff++;
              }
              if (scanRes) {
                imagesScanInfo.push(scanRes);
              } else {
                failedScannedArtifacts++;
                StatesHelper.Instance.failedArtifactsScan.add(image.image.imageId);
              }
            } catch (err) {
              logger.error(`[${this.token.name}] failed to run ${image.image.name} error`, err);
            }
          });
        });
      logger.info(
        `[${this.token.name}] finish to run tools scan on: ${imagesScanInfo.length} images, from total of: ${this.imagesObj.length}`,
      );

      const alertsInfo = {
        totalAlerts: 0,
        totalAlertsSecEvents: 0,
        totalAlertsSbom: 0,
        fromCash: 0,
        noneCash: 0,
        totalImages: 0,
      };

      progressIndex = 0;
      await PromisePool.for(imagesScanInfo)
        .withConcurrency(StatesHelper.Instance.concurrentRepoScans)
        .process(async (imageScanInfo: ImageScanInfo) => {
          await AsyncTracker.runWithAsyncTracker(async () => {
            AsyncTracker.setValue("ox-image-name", imageScanInfo.imageObj.image.name);
            AsyncTracker.setValue("ox-image-id", imageScanInfo.imageObj.image.imageDigest);
            try {
              await this.parseAndSetResFromTools(imageScanInfo, alertsInfo);

              progressIndex++;
              if (progressIndex % 2 == 0 && StatesHelper.Instance.scanInfoStats.totalImages > 1) {
                StatesHelper.Instance.artifactScanCountProgress++;
                await callObj.resultsHandler.updateScanInfoStateWithDBupdate();
                progressDiff++;
              }
            } catch (err) {
              logger.error(`[${this.token.name}] failed to run ${imageScanInfo.imageObj.image.name} error`, err);
            }
          });
        });

      const diff = this.imagesObj.length - progressDiff;
      if (diff > 0) {
        StatesHelper.Instance.artifactScanCountProgress += diff;
        await callObj.resultsHandler.updateScanInfoStateWithDBupdate();
      }

      const elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));
      StatesHelper.Instance.scanInfoStats.imageScanTimeInMinutes = elapsedTime.toString();

      imagesScanInfo.forEach(image => {
        if (!image.resource) {
          return;
        }
        if (!image.resource.scannedImage) {
          failedScannedArtifacts++;
          StatesHelper.Instance.failedArtifactsScan.add(image.imageObj.image.imageId);
        }
      });

      await MemoryMonitorHelper.Instance.printSnapshot(this.orgName, this.uuid, "after container scanning");

      logger.info(
        `[${this.token.name}] finish to run scan on: ${imagesScanInfo.length} images, alertsInfo: ${JSON.stringify(
          alertsInfo,
        )}, from total of: ${
          this.imagesObj.length
        }, elapsedTime: ${elapsedTime} minutes, failedScannedArtifacts: ${failedScannedArtifacts}`,
      );
    } catch (err) {
      logger.error(`[${this.token.name}] failed collect and add scan results for images`, err);
    }
  }

  async fetchTokenWithECRPermissions(): Promise<Token | null> {
    for (const tokenGetter of this.accountTokensEx) {
      const token = (await tokenGetter(true)).getToken();
      if (token.accessToDownloadECRonAWS) return token;
    }
    return null;
  }

  @PerformanceTelemetry()
  async parseAndSetResFromTools(imageScanInfo: ImageScanInfo, alertsInfo: any) {
    const imageObj: ImageInfo = imageScanInfo.imageObj;

    try {
      const startTime = new Date().getTime();
      const artifactoryToolsCollector: ArtifactoryToolsManager = imageScanInfo.artifactoryToolsManager;
      const resource: ArtifactoryResourceToRun = imageScanInfo.resource;
      const identifier: CacheIdentifier = imageScanInfo.identifier;
      let secAlerts: SecurityEvent[] = imageScanInfo.secAlertsFromCash;
      let sbomAlerts: SbomEvent[] = imageScanInfo.sbomAlertsFromCash;

      alertsInfo.totalImages++;

      if (artifactoryToolsCollector) {
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
              logger.info(`[${this.token.name}] no analisys file found for ${imageObj.image.name}`);
            }
          } catch (err) {
            logger.error(`[${this.token.name}] failed to get base image, image: ${imageObj.image.name}`, err);
          }

          //Security alerts
          secAlerts = await artifactoryToolsCollector.collectAlertsWithoutWait();

          //Compliance
          const complianceAlerts = await artifactoryToolsCollector.collectComplianceAlerts();
          complianceAlerts.forEach(i => {
            secAlerts.push(i);
          });
        }

        //Sbom
        sbomAlerts = await artifactoryToolsCollector.collectSbom();

        //Run blame and other service to enrich sec alerts and sbom data before cash
        await this.setArtifactSecurityEventForFakeApp(secAlerts, sbomAlerts, imageScanInfo);

        //Cash
        for (const sbom of sbomAlerts) {
          await this.cacheResovler.setSbomCache(identifier, sbom);
        }
        if (secAlerts.length) {
          await this.cacheResovler.setForCache<SecurityEvent>(identifier, secAlerts, Cache.SecurityEvents);
        }

        await this.fileHelper.deleteAllFilesInRootDir(resource.dirWhereToPutRes);
        this.fileHelper.deleteFile(resource.netShareDownloadArtifactPathForScan);

        logger.info(
          `[${this.token.name}] artifact scan res for image ${imageObj.image.name}, secAlerts: ${secAlerts.length}, sbom: ${sbomAlerts.length}`,
        );
      } else {
        alertsInfo.fromCash++;
      }

      // Set cache for this image
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
            extraInfo.push({
              key: "Machine Type",
              value: "EC2",
            });
            extraInfo.push({
              key: "Instance",
              value: "i-029a5dc63fb02711c",
            });
            extraInfo.push({
              key: "Location",
              value: "us-east-1",
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

  async collectAndAddScanResultsForSingleImages(callObj: RulesManager, imageObj: ImageInfo, properToken: Token | undefined = undefined) {
    try {
      if (properToken || process.env.DEBUG) {
        if (properToken.accessToDownloadECRonAWS != "") {
          let Token: Token = await this.CreateTokenFromToken(properToken);
          Token.password = properToken.accessToDownloadECRonAWS;
          return await this.runArtifactoryToolsOnImage(callObj, imageObj, Token);
        } else {
          return await this.runArtifactoryToolsOnImage(callObj, imageObj, properToken);
        }
      } else {
        logger.error(`[${this.token.name}] failed collectAndAddScanResultsForSingleImages images: ${imageObj.image.name}`);
      }
    } catch (err) {
      logger.error(`[${this.token.name}] failed collect and add scan results for single images: ${imageObj.image.name}`, err);
    }
  }

  async CreateTokenFromToken(token: Token): Promise<Token> {
    return new Token(
      token.type,
      token.name,
      token.friendlyName,
      token.userName,
      token.host,
      token.password,
      token.isTool,
      token.protocol,
      token.port,
      token.apiVersion,
      token.strictSSL,
      token.executionOrder,
      token.secret,
      token.tokenSession,
      token.accountName,
      token.tenantId,
      token.clientId,
      token.clientSecret,
      token.subscriptionId,
    );
  }

  @PerformanceTelemetry()
  async runArtifactoryToolsOnImage(callObj: RulesManager, imageObj: ImageInfo, token: Token) {
    let startTime = Date.now();
    try {
      let cacheFinishTime = 0;
      let downloadFinishTime = 0;
      let toolsFinishTime = 0;
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
        const cacheStartTime = Date.now();
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

        logger.info(
          `[${this.token.name}] retrieve sec alerts from cache for image: ${imageObj.image.name}, secAlertsFromCash: ${
            imageScanInfo.secAlertsFromCash.length
          }, sbomAlertsFromCash: ${imageScanInfo.sbomAlertsFromCash.length}, (${ms(cacheFinishTime)})`,
        );
      } else {
        //First download the artifacts
        const resourceToDownload = new ArtifactoryDownloadToRun(this.uuid, this.orgName, imageObj.image);
        logger.info(
          `[${this.token.name}] try run download artifactory tools on image name: ${imageObj.image.name}, to: ${resourceToDownload.artifactoryResultsDir}`,
        );

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
        await artifactoryDownloadCollector.waitForAlerts();

        downloadFinishTime = Date.now() - downloadStartTime;

        //Run the security tools on the downloaded artifact
        const resource = new ArtifactoryResourceToRun(this.uuid, this.orgName, imageObj.image);
        //This is shared data dir
        resource.netShareDownloadArtifactPathForScan = `${resourceToDownload.artifactoryResultsDir}/artifactdownload.tar`;
        try {
          const stats = await stat(resource.netShareDownloadArtifactPathForScan);
          imageObj.image.isHeavy = stats.size > ARTIFACT_HEAVY_SIZE_THRESHOLD_BYTES;
        } catch (error) {
          logger.error(
            `[${this.token.name}] image: ${imageObj.image.name}. cannot run trivy on artifact tar: ${resource.netShareDownloadArtifactPathForScan}, file not exist`,
            error,
          );
          return;
        }

        //Use token for this image only
        const toolsCreator = new ArtifactoryToolsCreator(this.uuid, this.orgPolicyParser, this.orgName, this.securityToolsQueue, token);
        toolsCreator.setTools();

        if (StatesHelper.Instance.isContainerEnable) {
          try {
            imageScanInfo.resource = resource;
            await RepositoryMatcher.instance.analyseImage(resource);
          } catch (err) {
            logger.error(`[${this.token.name}] failed to get base image, image: ${imageObj.image.name}`, err);
          }
        }

        const artifactoryToolsCollector = new ArtifactoryToolsManager(
          this.uuid,
          this.orgPolicyParser,
          this.orgName,
          resource,
          this.securityToolsQueue,
          toolsCreator,
          callObj.toolProgressBase,
        );
        const toolsStartTime = Date.now();
        await artifactoryToolsCollector.sendScanRequest();
        imageScanInfo.artifactoryToolsManager = artifactoryToolsCollector;
        //Only wait for res, parsing will be done at the end
        await artifactoryToolsCollector.waitForAlerts();
        toolsFinishTime = Date.now() - toolsStartTime;

        // const toolsStats = artifactoryToolsCollector.executionStats;
        // for (const stat of toolsStats.toolsExecutionTimes) {
        //   // const telemetryData = {
        //   //   "ox-job-name": stat.tool,
        //   //   "ox-job-time-waiting": stat.inQtime,
        //   //   "ox-job-time-processing": stat.toolExecutionTime,
        //   //   "ox-job-time-total": stat.totalTime,
        //   //   "ox-job-success": stat.jobSuccess,
        //   // };
        //   if (stat.totalTime > Constant.maxTimeToPrintWarnInLog) {
        //     logger.warn(
        //       `${this.token.name}, high time for finish run artifactory tool ${stat.tool} on image: ${imageObj.image.name} (${ms(
        //         stat.toolExecutionTime || 0,
        //       )}) json: ${JSON.stringify(stat)}`,
        //       undefined,
        //       // telemetryData,
        //     );
        //   } else {
        //     logger.info(
        //       `${this.token.name}, finish run artifactory tool ${stat.tool} on image: ${imageObj.image.name} (${ms(
        //         stat.toolExecutionTime || 0,
        //       )}) json: ${JSON.stringify(stat)}`,
        //       // telemetryData,
        //     );
        //   }
        // }

        logger.info(`[${this.token.name}] finish run tools on image: ${imageObj.image.name} (${ms(toolsFinishTime)})`);
      }

      logger.info(`[${this.token.name}] finished processing artifact: ${imageObj.image.name} (${ms(toolsFinishTime)})`, {
        "ox-image-get-cache-time": cacheFinishTime || undefined,
        "ox-image-download-time": downloadFinishTime || undefined,
        "ox-image-tools-time": toolsFinishTime || undefined,
        "ox-image-total": Date.now() - startTime,
      });
      return imageScanInfo;
    } catch (err) {
      logger.error(
        `[${this.token.name}] failed to run artifactory from cloud for image: ${imageObj.image.name} (${ms(Date.now() - startTime)})`,
        err,
        { "ox-image-total": Date.now() - startTime },
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
    };
  }

  async runSingleCloudSecurityResourceEval(callObj, resources) {
    logger.info(`[${this.token.name}] start collect and run policy for each single cloud event`);

    try {
      const cloudObj = {};
      cloudObj["resourceType"] = ResourceType[ResourceType.cloud];

      const apisProms = resources.map(resource => this.addFirstLevelItemCloudObj(cloudObj, resource));

      await Promise.all(apisProms);

      this.setRelevantSecEvents(cloudObj, callObj);

      await callObj.applicationsManager.updateAppManagerCloudItem(cloudObj);

      logger.info(`[${this.token.name}] finish collect and run policy for each single cloud event`);

      return true;
    } catch (err) {
      logger.error(`failed collect resources for cloud events, err: ${err}`);
    }
  }

  async runSingleCloudSecurityResourceEvalByOx(callObj, token: Token) {
    logger.info(`[${this.token.name}] start collect and run policy for each single cloud ox tool, account name: ${this.token.accountName}`);

    let totalNumberOfViolations = 0;

    //Create ox cloud tool based on token cred
    const toolsCreator = new CloudToolsCreator(this.uuid, this.orgPolicyParser, this.orgName, this.securityToolsQueue, token);
    toolsCreator.setTools();

    const resourcesToRun = await this.getResourcesToRunByOx(toolsCreator);

    logger.info(`[${this.token.name}] total cloud resources to execute ${resourcesToRun.length} for account name: ${token.accountName}`);

    //3 steps added as part of additional steps on cloud
    StatesHelper.Instance.cloudScanTotalCount += resourcesToRun.length + 3;
    await callObj.resultsHandler.updateScanInfoStateWithDBupdate();

    let defaultN = 50;
    try {
      if (process.env.CONCURRENT_PROWLER) {
        const num = parseInt(process.env.CONCURRENT_PROWLER);
        if (num && num > 0) {
          defaultN = num;
          logger.info(`[${this.token.name}] set CONCURRENT_PROWLER for: ${defaultN}`);
        }
      }
    } catch (err) {
      logger.error(`[${this.token.name}] failed set CONCURRENT_PROWLER for: ${process.env.CONCURRENT_PROWLER}`, err);
    }

    logger.info(`using CONCURRENT_PROWLER for: ${defaultN}`);

    await PromisePool.for(resourcesToRun)
      .withConcurrency(defaultN)
      .process(async (resourceToRun: CloudResourcesToRun) => {
        try {
          const cloudObj = {};
          const startTime = new Date().getTime();

          //process cloud event
          const numberOfViolations = await Timeout.wrap(
            this.processCloudItem(cloudObj, callObj, resourceToRun, toolsCreator),
            1000 * 60 * 45,
            `timeout process cloud test`,
          );

          let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - startTime);

          totalNumberOfViolations += numberOfViolations;
          this.totalFinish++;
          logger.info(
            `[${this.token.name}] finish process cloud test: ${resourceToRun.name} in ${elapsedTime} minutes for account name: ${token.accountName}, number of violation: ${numberOfViolations}`,
          );

          StatesHelper.Instance.cloudScanCountProgress++;
          await callObj.resultsHandler.updateScanInfoStateWithDBupdate();
        } catch (err) {
          StatesHelper.Instance.scanInfoStats.failedProcessSingleCloud++;

          logger.error(
            `[${this.token.name}] failed collect resources for cloud test: ${resourceToRun.name}, for account name: ${token.accountName}`,
            err,
          );
        }
      });

    logger.info(
      `[${this.token.name}] finish collect and run policy for each single cloud ox tool for account name: ${token.accountName}, total number of violations: ${totalNumberOfViolations}`,
    );
  }

  async processCloudItem(cloudObj: any, callObj: RulesManager, resourceToRun: CloudResourcesToRun, toolsCreator: CloudToolsCreator) {
    const securityToolsCollector = new CloudToolsManager(
      this.uuid,
      this.orgPolicyParser,
      this.orgName,
      resourceToRun,
      this.securityToolsQueue,
      toolsCreator,
      callObj.toolProgressBase,
    );

    await securityToolsCollector.sendScanRequest();

    const numberOfViolations = await this.collectScanResults(securityToolsCollector, resourceToRun, cloudObj);
    await callObj.applicationsManager.updateAppManagerCloudItem(cloudObj);

    return numberOfViolations;
  }

  setRelevantSecEvents(externalSecurityObj: any, callObj: any) {
    try {
      const secAlerts: CloudSecurityEvent[] = this.jsonHelper.lookupArrayVal(
        externalSecurityObj,
        CloudTypes[CloudTypes.cloudSecurityEvents],
      );

      const relevantAlets = [];
      for (const secAlert of secAlerts) {
        if (
          !StatesHelper.Instance.tooByCatLowEnabled[SecurityAlertType[SecurityAlertType.cspm]] &&
          secAlert.severity == AlertSeverity.Low
        ) {
          continue;
        }

        relevantAlets.push(secAlert);
      }
      externalSecurityObj[CloudTypes[CloudTypes.cloudSecurityEvents]] = relevantAlets;

      logger.info(`[${this.token.name}] relevant sec events, count: ${relevantAlets.length}`);
    } catch (err) {
      logger.error(`[${this.token.name}] failed set relevant sec events`, err);
    }
  }

  async collectScanResults(securityToolsCollector: CloudToolsManager, resourceToRun: CloudResourcesToRun, cloudObj: any) {
    try {
      const alerts: CloudSecurityEvent[] = await securityToolsCollector.collectAlerts();
      cloudObj[CloudTypes[CloudTypes.cloudSecurityEvents]] = alerts;

      return alerts.filter(i => i.isViolation).length;
    } catch (err) {
      logger.error(
        `[${this.token.name}] uuid: ${this.uuid}, failed extend Security alerts data for: ${JSON.stringify(resourceToRun.name)}`,
        err,
      );
    }
    return 0;
  }

  async addFirstLevelItemCloudObj(cloudObj: any, resource: Resource) {
    let data = [];

    try {
      if (this.funcNames.has(resource.name)) {
        data = await this[resource.name]();
        cloudObj[resource.name] = data;
      } else {
        cloudObj[resource.name] = [];
      }

      return true;
    } catch (err) {
      logger.error(`[${this.token.name}] failed collect resources: ${resource.name}`, err);
    }
    return false;
  }

  prepareImagesList() {
    try {
    } catch (err) {}
  }
}

export default CloudBase;
