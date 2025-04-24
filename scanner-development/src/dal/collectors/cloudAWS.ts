import { ImageDetail as EcrImageDetail } from "@aws-sdk/client-ecr";
import { TaskDefinition } from "@aws-sdk/client-ecs";
import { FunctionConfiguration, FunctionList } from "aws-sdk/clients/lambda";
import * as fs from "fs";
import { ApplicationManager } from "../../appmgr/AppManager";
import { AsyncTracker } from "../../async-tracker.service";
import {
  fetchAWSData,
  generateContainerLink,
  getEC2CpuAsString,
  getImageAndTagData,
} from "../../codeOpenSourceTools/cloudTools/specifcTools/AWSBussinessLogic";
import {
  associateContainerToTaskDefinition,
  associateImagesWithTrails,
  associateLambdaFunctionToTrails,
  fetchEC2InstancesFromStorage,
  placeLambdaFunctionsInRegionBins,
  populateECRRegistryImages,
  populateRegionsFromResourcesData,
} from "../../codeOpenSourceTools/cloudTools/specifcTools/AWSDataAdapters";
import getAwsStorage from "../../codeOpenSourceTools/cloudTools/specifcTools/AWStorage";
import getRunningImagesCollection from "../../codeOpenSourceTools/cloudTools/specifcTools/RunningImagesCollection";
import { ImageInfo } from "../../entitis/artifactoryTypes";
import { ArtifactorySecEventSystem, guessArtifactSystem } from "../../entitis/ArtifactTypes";
import { ImageDetail } from "../../entitis/cloudTypes";
import { AWSCredReturnType, Token } from "../../entitis/collectorEntitisTypes";
import {
  AWSEcrRepositoryName,
  AWSLambdaTrailData,
  AWSRegion,
  AWSResource,
  ContainerImageName,
  FunctionArn,
  ImageName,
  Instances,
  OXAWSImageTrailData,
} from "../../entitis/connectorsSpecific/AWSRelatedTypes";
import { cleanToolName } from "../../helper/commonUtils";
import { formatSizeUnits } from "../../helper/generalUtils";
import { AES } from "../../helper/hash";
import { SettingsService } from "../../helper/service/scan-settings-service/service/settings-service";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import CloudBase from "../base/cloudBase";

const logger = loggerImport.getDebugLogger();

class CloudAWS extends CloudBase {
  appMgr: ApplicationManager;
  AWStorage: ReturnType<typeof getAwsStorage>;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.appMgr = new ApplicationManager(this.uuid);
    this.AWStorage = getAwsStorage();
  }

  async initializeAWS() {
    // Read resource and fetch them from cache if possible
    await this.AWStorage.Config(this.accountTokensEx);
  }

  async handleOxCrawlerAPI(): Promise<CrawledData> {
    const oxAWSstartTime = new Date().getTime();

    if (process.env.CLOUD_MOCK !== undefined) {
      const serializedData = AES(process.env.AES_KEY, process.env.AES_IV).decrypt(
        fs.readFileSync(process.cwd() + "/tests/src/AWSStorageMockData/AWStorage.bin").toString(),
      );

      const awsResourcesMap = new Map<string, AWSResource>(JSON.parse(serializedData.toString()));

      for (const [id, resource] of awsResourcesMap) {
        this.AWStorage.populateMap(id, resource);
      }
    } else {
      // Production
      await this.initializeAWS();

      // Roman: all AWS flow starts here
      const AWSFlow: ((tokenGetter: AWSCredReturnType) => Promise<void>)[] = [fetchAWSData];

      for (const singleFlow of AWSFlow) {
        const singleFlowPromises = this.accountTokensEx.map(
          async userAccount =>
            await AsyncTracker.runWithAsyncTracker(async () => {
              for (let retry = 0; retry < 3; retry++) {
                try {
                  await singleFlow(userAccount);
                } catch (err) {
                  if (`${err}`.includes("ExpiredTokenException")) {
                    logger.info(`[${this.token.name}] ExpiredTokenException, generating new token for ${singleFlow}`);

                    continue;
                  }
                }
                break;
              }
            }),
        );

        await Promise.all(singleFlowPromises);
      }
    }

    // Save all cloud artifacts into artifact-screen collection
    await this.retainAWSInformation();

    const appMgrResults = await this.collectAWSdataByOxEx();

    const oxCrawlerElapsedTime = Math.floor((new Date().getTime() - oxAWSstartTime) / (1000 * 60));
    StatesHelper.Instance.scanInfoStats.oxCrawlerTime = `${oxCrawlerElapsedTime} minutes`;

    logger.info(`[${this.token.name}] finish init cloud aws in execution time in minutes: ${oxCrawlerElapsedTime}`);

    return appMgrResults;
  }

  async retainAWSInformation() {
    if (process.env.CLOUD_DEBUG_SAVE !== undefined) {
      const allItems = this.AWStorage.getCollection((item: AWSResource) => true === true);

      fs.writeFileSync(
        process.cwd() + "/tests/src/AWSStorageMockData/AWStorage.bin",
        AES(process.env.AES_KEY, process.env.AES_IV).encrypt(JSON.stringify(Array.from(allItems))),
      );
    }
  }

  async collectAWSdataByOxEx(): Promise<CrawledData> {
    try {
      const regions = new Set<string>();
      const awsECRRepositories = new Map<AWSRegion, EcrImageDetail[]>();
      let awsECRImages = new Map<AWSEcrRepositoryName, { imageDetails: EcrImageDetail[] }>();
      const containerMap = new Map<ContainerImageName, any>();
      const imageAuditTrails = new Map<ImageName, OXAWSImageTrailData>();
      const lambdaFunctions = new Map<AWSRegion, FunctionList>();
      const lambdaAuditTrails = new Map<FunctionArn, AWSLambdaTrailData>();
      let instances: Instances = {};

      //
      // Go over all regions
      //
      populateRegionsFromResourcesData(regions);

      //
      // Find all ECR libraries and their images
      //
      logger.info(`[${this.token.name}] Aws Ecr start populating artifact data`);
      populateECRRegistryImages(awsECRRepositories, awsECRImages);
      logger.info(`[${this.token.name}] Aws Ecr finished populating artifact data`);

      //
      // Connect each container to it's corresponding ECS Task, and image to trails
      //
      associateContainerToTaskDefinition(containerMap);
      associateImagesWithTrails(imageAuditTrails, containerMap);

      //
      // Associate region and it's Lambda functions
      //
      placeLambdaFunctionsInRegionBins(lambdaFunctions);

      //
      // Create an object that associates a function to it's trail
      //
      associateLambdaFunctionToTrails(lambdaAuditTrails);

      //
      //  Fetch all found EC2 Instances from storage
      //
      fetchEC2InstancesFromStorage(instances);

      // Filter user selected images
      let userSelectedImages = false;
      const filteredImages = new Map<AWSEcrRepositoryName, { imageDetails: EcrImageDetail[] }>();
      for (const [key, imagesInfo] of awsECRImages) {
        logger.info(`[${this.token.name}] Aws Ecr key: ${key}, total image count: ${imagesInfo?.imageDetails?.length}`);
        const image = imagesInfo.imageDetails[0];
        if (this.repoSelectedByUser(image.repositoryName, image.repositoryName, new Date(image.imagePushedAt).toDateString())) {
          userSelectedImages = true;
          filteredImages.set(key, { imageDetails: imagesInfo.imageDetails });
        }
      }

      if (userSelectedImages) {
        logger.info(`[${this.token.name}] ECR scanning images selected by user`);
        awsECRImages = filteredImages;
      } else {
        logger.info(`[${this.token.name}] ECR no images selected by user, scanning all images`);
      }

      // Transform ECR.ImageDetails to OX.ImageDetails
      const timeHelper: TimeHelper = new TimeHelper(this.uuid);
      for (const [key, imagesInfo] of awsECRImages) {
        for (const image of imagesInfo.imageDetails) {
          try {
            const imageEx: ImageDetail = image as any;
            imageEx.imagePushedAtInDays = timeHelper.getTimeIntervalFronNowInDays(imageEx.imagePushedAt);
            imageEx.imagePullAtInDays = -1;
            if (imageEx.lastRecordedPullTime != undefined) {
              imageEx.imagePullAtInDays = timeHelper.getTimeIntervalFronNowInDays(imageEx.lastRecordedPullTime);
            }

            //
            // Don't use the token here, use it later on
            //
            //imageEx.token = token;
            imageEx.name = key;
            imageEx.imageDigestWithoutPrefix = imageEx.imageDigest.split(":")[1];
            imageEx.imageTags = imageEx.imageTags == undefined ? [] : imageEx.imageTags;
            let link = imageEx.name.replace(`${imageEx.registryId}.dkr.ecr.`, "");
            imageEx.region = link.split(".amazonaws")[0];
            imageEx.cloudEnv = "AWS";
            imageEx.link = `https://${imageEx.region}.console.aws.amazon.com/ecr/repositories/private/${imageEx.registryId}/${imageEx.repositoryName}/_/image/${imageEx.imageDigest}/details/?region=${imageEx.region}`;
          } catch (err) {
            logger.error(`[${this.token.name}] failed extend image: ${key}`, err);
          }
        }
      }

      return {
        regions: regions,
        repos: awsECRRepositories,
        images: awsECRImages,
        containers: Array.from(containerMap.values()),
        imageAuditTrails: imageAuditTrails,
        lambdaFunctions: lambdaFunctions,
        lambdaAuditTrails: lambdaAuditTrails,
        ec2Images: instances,
      };
    } catch (err) {
      logger.error(`[${this.token.name}] Error initializing connector (non blocking)`, err);
      StatesHelper.Instance.globalApisFails.add(cleanToolName(this.token.name));
    }
    return null;
  }

  setImages(cloudObj: any) {
    const addedImages = new Set();
    const imageIrrelevantTimeInMonths = SettingsService.Instance.irrelevantImageTimeInMonths();
    const MONTH_IN_MILLISECONDS = 1000 * 60 * 60 * 24 * 30;
    for (const [name, entry] of cloudObj.images) {
      try {
        if (!name) {
          logger.error(`[${this.token.name}] no name for images`);
          continue;
        }

        let images: ImageDetail[] = entry.imageDetails;

        logger.info(`[${this.token.name}] found ${images.length} images for name: ${name} before filter`);

        //Keep only with time
        images = images.filter(i => i.imagePushedAtInDays !== -1 || i.imagePushedAt);

        //Sort to have the newest first
        images = images.sort((a, b) => new Date(b.imagePushedAt).getTime() - new Date(a.imagePushedAt).getTime());

        if (images.length == 0) {
          continue;
        }

        logger.info(`[${this.token.name}] found ${images.length} images for name: ${name} after filter`);

        // relevant images, are running images
        const relevantImages: ImageDetail[] = [];

        const running = [];
        for (const image of images) {
          if (getRunningImagesCollection().isRunning(name, image.imageTags[0] ?? "latest")) {
            image.imageRunningInCloud = true;

            image.runningContainerDescription =
              getRunningImagesCollection().getIS(`${name}:${image.imageTags[0] ?? "latest"}`) ?? "Running Cloud Container";

            running.push(image);
          }
        }
        logger.info(`[${this.token.name}] found ${running.length} running images for name: ${name}`);

        // Only consider images that were pushed in the last 6 months
        if (!(Date.now() - new Date(images[0].imagePushedAt).getTime() > MONTH_IN_MILLISECONDS * imageIrrelevantTimeInMonths)) {
          relevantImages.push(images[0]);
        } else {
          logger.info(`[${this.token.name}] not scanning image cause too old (limitInMonths: ${imageIrrelevantTimeInMonths})`, {
            debug: images[0].imagePushedAt,
          });
        }
        relevantImages.push(...running);

        relevantImages.forEach(image => {
          let key = image.imageDigest;
          if (addedImages.has(key)) {
            logger.info(`[${this.token.name}] image name: ${image.name} already exist by digest: ${image.imageDigest}`);
            return;
          }
          addedImages.add(key);

          const imageInfo = new ImageInfo();
          imageInfo.image = image;
          imageInfo.image.cloudEnv = ArtifactorySecEventSystem.ECR;
          image.imageId = `${image.name}_${ArtifactorySecEventSystem.ECR}`;
          this.imagesObj.push(imageInfo);
        });
      } catch (err) {
        logger.error(`[${this.token.name}] failed update single item for all images from registry via app manager, service: ${name}`, err);
      }
    }
  }
}

export default CloudAWS;

export interface CrawledData {
  regions: Set<string>;
  repos: Map<string, EcrImageDetail[]>;
  images: Map<string, { imageDetails: EcrImageDetail[] }>;
  containers: any[];
  imageAuditTrails: Map<string, OXAWSImageTrailData>;
  lambdaFunctions: Map<string, FunctionList>;
  lambdaAuditTrails: Map<string, AWSLambdaTrailData>;
  ec2Images: Instances;
}
