import PromisePool from "@supercharge/promise-pool/dist";
import axios, { AxiosInstance } from "axios";
import { ArtifactorySecEventSystem } from "../../entitis/ArtifactTypes";
import { ImageInfo } from "../../entitis/artifactoryTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ArtifactoryBase from "../base/artifactoryBase";

const logger = loggerImport.getDebugLogger();
const concurrent_pool_call = 5;

class NexusContainerRegistry extends ArtifactoryBase {
  timeHelper: TimeHelper;
  private axiosInstance: AxiosInstance;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
    _ArtifactoryURL: string,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);
    try {
      logger.info(`${this.token.name}, initialize with host: ${this.token.host}, user: ${this.token.userName}`);
      // Create axios instance once
      this.axiosInstance = axios.create({
        baseURL: this.token.host,
        auth: {
          username: this.token.userName,
          password: this.token.password,
        },
      });
    } catch (err) {
      logger.error(`${this.token.name}, failed initialize with host: ${this.token.host}, user: ${this.token.userName}, err: ${err}`);
    }
  }
  async initLib() {}

  /*
  Arugs - None
  Design - Going over all docker types repo and getting 2 latest images that we modified
  return - Returning an array of extandDates which hold repo name uri and date when file was modified.
  */
  private async getLatestArtifacts() {
    const allImages = [];
    try {
      // Fetch all registries from nexus
      const allRepositories = await this.getAllRepositories();
      logger.info(`${this.token.name}, found total repository count : ${allRepositories?.length}`);
      // Fetch all images from repository concurrently
      await PromisePool.for(allRepositories)
        .withConcurrency(concurrent_pool_call)
        .process(async repository => {
          await this.getAllImages(repository, allImages);
        });
    } catch (error) {
      logger.error(`${this.token.name}, failed to execute get latest artifacts, for: ${this.token.name} error: ${error}`);
    }
    logger.info(`${this.token.name}, found final latest total image count: ${allImages.length}`);
    return allImages;
  }

  /*
  Arugs - Files - the files we found in the repo , RepoName : in which repo we queryed in
  Design - Checking when all images modified and getting the last 2
  Return - A pair of the 2 images that were last modified.
  */
  private getTheMostRecentImages(images: any[] = []) {
    try {
      const sorted = images.sort((a, b) => {
        if (a.date.getTime() > b.date.getTime()) return -1;
        return 1;
      });
      const onlyImagesWeNeed = sorted.slice(0, 1);
      return onlyImagesWeNeed;
    } catch (error) {
      logger.error(`${this.token.name}, failed to get most recent image, for: ${this.token.name} error:${error}`);
    }
    return [];
  }

  /*
  Design - getting all registries from nexus
  Return - all registries
  */
  private async getAllRepositories() {
    let allRepositories = [];
    try {
      let getAllRepositoriesUrl = `/service/rest/v1/repositories`;

      const { data }: any = await this.axiosInstance.get(getAllRepositoriesUrl);
      allRepositories = data.filter(repository => repository.format == "npm");
      return allRepositories;
    } catch (error) {
      logger.error(`${this.token.name}, failed to run getAllRepositories for: ${this.token.name} with type error : ${error}`);
    }
    return allRepositories;
  }

  /*
  Design - getting all repositories under registry
  Return - all repositories
  */
  private async getAllImages(repository, allImages) {
    try {
      const images = [];
      const formattedImagesObj = {};
      // create get image tags url
      let getImageListUrl = `/service/rest/v1/search`;
      const params: any = {
        repository: repository.name,
        format: repository.format,
      };

      while (getImageListUrl) {
        const { data }: any = await this.axiosInstance.get(getImageListUrl, { params });
        if (!data?.items?.length) {
          return;
        }

        for (const image of data.items) {
          if (!image?.assets?.length) {
            continue;
          }
          const imageObj = {
            repo: image.repository,
            imageName: image.name,
            uri: image.assets[0].downloadUrl,
            tags: [image.version],
            sha256: image.assets[0].checksum.sha256,
            date: new Date(image.assets[0].lastModified),
          };
          if (formattedImagesObj[image.name]) {
            formattedImagesObj[image.name].push(imageObj);
          } else {
            formattedImagesObj[image.name] = [imageObj];
          }
        }
        // Check next link is present in data
        if (data.continuationToken) {
          getImageListUrl = null;
          params.continuationToken = data.continuationToken;
        } else {
          getImageListUrl = null;
        }
      }
      // get only most recent images
      for (const image in formattedImagesObj) {
        logger.info(
          `${this.token.name}, docker image count: ${formattedImagesObj[image]?.length} for image: ${image} in repository: ${repository.name}`,
        );
        const images = this.getTheMostRecentImages(formattedImagesObj[image]);
        if (images?.length) {
          allImages.push(...images);
        }
      }
    } catch (error) {
      logger.error(`${this.token.name}, failed to run getAllImages for: ${this.token.name} with type error : ${error}`);
    }
  }

  public async securityEvents() {
    try {
      const images = await this.getLatestArtifacts();
      const stats = {};
      const timeHelper: TimeHelper = new TimeHelper("");

      logger.info(`${this.token.name}, artifact count : ${images.length}`);

      let imagePool: ImageInfo[] = [];

      for (const ImageDetails of images) {
        try {
          if (ImageDetails.repo === undefined || ImageDetails.uri === undefined) {
            logger.error(
              `${this.token.name}, undefined repo or file, this is repo - ${ImageDetails.repo}, this is file ${ImageDetails.uri}`,
            );
            continue;
          }

          let imageObj: ImageInfo = new ImageInfo();
          imageObj.image.name = ImageDetails.imageName;
          imageObj.image.imageTags = ImageDetails.tags;
          imageObj.image.imageSizeInBytes = parseInt(ImageDetails.totalSize || 0) * 1024 * 1024; // we want this in bytes
          imageObj.image.repositoryName = ImageDetails.repo;
          imageObj.image.imagePushedAt = ImageDetails.date ? ImageDetails.date.toString() : "";
          if (ImageDetails.sha256) {
            imageObj.image.imageDigestWithoutPrefix = ImageDetails.sha256;
            imageObj.image.imageDigest = `sha256:${ImageDetails.sha256}`;
          }
          imageObj.image.link = ImageDetails.uri ? ImageDetails.uri : "";
          imageObj.image.location = ImageDetails.uri ? ImageDetails.uri : "";
          imageObj.image.imagePushedAtInDays = timeHelper.getTimeIntervalFronNowInDays(imageObj.image.imagePushedAt);
          imageObj.image.cloudEnv = ArtifactorySecEventSystem.NEXUS_CONTAINER_REGISTRY;
          imageObj.image.imageId = `${imageObj.image.name}_${ArtifactorySecEventSystem.NEXUS_CONTAINER_REGISTRY}`;

          imagePool.push(imageObj);
          this.foundImages.push(imageObj);

          //Debug
          // if (stats[imageObj.image.repositoryName]) {
          //   stats[imageObj.image.repositoryName]++;
          // } else {
          //   stats[imageObj.image.repositoryName] = 1;
          // }
        } catch (err) {
          logger.error(`${this.token.name}, failed to create image: ${JSON.stringify(imagePool)}, err: ${err}`);
        }
      }
      await this.runSecurityToolsOnArtifacts(imagePool);
      logger.info(`${this.token.name}, total alerts, stats: ${JSON.stringify(stats)}`);
    } catch (error) {
      logger.error(`${this.token.name}, failed to get all security events for: ${this.token.name}, err: ${error}`);
    }
  }
}

export default NexusContainerRegistry;
