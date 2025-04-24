import { ArtifactRegistryClient } from "@google-cloud/artifact-registry";
import { google } from "@google-cloud/artifact-registry/build/protos/protos";
import PromisePool from "@supercharge/promise-pool/dist";
import { setTimeout } from "node:timers/promises";
import { ImageInfo } from "../../entitis/artifactoryTypes";
import { ArtifactorySecEventSystem } from "../../entitis/ArtifactTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ArtifactoryBase from "../base/artifactoryBase";

const logger = loggerImport.getDebugLogger();
const concurrent_pool_call = 5;

class GKRArtifacts extends ArtifactoryBase {
  private artifactRegistryClient: ArtifactRegistryClient;
  private generateTokenTime;
  private projectId: string;
  private accessToken: string;
  private duplicatedRemoved: number = 0;
  private jsonKey;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
    _ArtifactoryURL: string,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);
    this.projectId = this.token.userName;
  }
  async initLib(): Promise<void> {
    try {
      logger.info(`[${this.token.name}] Decoding json base64 key, username: ${this.token.userName}`);
      const buffer = Buffer.from(this.token.password, "base64");
      const decodedJsonKey = buffer.toString("utf-8");
      this.jsonKey = JSON.parse(decodedJsonKey);
      // Initialize GCP instances
      await this.getNewRefreshToken();
    } catch (error) {
      logger.error(`[${this.token.name}] failed to write auth json file`, error);
    }
  }

  async getNewRefreshToken(): Promise<string | undefined> {
    try {
      logger.info(`[${this.token.name}] hit getNewRefreshToken`);
      this.artifactRegistryClient = new ArtifactRegistryClient({ credentials: this.jsonKey });
      this.accessToken = await this.artifactRegistryClient.auth.getAccessToken();
      // Set token expiry time to 60 minutes
      this.generateTokenTime = Date.now() + 60 * 60 * 1000;
      return this.accessToken;
    } catch (err) {
      logger.error(`[${this.token.name}] failed getNewRefreshToken`, err);
    }
  }

  needToRefreshToken(): boolean {
    try {
      const currentTime = Date.now();
      if (currentTime > this.generateTokenTime) {
        logger.info(`[${this.token.name}] Access token expired`);
        return true;
      }
      return false;
    } catch (err) {
      logger.error(`[${this.token.name}] failed needToRefreshToken`, err);
    }
    return false;
  }

  /*
  Arugs - None
  Design - Going over all docker types repo and getting 2 latest images that we modified
  return - Returning an array of extandDates which hold repo name uri and date when file was modified.
  */
  private async getLatestArtifacts(): Promise<ImageObject[]> {
    const results: ImageObject[] = [];
    try {
      // Fetch all locations for gcloud
      let allLocations = await this.getAllLocations();
      for (const location of allLocations) {
        // Fetch all repository from cloud
        let allRepos = await this.getAllRepos(location);
        logger.info(`[${this.token.name}] repository list count: ${allRepos.length} for location: ${location}`);
        if (!allRepos?.length) {
          continue;
        }
        // Fetch all images from repository concurrently
        const partialResults = await PromisePool.for(allRepos)
          .withConcurrency(concurrent_pool_call)
          .process(async repo => await this.getAllImages(location, repo));
        results.push(...partialResults.results.flat());
      }
    } catch (error) {
      logger.error(`[${this.token.name}] failed to execute get latest artifacts`, error);
    }
    return results;
  }

  /*
  Arugs - Files - the files we found in the repo , RepoName : in which repo we queryed in
  Design - Checking when all images modified and getting the last 2
  Return - A pair of the 2 images that were last modified.
  */
  private getTheMostRecentImages(images: ImageObject[] = []): ImageObject[] {
    try {
      const sorted = images.sort((a, b) => {
        if (a.date.getTime() > b.date.getTime()) return -1;
        return 1;
      });
      const onlyImagesWeNeed = sorted.slice(0, 1);
      return onlyImagesWeNeed;
    } catch (error) {
      logger.error(`[${this.token.name}] failed to get most recent image`, error);
    }
    return [];
  }

  /*
  Arugs - nextPageToken to fetch next data
  Design - getting all repos(packages)
  Return - all the repos(packages) that fetched
  */
  private async getAllImages(location: string, repository: string, retry = 3): Promise<ImageObject[]> {
    const allImages: ImageObject[] = [];
    try {
      const requestObj: google.devtools.artifactregistry.v1.IListDockerImagesRequest = {
        pageSize: 1000,
        parent: `projects/${this.projectId}/locations/${location}/repositories/${repository}`,
      };
      const data = this.artifactRegistryClient.listDockerImagesAsync(requestObj);
      const formattedImagesObj: Record<string, ImageObject[]> = {};
      for await (const image of data) {
        const imageNameWithSha = image.name.split("/dockerImages/").pop();
        let [imageName, sha256] = imageNameWithSha.split("@sha256:");

        // Skip image if upload time is not present
        if (!image.uploadTime.seconds || !image.uploadTime.nanos) {
          logger.info(`[${this.token.name}] Image Upload time is missing for: ${imageName}`);
          continue;
        }

        imageName = decodeURIComponent(imageName);
        const date = new Date(0);
        date.setUTCSeconds(
          typeof image.uploadTime.seconds === "string" ? parseInt(image.uploadTime.seconds) : (image.uploadTime.seconds as number),
        );
        date.setUTCMilliseconds(image.uploadTime.nanos / 1000000);

        const uri = image.uri.split("@sha256:")[0];
        const imageObj: ImageObject = {
          uri,
          repo: repository,
          imageName,
          sha256,
          date,
          totalSize: image.imageSizeBytes?.toString(),
          tags: image.tags ?? [],
          location,
          repoWithoutImageName: uri.replace(`/${imageName}`, ""),
        };

        if (!formattedImagesObj[imageName]) {
          formattedImagesObj[imageName] = [];
        }
        formattedImagesObj[imageName].push(imageObj);
      }
      // get only most recent images
      for (const image in formattedImagesObj) {
        const images = this.getTheMostRecentImages(formattedImagesObj[image]);
        logger.info(
          `[${this.token.name}] total count: ${formattedImagesObj[image]?.length}, reduced to ${images.length} for image: ${image} in repository: ${repository} and location ${location}`,
        );
        if (images?.length) {
          allImages.push(...images);
        }
      }
      return allImages;
    } catch (err) {
      //gkrArtifacts, failed to run getAllImages for location: us, repository: r with type error : Error: 4 DEADLINE_EXCEEDED: Deadline exceeded
      //sammer do this only for errors that need retry
      logger.error(`[${this.token.name}] failed to run getAllImages for location: ${location}, repository: ${repository}`, err);
      await setTimeout(60 * 1000);
      if (retry >= 0) {
        return await this.getAllImages(location, repository, retry - 1);
      }
    }
  }

  /*
  Arugs - nextPageToken to fetch next data
  Design - getting all repos(packages)
  Return - all the repos that fetched
  */
  private async getAllRepos(location: string): Promise<string[]> {
    try {
      const data = this.artifactRegistryClient.listRepositoriesAsync({
        pageSize: 1000,
        parent: `projects/${this.projectId}/locations/${location}`,
      });
      const repoNames: string[] = [];
      for await (const repo of data) {
        if (typeof repo?.format === "string" && repo.format.toLowerCase() == "docker") {
          const repoName = repo.name.split("/repositories/").pop();
          if (repoName) {
            repoNames.push(repoName);
          }
        }
      }
      return repoNames;
    } catch (error) {
      logger.error(`[${this.token.name}] failed to run getAllRepos for: ${location}`, error);
    }
    return [];
  }

  /*
  Arugs - nextPageToken to fetch next data
  Design - getting all locations
  Return - all the gcloud locations
  */
  private async getAllLocations(): Promise<string[]> {
    try {
      const locations: string[] = [];
      const locationsData = this.artifactRegistryClient.listLocationsAsync({
        name: `projects/${this.projectId}`,
      });
      for await (const location of locationsData) {
        if (location.locationId) {
          locations.push(location.locationId);
        }
      }
      logger.info(`[${this.token.name}] total locations count: ${locations.length}`);
      return locations;
    } catch (error) {
      logger.error(`[${this.token.name}] failed to run getAllLocations`, error);
    }
    return [];
  }

  public async securityEvents(): Promise<void> {
    try {
      const images = await this.getLatestArtifacts();
      const timeHelper: TimeHelper = new TimeHelper("");

      logger.info(`[${this.token.name}] artifact count : ${images.length} before remove duplication base on name`);

      const monitoredImages = [];
      logger.info(`[${this.token.name}] artifact count : ${images.length}`);

      images.forEach(image => {
        if (this.repoSelectedByUser(image.imageName, image.imageName, image.date.toDateString())) {
          monitoredImages.push(image);
        }
      });

      logger.info(`[${this.token.name}] artifact count after user selection filter : ${monitoredImages.length}`);

      let imageNames = images;
      if (StatesHelper.Instance.isContainerEnable && monitoredImages.length > 0) {
        imageNames = monitoredImages;
      } else if (monitoredImages.length === 0) {
        logger.error(
          `[${this.token.name}] something went wrong, artifact count after user selection filter is 0, setting default: ${imageNames.length} images`,
        );
      }

      let imagePool: ImageInfo[] = [];
      for (const ImageDetails of imageNames) {
        try {
          if (ImageDetails.repo === undefined || ImageDetails.uri === undefined) {
            logger.error(
              `[${this.token.name}] undefined repo or file, this is repo - ${ImageDetails.repo}, this is file ${ImageDetails.uri}`,
            );
            continue;
          }

          const imageObj: ImageInfo = new ImageInfo();

          imageObj.image.name = ImageDetails.imageName;
          imageObj.image.imageTags = ImageDetails.tags;
          imageObj.image.imageSizeInBytes = parseInt(ImageDetails.totalSize) * 1024 * 1024; // we want this in bytes
          imageObj.image.repositoryName = ImageDetails.repoWithoutImageName; // repoName with host url but not with image name
          imageObj.image.imagePushedAt = ImageDetails.date.toString();
          imageObj.image.accessToken = this.accessToken;
          if (ImageDetails.sha256) {
            imageObj.image.imageDigestWithoutPrefix = ImageDetails.sha256;
            imageObj.image.imageDigest = `sha256:${ImageDetails.sha256}`;
          }
          imageObj.image.link = `https://console.cloud.google.com/artifacts/docker/${this.projectId}/${ImageDetails.location}/${
            ImageDetails.repo
          }/${encodeURIComponent(ImageDetails.imageName)}`;
          imageObj.image.location = ImageDetails.uri ? ImageDetails.uri : "";
          imageObj.image.imagePushedAtInDays = timeHelper.getTimeIntervalFronNowInDays(imageObj.image.imagePushedAt);
          imageObj.image.cloudEnv = ArtifactorySecEventSystem.GCP_ARTIFACTS;
          imageObj.image.imageId = `${imageObj.image.name}_${ArtifactorySecEventSystem.GCP_ARTIFACTS}`;

          imagePool.push(imageObj);

          this.foundImages.push(imageObj);
        } catch (err) {
          logger.error(`[${this.token.name}] failed to create image`, err, { debug: JSON.stringify(imagePool) });
        }
      }

      //Take the last one
      const latestImagesMap = {};
      imagePool.forEach(item => {
        const key = item.image.name;
        if (latestImagesMap[key]) {
          const currItem: ImageInfo = latestImagesMap[key];
          if (currItem.image.imagePushedAt < item.image.imagePushedAt) {
            latestImagesMap[key] = item;
            this.duplicatedRemoved++;
          }
        } else {
          latestImagesMap[key] = item;
        }
      });

      //Stage for images
      const latestImages = Object.values(latestImagesMap) as ImageInfo[];

      logger.info(
        `[${this.token.name}] artifact count : ${latestImages.length} after remove duplication base on name, duplicatedRemoved: ${this.duplicatedRemoved}, totalImages: ${latestImages.length}, total alerts, starting run tools on artifacts`,
      );

      await this.runSecurityToolsOnArtifacts(latestImages);
    } catch (error) {
      logger.error(`[${this.token.name}] failed to get all security events`, error);
    }
  }
}

export default GKRArtifacts;

interface ImageObject {
  uri: string;
  repo: string;
  imageName: string;
  sha256: string;
  date: Date;
  totalSize: string;
  tags: string[];
  location: string;
  repoWithoutImageName: string;
}
