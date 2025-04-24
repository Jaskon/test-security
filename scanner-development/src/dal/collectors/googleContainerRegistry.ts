import { ArtifactRegistryClient } from "@google-cloud/artifact-registry";
import PromisePool from "@supercharge/promise-pool/dist";
import axios from "axios";
import { ArtifactorySecEventSystem } from "../../entitis/ArtifactTypes";
import { ImageInfo } from "../../entitis/artifactoryTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ArtifactoryBase from "../base/artifactoryBase";
import { RegistryName } from "../../entitis/codeRepoTypes";
import StatesHelper from "../../helper/statesHelper";

const logger = loggerImport.getDebugLogger();
const concurrent_pool_call = 5;

class GoogleContainerRegistry extends ArtifactoryBase {
  private artifactRegistryClient: ArtifactRegistryClient;
  private projectId: string;
  private apiAccessToken: string;
  private generateTokenTime;
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
  async initLib() {
    try {
      logger.info(`${this.token.name}, Decoding json base64 key, username: ${this.token.userName}`);
      const buffer = Buffer.from(this.token.password, "base64");
      const decodedJsonKey = buffer.toString("utf-8");
      this.jsonKey = JSON.parse(decodedJsonKey);
      // Initialize GCP instances
      await this.getNewRefreshToken();
    } catch (error) {
      logger.error(`${this.token.name}, failed to write auth json file, for: ${this.token.name} error: ${error}`);
    }
  }

  async getNewRefreshToken(): Promise<string | undefined> {
    try {
      logger.info(`${this.token.name}, hit getNewRefreshToken`);
      this.artifactRegistryClient = new ArtifactRegistryClient({ credentials: this.jsonKey });
      this.apiAccessToken = await this.artifactRegistryClient.auth.getAccessToken();
      // Set token expiry time to 55 minutes and create new token 5 minutes before expiry
      this.generateTokenTime = Date.now() + 55 * 60 * 1000;
      return this.apiAccessToken;
    } catch (err) {
      logger.error(`${this.token.name}, getNewRefreshToken, error: ${err}`);
    }
  }

  needToRefreshToken(): boolean {
    try {
      const currentTime = Date.now();
      if (currentTime > this.generateTokenTime) {
        logger.info(`${this.token.name}, Access token expired`);
        return true;
      }
      return false;
    } catch (err) {
      logger.error(`${this.token.name}, needToRefreshToken, error: ${err}`);
    }
    return false;
  }

  /*
  Arugs - None
  Design - Going over all docker types repo and getting 2 latest images that we modified
  return - Returning an array of extandDates which hold repo name uri and date when file was modified.
  */
  private async getLatestArtifacts() {
    const allImages = [];
    try {
      // Fetch all locations for gcloud
      const allLocations = await this.getAllLocations();
      for (const location of allLocations) {
        if (this.orgName === "org_Ge7tmoPGWMZ4n9HK") {
          // For testing added this condition
          if (location != "eu.gcr.io") {
            continue;
          }
        }

        // Fetch all repository from cloud
        const allRepos = await this.getAllRepos(location);
        logger.info(`${this.token.name}, repository list count: ${allRepos.length} for location: ${location}`);
        if (!allRepos?.length) {
          continue;
        }
        // Fetch all images from repository concurrently
        await PromisePool.for(allRepos)
          .withConcurrency(concurrent_pool_call)
          .process(async repo => {
            await this.getAllImages(location, repo, allImages);
          });
      }
      logger.info(`${this.token.name}, reduced artifact count: ${allImages.length}`);
    } catch (error) {
      logger.error(`${this.token.name}, failed to execute get latest images, for: ${this.token.name} error: ${error}`);
    }
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
  Arugs - nextPageToken to fetch next data
  Design - getting all repos(packages)
  Return - all the repos(packages) that fetched
  */
  private async getAllImages(location: string, repository: string, allImages) {
    try {
      let getAllImagesUrl = `https://${location}/v2/${repository}/tags/list?n=1000`;
      const headers = this.getHeader();
      const dockerImages = [];
      while (getAllImagesUrl) {
        const { data }: any = await axios.get(getAllImagesUrl, { headers });
        if (data?.tags?.length) {
          for (const shaKey in data.manifest) {
            const image = data.manifest[shaKey];
            const imageName = repository.split("/").pop() || "";
            const repo = repository.slice(0, repository.lastIndexOf("/"));
            // Formate image obj
            const imageObj = {
              uri: `${location}/${repository}`,
              repo,
              imageName: imageName,
              sha256: shaKey.split(":").pop(),
              date: new Date(parseInt(image.timeUploadedMs)),
              totalSize: image.imageSizeBytes,
              tags: image.tag,
              location,
            };
            dockerImages.push(imageObj);
          }
        }
        // Check if next page token is there for pagination call same api again
        if (data.next || data.nextPageToken) {
          getAllImagesUrl = data.next || data.nextPageToken;
        } else {
          getAllImagesUrl = null;
        }
      }
      // get only most recent images
      logger.info(`${this.token.name}, found docker image count: ${dockerImages?.length} for repository: ${repository}`);
      const images = this.getTheMostRecentImages(dockerImages);
      if (images?.length) {
        allImages.push(...images);
      }
    } catch (error) {
      logger.error(`${this.token.name}, failed to run getAllImages for: ${this.token.name} with type error : ${error}`);
    }
  }

  /*
  Arugs - location to fetch  data
  Design - getting all repos(packages)
  Return - all the repos that fetched
  */
  private async getAllRepos(location: string) {
    const allRepos = [];
    try {
      let getAllRepoUrl = `https://${location}/v2/_catalog?n=1000`;
      const headers = this.getHeader();

      while (getAllRepoUrl) {
        const { data }: any = await axios.get(getAllRepoUrl, { headers });
        if (data?.repositories?.length) {
          allRepos.push(...data.repositories);
        }
        // Check if next page token is there for pagination call same api again
        if (data.next || data.nextPageToken) {
          getAllRepoUrl = data.next || data.nextPageToken;
        } else {
          getAllRepoUrl = null;
        }
      } // end while

      return allRepos;
    } catch (error) {
      if (error?.response?.status == 404) {
        logger.info(`${this.token.name}, failed to run getAllRepos for: ${location} with type error : ${error}`);
      } else {
        logger.error(`${this.token.name}, failed to run getAllRepos for: ${location} with type error : ${error}`);
      }
    }
    return allRepos;
  }

  /*
  Arugs - nextPageToken to fetch next data
  Design - getting all locations
  Return - all the gcloud locations
  */
  private async getAllLocations() {
    const locations = ["gcr.io"];
    try {
      const locationsData = this.artifactRegistryClient.listLocationsAsync({
        name: `projects/${this.projectId}`,
      });
      for await (const location of locationsData) {
        if (location.locationId) {
          if (location.locationId.includes("europe")) {
            location.locationId = location.locationId.replace("europe", "eu");
          }
          locations.push(`${location.locationId}.gcr.io`);
        }
      }
      return locations;
    } catch (error) {
      logger.error(`${this.token.name}, failed to run getAllLocations for: ${this.token.name} with type error : ${error}`);
    }
    return locations;
  }

  private getHeader() {
    return {
      Authorization: `Bearer ${this.apiAccessToken}`,
    };
  }

  public async securityEvents() {
    try {
      const images = await this.getLatestArtifacts();
      const stats = {};

      const timeHelper: TimeHelper = new TimeHelper("");

      const monitoredImages = [];
      logger.info(`${this.token.name}, image count : ${images.length}`);

      images.forEach(image => {
        if (this.repoSelectedByUser(image.imageName, image.imageName, image.date.toDateString(), RegistryName.gcr)) {
          monitoredImages.push(image);
        }
      });

      logger.info(`${this.token.name}, artifact count after user selection filter : ${monitoredImages.length}`);

      let imageNames = images;
      if (StatesHelper.Instance.isContainerEnable && monitoredImages.length > 0) {
        imageNames = monitoredImages;
      } else if (monitoredImages.length === 0) {
        logger.error(
          `${this.token.name}, something went wrong, artifact count after user selection filter is 0, setting default: ${imageNames.length} images`,
        );
      }
      let imagePool: ImageInfo[] = [];
      for (const ImageDetails of imageNames) {
        try {
          if (ImageDetails.repo === undefined || ImageDetails.uri === undefined) {
            logger.error(
              `${this.token.name}, undefined repo or file, this is repo - ${ImageDetails.repo}, this is file ${ImageDetails.uri}`,
            );
            continue;
          }

          const imageObj: ImageInfo = new ImageInfo();

          let location = ImageDetails.location.split(".")[0];
          location = location === "gcr" ? "global" : location;
          let [projectName, ...repo] = ImageDetails.repo.split("/");
          if (repo?.length) {
            repo = `${repo.join("/")}/${ImageDetails.imageName}`;
          } else {
            repo = ImageDetails.imageName;
          }
          imageObj.image.name = ImageDetails.imageName;
          imageObj.image.imageTags = ImageDetails.tags;
          imageObj.image.imageSizeInBytes = parseInt(ImageDetails.totalSize); // we want this in bytes
          imageObj.image.repositoryName = ImageDetails.repo;
          imageObj.image.imagePushedAt = ImageDetails.date ? ImageDetails.date.toString() : "";
          imageObj.image.accessToken = this.apiAccessToken;
          if (ImageDetails.sha256) {
            imageObj.image.imageDigestWithoutPrefix = ImageDetails.sha256;
            imageObj.image.imageDigest = `sha256:${ImageDetails.sha256}`;
          }
          imageObj.image.link = `https://console.cloud.google.com/gcr/images/${projectName}/${location}/${repo}`;
          imageObj.image.location = ImageDetails.uri ? ImageDetails.uri : "";
          imageObj.image.imagePushedAtInDays = timeHelper.getTimeIntervalFronNowInDays(imageObj.image.imagePushedAt);
          imageObj.image.cloudEnv = ArtifactorySecEventSystem.GCP_CONTAINER;
          imageObj.image.imageId = `${imageObj.image.name}_${ArtifactorySecEventSystem.GCP_CONTAINER}`;

          imagePool.push(imageObj);
          this.foundImages.push(imageObj);
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

export default GoogleContainerRegistry;
