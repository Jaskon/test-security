import PromisePool from "@supercharge/promise-pool/dist";
import axios from "axios";
import { ImageInfo } from "../../entitis/artifactoryTypes";
import { ArtifactorySecEventSystem } from "../../entitis/ArtifactTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ArtifactoryBase from "../base/artifactoryBase";
import { ListTagsResponse } from "./dockerHub.types";
import { shouldRetry, sleep } from "../../helper/commonUtils";

const logger = loggerImport.getDebugLogger();
const concurrent_pool_call = 5;

class DockerHubRegistry extends ArtifactoryBase {
  timeHelper: TimeHelper;
  private accessToken: string;

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
      this.token.userName = this.token.userName.toLowerCase();
      logger.info(`${this.token.name}, initialize with user: ${this.token.userName}`);
    } catch (err) {
      logger.error(`failed in ${this.token.name}, initialize with user: ${this.token.userName}, err: ${err}`);
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
      // Generate access token
      await this.generateAccessToken();
      // Get all namespaces fromm docker hub
      const namespaces = await this.getAllNamespaces();
      logger.info(`${this.token.name}, found total namespaces count : ${namespaces?.length}`);
      // Get all organizations from docker hub
      const organizations = await this.getAllOrganizations();
      logger.info(`${this.token.name}, found total organizations count : ${organizations?.length}`);
      if (organizations.length) {
        for (const org of organizations) {
          if (!namespaces.includes(org)) {
            namespaces.push(...organizations);
          }
        }
      }

      for (const namespace of namespaces) {
        // Fetch all registries from nexus
        const allRepositories = await this.getAllRepositories(namespace);
        logger.info(`${this.token.name}, found total repository count : ${allRepositories?.length} from namespace: ${namespace}`);
        // Fetch all images from repository concurrently
        await PromisePool.for(allRepositories)
          .withConcurrency(concurrent_pool_call)
          .process(async repository => {
            await this.getAllImages(namespace, repository, allImages);
          });
      }
    } catch (error) {
      logger.error(`${this.token.name}, failed to execute get latest artifacts, for: ${this.token.name} error: ${error}`);
    }
    logger.info(`${this.token.name}, found final latest total image count: ${allImages.length}`);
    return allImages;
  }

  /**
   * @description Generate access token with provided username and password to get data from docker hub
   */
  private async generateAccessToken() {
    try {
      const getAccessTokenUrl = `https://hub.docker.com/v2/users/login`;
      const body = {
        username: this.token.userName,
        password: this.token.password,
      };
      const header = this.getHeader();
      const { data }: any = await axios.post(getAccessTokenUrl, body, header);
      this.accessToken = data.token;
    } catch (error) {
      logger.error(`${this.token.name}, failed to generate access token for: ${this.token.name} with type error : ${error}`);
      throw error;
    }
  }

  /**
   * @description This method is to get all namespaces to loop over
   * @returns array of namespaces
   */
  private async getAllNamespaces() {
    try {
      const getNamespacesUrl = `https://hub.docker.com/v2/repositories/namespaces`;
      const header = this.getHeader();

      const { data }: any = await axios.get(getNamespacesUrl, header);
      if (data?.namespaces?.length) {
        return data.namespaces;
      }
    } catch (error) {
      logger.error(`${this.token.name}, failed to getAllNamespaces for: ${this.token.name} with type error : ${error}`);
    }
    return [];
  }

  /**
   * @description This method is to get all organizations assigned to dockerhub user
   * @returns array of organizations
   */
  private async getAllOrganizations() {
    const organizations = [];
    try {
      let getOrganizationUrl = `https://hub.docker.com/v2/users/${this.token.userName}/orgs?page_size=100`;
      const header = this.getHeader();

      while (getOrganizationUrl) {
        const { data }: any = await axios.get(getOrganizationUrl, header);
        if (!data?.results?.length) {
          return organizations;
        }
        // filter only repo name from object
        for (const org of data.results) {
          organizations.push(org.orgname);
        }
        // check if we have next pages
        if (data.next) {
          getOrganizationUrl = data.next;
        } else {
          getOrganizationUrl = null;
          break;
        }
      } // end
    } catch (error) {
      if (error?.response?.status == 403 || error?.response?.status == 404) {
        logger.info(`${this.token.name}, failed to getAllOrganizations for: ${this.token.name} with type error : ${error}`);
      } else {
        logger.error(`${this.token.name}, failed to getAllOrganizations for: ${this.token.name} with type error : ${error}`);
      }
    }
    return organizations;
  }

  /**
   * @description This method is to get all repositories under a namespaces
   * @returns array of repositories
   */
  private async getAllRepositories(namespace: string) {
    const repositories = [];
    try {
      let getRepositoriesUrl = `https://hub.docker.com/v2/repositories/${namespace}?page_size=100`;
      const header = this.getHeader();

      while (getRepositoriesUrl) {
        const { data }: any = await axios.get(getRepositoriesUrl, header);
        if (!data?.results?.length) {
          return repositories;
        }
        // filter only repo name from object
        for (const repo of data.results) {
          repositories.push(repo.name);
        }
        // check if we have next pages
        if (data.next) {
          getRepositoriesUrl = data.next;
        } else {
          getRepositoriesUrl = null;
          break;
        }
      } // end
    } catch (error) {
      logger.error(`${this.token.name}, failed to getAllRepositories for: ${this.token.name} with type error : ${error}`);
    }
    return repositories;
  }

  /*
  Design - getting all images under repository
  Return - all images
  */
  private async getAllImages(namespace: string, repository: string, allImages, retry: number = 0) {
    try {
      // create get image tags url
      let getImageListUrl = `https://hub.docker.com/v2/repositories/${namespace}/${repository}/tags?page_size=1`;
      const header = this.getHeader();

      const { data } = await axios.get<ListTagsResponse>(getImageListUrl, header);
      if (!data?.results?.length) {
        return;
      }

      for (const image of data.results) {
        const firstImage = image.images[0];
        if (!firstImage?.digest) {
          logger.warn(`${this.token.name} Missing image digest ${JSON.stringify(image)}`);
          continue;
        }
        const imageObj = {
          repo: `${namespace}/${repository}`,
          imageName: repository,
          uri: `${namespace}/${repository}`,
          tags: [image.name],
          sha256: firstImage?.digest.split(":")[1] || "",
          date: new Date(image.last_updated),
          totalSize: image.full_size || firstImage?.size || 0,
          id: image.id,
        };
        allImages.push(imageObj);
      }
    } catch (err) {
      ++retry;
      if (shouldRetry(err) && retry < 3) {
        logger.warn(
          `${this.token.name}, failed to run getAllImages for namespace: ${namespace}, repository: ${repository}, retry: ${retry}, error : ${err}`,
          err,
        );
        await sleep(30 * 1000);
        return await this.getAllImages(namespace, repository, allImages, retry);
      }
      logger.error(
        `${this.token.name}, failed to run getAllImages for namespace: ${namespace}, repository: ${repository}, retry: ${retry}, error : ${err}`,
        err,
      );
    }
  }

  private getHeader() {
    return {
      timeout: 60 * 1000,
      headers: {
        Authorization: `Bearer ${this.accessToken}`,
      },
    };
  }

  public async securityEvents() {
    try {
      const images = await this.getLatestArtifacts();
      const stats = {};
      const timeHelper: TimeHelper = new TimeHelper("");
      const monitoredImages = [];
      logger.info(`${this.token.name}, artifact count : ${images.length}`);

      images.forEach(image => {
        if (this.repoSelectedByUser(image.id.toString(), image.imageName, image.date.toDateString())) {
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

          let imageObj: ImageInfo = new ImageInfo();
          imageObj.image.name = ImageDetails.imageName;
          imageObj.image.imageTags = ImageDetails.tags;
          imageObj.image.imageSizeInBytes = parseInt(ImageDetails.totalSize || 0); // we want this in bytes
          imageObj.image.repositoryName = ImageDetails.repo;
          imageObj.image.imagePushedAt = ImageDetails.date ? ImageDetails.date.toString() : "";
          if (ImageDetails.sha256) {
            imageObj.image.imageDigestWithoutPrefix = ImageDetails.sha256;
            imageObj.image.imageDigest = `sha256:${ImageDetails.sha256}`;
          }
          imageObj.image.link = ImageDetails.uri ? `https://hub.docker.com/repository/docker/${ImageDetails.uri}` : "";
          imageObj.image.location = ImageDetails.uri ? ImageDetails.uri : "";
          imageObj.image.imagePushedAtInDays = timeHelper.getTimeIntervalFronNowInDays(imageObj.image.imagePushedAt);
          imageObj.image.cloudEnv = ArtifactorySecEventSystem.DOCKER_HUB;
          imageObj.image.imageId = `${imageObj.image.name}_${ArtifactorySecEventSystem.DOCKER_HUB}`;

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

export default DockerHubRegistry;
