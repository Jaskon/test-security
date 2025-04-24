import PromisePool from "@supercharge/promise-pool/dist";
import axios from "axios";
import parseLinkHeader from "parse-link-header";
import qs from "qs";
import { ArtifactorySecEventSystem } from "../../entitis/ArtifactTypes";
import { ImageInfo } from "../../entitis/artifactoryTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { isJson } from "../../entitis/commonTypes";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ArtifactoryBase from "../base/artifactoryBase";
import { shouldRetry } from "../../helper/commonUtils";
import StatesHelper from "../../helper/statesHelper";

const logger = loggerImport.getDebugLogger();
const concurrent_pool_call = 5;

class AzureContainerRegistry extends ArtifactoryBase {
  refresh_token: string;
  usingOathToken: boolean = false;
  private_token: string;
  timeHelper: TimeHelper;
  isIdpToken: boolean = false;
  private readonly IGNORED_MEDIA_TYPES = ["application/vnd.oci.image.manifest.v1+json"];

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
    _ArtifactoryURL: string,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    const isIdpToken = isJson(token.password);
    if (isIdpToken) {
      logger.error(
        `${this.token.name}, is using idp, tenantId: ${this.token.tenantId}, clientId: ${this.token.clientId}, clientSecret: ${this.token.clientSecret}, subscriptionId: ${this.token.subscriptionId}`,
      );
      return;
    }
    logger.info(
      `${this.token.name}, is using token, tenantId: ${this.token.tenantId}, clientId: ${this.token.clientId}, clientSecret: ${this.token.clientSecret}, subscriptionId: ${this.token.subscriptionId}`,
    );
  }
  async initLib() {}

  /*
  Arugs - None
  Design - Going over all docker types repo and getting 2 latest images that we modified
  return - Returning an array of extandDates which hold repo name uri and date when file was modified.
  */
  private async getLatestArtifacts(): Promise<AcrImage[]> {
    if (this.isIdpToken) {
      return [];
    }

    const allImages: AcrImage[] = [];
    try {
      // First generate access token for azure
      await this.generateAccessToken();
      // Fetch all registries from azure
      const allRegistries = await this.getAllRegistries();
      logger.info(`${this.token.name}, found total registry count : ${allRegistries?.length}`);
      for (const registry of allRegistries) {
        // Fetch all repository under registry
        const { repos, acrExchangeToken } = await this.getAllRepositories(registry);
        if (!repos?.length) {
          logger.info(`${this.token.name}, repository not found for registry : ${registry.name}`);
          continue;
        }

        logger.info(`${this.token.name}, found total repository count: ${repos.length} for registry: ${registry.name}`);

        // Get new exchange token for repository
        const repoAccessTokenScope = `repository:*:*`;
        const repoAccessToken = await this.getAcrAccessToken(registry, repoAccessTokenScope, acrExchangeToken);

        // Fetch all images from repository concurrently
        await PromisePool.for(repos)
          .withConcurrency(concurrent_pool_call)
          .process(async repoName => {
            await this.getAllImages(registry, repoName, repoAccessToken, allImages);
          });
      }
    } catch (error) {
      logger.error(`${this.token.name}, failed to execute get latest artifacts, for: ${this.token.name} error: ${error}`);
    }
    logger.info(`${this.token.name}, found final latest total image count: ${allImages.length}`);
    return allImages;
  }

  /**
   * @description This method is to generate new access token for azure
   * @returns generated access token
   */
  private async generateAccessToken(): Promise<void> {
    try {
      const accessTokenUrl = `https://login.microsoftonline.com/${this.token.tenantId}/oauth2/v2.0/token`;
      const header = { headers: { "Content-Type": "application/x-www-form-urlencoded" } };
      const formData = {
        client_id: this.token.clientId,
        grant_type: "client_credentials",
        client_secret: this.token.clientSecret,
        scope: "https://management.azure.com/.default",
      };
      const { data } = await axios.post<{ access_token: string }>(accessTokenUrl, qs.stringify(formData), header);
      this.token.password = data.access_token;
      return;
    } catch (error) {
      logger.error(`${this.token.name}, failed to run generateAccessToken for: ${this.token.name} with type error : ${error}`);
      throw error;
    }
  }

  /*
  Arugs - Files - the files we found in the repo , RepoName : in which repo we queryed in
  Design - Checking when all images modified and getting the last 2
  Return - A pair of the 2 images that were last modified.
  */
  private getTheMostRecentImages(images: AcrImage[] = []): AcrImage[] {
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
  Design - getting all registries from azure
  Return - all registries
  */
  private async getAllRegistries(): Promise<AcrRegistry[]> {
    const allRegistries: AcrRegistry[] = [];
    try {
      let getAllRegistriesUrl = `https://management.azure.com/subscriptions/${this.token.subscriptionId}/providers/Microsoft.ContainerRegistry/registries?api-version=2023-01-01-preview`;
      const header = { headers: { Authorization: `Bearer ${this.token.password}` } };

      while (getAllRegistriesUrl) {
        const { data } = await axios.get<{
          value: Array<{ id: string; name: string; properties: { loginServer: string } }>;
          nextLink: string;
        }>(getAllRegistriesUrl, header);
        for (const registry of data.value) {
          const regObj = {
            id: registry.id,
            name: registry.name,
            loginServer: registry.properties.loginServer,
          };
          allRegistries.push(regObj);
        }
        getAllRegistriesUrl = data.nextLink ? data.nextLink : null;
      }
      return allRegistries;
    } catch (error) {
      logger.error(`${this.token.name}, failed to run getAllRegistries for: ${this.token.name} with type error : ${error}`);
    }
    return allRegistries;
  }

  /*
  Design - getting all repositories under registry
  Return - all repositories
  */
  private async getAllRepositories(registry: AcrRegistry): Promise<{ repos?: string[]; acrExchangeToken?: string }> {
    try {
      // Get new exchange token for registry
      const acrExchangeToken = await this.getAcrExchangeToken(registry);

      const repoAccessTokenScope = "registry:catalog:*";
      // Get new exchange token for registry
      const repoAccessToken = await this.getAcrAccessToken(registry, repoAccessTokenScope, acrExchangeToken);

      // create get repo list url
      let reposListUrl = `https://${registry.loginServer}/acr/v1/_catalog`;
      const params: any = { n: 1000 };
      const header = { headers: { Authorization: `Bearer ${repoAccessToken}` }, params };
      const repositories: string[] = [];
      // Recursive call if data contain nextLink
      while (reposListUrl) {
        const { data, headers } = await axios.get<{ repositories: string[] }>(reposListUrl, header);
        if (data?.repositories?.length) {
          repositories.push(...data.repositories);
        }
        // Check next link is present in header
        if (headers.link) {
          const parsedHeader = parseLinkHeader(headers.link);
          if (parsedHeader?.next?.last) {
            header.params.last = parsedHeader.next.last;
          } else {
            reposListUrl = null;
          }
        } else {
          reposListUrl = null;
        }
      }

      return { repos: repositories, acrExchangeToken };
    } catch (error) {
      logger.error(`${this.token.name}, failed to run getAllRepositories for registry: ${registry.name} with type error : ${error}`);
    }
    return {};
  }

  /*
  Design - getting all repositories under registry
  Return - all repositories
  */
  private async getAllImages(
    registry: AcrRegistry,
    repoName: string,
    imageAccessToken: string,
    allImages: AcrImage[],
  ): Promise<AcrImage[]> {
    const images: AcrImage[] = [];

    let retry = 3;
    while (retry > 0) {
      try {
        // create get image tags url
        let imageTagUrl = `https://${registry.loginServer}/acr/v1/${repoName}/_manifests`;
        const params: any = { n: 1000 };
        const header = { headers: { Authorization: `Bearer ${imageAccessToken}` }, params };

        while (imageTagUrl) {
          const { data, headers }: any = await axios.get(imageTagUrl, header);
          if (!data?.manifests?.length) {
            return images;
          }
          for (const image of data.manifests) {
            // Return if no tags found to avoid un-wanted image downloading
            if (!image?.tags?.length || this.IGNORED_MEDIA_TYPES.includes(image.mediaType)) {
              continue;
            }
            const imageObj: AcrImage = {
              repo: registry.loginServer,
              imageName: data.imageName,
              uri: `${registry.loginServer}/${repoName}`,
              tags: image.tags || [],
              sha256: image.digest.split(":").pop(),
              date: new Date(image.createdTime),
              totalSize: image.imageSize,
              accessToken: imageAccessToken,
            };
            images.push(imageObj);
          }
          // Check next link is present in header
          if (headers.link) {
            const parsedHeader = parseLinkHeader(headers.link);
            if (parsedHeader?.next?.last) {
              header.params.last = parsedHeader.next.last;
            } else {
              imageTagUrl = null;
            }
          } else {
            imageTagUrl = null;
          }
        }
        // get only most recent images
        logger.info(
          `${this.token.name}, found docker image count: ${images?.length} for repository: ${repoName}, inside registry: ${registry.name} `,
        );
        if (images?.length) {
          allImages.push(...this.getTheMostRecentImages(images));
        }

        return allImages;
      } catch (error) {
        if (shouldRetry(error)) {
          //Do nothing just retry
          logger.info(
            `${this.token.name}, failed to run getAllImages for registry: ${registry.name}, repository: ${repoName}, retry count: ${retry} with type error : ${error}`,
          );
        } else {
          logger.error(
            `${this.token.name}, failed to run getAllImages for registry: ${registry.name}, repository: ${repoName} with type error : ${error}`,
          );
          break;
        }
      }
      retry--;
    }

    return allImages;
  }

  private async getAcrExchangeToken(registry: AcrRegistry): Promise<string> {
    try {
      const acrExchangeTokenUrl = `https://${registry.loginServer}/oauth2/exchange`;
      const header = { headers: { "Content-Type": "application/x-www-form-urlencoded" } };
      const formData = { grant_type: "access_token", service: registry.loginServer, access_token: this.token.password };
      const { data } = await axios.post<{ refresh_token: string }>(acrExchangeTokenUrl, qs.stringify(formData), header);
      return data.refresh_token;
    } catch (error) {
      logger.error(`${this.token.name}, failed to run getAcrExchangeToken for registry: ${registry.name} with type error : ${error}`);
      throw error;
    }
  }

  private async getAcrAccessToken(registry: AcrRegistry, scope: string, refresh_token: string): Promise<string> {
    try {
      const acrAccessTokenUrl = `https://${registry.loginServer}/oauth2/token`;
      const header = { headers: { "Content-Type": "application/x-www-form-urlencoded" } };
      const formData = { grant_type: "refresh_token", service: registry.loginServer, scope, refresh_token };
      const { data } = await axios.post<{ access_token: string }>(acrAccessTokenUrl, qs.stringify(formData), header);
      return data.access_token;
    } catch (error) {
      logger.error(
        `${this.token.name}, failed to run getAcrAccessToken for registry: ${registry.name}, scope: ${scope} with type error : ${error}`,
      );
      throw error;
    }
  }

  public async securityEvents() {
    try {
      const images = await this.getLatestArtifacts();
      const stats = {};
      const timeHelper: TimeHelper = new TimeHelper("");

      logger.info(`${this.token.name}, artifact count before user selection filter : ${images.length}`);

      let imagePool: ImageInfo[] = [];

      const monitoredImages: AcrImage[] = [];
      logger.info(`${this.token.name}, artifact count : ${images.length}`);

      images.forEach((image: AcrImage) => {
        if (this.repoSelectedByUser(image.imageName, image.imageName, image.date.toDateString())) {
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
          imageObj.image.imageSizeInBytes = ImageDetails.totalSize; // we want this in bytes
          imageObj.image.repositoryName = ImageDetails.repo;
          imageObj.image.imagePushedAt = ImageDetails.date ? ImageDetails.date.toString() : "";
          if (ImageDetails.sha256) {
            imageObj.image.imageDigestWithoutPrefix = ImageDetails.sha256;
            imageObj.image.imageDigest = `sha256:${ImageDetails.sha256}`;
          }
          imageObj.image.link = ImageDetails.uri ? ImageDetails.uri : "";
          imageObj.image.location = ImageDetails.uri ? ImageDetails.uri : "";
          imageObj.image.imagePushedAtInDays = timeHelper.getTimeIntervalFronNowInDays(imageObj.image.imagePushedAt);
          imageObj.image.accessToken = ImageDetails.accessToken;
          imageObj.image.cloudEnv = ArtifactorySecEventSystem.AZURE_CONTAINER_REGISTRY;
          imageObj.image.imageId = `${imageObj.image.name}_${ArtifactorySecEventSystem.AZURE_CONTAINER_REGISTRY}`;

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
      logger.info(`${this.token.name}, total repos, stats: ${JSON.stringify(stats)}`);
    } catch (error) {
      logger.error(`${this.token.name}, failed to get all security events for: ${this.token.name}, err: ${error}`);
    }
  }
}

export default AzureContainerRegistry;

interface AcrRegistry {
  id: string;
  name: string;
  loginServer: string;
}

interface AcrImage {
  repo: string;
  imageName: string;
  uri: string;
  tags: string[];
  sha256: string;
  date: Date;
  totalSize: number;
  accessToken: string;
}
