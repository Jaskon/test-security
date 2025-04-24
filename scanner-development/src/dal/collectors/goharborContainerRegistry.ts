import FeatureFlags from "@oxappsec/ox-feature-flag";
import PromisePool from "@supercharge/promise-pool/dist";
import axios, { AxiosInstance } from "axios";
import https from "https";
import parseLinkHeader from "parse-link-header";
import { ArtifactorySecEventSystem } from "../../entitis/ArtifactTypes";
import { ImageInfo } from "../../entitis/artifactoryTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import StatesHelper from "../../helper/statesHelper";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ArtifactoryBase from "../base/artifactoryBase";
import resolveDomainNameToIp from "../../helper/commonUtils";

const logger = loggerImport.getDebugLogger();
const concurrent_pool_call = 5;

class GoHarborContainerRegistry extends ArtifactoryBase {
  timeHelper: TimeHelper;
  private axiosInstance: AxiosInstance;
  private hostRegistryDomain: string;
  private bypassSelfSignedCertificate = false;

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
      // remove https from host name
      this.hostRegistryDomain = this.token.host.substring("https://".length);
      if (this.hostRegistryDomain.includes("/")) {
        this.hostRegistryDomain = this.hostRegistryDomain.slice(0, this.hostRegistryDomain.indexOf("/"));
      }
    } catch (err) {
      logger.error(`${this.token.name}, failed initialize with host: ${this.token.host}, user: ${this.token.userName}, err: ${err}`);
    }
  }

  async isApplicationBehindIngress(url: string): Promise<string> {
    try {
      try {
        await axios.get(`${url}/v2/`, {
          httpsAgent: new https.Agent({
            rejectUnauthorized: false,
          }),
        });
      } catch (e) {
        // We are supposed to be here
        if (e.response.status === 401) {
          if (e.response.headers["www-authenticate"]) {
            const wwwAuthenticate = e.response.headers["www-authenticate"];
            if (wwwAuthenticate.includes('realm="https://')) {
              const realm = wwwAuthenticate.split("https://")[1].split("/service/token")[0];

              if (!realm.includes(url)) {
                const ip = await resolveDomainNameToIp(url.split("https://")[1]);
                if (ip) {
                  return `echo ${ip[0]} ${realm} >> /etc/hosts`;
                }
              }
            }
          }
        }
      }
    } catch (err) {
      logger.error(`${this.token.name}, failed to determine if application is behind ingress, err: ${err}`);
    }

    return "";
  }

  async initLib() {
    this.bypassSelfSignedCertificate = await FeatureFlags.isFeatureEnabled.execute(this.orgName, "ox-disable-harbor-cert-validation", true);

    if (this.bypassSelfSignedCertificate) {
      StatesHelper.Instance.allowSkopeoToAcceptSelfSignedCertificate = true;

      // Create axios instance once
      this.axiosInstance = axios.create({
        baseURL: this.token.host,
        httpsAgent: new https.Agent({
          rejectUnauthorized: false,
        }),
        auth: {
          username: this.token.userName,
          password: this.token.password,
        },
      });

      // Determine if the application is running behind ingress
      StatesHelper.Instance.dnsNameOverride = await this.isApplicationBehindIngress(this.token.host);

      if (StatesHelper.Instance.dnsNameOverride) {
        logger.info(
          `${this.token.name}, detected application is running behind ingress, updating with ${StatesHelper.Instance.dnsNameOverride}`,
        );
      }
    } else {
      // Create axios instance once
      this.axiosInstance = axios.create({
        baseURL: this.token.host,
        auth: {
          username: this.token.userName,
          password: this.token.password,
        },
      });
    }
  }

  /*
  Arugs - None
  Design - Going over all docker types repo and getting 2 latest images that we modified
  return - Returning an array of extandDates which hold repo name uri and date when file was modified.
  */
  private async getLatestArtifacts() {
    const allImages = [];
    try {
      // Fetch all projects
      const allProjects = await this.getAllProjects();
      logger.info(`${this.token.name}, found total projects count : ${allProjects?.length}`);
      // Fetch all repositories
      for (const projectName of allProjects) {
        const allRepositories = await this.getAllRepositories(projectName);
        // Fetch all images from repository concurrently
        await PromisePool.for(allRepositories)
          .withConcurrency(concurrent_pool_call)
          .process(async repository => {
            await this.getAllImages(projectName, repository, allImages);
          });
      }
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
  Design - getting all projects from GoHarbor
  Return - all projects
  */
  private async getAllProjects() {
    let allProjects = [];
    try {
      let getAllProjectsUrl = `/api/v2.0/projects`;
      const params: any = {
        page_size: 100,
      };
      while (getAllProjectsUrl) {
        const { data, headers }: any = await this.axiosInstance.get(getAllProjectsUrl, { params });
        if (data.length) {
          for (const project of data) {
            allProjects.push(project.name);
          }
        }
        // Check next link is present in header
        if (headers.link) {
          const parsedHeader = parseLinkHeader(headers.link);
          if (parsedHeader?.next?.page) {
            params.page = parsedHeader.next.page;
          } else {
            getAllProjectsUrl = null;
          }
        } else {
          getAllProjectsUrl = null;
        }
      }
    } catch (error) {
      logger.error(`${this.token.name}, failed to run getAllProjects for: ${this.token.name} with type error : ${error}`);
    }
    return allProjects;
  }

  /*
  Design - getting all registries from Goharbor
  Return - all registries
  */
  private async getAllRepositories(projectName: string) {
    let allRepositories = [];
    try {
      let getAllRepositoriesUrl = `/api/v2.0/projects/${projectName}/repositories`;
      const params: any = {
        page_size: 100,
      };
      while (getAllRepositoriesUrl) {
        const { data, headers }: any = await this.axiosInstance.get(getAllRepositoriesUrl, { params });
        if (data.length) {
          for (const repo of data) {
            if (repo.name) {
              const repoName = repo.name.replace(`${projectName}/`, "");
              allRepositories.push(repoName);
            }
          }
        }
        // Check next link is present in header
        if (headers.link) {
          const parsedHeader = parseLinkHeader(headers.link);
          if (parsedHeader?.next?.page) {
            params.page = parsedHeader.next.page;
          } else {
            getAllRepositoriesUrl = null;
          }
        } else {
          getAllRepositoriesUrl = null;
        }
      }
    } catch (error) {
      logger.error(`${this.token.name}, failed to run getAllRepositories for: ${this.token.name} with type error : ${error}`);
    }
    return allRepositories;
  }

  /*
  Design - getting all repositories under registry
  Return - all repositories
  */
  private async getAllImages(projectName: string, repositoryName: string, allImages) {
    try {
      const images = [];
      // create get image tags url
      let getImageListUrl = `/api/v2.0/projects/${projectName}/repositories/${repositoryName}/artifacts`;
      const params: any = {
        page_size: 100,
      };

      while (getImageListUrl) {
        const { data, headers }: any = await this.axiosInstance.get(getImageListUrl, { params });
        if (!data?.length) {
          return;
        }

        for (const image of data) {
          const imageObj = {
            repo: projectName,
            imageName: repositoryName,
            uri: `${this.hostRegistryDomain}/${projectName}/${repositoryName}`,
            tags: ["latest"],
            sha256: image.digest.split(":").pop(),
            date: new Date(image.push_time),
            totalSize: image.size,
          };
          if (image?.tags?.length) {
            imageObj.tags = image.tags.map(tag => tag.name);
          }
          images.push(imageObj);
        }
        // Check next link is present in header
        if (headers.link) {
          const parsedHeader = parseLinkHeader(headers.link);
          if (parsedHeader?.next?.page) {
            params.page = parsedHeader.next.page;
          } else {
            getImageListUrl = null;
          }
        } else {
          getImageListUrl = null;
        }
      }
      // get only most recent images
      logger.info(`${this.token.name}, docker image count: ${images?.length} in repository: ${repositoryName}`);
      const recentImages = this.getTheMostRecentImages(images);
      if (recentImages?.length) {
        allImages.push(...recentImages);
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
          imageObj.image.imageSizeInBytes = parseInt(ImageDetails.totalSize || 0); // we want this in bytes
          imageObj.image.repositoryName = ImageDetails.repo;
          imageObj.image.imagePushedAt = ImageDetails.date ? ImageDetails.date.toString() : "";
          if (ImageDetails.sha256) {
            imageObj.image.imageDigestWithoutPrefix = ImageDetails.sha256;
            imageObj.image.imageDigest = `sha256:${ImageDetails.sha256}`;
          }
          imageObj.image.link = ImageDetails.uri ? ImageDetails.uri : "";
          imageObj.image.location = ImageDetails.uri ? ImageDetails.uri : "";
          imageObj.image.imagePushedAtInDays = timeHelper.getTimeIntervalFronNowInDays(imageObj.image.imagePushedAt);
          imageObj.image.cloudEnv = ArtifactorySecEventSystem.GOHARBOR_CONTAINER_REGISTRY;
          imageObj.image.imageId = `${imageObj.image.name}_${ArtifactorySecEventSystem.GOHARBOR_CONTAINER_REGISTRY}`;

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

export default GoHarborContainerRegistry;
