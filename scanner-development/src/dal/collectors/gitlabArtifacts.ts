import { Gitlab } from "@gitbeaker/node";
import axios from "axios";
import { ArtifactorySecEventSystem, guessArtifactSystem } from "../../entitis/ArtifactTypes";
import { ImageInfo } from "../../entitis/artifactoryTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { isJson } from "../../entitis/commonTypes";
import { getGitlabRepoName } from "../../helper/commonUtils";
import { RateLimitHelperFactory } from "../../helper/rateLimitHelper";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ArtifactoryBase from "../base/artifactoryBase";
import StatesHelper from "../../helper/statesHelper";

const timeout_to_wait_after_rate_limit_happen = 1000 * 60 * 1.5;
const per_page_max_res = 100;
const max_pages = 5;
const retry_count = 4;

const fs = require("fs");
const logger = loggerImport.getDebugLogger();

class GitlabArtifactRequest {
  query: any;
  page: number = 1;
  maxPage: number;
}

class GitlabArtifactsObj {
  id: number;
  projectId: string;
  uri: string;
  name: string;
  repo: string;
  createdAt: Date;
  totalSize: number = 0;
  sha256: string;
  tags: string[] = [];
}

class GitlabArtifacts extends ArtifactoryBase {
  api: InstanceType<typeof Gitlab>;
  host: string;
  private_token: string;
  usingOathToken = false;
  timeHelper: TimeHelper;
  isIdp: boolean = false;

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
      let tempToken = token.password;
      const isIdpToken = isJson(token.password);

      this.rateLimitHelper = RateLimitHelperFactory.getRateLimitHelperPerToken("gitlabArtifacts", 200);

      if (isIdpToken) {
        const idpToken = JSON.parse(token.password);
        tempToken = idpToken.access_token;
        this.isIdp = true;
        logger.info(`${this.token.name} using idp`);
        return;
      }

      this.host = token.host;
      this.private_token = tempToken;
      this.timeHelper = new TimeHelper(this.uuid);
    } catch (err) {
      logger.error(`failed init contractor for: ${this.token.name}, err: ${err}`);
    }
  }

  async initLib() {
    logger.info(`try init lib for: ${this.token.name}, url: ${this.token.host}`);

    try {
      if (this.isIdp) {
        return;
      }

      const oauthTokenRegex = /[a-z0-9]{64}/g;
      const personalTokenRegex = /glpat-[0-9a-zA-Z\-]{20}/g;
      const oldPersonalTokenRegex = /[0-9a-zA-Z\-\_]{20}/g;

      if (this.private_token.match(oauthTokenRegex)) {
        this.api = new Gitlab({
          host: this.token.host,
          oauthToken: this.private_token,
        });
        this.usingOathToken = true;
      } else if (this.private_token.match(personalTokenRegex) || this.private_token.match(oldPersonalTokenRegex)) {
        this.api = new Gitlab({
          host: this.token.host,
          token: this.token.password,
        });
      } else {
        logger.error(`got unfamiliar token type for: ${this.token.name}, trying to use personal token`);

        this.api = new Gitlab({
          host: this.token.host,
          token: this.token.password,
        });
      }
    } catch (err) {
      logger.error(`${this.token.name}, failed init lib, for: ${this.token.name} err: ${err}`);
    }

    logger.info(`finish init lib for: ${this.token.name}, url: ${this.token.host}`);
  }

  getTokenHeader() {
    if (this.usingOathToken) {
      return {
        Authorization: `Bearer ${this.private_token}`,
      };
    }

    return { "private-token": this.private_token };
  }

  /*
  Arugs - None
  Design - Going over all docker types repo and getting 2 latest images that we modified
  return - Returning an array of extandDates which hold repo name uri and date when file was modified.
  */
  private async getLatestArtifacts() {
    let allImages: GitlabArtifactsObj[] = [];
    try {
      // if (StatesHelper.Instance.orgName !== "org_VEcO8vFdsYdBvExw" && StatesHelper.Instance.orgName !== "org_y0iMmsIWOrstQ1gU") {
      //   return [];
      // }

      if (this.isIdp) {
        return [];
      }

      await this.checkGitlabUser();

      const projectList = await this.api.Projects.all({
        maxPages: 100000,
        perPage: 100,
        membership: true,
      });

      //TODO-REMOVE
      // //Remove project that not selected by the user
      // const projectList = projectListBeforeFilter.filter(apiRepo =>
      //   this.repoSelectedByUser(apiRepo.id.toString(), apiRepo.name_with_namespace, apiRepo.created_at),
      // );

      logger.info(`${this.token.name}, project list: ${projectList.length}`);

      // Fetch all artifacts under project
      const formattedImages = [];
      const getAllArtifactsPromises = projectList.map(project => {
        return this.getAllArtifactList(project, formattedImages);
      });
      await Promise.allSettled(getAllArtifactsPromises);

      logger.info(`${this.token.name}, all artifact count: ${getAllArtifactsPromises.length}`);

      // Get the most recent two images
      for (const listOfImages of formattedImages) {
        const images = this.getTheMostRecentImages(listOfImages);
        if (images?.length) {
          allImages.push(...images);
        }
      }

      logger.info(`${this.token.name}, reduced artifact count: ${allImages.length}`);

      const getAllImagesWithShaPromises = allImages.map(image => {
        return this.getImageDetails(image);
      });
      await Promise.allSettled(getAllImagesWithShaPromises);

      logger.info(`${this.token.name}, finish get details for each artifact`);
      if (process.env.DEBUG) {
        allImages = allImages.slice(0, 1);
      }
      return allImages;
    } catch (error) {
      logger.error(`${this.token.name}, failed to execute get latest artifacts, for: ${this.token.name} error: ${error}`);
    }
    return allImages;
  }

  /*
  Arugs - Files - the files we found in the repo , RepoName : in which repo we queryed in
  Design - Checking when all images modified and getting the last 2
  Return - A pair of the 2 images that were last modified.
  */
  private getTheMostRecentImages(images: GitlabArtifactsObj[] = []) {
    try {
      const sorted = images.sort((a, b) => {
        if (a.createdAt.getTime() > b.createdAt.getTime()) return -1;
        return 1;
      });
      const onlyImagesWeNeed = sorted.slice(0, 1);
      return onlyImagesWeNeed;
    } catch (error) {
      logger.error(`${this.token.name}, failed to get most recent image, for: ${this.token.name} error:${error}`);
    }
    return [];
  }

  /**
   * This function fetch the gitlab user info from personal access token and set username in token object
   */
  private async checkGitlabUser() {
    try {
      this.token.password = this.private_token;

      let userUrl = `/api/v4/user`;
      const completeUserUrl = `${this.token.host}${userUrl}`;
      const header = this.getTokenHeader();
      const { data }: any = await axios.get(completeUserUrl, { headers: header });
      if (!data?.username) {
        throw new Error("Gitlab user is not found with the given token");
      }
      // set the username in token for future use
      this.token.userName = data.username;
      logger.info(`${this.token.name}, user: ${this.token.userName}`);
    } catch (error) {
      logger.error(`${this.token.name}, failed to get Gitlab user for: ${this.token.name} with type error : ${error}`);
      throw error;
    }
  }

  private async getAllArtifactList(project: any, formattedImages: any) {
    const formattedImagesPerProject: GitlabArtifactsObj[] = [];
    const mapOfImages = {};

    try {
      const query = {
        url: `${this.host}/api/v4/projects/${project.id}/registry/repositories?tags=true`,
        params: {
          page: 1,
          per_page: per_page_max_res,
          timeout: 30000,
          headers: this.getTokenHeader(),
        },
      };

      const artifacts: any = await this.invokeRequest(query);
      for (const artifact of artifacts) {
        try {
          const imageObj = new GitlabArtifactsObj();

          imageObj.id = artifact.id;
          imageObj.projectId = project.id;
          imageObj.uri = artifact.location;
          imageObj.name = artifact.name;
          imageObj.repo = getGitlabRepoName(project.name_with_namespace);
          imageObj.createdAt = new Date(artifact.created_at);

          // Image not have tags object but may have it in the name
          if (!artifact?.tags?.length) {
            if (imageObj.uri.includes(":")) {
              const splitted = imageObj.uri.split(":");
              imageObj.uri = splitted[0];
              imageObj.tags.push(splitted[1]);
            }
            formattedImagesPerProject.push(imageObj);
          } else {
            //Image have tags by API
            for (const tag of artifact?.tags) {
              const temp: GitlabArtifactsObj = JSON.parse(JSON.stringify(imageObj));
              temp.createdAt = new Date(temp.createdAt);
              temp.uri = tag.location;
              if (temp.uri.includes(":")) {
                const splitted = temp.uri.split(":");
                temp.uri = splitted[0];
                temp.tags.push(splitted[1]);
              } else {
                temp.tags.push(tag.name);
              }
              formattedImagesPerProject.push(temp);
            }
          }

          if (mapOfImages[imageObj.name]) {
            mapOfImages[imageObj.name].push(imageObj);
          } else {
            mapOfImages[imageObj.name] = [imageObj];
          }
        } catch (err) {
          logger.error(
            `${this.token.name}, failed to get single artifact: ${JSON.stringify(artifact)} for: ${project.name} with type error : ${err}`,
          );
        }
      }
    } catch (error) {
      logger.error(`${this.token.name}, failed to get all artifacts for: ${project.name} with type error : ${error}`);
    }

    for (const [name, entry] of Object.entries(mapOfImages)) {
      formattedImages.push(entry);
    }
  }

  private async getImageDetails(image: GitlabArtifactsObj) {
    try {
      const query = {
        url: `${this.host}/api/v4/projects/${image.projectId}/registry/repositories/${image.id}/tags/${image.tags[0]}?tags=true`,
        params: {
          timeout: 30000,
          headers: this.getTokenHeader(),
        },
        singleRequest: true,
      };

      const imageDetail: any = await this.invokeRequest(query);
      if (imageDetail?.length) {
        image.sha256 = imageDetail[0].digest.split(":").pop() || "";
        image.totalSize = imageDetail[0].total_size;
      }
    } catch (error) {
      logger.error(`${this.token.name}, failed to get artifacts for: ${image.repo} with type error : ${error}`);
    }
  }

  public async securityEvents() {
    try {
      const images = await this.getLatestArtifacts();
      const stats = {};
      const monitoredImages = [];
      logger.info(`${this.token.name}, image count : ${images.length}`);

      images.forEach(image => {
        if (this.repoSelectedByUser(image.id.toString(), image.name, image.createdAt.toDateString())) {
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
          if (!ImageDetails.repo) {
            logger.error(`${this.token.name}, artifact missing info, artifact: ${JSON.stringify(ImageDetails)}`);
            continue;
          }

          let imageObj: ImageInfo = new ImageInfo();
          imageObj.image.name = ImageDetails.name;
          imageObj.image.imageTags = ImageDetails.tags;
          imageObj.image.repositoryName = ImageDetails.repo;
          imageObj.image.imagePushedAt = ImageDetails.createdAt ? ImageDetails.createdAt.toString() : "";
          if (ImageDetails.totalSize) {
            imageObj.image.imageSizeInBytes = ImageDetails.totalSize;
          }
          if (ImageDetails.sha256) {
            imageObj.image.imageDigestWithoutPrefix = ImageDetails.sha256;
            imageObj.image.imageDigest = `sha256:${ImageDetails.sha256}`;
          }
          imageObj.image.link = ImageDetails.uri ? ImageDetails.uri : "";
          imageObj.image.location = ImageDetails.uri ? ImageDetails.uri : "";
          imageObj.image.imagePushedAtInDays = this.timeHelper.getTimeIntervalFronNowInDays(imageObj.image.imagePushedAt);
          imageObj.image.imageTags = ImageDetails.tags ?? ["latest"];
          imageObj.image.cloudEnv = ArtifactorySecEventSystem.GITLAB_REGISTRY;
          imageObj.image.imageId = `${imageObj.image.name}_${ArtifactorySecEventSystem.GITLAB_REGISTRY}`;
          this.foundImages.push(imageObj);
        } catch (err) {
          logger.error(`${this.token.name}, failed to create image: ${JSON.stringify(this.foundImages)}, err: ${err}`);
        }
      }

      logger.info(`${this.token.name}, try run tools on artifact count: ${this.foundImages.length}`);
      await this.runSecurityToolsOnArtifacts(this.foundImages);
      logger.info(`${this.token.name}, finish run tools on artifact, stats: ${JSON.stringify(stats)}`);
    } catch (error) {
      logger.error(`${this.token.name}, failed to get all security events for: ${this.token.name}, err: ${error}`);
    }
  }

  async invokeRequest(query: any, maxPageCount: number = max_pages) {
    const r: GitlabArtifactRequest = new GitlabArtifactRequest();
    r.query = query;
    r.maxPage = maxPageCount;

    const res = await this.rateLimitHelper.sendApiRequest(
      r.query.url,
      r,
      this.isRateLimitErrFunction,
      this.axiosCall,
      this.getQueryNextPage,
      retry_count,
      this,
    );

    return res.flat();
  }

  isRateLimitErrFunction(err: any) {
    try {
      if (err.toString().includes("rate limit")) {
        return true;
      }
      if (err.toString().includes("ECONNRESET".toLowerCase())) {
        return true;
      }
      if (err.toString().includes("timeout of")) {
        return true;
      }

      if (err.response?.status) {
        if (err.response.status == 429) {
          return true;
        }
      }
    } catch (e) {
      logger.error(`failed pare error output for: ${this.token.type}, err: ${e}, original err: ${err}`);
    }
    return false;
  }

  getQueryNextPage(r: GitlabArtifactRequest, singleRes: any) {
    if (r.query.singleRequest) {
      if (r.query.singleRequest) return false;
    }
    if (r.page > r.maxPage) return false;
    if (singleRes.length < per_page_max_res) return false;
    r.page++;
    return true;
  }

  async axiosCall(r: GitlabArtifactRequest) {
    const instance = axios.get(r.query.url + `&per_page=${per_page_max_res}&page=${r.page}`, r.query.params);

    const res: any = await instance;
    return res.data;
  }

  async getTimeToWait() {
    return timeout_to_wait_after_rate_limit_happen;
  }
}

export default GitlabArtifacts;
