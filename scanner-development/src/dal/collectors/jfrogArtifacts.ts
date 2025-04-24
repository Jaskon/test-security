import FeatureFlags from "@oxappsec/ox-feature-flag";
import memoryDB from "@oxappsec/ox-memory-db";
import PromisePool from "@supercharge/promise-pool/dist";
import axios, { AxiosInstance, AxiosRequestConfig, AxiosResponse } from "axios";
import { parse, stringify } from "flatted";
import https from "https";
import { ImageInfo } from "../../entitis/artifactoryTypes";
import { ArtifactorySecEventSystem, guessArtifactSystem } from "../../entitis/ArtifactTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import TimeHelper from "../../helper/timeHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ArtifactoryBase from "../base/artifactoryBase";

import { isLocalDevelopment } from "../../helper/envUtils";
import { hash } from "../../helper/hash";
import StatesHelper from "../../helper/statesHelper";

const logger = loggerImport.getDebugLogger();
const oneMonth = 2629800;
const oneDay = 86400; // basically for testing
const concurrencyFactor = process.env.DEBUG ? 20 : 20;

interface child {
  readonly uri: string;
  readonly folder: boolean;
}
interface FileRepoUriAndSha256 {
  readonly repo: string;
  uri: string;
  sha256: string;
  userNameCreated: string;
  size: string;
}
interface ExtendedDates extends FileRepoUriAndSha256 {
  ModifiedDate: Date;
  CreatedDate: Date;
  UploadedDate: Date;
  LastUpdated: Date;
}
enum typeOfRepo {
  Docker = "Docker",
  Generic = "Generic",
}

class JfrogArtifacts extends ArtifactoryBase {
  timeHelper: TimeHelper;
  private axiosInstance: AxiosInstance;
  private bypassSelfSignedCertificate = false;
  usingTokenForAuthentication = true; // Otherwise username and password

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
    _ArtifactoryURL: string,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);
    this.timeHelper = new TimeHelper(this.uuid);
  }

  async fetchImpl(functor: Function, retryBackoff: number) {
    return new Promise(async resolve => {
      setTimeout(async () => {
        try {
          const response = await functor();
          logger.debug(`Waited ${retryBackoff} seconds before fetching the data`);
          resolve(response);
        } catch (e) {
          if (e.code === "ECONNREFUSED" || e.code === "ECONNRESET" || e.code === "ECONNABORTED") {
            logger.info(`Going to wait ${retryBackoff + 5} seconds now`);
            resolve(await this.fetchImpl(functor, retryBackoff + 5));
          } else if (e.message === "Request failed with status code 404") {
            logger.info(`File not found ${e.request?.path}`);
            resolve({ status: 404 });
          } else {
            logger.error(`${this.token.name}, Failed with error status: ${e.code}}`, e);
            resolve({ status: e.code });
          }
        }
      }, retryBackoff * 1000);
    });
  }

  async smartFetch(request: string, post = false, postData = undefined) {
    try {
      //KYZ: cache only manifest.json files
      const cachedResult = await memoryDB.get.execute(post ? `post:${JSON.stringify(postData)}` : request);

      if (cachedResult) {
        return parse(cachedResult);
      } else {
        let res = { status: 400, data: {} };

        if (post) {
          res = (await this.fetchImpl(async () => {
            return this.axiosInstance.post(request, postData.data, {
              headers: {
                Accept: "application/json, text/plain, */*",
                "Content-Type": "application/json",
                "X-Requested-With": "XMLHttpRequest",
              },
            });
          }, 1)) as any;
        } else {
          res = (await this.fetchImpl(async () => {
            return this.axiosInstance.get(request);
          }, 1)) as any;
        }

        await memoryDB.set.execute(
          post ? `post:${JSON.stringify(postData)}` : request,
          oneDay,
          stringify({ status: res.status, data: res.data }),
        );

        if (res.status !== 200) {
          logger.info(`Failed to fetch data with status: ${res.status}`);
        }

        return res;
      }
    } catch (e) {
      return { status: 400, data: {} };
    }
  }

  async initLib() {
    if (this.token.password.length < 56) {
      this.usingTokenForAuthentication = false;
    }

    //kosta
    if (isLocalDevelopment()) {
      this.bypassSelfSignedCertificate = true; //await FeatureFlags.isFeatureEnabled.execute(this.orgName, "ox-disable-jfrog-cert-validation");
    } else {
      this.bypassSelfSignedCertificate = await FeatureFlags.isFeatureEnabled.execute(
        this.orgName,
        "ox-disable-jfrog-cert-validation",
        true,
      );
    }

    const axiosConfig: AxiosRequestConfig<any> = {
      baseURL: this.token.host,
      //timeout: 120000,
    };

    if (this.bypassSelfSignedCertificate) {
      axiosConfig.httpsAgent = new https.Agent({
        rejectUnauthorized: false,
      });
    }

    if (this.usingTokenForAuthentication) {
      axiosConfig.headers = { "X-JFrog-Art-Api": `${this.token.password}` };
    } else {
      axiosConfig.auth = {
        username: this.token.userName,
        password: this.token.password,
      };
    }

    this.axiosInstance = axios.create(axiosConfig);
  }

  /*
  Arguments - None
  Design - Going over all docker types repo and getting 2 latest images that we modified
  return - Returning an array of extandDates which hold repo name uri and date when file was modified.
  */
  private async getLatestArtifacts(): Promise<Array<ExtendedDates>> {
    try {
      let arrayOfDates: Array<ExtendedDates> = [];
      const allRepos = await this.getAllRepoType(typeOfRepo.Docker);

      const fetchArray = async (repo: string) => {
        const repoInfo = `api/storage/${repo}`;
        const fullUrl = `${this.token.host}/${repoInfo}`;
        const res = await this.smartFetch(fullUrl);

        const fileDetails: Array<ExtendedDates> = await this.getTheMostRecentChangeToFile(res.data["children"], repo);
        const relevantArr = await this.GetLatestImagesFromArray(fileDetails, 1);
        arrayOfDates.push(...relevantArr);
      };

      for (const repo of allRepos) {
        await fetchArray(repo);
      }

      return arrayOfDates;
    } catch (error) {
      logger.error(`${this.token.name}, failed to execute getLastestArtifacts error : ${error}`, error);
    }
    return [];
  }

  /*
  Arguments - Files - the files we found in the repo , RepoName : in which repo we queryed in
  Design - Getting all images
  Return - Return all images in repo
  */

  private async getTheMostRecentChangeToFile(Files: Array<child>, RepoName: string): Promise<Array<ExtendedDates>> {
    try {
      const arrOfFoundImages = await this.getAllFilesInJfrogFolder(RepoName, Files);
      if (arrOfFoundImages.length == 0) {
        logger.warn(`${this.token.name}, couldn't find images for repo ${RepoName}`);
        return [];
      }
      return arrOfFoundImages;
    } catch (error) {
      logger.error(`${this.token.name}, failed to get most recent file in repo ${RepoName} error:${error}`, error);
    }
    return [];
  }

  /*
  Arguments - ImageDetails - Images to check , how many images to return
  Design - Getting 2 latest images from same type (Name)
  Return - All 2 images info for each name.
  */
  private async GetLatestImagesFromArray(ImageDetail: Array<ExtendedDates>, NumberOfImagesToGet: number): Promise<Array<ExtendedDates>> {
    try {
      let workedImages: Array<string> = [];
      let releventImages: Array<ExtendedDates> = [];
      let isAnotherImage: boolean = true;
      while (isAnotherImage) {
        isAnotherImage = false;
        let currentStringToWork: string = "";
        let CurrentArrayToWorkOn: Array<ExtendedDates> = [];
        for (const image of ImageDetail) {
          let ImageNameNoTag: string = image.uri.substring(1, image.uri.indexOf(":"));
          if (workedImages.includes(ImageNameNoTag)) {
            // worked on this image already skipping
            continue;
          }
          if (currentStringToWork === "") {
            // no init value, init now
            currentStringToWork = ImageNameNoTag;
            CurrentArrayToWorkOn.push(image);
            continue;
          }
          if (currentStringToWork !== ImageNameNoTag) {
            // image name is different
            isAnotherImage = true;
            continue;
          }
          if (currentStringToWork === ImageNameNoTag) {
            CurrentArrayToWorkOn.push(image);
          }
        }
        CurrentArrayToWorkOn.sort((a, b) => {
          return b.ModifiedDate.getTime() - a.ModifiedDate.getTime();
        });

        if (CurrentArrayToWorkOn.length >= NumberOfImagesToGet) {
          const finalArr = CurrentArrayToWorkOn.slice(0, NumberOfImagesToGet);
          releventImages.push(...finalArr.flat());
        } else {
          releventImages.push(...CurrentArrayToWorkOn.flat());
        }
        workedImages.push(currentStringToWork);
      }

      return releventImages;
    } catch (err) {
      logger.error(`${this.token.name}, failed to run GetLatestImagesFromArray ${err}`, err);
      return [];
    }
  }
  /*
  Arguments - Typeofrepo to get - docker or generic
  Design - getting all types wanted repos
  Return - the repos on the same type that we got as parm
  */
  private async getAllRepoType(RepoType: typeOfRepo) {
    let ArrayOfReposToUse = [];
    try {
      logger.info(`Trying to find ${RepoType}`);
      const repoListUrl = `api/repositories`;
      const completeUrl = `${this.token.host}/${repoListUrl}?packageType=${RepoType}`;
      const res = await this.smartFetch(completeUrl);

      const data = res.data as any[];

      for (const repo of data) {
        if (repo.type.toLowerCase() === "virtual" || repo.type.toLowerCase() === "local") {
          ArrayOfReposToUse.push(repo.key);
        }
      }
      logger.info(`Found ${ArrayOfReposToUse.length} ${RepoType} types repos`);
      return ArrayOfReposToUse;
    } catch (error) {
      logger.error(`${this.token.name}, failed to run getAllRepoType with type ${RepoType} error : ${error}`, error);
    }
    return ArrayOfReposToUse;
  }

  private async SubtrackDataFromRequest(image: child, res: AxiosResponse): Promise<ExtendedDates> {
    const lastSlashIndex = image.uri.lastIndexOf("/");
    const imageInfo: ExtendedDates = {
      ModifiedDate: new Date(res["data"]["lastModified"]),
      size: res["data"]["size"] ?? `0`,
      CreatedDate: new Date(res["data"]["created"]),
      LastUpdated: new Date(res["data"]["lastUpdated"]),
      userNameCreated: res["data"]["createdBy"],
      sha256: res["data"]["originalChecksums"]["sha256"],
      uri: image.uri
        .substring(0, lastSlashIndex)
        .concat(":")
        .concat(image.uri.substring(lastSlashIndex + 1)),
      UploadedDate: new Date(res["data"]["lastUpdated"]),
      repo: "",
    };
    return imageInfo;
  }

  private async CheckIfItemImage(image: child, repoName: string) {
    const repoInfo = `api/storage/${repoName}${image.uri}`;
    const fullUrl = `${this.token.host}/${repoInfo}`;
    const res = await this.smartFetch(fullUrl);

    if ("children" in res["data"]) {
      let results: ExtendedDates[] = [];
      let FoundManiFest: boolean = false;
      let FoundLayers: boolean = false;
      let imageInfo: ExtendedDates;
      const data = res["data"]["children"] as any[];
      await PromisePool.for(data)
        .withConcurrency(concurrencyFactor)
        .process(async (child: any) => {
          if (child.folder) {
            const result = await this.CheckIfItemImage({ uri: `${image.uri}${child.uri}`, folder: true }, repoName);
            if (Array.isArray(result)) {
              results = results.concat(result);
            } else {
              results.push(result);
            }
          } else if (child.uri.startsWith("/manifest.json")) {
            FoundManiFest = true;
            const uriOfManiFest = `${this.token.host}/${repoInfo}/${child.uri}`;

            const res = await this.smartFetch(uriOfManiFest);
            imageInfo = await this.SubtrackDataFromRequest(image, res);
          } else if (child.uri.startsWith("/sha256")) {
            FoundLayers = true;
          } else if (child.uri.startsWith("/list.manifest.json")) {
            FoundLayers = true;
            FoundManiFest = true;
            const manifestUri = `${this.token.host}/${repoInfo}/${child.uri}`;
            const res = await this.smartFetch(manifestUri);

            imageInfo = await this.SubtrackDataFromRequest(image, res);
          }
        });
      if (FoundLayers && FoundManiFest) {
        const posOfColoum = imageInfo.uri.indexOf(":");
        const tag = imageInfo.uri.substring(posOfColoum + 1, imageInfo.uri.length);
        logger.debug(`Working on tag ${tag} full image name ${imageInfo.uri}`);
        const requiresAnalysis = tag.match(/([0-9a-z._-]+)/);
        if (requiresAnalysis[0] === tag) {
          logger.debug(`Found ${imageInfo.uri} as image sha256 ${imageInfo.sha256} adding to array`);

          results.push({
            uri: imageInfo.uri,
            repo: repoName,
            ModifiedDate: imageInfo.ModifiedDate,
            size: imageInfo.size,
            sha256: imageInfo.sha256,
            CreatedDate: imageInfo.CreatedDate,
            userNameCreated: imageInfo.userNameCreated,
            UploadedDate: imageInfo.UploadedDate,
            LastUpdated: imageInfo.LastUpdated,
          });
          return results;
        }
      }
      return results;
    }
  }

  /*
  Arguments - RepoName : in which repo to look on , Childs - all the files in the repo.
  Design - Going over all the files in the array and checking if they are images.
  Return - Returning list of files that we found that they are images.
  */
  private async getAllFilesInJfrogFolder(repoName: string, Childs: Array<child>): Promise<ExtendedDates[]> {
    try {
      let ArrayOfFileAndRepo: ExtendedDates[] = [];
      let setOfFoundSha256: Set<string> = new Set<string>();
      await PromisePool.for(Childs)
        .withConcurrency(concurrencyFactor)
        .process(async (image: child) => {
          try {
            const item = await this.CheckIfItemImage(image, repoName);
            if (item !== undefined) {
              for (const i of item) {
                if (!setOfFoundSha256.has(i.sha256)) {
                  setOfFoundSha256.add(i.sha256);
                  ArrayOfFileAndRepo.push(i);
                }
              }
            }
          } catch (err) {
            logger.error(`${this.token.name}, failed CheckIfItemImage, err: ${err}`, err);
            return false;
          }
        });
      logger.info(`Found ${ArrayOfFileAndRepo.length} images inside ${repoName}`);
      return ArrayOfFileAndRepo;
    } catch (error) {
      logger.error(`${this.token.name}, failed to run getAllFilesInJfrogFolder error : ${error}`, error);
    }
    return [];
  }

  public async securityEvents() {
    try {
      let images = [];

      images = await this.getLatestArtifacts();

      logger.info(`${this.token.name}, artifact count : ${images.length} before remove duplication base on name`);

      const monitoredImages = [];

      images.forEach(image => {
        const imageName = image.uri.slice(1).split(":")[0];
        if (this.repoSelectedByUser(imageName, imageName, image.CreatedDate.toDateString())) {
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

      const imagePool: ImageInfo[] = [];
      for (const image of imageNames) {
        try {
          if (!image.repo || !image.uri) {
            logger.info(`${this.token.name}, undefined repo or file, this is repo - ${image.repo}, this is file ${image.uri}`);
            continue;
          }
          const imageObj: ImageInfo = new ImageInfo();

          const jfrogHost = this.token.host.substring("https://".length, this.token.host.indexOf("/artifactory"));

          imageObj.image.name = image.uri;
          imageObj.image.repositoryName = `${jfrogHost}/${image.repo}`;
          if (imageObj.image.name.includes(":")) {
            const tagToName = imageObj.image.name.split(":");
            imageObj.image.name = tagToName[0].includes("/") ? tagToName[0].replace("/", "") : tagToName[0];
            imageObj.image.imageTags = [tagToName[1]];
          }
          imageObj.image.location = `${jfrogHost}/${image.repo}/${imageObj.image.name}`;
          imageObj.image.imageDigestWithoutPrefix = image.sha256;
          imageObj.image.imageDigest = image.sha256;
          imageObj.image.imagePushedAt = `${image.UploadedDate}`;
          imageObj.image.imagePushedAtInDays = this.timeHelper.getTimeIntervalFronNowInDays(imageObj.image.imagePushedAt);
          imageObj.image.imageSizeInBytes = parseInt(image.size) * 1024 * 1024; // we want this in bytes
          imageObj.image.link = `${this.token.host.substring(0, this.token.host.lastIndexOf("/"))}/ui/repos/tree/${image.repo}/${
            imageObj.image.name
          }`;
          imageObj.image.cloudEnv = ArtifactorySecEventSystem.JFROG_REGISTRY;
          imageObj.image.imageId = `${imageObj.image.name}_${ArtifactorySecEventSystem.JFROG_REGISTRY}`;

          imagePool.push(imageObj);
          this.foundImages.push(imageObj);
        } catch (err) {
          logger.error(`${this.token.name}, failed to create image: ${JSON.stringify(imagePool)}, err: ${err}`, err);
        }
      }

      await this.runSecurityToolsOnArtifacts(imagePool);
      logger.info(`${this.token.name}, finish sec event`);
    } catch (error) {
      logger.error(`${this.token.name}, failed to get all security events for jfrog, err: ${error}`, error);
    }
  }
}

export default JfrogArtifacts;
