import type { Queue } from "bull";
import { readFile, stat } from "node:fs/promises";
import { join } from "node:path";
import { setTimeout } from "node:timers/promises";
import { ArtifactoryResourceToRun } from "../../entitis/artifactoryTypes";
import { ArtifactorySecEventSystem } from "../../entitis/ArtifactTypes";
import { ImageDetail } from "../../entitis/cloudTypes";
import { File, Repo } from "../../entitis/codeRepoTypes";
import loggerImport from "../../logger";
import { ArtifactRepositoryService } from "../../mongo/artifact-repository.service";
import { ArtifactRepository, MatchMethod } from "../../mongo/ArtifactRepository.schema";
import MongoConnect from "../../mongo/mongoConnect";
import EnvQueueFactory from "../queue/envQueueFactory";
import StatesHelper from "../statesHelper";
import getAFC from "./artifact-family-cache";
import { DockerMatchingService, ParsedDockerCommand } from "./docker-matching";
import { FileMatchingService } from "./file-matching";
import imageToRepositoryAdapter from "./image-afc-adapter";
import { NodeMatchingService } from "./node-matching";
const logger = loggerImport.getDebugLogger();

export class RepositoryMatcher {
  private static _instance: RepositoryMatcher;
  private readonly imageFsAnalyseQueue: Queue;
  private readonly imageFsAnalyseQueueHeavy: Queue;
  private readonly JOB_TIMEOUT_MS = 1000 * 60 * 30; // 30 minutes
  private readonly analysJobMap: Map<string, JobMapEntry> = new Map();

  private constructor(
    private readonly orgId: string,
    private readonly scanId: string,
    private readonly artifactRepositoryService: ArtifactRepositoryService,
    private readonly fileMatching: FileMatchingService,
    private readonly nodeMatching: NodeMatchingService,
    private readonly dockerMatching: DockerMatchingService,
  ) {
    this.imageFsAnalyseQueue = EnvQueueFactory.getNewQueue(process.env.IMAGE_FS_ANALYSER_QUEUE as string);
    this.imageFsAnalyseQueueHeavy = EnvQueueFactory.getNewQueue(process.env.IMAGE_FS_ANALYSER_QUEUE as string, true);
  }

  static get instance(): RepositoryMatcher {
    if (!this._instance) {
      throw new Error("RepositoryMatcher has not been initialized");
    }
    return this._instance;
  }

  static init(mongoConnect: MongoConnect, scanId: string, orgId: string): void {
    if (this._instance) {
      return;
    }
    RepositoryMatcher._instance = new RepositoryMatcher(
      orgId,
      scanId,
      new ArtifactRepositoryService(orgId, scanId, mongoConnect),
      new FileMatchingService(),
      new NodeMatchingService(),
      new DockerMatchingService(),
    );
  }

  async analyseImage(image: ArtifactoryResourceToRun): Promise<string | undefined> {
    try {
      const run = StatesHelper.Instance.isContainerEnable;
      if (!run) {
        return;
      }

      const outputFile = join(image.dirWhereToPutRes, "imageFsAnalysis.json");
      this.analysJobMap.set(this.getImageKey(image.imageDetail), { outputFile, startTime: Date.now() });
      const isHeavy = image.imageDetail.isHeavy;
      const job = await (isHeavy ? this.imageFsAnalyseQueueHeavy : this.imageFsAnalyseQueue).add({
        scanId: this.scanId,
        orgId: this.orgId,
        imageName: image.imageDetail.name,
        inputFilePath: process.env.DEBUG
          ? image.netShareDownloadArtifactPathForScan.replace(process.env.OX_SHARED_DATA, "/shared")
          : image.netShareDownloadArtifactPathForScan,
        outputFilePath: process.env.DEBUG ? outputFile.replace(process.env.OX_SHARED_DATA, "/shared") : outputFile,
      });
      logger.info(`[${RepositoryMatcher.name}] Initiated analysis for ${image.imageDetail.name} (jobId: ${job.id})`);
      // return await this.waitForJobFinished(image.imageDetail);
    } catch (err) {
      logger.error(`[${RepositoryMatcher.name}] Failed to analyse image ${image?.imageDetail?.name}`, err);
    }
  }

  async getAnalyzedImage(image: ArtifactoryResourceToRun): Promise<string | undefined> {
    try {
      const run = StatesHelper.Instance.isContainerEnable;
      if (!run) {
        return;
      }
      return await this.waitForJobFinished(image.imageDetail);
    } catch (err) {
      logger.error(`[${RepositoryMatcher.name}] Failed to getAnalyzedImage image ${image?.imageDetail?.name}`, err);
    }
  }

  async addCodeRepositoryFilesToMap(repository: Repo, allFiles: RepoFile[], selectedFiles: File[]): Promise<void> {
    const repoIdentifier: MatchResultString = `${repository.name}|${repository.id}`;
    const dockerfiles: File[] = [];
    try {
      this.fileMatching.addFilesToMap(repoIdentifier, allFiles);
      for (const file of selectedFiles) {
        if (file.name === "package.json" && !file.path.includes("node_modules")) {
          const fileContent = await readFile(file.path, "utf-8");
          this.nodeMatching.addPackageJsonToMap(repoIdentifier, fileContent, file.path);
        }

        if (file.name.toLowerCase().includes("dockerfile")) {
          dockerfiles.push(file);
          const fileContent = await readFile(file.path, "utf-8");
          this.dockerMatching.parseDockerfile(repoIdentifier, fileContent, file.fileNameWithoutDisk);
        }
      }
      if (dockerfiles.length) {
        repository.dockerfiles = dockerfiles.map(file => ({ path: file.fileNameWithoutDisk }));
      }
      logger.info(`[${RepositoryMatcher.name}] Added ${dockerfiles.length} dockerfiles to repository ${repository.name}`);
    } catch (err) {
      logger.error(`[${RepositoryMatcher.name}] Failed to add files from repository ${repository.name} to codeRepoFilesMap`, err);
    }
  }

  async findRepoForImage(imageDetail: ImageDetail, appsMap: Map<string, MatchResultString>): Promise<MatchResult | undefined> {
    const artifactRepository = await this.artifactRepositoryService.getArtifactRepositoryByName(imageDetail);
    const imageAnalysis = await this.getImageAnalysisResult(imageDetail);
    const imageRepoAssociationMap = await getAFC().get();

    const matchingMethods: Array<{ method: MatchMethod; matcher: () => MatchResultString | undefined }> = [
      { method: MatchMethod.Manual, matcher: () => undefined },
      { method: MatchMethod.Cicd, matcher: () => this.matchByCicd(imageDetail, imageRepoAssociationMap) },
      { method: MatchMethod.Name, matcher: () => this.matchByName(imageDetail, appsMap) },
      { method: MatchMethod.PackageJson, matcher: () => this.nodeMatching.matchPackageJson(imageDetail, imageAnalysis) },
      { method: MatchMethod.FileNames, matcher: () => this.fileMatching.matchFiles(imageDetail, imageAnalysis) },
      { method: MatchMethod.Dockerfile, matcher: () => this.dockerMatching.matchInstructions(imageDetail, imageAnalysis) },
    ];
    let newArtifactRepository: ArtifactRepository = {
      registry: imageDetail.repositoryName,
      name: imageDetail.name,
      cloudEnv: imageDetail.cloudEnv,
      link: imageDetail.link,
      region: imageDetail.region,
      location: imageDetail.location,
    };
    let foundInCache = false;
    let matchedMethod: MatchMethod = MatchMethod.Manual;
    for (const matchingMethod of matchingMethods) {
      if (artifactRepository?.matchedApp?.method === matchingMethod.method) {
        logger.info(
          `[${RepositoryMatcher.name}] Image ${imageDetail.name} has been previously matched to repository ${artifactRepository.matchedApp.name} (${matchingMethod.method})`,
        );
        newArtifactRepository = artifactRepository;
        foundInCache = true;
        matchedMethod = matchingMethod.method;
        break;
      }
      const result = matchingMethod.matcher();
      if (result) {
        logger.info(`[${RepositoryMatcher.name}] Image ${imageDetail.name} matches repository ${result} (${matchingMethod.method})`);
        const [name, id, dockerfilePath] = result.split("|");
        newArtifactRepository.matchedApp = { name, id, dockerfilePath, method: matchingMethod.method };
        matchedMethod = matchingMethod.method;
        break;
      }
    }
    if (!newArtifactRepository.matchedApp) {
      logger.warn(`[${RepositoryMatcher.name}] Image ${imageDetail.name} has no repository match`);
    } else if (!newArtifactRepository.matchedApp.dockerfilePath) {
      const result = this.dockerMatching.matchInstructions(imageDetail, imageAnalysis, newArtifactRepository.matchedApp.id);
      newArtifactRepository.matchedApp.dockerfilePath = result?.split("|")[2];
    }
    await this.artifactRepositoryService.setArtifactRepository(newArtifactRepository);
    if (newArtifactRepository.matchedApp) {
      logger.info(`[${RepositoryMatcher.name}] Telemetry match found`, {
        "ox-repo-matcher-method": matchedMethod,
        "ox-repo-matcher-cache": foundInCache,
        "ox-repo-matcher-repo": newArtifactRepository.matchedApp?.name,
      });
    } else {
      logger.info(`[${RepositoryMatcher.name}] Telemetry match NOT found`);
    }
    return newArtifactRepository.matchedApp;
  }

  private async getImageAnalysisResult(imageDetail: ImageDetail): Promise<ImageAnalysis | undefined> {
    const jobOutputFilePath = await this.waitForJobFinished(imageDetail);
    if (!jobOutputFilePath) {
      return;
    }
    const resultContent = await readFile(jobOutputFilePath, "utf-8");
    const imageAnalysis: ImageAnalysis = JSON.parse(resultContent);
    if (!imageAnalysis?.files?.length && !imageAnalysis?.dockerCommands?.length) {
      logger.warn(`[${RepositoryMatcher.name}] Image ${imageDetail.name} has no files or commands and cannot be matched to a repository`);
      return;
    }
    return imageAnalysis;
  }

  private matchByName(imageDetail: ImageDetail, appsMap: Map<string, MatchResultString>): MatchResultString | undefined {
    const name = imageDetail.cloudEnv === ArtifactorySecEventSystem.ECR ? imageDetail.name.split("/")[1] : imageDetail.name;
    return appsMap.get(name);
  }

  private matchByCicd(imageDetail: ImageDetail, imageRepoAssociationMap: Map<string, string>): MatchResultString {
    try {
      //defensive code
      if (imageDetail && imageDetail.name) {
        const match = imageToRepositoryAdapter.associateImageToRepository(imageDetail.name.split(":")[0], imageRepoAssociationMap);

        if (match) {
          logger.info(`Image ${imageDetail.name} matches repository ${match} (CICD)`);
        }

        return match;
      } else {
        logger.warn(`[${RepositoryMatcher.name}] Image ${JSON.stringify(imageDetail)} has no name`);
      }
    } catch (err) {
      logger.error(`[${RepositoryMatcher.name}] Failed to match image ${imageDetail.name} by CICD`, err);
    }
  }

  private async waitForJobFinished(imageDetail: ImageDetail): Promise<string | undefined> {
    const job = this.analysJobMap.get(this.getImageKey(imageDetail));
    if (!job) {
      logger.warn(`[${RepositoryMatcher.name}] Image ${imageDetail.name} has no analysis job`);
      return;
    }
    let doneFileExists: boolean;
    do {
      doneFileExists = await stat(`${job.outputFile}.done`)
        .then(() => true)
        .catch(() => false);
      await setTimeout(200);
    } while (!doneFileExists && job.startTime + this.JOB_TIMEOUT_MS > Date.now());

    if (!doneFileExists) {
      logger.error(`[${RepositoryMatcher.name}] Image ${imageDetail.name} analysis job timed out`);
      return;
    }
    logger.info(`[${RepositoryMatcher.name}] Finished analysis for ${imageDetail.name}`);
    return job.outputFile;
  }

  private getImageKey(image: ImageDetail): string {
    return `${image.cloudEnv}|${image.repositoryName}|${image.name}`;
  }
}

interface RepoFile {
  filePath: string;
  language: string;
}

interface JobMapEntry {
  outputFile: string;
  startTime: number;
}

export type MatchResultString = `${string}|${string}` | `${string}|${string}|${string}` | undefined;

export interface ImageAnalysis {
  files: ImageFile[];
  dockerCommands: ParsedDockerCommand[];
  diffIds: string[];
}

export interface ImageFile {
  language: string;
  hash: string;
  filePath: string;
  pkgJsonName?: string;
}

export type MatchResult = ArtifactRepository["matchedApp"];
