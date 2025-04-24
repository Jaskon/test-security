import { basename } from "node:path";
import { ImageDetail } from "../../entitis/cloudTypes";
import loggerImport from "../../logger";
import { ImageAnalysis, MatchResultString } from "./RepositoryMatcher";
const logger = loggerImport.getDebugLogger();

export class FileMatchingService {
  private readonly SUPPORTED_LANGUAGES = ["python"];
  private readonly MIN_MATCHING_FILES_PERCENTAGE = 50;
  private readonly MIN_IMAGE_FILES = 2;
  private readonly filesMap: Map<string, Set<MatchResultString>> = new Map();

  addFilesToMap(repoIdentifier: MatchResultString, files: RepoFile[]): void {
    try {
      let fileCount = 0;
      for (const file of files.filter(({ language }) => this.SUPPORTED_LANGUAGES.includes(language?.toLowerCase()))) {
        const fileName = basename(file.filePath);
        this.filesMap.set(fileName, (this.filesMap.get(fileName) || new Set()).add(repoIdentifier));
        fileCount++;
      }
      logger.info(`[${FileMatchingService.name}] Added ${fileCount} files from repository ${repoIdentifier}`);
    } catch (err) {
      logger.error(`[${FileMatchingService.name}] Could not add files from repository ${repoIdentifier}`, err);
    }
  }

  matchFiles(imageDetails: ImageDetail, imageAnalysis?: ImageAnalysis): MatchResultString {
    if (!imageAnalysis?.files?.length) {
      return;
    }
    const { files } = imageAnalysis;
    if (files.length < this.MIN_IMAGE_FILES) {
      logger.info(`[${FileMatchingService.name}] Image ${imageDetails.name} has not enough files for an accurate match`);
      return;
    }
    const repoFileCount = new Map<MatchResultString, number>();
    for (const file of files) {
      const mapEntry = this.filesMap.get(basename(file.filePath)) || new Set();
      for (const repo of mapEntry) {
        repoFileCount.set(repo, (repoFileCount.get(repo) || 0) + 1);
      }
    }
    // Sort list and take last eleement (biggest file count)
    const result = [...repoFileCount.entries()].sort((a, b) => a[1] - b[1]).pop();
    // Only take result if we match at least half of the files
    if (result) {
      if (Math.round((result[1] / files.length) * 100) > this.MIN_MATCHING_FILES_PERCENTAGE) {
        logger.info(
          `[${FileMatchingService.name}] Image ${imageDetails.name} files match repository ${result[0]} (${result[1]} out of ${files.length})`,
        );
      } else {
        logger.info(
          `[${FileMatchingService.name}] Not enough matching files for image ${imageDetails.name} and repository ${result[0]} (${result[1]} out of ${files.length})`,
        );
        return undefined;
      }
    }
    return result?.[0];
  }
}

interface RepoFile {
  filePath: string;
  language: string;
}
