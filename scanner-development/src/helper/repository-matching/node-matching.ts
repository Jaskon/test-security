import { ImageDetail } from "../../entitis/cloudTypes";
import loggerImport from "../../logger";
import { ImageAnalysis, MatchResultString } from "./RepositoryMatcher";
const logger = loggerImport.getDebugLogger();

export class NodeMatchingService {
  private readonly packageJsonMap: Map<string, MatchResultString> = new Map();

  addPackageJsonToMap(repoIdentifier: MatchResultString, packageJsonContent: string, filePath: string): void {
    try {
      const packageJson = JSON.parse(packageJsonContent);
      this.packageJsonMap.set(packageJson.name, repoIdentifier);
      logger.info(`[${NodeMatchingService.name}] Parsed package.json ${filePath} from repository ${repoIdentifier}`);
    } catch (err) {
      logger.warn(`[${NodeMatchingService.name}] Could not parse package.json ${filePath} from repository ${repoIdentifier}`, err);
    }
  }

  matchPackageJson(imageDetails: ImageDetail, imageAnalysis?: ImageAnalysis): MatchResultString {
    if (!imageAnalysis?.files?.length) {
      return;
    }
    const packageJsonName = imageAnalysis.files.find(({ pkgJsonName }) => !!pkgJsonName)?.pkgJsonName;
    if (packageJsonName) {
      const result = this.packageJsonMap.get(packageJsonName);
      if (result) {
        logger.info(`[${NodeMatchingService.name}] Image ${imageDetails.name} match repository ${result} by package.json`);
        return result;
      }
    }
    logger.info(`[${NodeMatchingService.name}] Image ${imageDetails.name} does not match any repository by package.json`);
  }
}
