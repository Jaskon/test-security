import loggerImport from "../../logger";
import { MatchResultString } from "./RepositoryMatcher";
import getAFC from "./artifact-family-cache";
const logger = loggerImport.getDebugLogger();

export default class imageToRepositoryAdapter {
  static associateImageToRepository(imageName: string, imageRepoAssociationMap: Map<string, string>): MatchResultString | undefined {
    const afc = getAFC();

    const repoImageMap = imageRepoAssociationMap;
    const repoId = repoImageMap.get(imageName);

    if (repoId) {
      const repoName = afc.getRepoNameFromId(repoId);

      if (repoName) {
        return `${repoName}|${repoId}`;
      } else {
        logger.error(`imageToRepositoryAdapter: cannot find repoName for repoId ${repoId}`);
      }
    }

    return undefined;
  }
}
