import { ArtifactorySecEventSystem } from "../../entitis/ArtifactTypes";
import { CICD } from "../../entitis/cicidRepoTypes";
import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();

export default function retainApplicationsForArtifactScreen(
  name: string,
  matchedName: string,
  cloudSize: string,
  cloudLink: string,
  cicd: CICD,
) {
  for (const job of cicd.jobs) {
    for (const artifact of job.parsedArtifacts) {
      if (name !== artifact.name) {
        continue;
      }
    }
  }
}
