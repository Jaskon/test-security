import { ArtifactoryDownloadToRun } from "../../entitis/artifactoryTypes";
import Iqueue from "../../helper/queue/Iqueue";
import loggerImport from "../../logger";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import ToolProgressBase from "../base/toolProgressBase";
import ToolsManagerBase from "../base/toolsManagerBase";
import ArtifactoryDownloadCreator from "./artifactoryDownloadCreator";

const logger = loggerImport.getDebugLogger();

class ArtifactoryDownloadManager extends ToolsManagerBase {
  constructor(
    uuid: string,
    orgPolicyParser: OrgPolicyParser,
    orgName: string,
    resource: ArtifactoryDownloadToRun,
    securityToolsQueue: Iqueue,
    artifactoryDownloadCreator: ArtifactoryDownloadCreator,
    toolProgressBase: ToolProgressBase,
  ) {
    const resultsDir = resource.artifactoryResultsDir;
    const filterMessage = resource.imageDetail.name;
    const id = resource.imageDetail.imageDigest;

    super(
      uuid,
      orgPolicyParser,
      orgName,
      resultsDir,
      filterMessage,
      resource,
      securityToolsQueue,
      artifactoryDownloadCreator,
      "artifactory_download_all_done",
      "artifact",
      toolProgressBase,
      id,
    );
  }

  async sendScanRequest() {
    if (process.env.DOCKER_DEBUG) {
      return await this.sendAlertToShell();
    }
    return await super.sendScanRequest();
  }
}

export default ArtifactoryDownloadManager;
