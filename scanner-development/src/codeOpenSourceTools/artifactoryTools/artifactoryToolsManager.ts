import { ArtifactoryResourceToRun } from "../../entitis/artifactoryTypes";
import Iqueue from "../../helper/queue/Iqueue";
import loggerImport from "../../logger";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import ToolProgressBase from "../base/toolProgressBase";
import ToolsManagerBase from "../base/toolsManagerBase";
import ArtifactoryToolsCreator from "./artifactoryToolsCreator";

const logger = loggerImport.getDebugLogger();

class ArtifactoryToolsManager extends ToolsManagerBase {
  constructor(
    uuid: string,
    orgPolicyParser: OrgPolicyParser,
    orgName: string,
    resource: ArtifactoryResourceToRun,
    securityToolsQueue: Iqueue,
    artifactoryToolsCreator: ArtifactoryToolsCreator,
    toolProgressBase: ToolProgressBase,
  ) {
    const resultsDir = resource.dirWhereToPutRes;
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
      artifactoryToolsCreator,
      "artifactory_all_done",
      "artifact",
      toolProgressBase,
      id,
    );
  }
}

export default ArtifactoryToolsManager;
