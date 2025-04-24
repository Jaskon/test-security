import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import loggerImport from "../../logger";
import artifactoryDownloadJson from "../config/artifactoryDownload.json";
import Iqueue from "../../helper/queue/Iqueue";
import ToolsCreatorBase from "../base/toolsCreatorBase";
import ArtifactoryDownloadTool from "./artifactoryDownloadTool";
import { Token } from "../../entitis/collectorEntitisTypes";

const logger = loggerImport.getDebugLogger();

class ArtifactoryDownloadCreator extends ToolsCreatorBase {
  constructor(uuid: string, orgPolicyParser: OrgPolicyParser, orgName: string, securityToolsQueue: Iqueue, token: Token) {
    super(uuid, orgPolicyParser, orgName, securityToolsQueue, token);
  }

  setTools() {
    artifactoryDownloadJson.tools.forEach(artifactoryToolConfig => {
      this.addScanner(
        new ArtifactoryDownloadTool(
          this.uuid,
          this.orgPolicyParser,
          artifactoryToolConfig,
          this.securityToolsQueue,
          this.orgName,
          this.token,
        ),
      );
    });
  }
}

export default ArtifactoryDownloadCreator;
