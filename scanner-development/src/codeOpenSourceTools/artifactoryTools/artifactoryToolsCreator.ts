import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import loggerImport from "../../logger";
import artifactoryToolsJson from "../config/artifactoryTools.json";
import Iqueue from "../../helper/queue/Iqueue";
import ToolsCreatorBase from "../base/toolsCreatorBase";
import TrivyContainers from "./specifcTools/trivyContainers";
import Gitleaks from "./specifcTools/gitleaks";
import { Token } from "../../entitis/collectorEntitisTypes";
import { isDevelopment, isLocalDevelopment } from "../../helper/envUtils";
import StatesHelper from "../../helper/statesHelper";

const logger = loggerImport.getDebugLogger();

class ArtifactoryCreator extends ToolsCreatorBase {
  constructor(uuid: string, orgPolicyParser: OrgPolicyParser, orgName: string, securityToolsQueue: Iqueue, token: Token) {
    super(uuid, orgPolicyParser, orgName, securityToolsQueue, token);
  }

  setTools() {
    artifactoryToolsJson.tools.forEach(artifactoryToolConfig => {
      if (artifactoryToolConfig.name.toLowerCase() === "trivy-sbom") {
        this.addScanner(
          new TrivyContainers(this.uuid, this.orgPolicyParser, artifactoryToolConfig, this.securityToolsQueue, this.orgName, this.token),
        );
      } else if (artifactoryToolConfig.name.toLowerCase() === "gitleaks" && StatesHelper.Instance.isContainerEnable) {
        this.addScanner(
          new Gitleaks(this.uuid, this.orgPolicyParser, artifactoryToolConfig, this.securityToolsQueue, this.orgName, this.token),
        );
      }
    });
  }
}

export default ArtifactoryCreator;
