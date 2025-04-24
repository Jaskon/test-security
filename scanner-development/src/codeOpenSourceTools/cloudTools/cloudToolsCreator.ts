import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import loggerImport from "../../logger";
import securityToolsJson from "../config/cloudSecurityTools.json";
import Iqueue from "../../helper/queue/Iqueue";
import ToolsCreatorBase from "../base/toolsCreatorBase";
import CloudSecurityTools from "./cloudSecurityTools";
import Prowler from "./specifcTools/prowler";
import { Token } from "../../entitis/collectorEntitisTypes";

const logger = loggerImport.getDebugLogger();

class cloudToolsCreator extends ToolsCreatorBase {
  constructor(uuid: string, orgPolicyParser: OrgPolicyParser, orgName: string, securityToolsQueue: Iqueue, token: Token) {
    super(uuid, orgPolicyParser, orgName, securityToolsQueue, token);
  }

  setTools() {
    securityToolsJson.tools.forEach(securityToolsConfig => {
      if (securityToolsConfig.name.toLowerCase() === "prowler") {
        this.addScanner(
          new Prowler(this.uuid, this.orgPolicyParser, securityToolsConfig, this.securityToolsQueue, this.orgName, this.token),
        );
      } else {
        this.addScanner(
          new CloudSecurityTools(this.uuid, this.orgPolicyParser, securityToolsConfig, this.securityToolsQueue, this.orgName, this.token),
        );
      }
    });
  }
}

export default cloudToolsCreator;
