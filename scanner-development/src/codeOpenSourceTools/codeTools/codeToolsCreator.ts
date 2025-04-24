import { Token } from "../../entitis/collectorEntitisTypes";
import { Constant } from "../../entitis/constant";
import { isDevelopment, isLocalDevelopment } from "../../helper/envUtils";
import Iqueue from "../../helper/queue/Iqueue";
import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import ToolsCreatorBase from "../base/toolsCreatorBase";
import securityToolsJson from "../config/codeSecurityTools.json";
import CodeSecurityTool from "./codeSecurityTools";
import Checkov from "./specifcTools/checkov";
import Semgrep from "./specifcTools/semgrep";
import SnykCli from "./specifcTools/snykCli";
import { Trivy } from "./specifcTools/trivy";

const logger = loggerImport.getDebugLogger();

class codeToolsCreator extends ToolsCreatorBase {
  constructor(uuid: string, orgPolicyParser: OrgPolicyParser, orgName: string, securityToolsQueue: Iqueue, token: Token) {
    super(uuid, orgPolicyParser, orgName, securityToolsQueue, token);
  }

  setTools() {
    securityToolsJson.tools.forEach(securityToolsConfig => {
      this.addTool(securityToolsConfig, false);
    });
  }

  setToolsByCat(cat: string) {
    securityToolsJson.tools
      .filter(i => i.defaultType.toLowerCase() === cat)
      .forEach(securityToolsConfig => {
        this.addTool(securityToolsConfig, false);
      });
  }

  setAllToolsExceptCat(cat: string) {
    securityToolsJson.tools
      .filter(i => i.defaultType.toLowerCase() !== cat)
      .forEach(securityToolsConfig => {
        this.addTool(securityToolsConfig, false);
      });
  }

  addTool(securityToolsConfig, specificTool: boolean) {
    if (securityToolsConfig.name.toLowerCase() === "checkov") {
      this.addScanner(new Checkov(this.uuid, this.orgPolicyParser, securityToolsConfig, this.securityToolsQueue, this.orgName, this.token));
    } else if (securityToolsConfig.name.toLowerCase() === "trivy") {
      this.addScanner(new Trivy(this.uuid, this.orgPolicyParser, securityToolsConfig, this.securityToolsQueue, this.orgName, this.token));
      //Dont add this for first step of running the tools
    } else if (securityToolsConfig.name.toLowerCase() === "semgrep") {
      this.addScanner(new Semgrep(this.uuid, this.orgPolicyParser, securityToolsConfig, this.securityToolsQueue, this.orgName, this.token));
    } else if (securityToolsConfig.name.toLowerCase() === "semgrep pro" && StatesHelper.Instance.orgName === "org_f0AdAbSkUFpaznEc") {
      logger.info("add semgrep pro");
      this.addScanner(new Semgrep(this.uuid, this.orgPolicyParser, securityToolsConfig, this.securityToolsQueue, this.orgName, this.token));
    } else if (securityToolsConfig.name.toLowerCase() == Constant.snykCLItool) {
      const shouldRun = StatesHelper.Instance.isSofi || process.env.ENABLE_SNYL_CLI;
      //Set this tool only on demand
      if (shouldRun && specificTool) {
        this.addScanner(
          new SnykCli(this.uuid, this.orgPolicyParser, securityToolsConfig, this.securityToolsQueue, this.orgName, this.token),
        );
      }
    } else {
      this.addScanner(
        new CodeSecurityTool(this.uuid, this.orgPolicyParser, securityToolsConfig, this.securityToolsQueue, this.orgName, this.token),
      );
    }
  }
}

export default codeToolsCreator;
