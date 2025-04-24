import loggerImport from "../../logger";
import { OrgPolicy } from "../../entitis/orgPolicyTypes";
import orgPolicyJson from "../org/config/orgPolicy.json";
import cicdToolsJson from "../org/config/cicd.json";
import securityVendorsToolsJson from "../org/config/securityVendors.json";
import { SecurityTool } from "../../entitis/tool/securityVendorsTypes";
import { CicdTool } from "../../entitis/cicdTypes";
import { getCICDProvider } from "../../entitis/cicidRepoTypes";

const logger = loggerImport.getDebugLogger();

class OrgPolicyParser {
  private orgPolicy: OrgPolicy;
  private cicdToolsFromOurConfig: CicdTool[] = [];
  private securityVendorsToolsFromOurConfig: SecurityTool[] = [];

  constructor(uuid: string) {
    this.init();
  }

  getOrgPolicy(): OrgPolicy {
    return this.orgPolicy;
  }

  getCICDToolsBasededOnPolicy(tools): CicdTool[] {
    if (tools == null) {
      return this.cicdToolsFromOurConfig;
    }

    const orgCicdTools = this.cicdToolsFromOurConfig.filter(cicdTool =>
      tools.some(tool => tool.toLowerCase() === cicdTool.name.toLowerCase()),
    );

    return orgCicdTools;
  }

  getSecurityToolsBasededOnPolicy(tools): SecurityTool[] {
    if (tools == null) {
      return this.securityVendorsToolsFromOurConfig;
    }
    const securityTools = this.securityVendorsToolsFromOurConfig.filter(securityVendorsTool =>
      tools.some(tool => tool.toLowerCase() === securityVendorsTool.name.toLowerCase()),
    );

    return securityTools;
  }

  init() {
    this.orgPolicy = orgPolicyJson as OrgPolicy;

    cicdToolsJson.cicdTools.forEach(i => {
      const item = new CicdTool(getCICDProvider(i.name), i.regex);
      if (!item.name) {
        return;
      }

      this.cicdToolsFromOurConfig.push(new CicdTool(i.name, i.regex));
    });

    securityVendorsToolsJson.securityVendorsTools.forEach(i =>
      this.securityVendorsToolsFromOurConfig.push(
        new SecurityTool(
          i.name,
          i.connectorName,
          i.regex,
          i.regexFilePath,
          i.product,
          i.sastLanguages,
          i.scaLanguages,
          i.containerFiles,
          i.type,
          i.oxDelivered,
        ),
      ),
    );
  }
}

export default OrgPolicyParser;
