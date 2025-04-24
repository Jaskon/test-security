export type ToolCategoryMap = Map<string, string[]>;
import { SourceToolType } from "@oxappsec/ox-consolidated-categories";

export default class ToolsConnectorsHelper {
  private static _instance: ToolsConnectorsHelper;

  private toolMap: ToolCategoryMap = new Map([
    ["oxSast", ["Bandit", "DevSkim", "SemGrep"]],
    ["oxSca", ["Trivy"]],
    ["oxContainers", ["Trivy-Sbom"]],
    ["oxSecrets", ["GitHub Secret Detection", "Gitleaks"]],
    ["oxSbom", ["Trivy-Sbom"]],
    ["oxCloud", ["Prowler"]],
  ]);

  private oxInternalToolToFriendlyNameMap = {
    bandit: SourceToolType["Code Security"],
    checkov: SourceToolType["Infrastructure as Code Scan"],
    devskim: SourceToolType["Code Security"],
    semgrep: SourceToolType["Code Security"],
    gitleaks: SourceToolType["Secret/PII Scan"],
    trivy: SourceToolType["Open Source Security"],
    prowler: SourceToolType["Cloud Security"],
    "trivy-sbom": SourceToolType["Container Security"],
  };

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  oxInternalToolToFriendlyName(name: string) {
    if (this.oxInternalToolToFriendlyNameMap[name.toLowerCase()]) {
      return this.oxInternalToolToFriendlyNameMap[name.toLowerCase()];
    }
    return name;
  }

  getOXConnectorForTool(toolName: string) {
    for (const [oxConnector, tools] of this.toolMap.entries()) {
      if (tools.includes(toolName)) {
        return oxConnector;
      }
    }
  }
}
