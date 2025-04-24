import Constant from "../../entitis/constant";
import loggerImport from "../../logger";

const fs = require("fs");
const logger = loggerImport.getDebugLogger();

class ToolSeverity {
  uuid: string;
  severityToolsBaseOnRuleName: any = {};
  toolConfigName: string;
  init: boolean = false;

  constructor(uuid: string, toolConfigName: string) {
    this.uuid = uuid;
    this.toolConfigName = toolConfigName;
  }

  parseConfigFile(path: string) {
    try {
      if (!path) {
        return;
      }

      const items = require("../../codeOpenSourceTools/config/" + path);
      if (!items) {
        return;
      }
      for (const itemsSverity of items.severity) {
        this.severityToolsBaseOnRuleName[itemsSverity.id.toLowerCase()] = itemsSverity.severity.toLowerCase();
      }

      this.init = true;
    } catch (err) {
      logger.error(`cannot parse file: ${path} err: ${err}`);
    }
  }

  getSeverityToolBaseOnRuleId(ruleId: string, title: string) {
    try {
      const cleanRuleId = ruleId.toLowerCase().trim();
      if (this.severityToolsBaseOnRuleName.hasOwnProperty(cleanRuleId)) {
        const res = this.severityToolsBaseOnRuleName[cleanRuleId];
        return res.toLowerCase();
      } else {
        if (this.toolConfigName.toLowerCase() === "devskim") {
          if (title.includes("without TLS")) {
            if (title.includes("localhost") || title.includes("127.0.")) return "low";

            return "medium";
          }
        }
        if (this.toolConfigName.toLowerCase() === "semgrep") {
          if (
            ruleId.includes("best-practice.") ||
            ruleId.includes("correctness.") ||
            ruleId.includes("compatibility.") ||
            ruleId.includes("performance.") ||
            ruleId.includes("portability.") ||
            ruleId.includes("maintainability.")
          ) {
            return "info";
          } else if (title.includes("http")) {
            if (title.includes("localhost") || title.includes("127.0.")) return "low";
            else {
              return "medium";
            }
          }
        }

        logger.debug(`cannot find ruleId: ${ruleId} to get severity level`);
      }
    } catch (err) {
      logger.error(`failed get ruleId: ${ruleId} tools, err: ${err}`);
    }
    return "";
  }

  getSevirtyBasedOnProperty(info) {
    if (this.toolConfigName.toLowerCase() === "devskim") {
      if (!info?.properties?.DevSkimSeverity) return "";

      const devSeverity = info?.properties?.DevSkimSeverity;
      if (devSeverity == 1) return "low";
      if (devSeverity == 2) return "medium";
      if (devSeverity == 3) return "high";
      if (devSeverity == 4) return "critical";
    }
    if (this.toolConfigName.toLowerCase() === "bandit") {
      if (info?.properties?.issue_severity) return info?.properties?.issue_severity;
    }
    return "";
  }

  bumpSeverityBasedOnSecuirtyContext(severity: string) {
    if (Constant.infoRegex.exec(severity)) {
      return "low";
    }
    if (Constant.lowRegex.exec(severity)) {
      return "medium";
    }
    if (Constant.mediumRegex.exec(severity)) {
      return "high";
    }
    if (Constant.highRegex.exec(severity)) {
      return "critical";
    }
    if (Constant.criticalRegex.exec(severity)) {
      return "appoxalypse";
    }
    if (Constant.applRegex.exec(severity)) {
      return "appoxalypse";
    }
    return severity;
  }

  lowerSeverityBasedOnSecretHistory(severity: string) {
    if (Constant.applRegex.exec(severity) || Constant.criticalRegex.exec(severity)) {
      return "high";
    } else if (Constant.highRegex.exec(severity)) {
      return "medium";
    }
    return "medium";
  }
}

export default ToolSeverity;
