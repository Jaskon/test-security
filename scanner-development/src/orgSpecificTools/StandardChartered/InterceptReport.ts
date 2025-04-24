import { AlertSeverity, SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { capitalizeFirstLetter } from "../../helper/commonUtils";
import { replaceAll } from "../../helper/generalUtils";
import he from "he";

import loggerImport from "../../logger";
import { ToolDefinition } from "./types";

const fs = require("fs");
const logger = loggerImport.getDebugLogger();

export enum InterceptorType {
  Kong = "Kong-api-gateway",
  Solace = "Solace",
}

interface InterceptorReportText {
  text: string;
}

interface InterceptorReportToolHelp {
  text: string;
  markdown: string;
}

interface InterceptorReportToolProperties {
  impact: string;
  resolution: string;
}

interface InterceptorReportToolRules {
  id: string;
  shortDescription: InterceptorReportText;
  helpUri: string;
  help: InterceptorReportToolHelp;
  properties: InterceptorReportToolProperties;
}

interface InterceptorReportToolDriver {
  informationUri: string;
  name: string;
  rules: InterceptorReportToolRules[];
  semanticVersion: string;
}

interface InterceptorReportTool {
  driver: InterceptorReportToolDriver;
}

interface InterceptorReportArtifactLocation {
  uri: string;
}

interface InterceptorReportArtifact {
  location: InterceptorReportArtifactLocation;
  length: number;
}

interface InterceptorReportRegion {
  startLine: number;
  endLine: number;
  snippet: InterceptorReportText;
}

interface InterceptorReportPhysicalLocation {
  artifactLocation: InterceptorReportArtifactLocation;
  region: InterceptorReportRegion;
}

interface InterceptorReportLocation {
  physicalLocation: InterceptorReportPhysicalLocation;
}

interface InterceptorReportResult {
  ruleId: string;
  ruleIndex: number;
  level: string;
  message: InterceptorReportText;
  locations: InterceptorReportLocation[];
}

interface InterceptorReportRuns {
  tool: InterceptorReportTool;
  artifacts: InterceptorReportArtifact[];
  results: InterceptorReportResult[];
}

interface InterceptorReport {
  version: string;
  runs: InterceptorReportRuns[];
}

export class InterceptReport {
  static createSecurityEvents(path: string, metadata: ToolDefinition["metadata"]): SecurityEvent[] {
    const securityEventList: SecurityEvent[] = [];

    logger.info(`[${InterceptReport.name}] - getReport ** Begin **`);
    const reports: InterceptorReport = this.parseReport(path);
    logger.info(`[${InterceptReport.name}] - getReport ** End **, reports: ${JSON.stringify(reports)}`);

    logger.info(`[${InterceptReport.name}] - createSecurityEvent ** Begin **`);

    for (const report of reports.runs) {
      for (const issue of report.results) {
        for (const location of issue.locations) {
          this.createSecurityEvent(issue, location, report.tool.driver.rules, securityEventList, metadata);
        }
      }
    }

    logger.info(
      `[${InterceptReport.name}] - createSecurityEvent ** End ** , Finish Collecting Security Events with Count: ${
        securityEventList.length
      } for metadata: ${JSON.stringify(metadata)}`,
    );
    return securityEventList;
  }

  private static parseReport(path: string) {
    try {
      let rawdata = fs.readFileSync(path, "utf-8");

      if (!rawdata) {
        logger.error(`[${InterceptReport.name}] - Error in getReport , No Data Found!`);
        return { version: "", runs: [] };
      }

      return JSON.parse(rawdata);
    } catch (err) {
      logger.error(`[${InterceptReport.name}] - Error in getReport , Error : ${err}`);
      return { version: "", runs: [] };
    }
  }

  private static createSecurityEvent(
    issue: InterceptorReportResult,
    location: InterceptorReportLocation,
    rules: InterceptorReportToolRules[],
    securityEventList: SecurityEvent[],
    metadata: ToolDefinition["metadata"],
  ): void {
    try {
      let securityEvent: SecurityEvent;

      let alertSeverity: AlertSeverity = AlertSeverity.Unknown;
      switch (issue.level) {
        case "note":
          alertSeverity = AlertSeverity.Info;
          break;
        case "warning":
          alertSeverity = AlertSeverity.Medium;
          break;
        case "error":
          alertSeverity = AlertSeverity.High;
          break;
      }
      if (location?.physicalLocation?.region?.snippet?.text?.toLowerCase()?.includes("critical")) {
        alertSeverity = AlertSeverity.Critical;
      }

      const rule = rules[issue.ruleIndex];
      let title;

      if (metadata.type === "generic") {
        title = capitalizeFirstLetter(`${replaceAll(issue.message.text, "_", " ")} settings check`);
      }
      if (metadata.type === "kong") {
        title = capitalizeFirstLetter(`${replaceAll(issue.message.text, "_", " ")} settings check`);
      }
      if (metadata.type === "solace") {
        title = capitalizeFirstLetter(issue.ruleId);
      }
      const violationInfo = he.encode(location.physicalLocation.region.snippet.text);

      if (metadata.type === "solace") {
        securityEvent = new SecurityEvent(
          metadata.type,
          true,
          "",
          new Date().toLocaleString(),
          "",
          "",
          "",
          `${violationInfo}`,
          title,
          location.physicalLocation.artifactLocation.uri,
          AlertSeverity[alertSeverity],
          "",
          location.physicalLocation.region.startLine,
          AlertSeverity[alertSeverity],
          SecurityAlertType.runTimeConfiguration,
          rule.properties.resolution,
          "N/A",
          "N/A",
          -1,
          false,
          false,
          "N/A",
          "",
          "N/A",
          new Date().toLocaleString(),
          issue.ruleId,
          "",
          "",
          "",
          "",
          location.physicalLocation.artifactLocation.uri,
          metadata.type,
        );
        securityEventList.push(securityEvent);
        // }
      } else {
        securityEvent = new SecurityEvent(
          metadata.type,
          true,
          "",
          new Date().toLocaleString(),
          "",
          "",
          "",
          `${violationInfo}`,
          title,
          location.physicalLocation.artifactLocation.uri,
          AlertSeverity[alertSeverity],
          "",
          location.physicalLocation.region.startLine,
          AlertSeverity[alertSeverity],
          SecurityAlertType.runTimeConfiguration,
          rule.properties.resolution,
          "N/A",
          "N/A",
          -1,
          false,
          false,
          "N/A",
          "",
          "N/A",
          new Date().toLocaleString(),
          issue.ruleId,
          "",
          "",
          "",
          "",
          location.physicalLocation.artifactLocation.uri,
          metadata.type,
        );
        securityEventList.push(securityEvent);
      }

      if (securityEvent) {
        securityEvent.extraInfo = [];
        securityEvent.extraInfo.push(
          { key: "Policy version", value: metadata.version },
          { key: "Upload policy date", value: metadata.lastUploadDate },
        );
      }
    } catch (err) {
      logger.error(`[${InterceptReport.name}] - Error in createSecurityEvent , Error : ${err} , Issue Object : ${issue}`);
    }
  }
}
