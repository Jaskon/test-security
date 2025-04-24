import fs from "fs";
import loggerImport from "../logger";

const logger = loggerImport.getDebugLogger();

export interface Rules {
  id: string;
  severity: string;
  summaryTitle: string;
  WhyDoesItMatter?: string;
  HowToFix: string;
  eduVideoLink: string;
  violationInfo?: string;
  Skip: boolean;
}

export interface trivyComplianceIssues {
  jsonVersion: string;
  usage: string;
  toolName: string;
  Rules: Rules[];
}

class jsonParser {
  private static instance: jsonParser;
  private static parsedJson: Map<string, Map<string, Rules>> = new Map<string, Map<string, Rules>>();

  private constructor() {}

  public doParse(jsonFile: string, toolName: string) {
    try {
      if (!fs.existsSync(jsonFile)) {
        logger.error(`Failed to open file ${jsonFile}`);
        return;
      }
      const jsonContent: string = fs.readFileSync(jsonFile, "utf-8");
      const jsonObject: trivyComplianceIssues = JSON.parse(jsonContent);
      let mapOfRules = new Map<string, Rules>();
      for (const rule of jsonObject.Rules) {
        mapOfRules.set(rule.id, rule);
      }
      jsonParser.parsedJson.set(toolName, mapOfRules);
    } catch (err) {
      logger.error(`Failed to execute doParse ${err}`);
    }
  }

  public getIdObject(id: string, toolName: string) {
    try {
      return jsonParser.parsedJson.get(toolName).get(id);
    } catch (err) {
      logger.error(`Failed to getIdObject ${err}`);
    }
  }

  public static getInstance() {
    if (!this.instance) {
      this.instance = new jsonParser();
    }
    return this.instance;
  }
}

export default jsonParser;
