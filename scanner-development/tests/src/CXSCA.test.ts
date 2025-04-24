import { SecurityEvent } from "../../src/entitis/codeRepoTypes";
import { CXSCAAnalyzer } from "../../src/dal/collectors/checkmarxSCA";
import * as fs from "fs";

describe("Test CheckMarx SCA", () => {
  const projects = fs.readFileSync(process.cwd() + "/tests/src/CXSCA/SCAProjects.json", "utf8");
  const riskReports = fs.readFileSync(process.cwd() + "/tests/src/CXSCA/SCARiskReport.json", "utf8");
  const allSCanResults = fs.readFileSync(process.cwd() + "/tests/src/CXSCA/SCAAllscans.json", "utf8");

  it("Read and verify the CXSCA data correct", () => {
    expect(projects).toBeDefined();
    expect(riskReports).toBeDefined();
    expect(allSCanResults).toBeDefined();
  });

  it("Test CheckMarx SCA Analyzer", () => {
    const projectsMap = new Map(JSON.parse(projects));
    const riskReportsMap = new Map(JSON.parse(riskReports));
    const vulnerabilitiesMap = new Map(JSON.parse(allSCanResults));

    const accumulatedSecurityEvents: SecurityEvent[] = [];
    for (let [key, value] of vulnerabilitiesMap) {
      const currentIssues = JSON.parse(value as string);
      const securityData = CXSCAAnalyzer().analyzeScanResults(key as string, currentIssues);
      accumulatedSecurityEvents.push(...securityData);
    }

    expect(accumulatedSecurityEvents.length).toBe(1040);
  });
});
