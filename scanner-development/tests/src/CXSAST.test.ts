import { SecurityEvent } from "../../src/entitis/codeRepoTypes";
import { CXSastAnalyzer, CXSast } from "../../src/dal/collectors/checkmarxSAST";
import * as fs from "fs";

describe("Test CheckMarx SCA", () => {
  const projects = fs.readFileSync(process.cwd() + "/tests/src/CXSAST/projects.json", "utf8");
  const scanResults = fs.readFileSync(process.cwd() + "/tests/src/CXSAST/scanResults.json", "utf8");
  const reports = fs.readFileSync(process.cwd() + "/tests/src/CXSAST/reports.json", "utf8");

  it("Test CXSast class", async () => {
    class cxSastDemoClass {
      private cxsast: any;

      constructor() {
        this.cxsast = CXSast("username", "password", "localhost");
      }

      public async callLoginFunction() {
        return await this.cxsast.login();
      }
    }

    const cxSastDemo = new cxSastDemoClass();

    expect(await cxSastDemo.callLoginFunction()).toBeUndefined();
  }, 666999666);

  it("Read and verify the CXSCA data correct", () => {
    expect(projects).toBeDefined();
    expect(scanResults).toBeDefined();
    expect(reports).toBeDefined();
  });

  it("Test CheckMarx SCA Analyzer", async () => {
    const projectsMap = new Map(JSON.parse(projects));
    const scanResultsMap = new Map(JSON.parse(scanResults));
    const reportsSet = new Set<string>(JSON.parse(reports));

    const accumulatedSecurityEvents: SecurityEvent[] = [];
    for (const report of reportsSet) {
      try {
        const currentReport = JSON.parse(report);
        const securityData = await CXSastAnalyzer().analyzeScanResults(currentReport);
        accumulatedSecurityEvents.push(...securityData);
      } catch (error) {
        console.log(`CheckMarx SAST: Error parsing report: ${error}`);
      }
    }

    expect(accumulatedSecurityEvents.length).toBe(17841);
  });
});
