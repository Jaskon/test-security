import * as fs from "fs";
import { Result } from "sarif";
import { SarifBuilder, SarifRunBuilder, SarifResultBuilder, SarifRuleBuilder } from "node-sarif-builder";

import crypto from "crypto";

import { AlertSeverity } from "../../src/entitis/codeRepoTypes";

describe("Sarif data parsing", () => {
  const megaJson: any = fs.readFileSync(process.cwd() + "/tests/src/Sarif/megajson1.json", "utf8");

  it("Read and verify the data correct", () => {
    expect(JSON.parse(megaJson)).toBeDefined();
  });

  it("Build Sarif for a single issue and verify it", () => {
    const sarif = new SarifBuilder();

    const sarifRunBuilder = new SarifRunBuilder().initSimple({
      toolDriverName: "ox-scanner",
      toolDriverVersion: "1.0.0",
    });

    const badRepoIssue = JSON.parse(megaJson).repos[5].issues[23];
    expect(badRepoIssue).toBeDefined();

    //
    // This is the issue text
    //
    expect(badRepoIssue.list[0].info).toBe(
      "When using $_GET/POST/COOKIE values via echo, failure to  encode the values will lead to Cross Site Scription (XSS), where a malicious party can inject script into the webpage.",
    );

    //
    // Those are the issue locations and fixes (per issue)
    //
    expect(badRepoIssue.list[0].aggregatedInfo.aggregatedItems).toBeDefined();

    const singleFileIssue = badRepoIssue.list[0].aggregatedInfo.aggregatedItems[0];
    expect(singleFileIssue.fileName).toBe("csrf.php");
    expect(singleFileIssue.region).toBeDefined();
    expect(singleFileIssue.fixes).toBeDefined();

    const sarifResultBuilder = new SarifResultBuilder();

    //
    // We have a special handling of this case
    //
    // type level =
    //     "none" |
    //     "note" |
    //     "warning" |
    //     "error";
    const getSevirityString = (severity: number): Result.level => {
      if (severity <= AlertSeverity.High) return "warning";
      if (severity >= AlertSeverity.Critical) return "error";
    };

    const sarifResultInit = {
      // Transcode to a SARIF level:  can be "warning" or "error" or "note"
      level: getSevirityString(badRepoIssue.severity),
      messageText: badRepoIssue.list[0].info,
      ruleId: badRepoIssue.list[0].ruleId,
      fileUri: singleFileIssue.fileName,
      startLine: singleFileIssue.region.startLine,
      startColumn: singleFileIssue.region.startColumn,
      endLine: singleFileIssue.region.endLine,
      endColumn: singleFileIssue.region.endColumn,
      fixes: singleFileIssue.fixes,
    };

    // Init sarifResultBuilder
    sarifResultBuilder.initSimple(sarifResultInit);
    // Add result to sarifRunBuilder
    sarifRunBuilder.addResult(sarifResultBuilder);

    sarif.addRun(sarifRunBuilder);
    const sarifJsonString = sarif.buildSarifJsonString({ indent: true });

    const hash = crypto.createHash("md5").update(sarifJsonString).digest("hex");

    expect(hash).toBe("fb2a6bddc72a6fe5b4a9bdf706eaa7a7");
    console.log(sarifJsonString);
  });
});
