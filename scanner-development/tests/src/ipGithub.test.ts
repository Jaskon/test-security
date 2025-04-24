import { getSharedFolder } from "../../src/helper/generalUtils";
import { SASTscan } from "../../src/index";
const fs = require("fs");

const dotenv = require("dotenv");
dotenv.config();

if (process.env.GITHUB_IDP_TEST) {
  describe("end2endScanner", () => {
    const uid = "1";
    const oxDir = process.cwd() + "/ox-security/" + uid;
    const detailsJsonPath = getSharedFolder(uid) + "/report/appoxalypse_json.js";
    let detailesjSON;

    //Test expected results
    const expectedRepoCount = 6;

    //Should run first always
    it("scanner finish successfully", async () => {
      let res = false;
      try {
        res = await SASTscan({
          MessageDeduplicationId: uid,
          MessageBody:
            '{"org_id":"IPGithubTest","configuredConnectors":[{"id":"1","name":"GitHub","description":"GitHub, Inc. is a provider of Internet hosting for software development and version control using Git. It offers the distributed version control and source code management functionality of Git, plus its own features","hostURL":"https://api.github.com","identityProviderBaseURL":"https://github.com/login/oauth/","iconURL":"https://d1wa508hvqs2kv.cloudfront.net/1.0.1/connectors/github.png","credentialsType":"Token","credentialsTypes":["IdentityProvider","Token"],"family":"Source Control","isResourceAvailable":true,"isOxBuiltIn":false,"isOpenSource":false,"isConfigured":true,"credentials":[{"idpToken":"{\\"access_token\\":\\"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\\",\\"token_type\\":\\"bearer\\",\\"scope\\":\\"\\"}","credentialsType":"IdentityProvider","hostURL":"https://api.github.com","tokenExpirationDate":null}]}]}',
        });
      } catch (err) {
        console.error(err);
        console.error("test failed, exception from scanner", err);
        expect(false).toBe(true);
      }

      //Validate scanner finish
      expect(res == true).toBe(true);

      let content = fs.readFileSync(detailsJsonPath, "utf-8");
      content = content.replace("function getAnalysisJSON() { var AnalysisJSON = ", "");
      content = content.replace("; return AnalysisJSON; }", "");

      detailesjSON = JSON.parse(content);
    }, 190000);

    it("Total count of repos", async () => {
      const reposCount = detailesjSON.repos.length;

      if (reposCount != expectedRepoCount) {
        console.error(`Expected ${expectedRepoCount} repos, but got ${reposCount}`);
      }

      expect(reposCount == expectedRepoCount).toBe(true);
    }, 190000);

    it("Close Redis connection", async () => {
      const delay = ms => new Promise(res => setTimeout(res, ms));
      await delay(5000);
    }, 60000);
  });
} else {
  describe("Github IDP not configured", () => {
    it("not configured", () => {
      console.log("Fill environment variables to test");
      expect(true).toBe(true);
    });
  });
}
