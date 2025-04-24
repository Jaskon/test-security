import { getSharedFolder } from "../../src/helper/generalUtils";
import { SASTscan } from "../../src/index";

const fs = require("fs");

const dotenv = require("dotenv");
dotenv.config();

if (process.env.GITLAB_IDP_TEST) {
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
            '{"org_id":"IPGitLabTest","configuredConnectors":[{"id":"2","name":"GitLab","description":"GitLab is a web-based DevOps lifecycle tool that provides a Git repository manager providing wiki, issue-tracking and continuous integration and deployment pipeline features, using an open-source license, developed by GitLab Inc","hostURL":"https://gitlab.com","identityProviderBaseURL":"https://gitlab.com/oauth/","iconURL":"https://d1wa508hvqs2kv.cloudfront.net/1.0.1/connectors/gitlab.png","credentialsType":"Token","credentialsTypes":["IdentityProvider","Token"],"family":"Source Control","isResourceAvailable":true,"isOxBuiltIn":false,"isOpenSource":false,"isConfigured":true,"credentials":[{"idpToken":"{\\"access_token\\":\\"bb8da1db7f2e43432f02d35bbe102ff1e5b31fea0c0669a5217b1f50f0bd748a\\",\\"token_type\\":\\"bearer\\",\\"refresh_token\\":\\"\\",\\"scope\\":\\"\\",\\"created_at\\":\\"\\"}","credentialsType":"IdentityProvider","hostURL":"https://gitlab.com","tokenExpirationDate":null}]}]}',
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
  });
} else {
  describe("Gitlab IDP not configured", () => {
    it("not configured", () => {
      console.log("Fill environment variables to test");
      expect(true).toBe(true);
    });
  });
}
