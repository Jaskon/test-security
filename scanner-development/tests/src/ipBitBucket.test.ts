import { getSharedFolder } from "../../src/helper/generalUtils";
import { SASTscan } from "../../src/index";
const fs = require("fs");

const dotenv = require("dotenv");
dotenv.config();

if (process.env.BITBUCKET_IDP_TEST) {
  describe("end2endScanner", () => {
    const uid = "1";
    const oxDir = process.cwd() + "/ox-security/" + uid;
    const detailsJsonPath = getSharedFolder(uid) + "/report/appoxalypse_json.js";
    let detailesjSON;

    //Test expected results
    const expectedRepoCount = 1;

    //Should run first always
    it("scanner finish successfully", async () => {
      let res = false;
      try {
        res = await SASTscan({
          MessageDeduplicationId: uid,
          MessageBody:
            '{"org_id":"IPGitLabTest","configuredConnectors":[{"id":"3","name":"Bitbucket","description":"Bitbucket is a Git-based source code repository hosting service owned by Atlassian. Bitbucket offers both commercial plans and free accounts with an unlimited number of private repositories.","hostURL":"https://api.bitbucket.org/2.0","identityProviderBaseURL":"https://bitbucket.org/site/oauth2/","iconURL":"https://d1wa508hvqs2kv.cloudfront.net/1.0.1/connectors/bitbucket.png","credentialsType":"UserPassword","credentialsTypes":["IdentityProvider","UserPassword"],"family":"Source Control","isResourceAvailable":true,"isOxBuiltIn":false,"isOpenSource":false,"isConfigured":true,"credentials":[{"idpToken":"{\\"access_token\\":\\"0nhITIW9S87Ta0TkJP3YQQp_RuhejbmdusEFJPiFm-4JIMLUIks-voWKZhfzw4C7Wljk8sstwj6_yhnwfjZD3uEblcgk9NjSgJzwdG-kSdPeCsNRMUPfMZfT\\",\\"token_type\\":\\"bearer\\",\\"expires_in\\":7200,\\"refresh_token\\":\\"ehhQ5r6w4CYg3mM2tG\\",\\"scopes\\":\\"account webhook pullrequest\\",\\"state\\":\\"authorization_code\\"}","credentialsType":"IdentityProvider","hostURL":"https://api.bitbucket.org/2.0","tokenExpirationDate":null}]}]}',
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
  describe("BitBucket IDP not configured", () => {
    it("not configured", () => {
      console.log("Fill environment variables to test");
      expect(true).toBe(true);
    });
  });
}
