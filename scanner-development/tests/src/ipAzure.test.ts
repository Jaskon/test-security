import { getSharedFolder } from "../../src/helper/generalUtils";
import { SASTscan } from "../../src/index";

const fs = require("fs");

const dotenv = require("dotenv");
dotenv.config();

if (process.env.AZURE_IDP_TEST) {
  describe("end2endScanner", () => {
    const uid = "1";
    const oxDir = process.cwd() + "/ox-security/" + uid;
    const detailsJsonPath = getSharedFolder(uid) + "/report/appoxalypse_json.js";
    let detailesjSON;

    //Test expected results
    const expectedRepoCount = 5;

    //Should run first always
    it("scanner finish successfully", async () => {
      let res = false;
      try {
        res = await SASTscan({
          MessageDeduplicationId: uid,
          MessageBody:
            '{"org_id":"osxX","configuredConnectors":[{"id":"2","name":"Azure","description":"Azure is a web-based DevOps lifecycle tool that provides a Git repository manager providing wiki, issue-tracking and continuous integration and deployment pipeline features, using an open-source license, developed by Microsoft Inc","hostURL":"https://azure.com","identityProviderBaseURL":"https://dev.azure.com/oauth/","iconURL":"http://code.benco.io/icon-collection/azure-icons/Dev-Console.svg","credentialsType":"Token","credentialsTypes":["IdentityProvider","Token"],"family":"Source Control","isResourceAvailable":true,"isOxBuiltIn":false,"isOpenSource":false,"isConfigured":true,"credentials":[{"idpToken":"{\\"access_token\\":\\"wcxf7kczquadrfrulw2cakvftnlddpqmhdfadw2fsiyvx6jaccva\\",\\"token_type\\":\\"bearer\\",\\"refresh_token\\":\\"\\",\\"scope\\":\\"\\",\\"created_at\\":\\"\\"}","credentialsType":"IdentityProvider","hostURL":"https://azure.com","tokenExpirationDate":null}]}]}',
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
  describe("Azure IDP not configured", () => {
    it("not configured", () => {
      console.log("Fill environment variables to test");
      expect(true).toBe(true);
    });
  });
}
