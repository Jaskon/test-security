import { SASTscan } from "../../src/index";
const fs = require("fs");

const dotenv = require("dotenv");
dotenv.config();
const uid = "1";

describe("end2endScanner", () => {
  //Should run first always
  it("scanner finish successfully", async () => {
    let res = false;
    try {
      res = (await SASTscan({
        MessageDeduplicationId: uid,
        MessageBody:
          '{"org_id":"Michelle3","configuredConnectors":[{"hostURL":"https://api.github.com","name":"GitHub","credentials":[{"token":"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"}],"description":"GitHub","isConfigured":true}]}',
      })) as boolean;
    } catch (err) {
      console.error(err);
      console.error("test failed, exception from scanner", err);
      expect(false).toBe(true);
    }

    //Validate scanner finish
    expect(res == true).toBe(true);
  }, 400000);
});
