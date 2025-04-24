require("dotenv").config({ path: "./.env" });
import config from "../config/policyCloudMidSecurityScan.json";
import policyCloudSecurityScan from "../../../../src/policy/rules/code/policyCloudSecurityScan"
import { ToolNameForUI } from "../../../../src/entitis/tool/toolsTypes";
import jsonData from "../config/mockData.json";

describe("Runs test based on tool enabled/disabled detection", () => {
  const cloudpolicy = new policyCloudSecurityScan();
  cloudpolicy.policyRuleMetadata = config;
  let result;

  beforeAll(async () => {
    result = await cloudpolicy.eval(jsonData);
  });

  // Prowler is ON by client
  if (cloudpolicy.enableByPolicy(ToolNameForUI.prowler)) {
    describe("Test detected that client turned Prowler ON", () => {
      it("Should be on", () => {
        expect(process.env.TOOLS_PROWLER).toEqual("enabled");
      });
      it("Should have collected cloudSecurityEvents", () => {
        expect(jsonData.cloudSecurityEvents.length).toBeTruthy();
      });
      it("Should return a non-empty array with at least one result", () => {
        expect(result.length).toBeTruthy();
      });
    });
  }

  // Prowler is OFF by client
  if (!cloudpolicy.enableByPolicy(ToolNameForUI.prowler)) {
    describe("Test detected that client turned Prowler OFF", () => {
      it("Prowler should be off", () => {
        expect(process.env.TOOLS_PROWLER).not.toEqual("enabled");
      });

      it("should have collected cloudSecurityEvents", () => {
        expect(jsonData.cloudSecurityEvents.length).toBeTruthy();
      });

      it("should return an empty array with no results", () => {
        expect(result.length).not.toBeTruthy();
      });
    })
  }

  describe("Testing what happens when Prowler is defenetly OFF", () => {
    beforeAll(async () => {
      process.env.TOOLS_PROWLER = "disabled";
      result = await cloudpolicy.eval(jsonData);
    });

    it("Prowler should be off", () => {
      expect(process.env.TOOLS_PROWLER).not.toEqual("enabled");
    });

    it("should have collected cloudSecurityEvents nevertheless", () => {
      expect(jsonData.cloudSecurityEvents.length).toBeTruthy();
    });

    it("should not return policy results", () => {
      expect(result.length).not.toBeTruthy();
    });
  });
});



