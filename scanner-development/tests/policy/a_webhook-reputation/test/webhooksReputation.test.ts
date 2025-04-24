import WebhooksReputation from "../../../../src/policy/rules/code/webhooksReputation";
import MaliciousWebhooksReputationConfig from "../config/policyWebhooksReputation.json";
import SuspiciousWebhooksReputationConfig from "../config/policyWebhooksSuspicious.json";
import VTHelper from "../../../../src/helper/policy/vtHelper";
import * as mockJsons from "../config/mockJson";
import * as jsondata2 from "../config/jsonDATA.json";
import { isRegExp } from "util/types";

describe("Testing the webhook reputation policy", () => {
  const WR = new WebhooksReputation();
  WR.policyRuleMetadata = MaliciousWebhooksReputationConfig;
  const jsonData = jsondata2;

  // texts test
  let res;

  beforeAll(async () => {
    res = await WR.eval(jsonData);
  });

  it("Should output a violation", () => {
    const items = res;
    const isViolated = items.length;
    expect(isViolated).toBeTruthy();
  });

  it("Should have been violated twice", () => {
    if (res.length) {
      const isViolated = res[0].aggregatedInfo.aggregatedItems.length;
      expect(isViolated).toBe(2);
    }
  });
});

describe("Webhooks reputation 'eval' function", () => {
  const WR = new WebhooksReputation();
  const jsonData = jsondata2;
  const WReval = jest.fn(WR.eval);

  WReval(jsonData);

  it("Should recieve an object with 'webhooks' property", async () => {
    expect(WReval).toBeCalledWith(
      expect.objectContaining({
        webhooks: expect.anything(),
      }),
    );
  });

  it("The 'webhooks' property should be of type array", async () => {
    expect(WReval).toBeCalledWith(
      expect.objectContaining({
        webhooks: expect.any(Array),
      }),
    );
  });
});

describe("Webhooks config files", () => {
  describe("Suspicious", () => {
    const WR = new WebhooksReputation();
    WR.policyRuleMetadata = SuspiciousWebhooksReputationConfig;
    const getValueFromRuleArgs = WR.getValueFromRuleArgs;
    it("Config file should have a target value 'Suspicious'", async () => {
      expect(WR.getValueFromRuleArgs("reputation")).toEqual(["Suspicious"]);
    });
  });

  describe("Malicious", () => {
    const WR = new WebhooksReputation();
    WR.policyRuleMetadata = MaliciousWebhooksReputationConfig;
    const getValueFromRuleArgs = WR.getValueFromRuleArgs;
    it("Config file should have a target value 'Malicious'", async () => {
      expect(WR.getValueFromRuleArgs("reputation")).toEqual(["Malicious"]);
    });
  });
});

describe("VirusTotal helper class getClassification() function", () => {
  const vt = VTHelper.getInstance;
  const getClassification = jest.fn(vt().getCalssification);

  it("should return a string", async () => {
    expect(typeof getClassification(mockJsons.malRep)).toBe("string");
  });

  it("should return 'malicious' if more than 3 VirusTotal vendors classified the webhook as 'malicious'", async () => {
    expect(getClassification(mockJsons.malRep)).toBe("malicious");
  });

  it("should return 'suspicious' if more than 3 VirusTotal vendors classified the webhook as 'suspicious'", async () => {
    expect(getClassification(mockJsons.susRep)).toBe("suspicious");
  });

  it("should return 'harmless' if more than 10 VirusTotal vendors classified the webhook as 'harmless'", async () => {
    expect(getClassification(mockJsons.harmlessRep)).toBe("harmless");
  });

  it("should return 'unknown' if attribute of getClassification() is null", async () => {
    expect(getClassification(mockJsons.nullRep)).toBe("unknown");
  });

  it("should return 'unknown' if no other classification was determined", async () => {
    expect(getClassification(mockJsons.unknownRep)).toBe("unknown");
  });
});
