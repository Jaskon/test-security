import policyRarePusherVeteranReviews from "../../../../src/policy/rules/code/policyRarePusherVeteranReviews";
import policyRareCommitterReviews from "../config/policyRareCommitterReviews.json";
import noVeteransReviewers from "../config/jsonData/no-veterans-reviewers.json";

import withVeteransReviewers from "../config/jsonData/with-veteran-reviewers.json";

describe("Test for with veterans", () => {
  const rareCommmiter = new policyRarePusherVeteranReviews();
  rareCommmiter.policyRuleMetadata = policyRareCommitterReviews;
  let res;
  let resString = "";

  beforeAll(async () => {
    res = await rareCommmiter.eval(withVeteransReviewers);
    resString = JSON.stringify(res);
  });
  it("should return itay basoni as highest reviewer", () => {
    expect(rareCommmiter.mostHighersVeteranCommiter).toEqual("Itay Basoni");
  });
  it("should be 5 veteran reviewers in repo", () => {
    expect(rareCommmiter.veteranCommiters.size).toEqual(5);
  });
  it("should be 3 rare commiters in repo", () => {
    expect(rareCommmiter.rareCommiters.size).toEqual(3);
  });
  it("Inbar rose should be rare commiter in repo and should violate since has not been reviewed", () => {
    const isViolated = resString.includes("The following code pushes were made by Ofir Michaely");
    expect(isViolated).toBeTruthy();
    expect(rareCommmiter.rareCommiters.has("inbar rose")).toBeTruthy();
  });
  it("Ofir Michaely should be rare commiter in repo and should violate since has not been reviewed", () => {
    const isViolated = resString.includes("The following code pushes were made by inbar rose");
    expect(isViolated).toBeTruthy();
    expect(rareCommmiter.rareCommiters.has("Ofir Michaely")).toBeTruthy();
  });
  it("dvir hacohen should be rare commiter in repo and should pass since he has veen reviewd by veteran reviewer", () => {
    const isViolated = resString.includes("The following code pushes were made by dvir hacohen");
    expect(isViolated).toBeFalsy();
    expect(rareCommmiter.rareCommiters.has("dvir hacohen")).toBeTruthy();
  });
});

describe("Test for no veterans reviewers in repo", () => {
  const rareCommmiter = new policyRarePusherVeteranReviews();
  rareCommmiter.policyRuleMetadata = policyRareCommitterReviews;
  let res;
  let resString = "";
  beforeAll(async () => {
    res = await rareCommmiter.eval(noVeteransReviewers);
    resString = JSON.stringify(res);
  });
  it("Inbar should not be rare commiter since he owner of repo and pass the policy", () => {
    expect(rareCommmiter.rareCommiters.has("inbar rose")).toBeFalsy();
  });
  it("Dvir hacohen should be rare commiter and should violate the policy", () => {
    const isViolated = resString.includes("The following code pushes were made by dvir hacohen");
    const noVeteranMessage = resString.includes(
      "Please note that there is no veteran of the repo to review the commits. Please consider a veteran reviewer from another repo to review the commits.",
    );
    expect(noVeteranMessage).toBeTruthy();
    expect(isViolated).toBeTruthy();
    expect(rareCommmiter.rareCommiters.has("dvir hacohen")).toBeTruthy();
  });
});
