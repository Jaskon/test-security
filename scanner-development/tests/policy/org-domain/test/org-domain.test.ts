import policyOrgDomainRepo from "../../../../src/policy/rules/code/policyOrgDomainRepo";
import policyOrgDomainRepoConfig from "../config/policyOrgDomainRepo.json";
import users from "../config/jsonData/users-api.json";

// import withVeteransReviewers from "../config/jsonData/with-veteran-reviewers.json";

describe("Test policy Org-Domain-Repo", () => {
  const orgDomain = new policyOrgDomainRepo();
  orgDomain.policyRuleMetadata = policyOrgDomainRepoConfig;
  let res;
  let resString = "";

  beforeAll(async () => {
    res = await orgDomain.eval(users);
    resString = JSON.stringify(res);
  });
  it("Should return yaniv as the problematic user domain", () => {
    expect(orgDomain.problematicUserDomain).toEqual("yaniv");
  });
});
