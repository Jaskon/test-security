import { getSecInfraObj, applySecInfra, setSecInfra } from "../config/mockFn";

import allApps from "../config/allApps.json";

describe("Testing security and infrastructure data", () => {
  let relevantAppCount = 0;
  for (const apps of Object.values(allApps)) {
    const app = apps[0].collectorData;
    if (app.repoImportance.total > 0) {
      // simulate having tools enabled.
      app.oxSecurityTools.oxIacTools.push("checkov");
      app.oxSecurityTools.oxContainerTools.push("checkov");
      app.oxSecurityTools.oxSecretsTools.push("gitleaks");
      relevantAppCount++;
      setSecInfra(apps[0]);
    }
  }

  applySecInfra(relevantAppCount);

  describe("SAST data should return the coreect percentage calculation", () => {
    it("Should return 78% coverage by Ox", () => {
      const sast = getSecInfraObj("sast");
      expect(sast.oxCoverage).toEqual(78);
    });

    it("Should return 10% not covered", () => {
      const sast = getSecInfraObj("sast");
      expect(sast.noCoverage).toEqual(10);
    });

    it("Should return 12% not applicable", () => {
      const sast = getSecInfraObj("sast");
      expect(sast.notApplicable).toEqual(12);
    });
  });

  describe("SCA data should return the correct percentage calculation", () => {
    it("Should return 78% coverage by Ox", () => {
      const sast = getSecInfraObj("sca");
      expect(sast.oxCoverage).toEqual(78);
    });

    it("Should return 10% not covered", () => {
      const sast = getSecInfraObj("sca");
      expect(sast.noCoverage).toEqual(10);
    });

    it("Should return 12% not applicable", () => {
      const sast = getSecInfraObj("sca");
      expect(sast.notApplicable).toEqual(12);
    });
  });

  describe("IaC data should return the correct percentage calculation", () => {
    const iac = getSecInfraObj("iac");

    it("Should return 100% coverage by Ox", () => {
      expect(iac.oxCoverage).toEqual(100);
    });
    it("Should return 0% not covered", () => {
      expect(iac.noCoverage).toEqual(0);
    });
    it("Should return 0% not applicable", () => {
      expect(iac.notApplicable).toEqual(0);
    });
  });

  describe("CSPM data should return the correct percentage calculation", () => {
    const iac = getSecInfraObj("cspm");

    it("Should return 15% coverage by Ox", () => {
      expect(iac.oxCoverage).toEqual(15);
    });
    it("Should return 0% not covered", () => {
      expect(iac.noCoverage).toEqual(0);
    });
    it("Should return 85% not applicable", () => {
      expect(iac.notApplicable).toEqual(85);
    });
  });

  describe("Container Security data should return the correct percentage calculation", () => {
    const containerSecurity = getSecInfraObj("container security");

    it("Should return 53% coverage by Ox", () => {
      expect(containerSecurity.oxCoverage).toEqual(53);
    });
    it("Should return 0% not covered", () => {
      expect(containerSecurity.noCoverage).toEqual(0);
    });
    it("Should return 47% not applicable", () => {
      expect(containerSecurity.notApplicable).toEqual(47);
    });
  });

  describe("Secrets search data should return the correct percentage calculation", () => {
    const secrets = getSecInfraObj("secret search");

    it("Should return 100% coverage by Ox", () => {
      expect(secrets.oxCoverage).toEqual(100);
    });
    it("Should return 0% not covered", () => {
      expect(secrets.noCoverage).toEqual(0);
    });
    it("Should return 0% not applicable", () => {
      expect(secrets.notApplicable).toEqual(0);
    });
  });
});
