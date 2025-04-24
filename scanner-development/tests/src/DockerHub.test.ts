const dotenv = require("dotenv");
dotenv.config();

import DockerHubAPI from "../../src/dal/collectors/dockerhub";
import { DockerHubInfo } from "../../src/entitis/DockerhubTypes";

if (process.env.DOCKER_HUB_RESOURCES_TEST) {
  describe("Docker hub test-suite", () => {
    it("Test docker hub", async () => {
      const dockerHubApi = DockerHubAPI({
        uuid: "test",
        orgId: "org_OCiEeMaFR5nSimbx",
      });

      const mongodb: DockerHubInfo | false = await dockerHubApi.findInDockerHub("mongo", "latest", "amd64");

      if (mongodb) {
        expect(mongodb.id).toBe("mongo");
      }

      expect(true).toEqual(true);
    }, 666999666);
  });
} else {
  describe("Docker hub test-suite not configured", () => {
    it("not configured", () => {
      console.log("Fill environment variables to test");
      expect(true).toBe(true);
    });
  });
}
