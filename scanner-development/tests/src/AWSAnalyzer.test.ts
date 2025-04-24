const dotenv = require("dotenv");
dotenv.config();

import redisCacheDB from "../../src/cache/CacheInterface";
import AWSAnalyzer from "../../src/codeOpenSourceTools/cloudTools/specifcTools/AWSAnalyzer";
import { ApplicationManager } from "../../src/appmgr/AppManager";
import { fetchApplicationFlowJsonFromMemory } from "../../src/appmgr/FetchApplications";
import { CICDJob } from "../../src/entitis/cicidRepoTypes";
import crypto from "crypto";
import * as fs from "fs";
import { AWSContainerDefinition, AWSECSTaskDefinition, ECRImageDetails, ECRRepository } from "../../src/entitis/cloudTypes";

describe("Serialized Data analysis", () => {
  const data: any = JSON.parse(fs.readFileSync(process.cwd() + "/tests/src/AWSMockData/AWSImageData.json", "utf8"));

  it("Read and verify the data size is correct", () => {
    expect(data.length).toEqual(8);
  });

  it("Analyze regions information", () => {
    const awsAnalyzer: any = AWSAnalyzer(data);

    try {
      awsAnalyzer.loadSerializedAWSData();

      const regions: any = awsAnalyzer.fetchRegions();

      expect(regions.size).toEqual(17);
      expect(regions.has("eu-west-1")).toBeTruthy();
    } catch (e) {
      console.log(e);
      expect(true).toBeFalsy();
    }
  });

  it("Analyze repository information", () => {
    const awsAnalyzer: any = AWSAnalyzer(data);

    try {
      awsAnalyzer.loadSerializedAWSData();

      const repositories: Map<string /*Region*/, ECRRepository> = awsAnalyzer.fetchAllECRRepositories();

      expect(repositories.size).toEqual(17);
      expect(repositories.has("eu-west-1")).toBeTruthy();

      for (const [key, value] of repositories.entries()) {
        if (key === "eu-west-1") {
          expect(value.repositoriesData[0].repositories.length).toEqual(28);
        }
      }
    } catch (e) {
      console.log(e);
      expect(true).toBeFalsy();
    }
  });

  it("Analyze image information", () => {
    const awsAnalyzer: any = AWSAnalyzer(data);

    try {
      awsAnalyzer.loadSerializedAWSData();

      const images: Map<string /*Image Uri*/, ECRImageDetails> = awsAnalyzer.fetchAllECRImages();

      expect(images.size).toEqual(28);

      // Image URI example
      expect(images.has("857809147732.dkr.ecr.eu-west-1.amazonaws.com/scanner")).toBeTruthy();

      // Make sure all images have a digest
      for (const [key, value] of images.entries()) {
        if (value.imageDetails.length > 0) {
          expect(value.imageDetails[0].imageDigest).toBeDefined();
        }
      }
    } catch (e) {
      console.log(e);
      expect(true).toBeFalsy();
    }
  });

  it("Analyze definitions information", () => {
    const awsAnalyzer: any = AWSAnalyzer(data);

    try {
      awsAnalyzer.loadSerializedAWSData();

      const definitions: Map<string /*arn of task definition*/, AWSECSTaskDefinition> = awsAnalyzer.fetchAllTaskDefinitions();

      expect(definitions.size).toEqual(338);
      expect(definitions.has("arn:aws:ecs:eu-west-1:857809147732:task-definition/devapp:15")).toBeTruthy();
    } catch (e) {
      console.log(e.message);
      expect(true).toBeFalsy();
    }
  });

  it("Analyze containers information", () => {
    const awsAnalyzer: any = AWSAnalyzer(data);

    try {
      awsAnalyzer.loadSerializedAWSData();

      const containers: Map<string /* image name */, AWSContainerDefinition> = awsAnalyzer.fetchAllContainerData();

      expect(containers.size).toEqual(68);
      const value = containers.get("857809147732.dkr.ecr.eu-west-1.amazonaws.com/oxparser:v71") as any;
      expect(value.region).toEqual("eu-west-1");

      expect(containers.has("857809147732.dkr.ecr.eu-west-1.amazonaws.com/scanner:v234")).toBeTruthy();
    } catch (e) {
      console.log(e);
      expect(true).toBeFalsy();
    }
  });

  // This test requires REDIS to be enabled through REDIS_ENABLED
  it("Retain containers information in application manager", async () => {
    const awsAnalyzer: any = AWSAnalyzer(data);

    try {
      awsAnalyzer.loadSerializedAWSData();

      const containers: any = awsAnalyzer.fetchAllContainerData();

      const uid = "pseudo-uuid";
      const appMgr = new ApplicationManager(uid);

      //
      // Start with application manager saving repository information
      //
      await appMgr.CreateRepoNode({
        repo_name: "test",
        repo_id: "1",
        vcs_type: "github",
        url: "url",
        default_branch: "master",
      });

      //
      // Create a pipeline information
      //
      await appMgr.CreateCITool(
        {
          reponame: "test",
          username: "multi",
          vcs_type: "github",
          default_branch: "master",
          vcs_url: "url",
        },
        "GitHub",
      );

      //
      // Save pipeline information
      //
      for (let i = 0; i < 22; i++) {
        const ciJob: CICDJob = new CICDJob("test", "success", "pipeline", "multi", "sha", "master", `url${i}`, "", "", "UNKNOWN");

        appMgr.CreateCIJob(ciJob);
      }
      //
      // Create artifacts built by the pipeline
      //
      let i = 0;
      for (const [key, value] of containers) {
        await appMgr.CreateNode("Artifact", {
          buildUrl: `url${i}`,
          type: "file",
          subType: "Docker Container",
          name: value.image.split(":")[0],
          size: "",
          hashType: "SHA-256",
          hash: `${i}`,
          resolved: true,
        });
        i++;
      }

      //
      // Create active product artifacts
      //
      for (const [key, value] of containers) {
        appMgr.CreateProductArtifact({
          subType: "Docker Container",
          name: key,
          image: value.image.split(":")[0],
          version: value.image.split(":")[1],
          type: "container",
          hashType: "SHA-256",
          hash: `${crypto.createHash("sha256").update(`${value.region}:${value.image}`).digest("hex")}`,
          resolved: true,
        });
      }

      const applicationsFlows = await fetchApplicationFlowJsonFromMemory(uid, "pesudo-org");

      expect(containers.size).toEqual(68);
      expect(applicationsFlows[0].flow[0].repo).toEqual("test");
      expect(applicationsFlows[0].flow[0].cloudDeployment.length).toEqual(14);
      expect(containers.has("857809147732.dkr.ecr.eu-west-1.amazonaws.com/oxparser:v71")).toBeTruthy();

      // Close redis connection
      redisCacheDB.instance.quit();
    } catch (e) {
      console.log(e);
      expect(true).toBeFalsy();
    }
  }, 666000000);
});
