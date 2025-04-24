const dotenv = require("dotenv");
dotenv.config();

import AWSCloudTrail from "../../src/codeOpenSourceTools/cloudTools/specifcTools/AWSCloudTrail";
import AWSContainers from "../../src/codeOpenSourceTools/cloudTools/specifcTools/AWSContainers";
import { AWSTaskARN, ImageDigest, OXAWSImageTrailData, OXAWSRunningTaskData } from "../../src/entitis/connectorsSpecific/AWSRelatedTypes";

jest.mock("../../src/codeOpenSourceTools/cloudTools/specifcTools/AWSCloudTrail");
jest.mock("../../src/codeOpenSourceTools/cloudTools/specifcTools/AWSContainers");

describe("AWS Image tests", () => {
  it("Read and verify the data size is correct", async () => {
    const awsData = AWSContainers(
      process.env.CLOUD_AWS_ACCESS_KEY ?? undefined,
      process.env.CLOUD_AWS_SECRET_ACCESS_KEY ?? undefined,
      undefined,
    );

    const trail = AWSCloudTrail(
      process.env.CLOUD_AWS_ACCESS_KEY ?? undefined,
      process.env.CLOUD_AWS_SECRET_ACCESS_KEY ?? undefined,
      undefined,
    );

    expect(trail).toBeDefined();

    const runningTasksByCluster = (await awsData.fetchRunningTasksDefinitions()) as Map<AWSTaskARN, OXAWSRunningTaskData>;

    const imagesTrailData = (await trail.fetchAllRunningImagesTrails(new Map())) as Map<ImageDigest, OXAWSImageTrailData>;
    expect(imagesTrailData).toBeDefined();
    expect(imagesTrailData.size).toBe(18);

    for (const [hash, trailData] of imagesTrailData) {
      if ("ecr_poc" !== trailData.trailEvents.Username) console.log(`${hash} ${trailData.trailEvents.Username}`);
      else expect(trailData.trailEvents.Username).toBe("ecr_poc");
    }
  }, 666999666);
});
