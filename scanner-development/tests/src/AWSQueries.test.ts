import AWSQueries from "../../src/codeOpenSourceTools/cloudTools/specifcTools/AWSQueries";
import AWSContainers from "../../src/codeOpenSourceTools/cloudTools/specifcTools/AWSContainers";

import * as fs from "fs";

jest.mock("../../src/codeOpenSourceTools/cloudTools/specifcTools/AWSQueries");

describe("Simple queries tests", () => {
  it("Region query verification", async () => {
    expect(await AWSQueries(undefined, undefined, undefined).describeRegions()).toContain("eu-west-1");
    const regions: any = await AWSQueries(undefined, undefined, undefined).describeRegions();

    expect(JSON.parse(regions).Regions[0].RegionName).toContain("eu-north-1");
  });

  it("Tasks definitions", async () => {
    expect(await AWSQueries(undefined, undefined, undefined).queryECSTasksDefinitions("eu-west-1").getAllDefinitions()).toContain(
      "arn:aws:ecs:eu-west-1:857809147732:task-definition/betaapp_fargate:10",
    );

    const definitions: any = await AWSQueries(undefined, undefined, undefined).queryECSTasksDefinitions("eu-west-1").getAllDefinitions();
    expect(JSON.parse(definitions).taskDefinitionArns[0]).toBe(
      "arn:aws:ecs:eu-west-1:857809147732:task-definition/beta_scan_tool_manager_service:1",
    );
  });

  it("Tasks definitions data", async () => {
    const definitionData: any = await AWSQueries(undefined, undefined, undefined)
      .queryECSTasksDefinitions("eu-west-1")
      .getDefinitionData("arn:aws:ecs:eu-west-1:857809147732:task-definition/betaapp_fargate:10");
    expect(definitionData).toContain("857809147732.dkr.ecr.eu-west-1.amazonaws.com/oxparser:v23");
  });
});

describe("Containers fetching", () => {
  it("Fetch all tasks definitions", async () => {
    const tasks: any = await AWSContainers(undefined, undefined, undefined).fetchActiveDefinitions();

    for (const [key, value] of tasks) {
      console.log(`Tasks found: ${JSON.stringify(key)}\n`);
    }

    expect(tasks.has("arn:aws:ecs:eu-west-1:857809147732:task-definition/betaapp:15")).toBeTruthy();
  });

  it("Fetch all containers in a given definition", async () => {
    const definitions: any = await AWSContainers(undefined, undefined, undefined).fetchActiveDefinitions();
    const containers: any = await AWSContainers(undefined, undefined, undefined).parseContainersFromDefinition(
      definitions.get("arn:aws:ecs:eu-west-1:857809147732:task-definition/betaapp:15") as string,
    );

    expect(containers.has("oxparser")).toBeTruthy();
  });

  it("Serialize the cloud data", async () => {
    const awsData = AWSContainers(undefined, undefined, undefined);
    const definitions: any = await awsData.fetchActiveDefinitions();
    const serializedData = await awsData.serializeCloudData();

    expect(serializedData.length).toEqual(8);

    // Save serialized data to file and delete it
    fs.writeFileSync("test.json", JSON.stringify(serializedData));
    fs.unlinkSync("test.json");

    expect(fs.existsSync("test.json")).toBeFalsy();
  });
});

describe("Serialized Data analysis", () => {
  const data: any = JSON.parse(fs.readFileSync(process.cwd() + "/tests/src/AWSMockData/ox.json", "utf8"));

  it("Read and verify the data size is correct", () => {
    expect(data.length).toEqual(3);
  });
});
