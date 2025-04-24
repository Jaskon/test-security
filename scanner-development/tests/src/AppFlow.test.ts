const dotenv = require("dotenv");
dotenv.config();

import redisCacheDB from "../../src/cache/CacheInterface";
import { ApplicationManager } from "../../src/appmgr/AppManager";
import { parseArtifacts } from "../../src/appmgr/ParseArtifacts";
import AppFlowParser from "../../src/appmgr/AppFlowParser";
import { fetchApplicationFlowJsonFromMemory } from "../../src/appmgr/FetchApplications";
// import AWSAnalyzer from "../../src/codeOpenSourceTools/cloudTools/specifcTools/AWSAnalyzer";
import crypto from "crypto";
import * as fs from "fs";
import { uncompress } from "../../src/helper/compression/zStream";

jest.mock("../../src/appmgr/ParseArtifacts");

describe("Serialized Data analysis", () => {
  const zlibedConnections: any = fs.readFileSync(process.cwd() + "/tests/src/AppFlow/connections.zlib", "utf8");

  const data: any = JSON.parse(fs.readFileSync(process.cwd() + "/tests/src/AWSMockData/AWSImageData.json", "utf8"));

  it("Read and verify the data size is correct", () => {
    expect(zlibedConnections).toBeDefined();
  });

  // This test requires REDIS to be enabled through REDIS_ENABLED
  it("Retain containers information in application manager", async () => {
    //
    // Test body
    //
    const connections = await uncompress(zlibedConnections);
    expect(connections).toBeDefined();

    const session = "{A3BD02F3-1280-47A3-9E0D-17A2A27E0896}";
    const appMgr = new ApplicationManager(session);

    const parsedConnections = JSON.parse(connections);
    expect(parsedConnections.length === 1464).toBeTruthy();

    for (const connection of parsedConnections) {
      redisCacheDB.instance.multiSet(session, connection);
    }

    // Load AWS data as well
    const awsAnalyzer: any = AWSAnalyzer(data);
    awsAnalyzer.loadSerializedAWSData();
    const containers: any = awsAnalyzer.fetchAllContainerData();

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

    // Generate app flow connections
    const applicationsFlows = await fetchApplicationFlowJsonFromMemory(session, "pesudo-org");

    expect(applicationsFlows[0].flow.length).toEqual(65);

    // Close redis connection
    redisCacheDB.instance.quit();
  }, 666000000);
});

describe("App Flow new API", () => {
  it("Parse Artifacts", async () => {
    const arrayBuffer = new ArrayBuffer(3);
    const artifactsBulk = await AppFlowParser("{C308A741-E77E-408D-8803-DB255B50726C}").parseJob(arrayBuffer, "url", "pesudo-org");

    expect(artifactsBulk.length).toEqual(1);
    expect((artifactsBulk[0] as any).output.length).toEqual(23);

    const artifact: any = await redisCacheDB.instance.multiGet("{C308A741-E77E-408D-8803-DB255B50726C}");

    expect(artifact).toBeDefined();
    expect(artifact.hash).toBe("033d4c55c10dc0714b2b59a5bb3ed0026aef021785eafed7381f611803c5e5c6");
  });
});
