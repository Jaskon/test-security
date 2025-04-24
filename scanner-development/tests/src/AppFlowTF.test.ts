const dotenv = require("dotenv");
dotenv.config();

import redisCacheDB from "../../src/cache/CacheInterface";
import { ApplicationManager } from "../../src/appmgr/AppManager";
import { fetchApplicationFlowJsonFromMemory } from "../../src/appmgr/FetchApplications";
import { parseArtifacts } from "../../src/appmgr/ParseArtifacts";
import AppFlowParser from "../../src/appmgr/AppFlowParser";
import * as fs from "fs";
import { uncompress } from "../../src/helper/compression/zStream";

jest.mock("../../src/appmgr/ParseArtifacts");

describe("TF State Serialized Data analysis", () => {
  const zlibedConnections: any = fs.readFileSync(process.cwd() + "/tests/src/AppFlow/connections_tf2.zlib", "utf8");

  it("TF State Serialized Data analysis", () => {
    expect(zlibedConnections).toBeDefined();
  });

  // This test requires REDIS to be enabled through REDIS_ENABLED
  it("Retain containers information in application manager", async () => {
    //
    // Test body
    //
    const connections = await uncompress(zlibedConnections);
    expect(connections).toBeDefined();

    const session = "{A3BD02F3-1280-47A3-9E0D-17A2A27E0897}";
    const appMgr = new ApplicationManager(session);

    const parsedConnections = JSON.parse(connections);
    expect(parsedConnections.length === 1947).toBeTruthy();

    for (const connection of parsedConnections) {
      redisCacheDB.instance.multiSet(session, connection);
    }

    // Generate app flow connections
    const applicationsFlows = await fetchApplicationFlowJsonFromMemory(session, "pesudo-org");

    expect(applicationsFlows[0].flow.length).toEqual(68);

    // Close redis connection
    redisCacheDB.instance.quit();
  }, 666000000);
});

describe("Parse Terraform State tests", () => {
  it("Parse Terraform plan", async () => {
    const session = "{E1F1E53A-2FDC-473B-9DB4-BD4610548EEE}";

    await AppFlowParser(session).parseTFState(
      fs.readFileSync(process.cwd() + "/tests/src/AppFlow/tfstate", null).buffer,
      "plan",
      "pesudo-org",
    );

    const artifact: any = await redisCacheDB.instance.multiGet(session);

    expect(artifact).toBeDefined();
    expect(artifact.hash).toBe("033d4c55c10dc0714b2b59a5bb3ed0026aef021785eafed7381f611803c5e5c6");
  });
});
