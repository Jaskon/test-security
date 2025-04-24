const dotenv = require("dotenv");
dotenv.config();

import redisCacheDB from "../../src/cache/CacheInterface";
import { uncompress } from "../../src/helper/compression/zStream";
import { ApplicationManager } from "../../src/appmgr/AppManager";
import { fetchApplicationFlowJsonFromMemory } from "../../src/appmgr/FetchApplications";
import * as fs from "fs";

jest.mock("../../src/appmgr/ParseArtifacts");

describe("Serialized Data analysis", () => {
  const zlibedConnections: any = fs.readFileSync(process.cwd() + "/tests/src/AppFlow/connections_1.zlib", "utf8");

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

    const session = "{A3BD02F3-1280-47A3-9E0D-17A2A27E0817}";
    const appMgr = new ApplicationManager(session);

    const parsedConnections = JSON.parse(connections);
    expect(parsedConnections.length === 18854).toBeTruthy();

    for (const connection of parsedConnections) {
      redisCacheDB.instance.multiSet(session, connection);
    }

    // Generate app flow connections
    const applicationsFlows = await fetchApplicationFlowJsonFromMemory(session, "pesudo-org");

    expect(applicationsFlows[0].flow.length).toEqual(46);

    // Close redis connection
    redisCacheDB.instance.quit();
  }, 666000000);
});
