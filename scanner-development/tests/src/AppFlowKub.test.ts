const dotenv = require("dotenv");
dotenv.config();

import redisCacheDB from "../../src/cache/CacheInterface";
import { fetchApplicationFlowJsonFromMemory } from "../../src/appmgr/FetchApplications";
import AppFlowParser from "../../src/appmgr/AppFlowParser";
import * as fs from "fs";

describe("Kub State Serialized Data analysis", () => {
  const zlibedConnections: any = fs.readFileSync(process.cwd() + "/tests/src/AppFlow/connections_kub.json", "utf8");

  it("Kub State Serialized Data analysis", () => {
    expect(zlibedConnections).toBeDefined();
  });

  // This test requires REDIS to be enabled through REDIS_ENABLED
  it("Retain containers information in application manager", async () => {
    //
    // Test body
    //
    const connections = zlibedConnections;
    expect(connections).toBeDefined();

    const session = "{3EC3A643-6C70-4F78-ADD5-8D95B6BCB428}";
    const appMgr = new ApplicationManager(session);

    const parsedConnections = JSON.parse(connections);
    expect(parsedConnections.length === 2551).toBeTruthy();

    for (const connection of parsedConnections) {
      redisCacheDB.instance.multiSet(session, connection);
    }

    // Generate app flow connections
    const applicationsFlows = await fetchApplicationFlowJsonFromMemory(session, "pesudo-org");

    expect(applicationsFlows[0].flow.length).toEqual(71);

    for (const flow of applicationsFlows[0].flow) {
      if (flow.repo === "deployments / oxdemo") {
        expect(flow.kubernetes.length).toEqual(4);
        expect(flow.kubernetes[0].hash).toEqual("6ed47a6b2e70665ec2f7df6d78715e063bf70dd532335f1744cb3668dfec5bc8");
        expect(flow.kubernetes[1].hash).toEqual("1b86bfe1d30c588840337982df100ab581fa03ffa5fc45b363b4cf73e7a60027");
        expect(flow.kubernetes[2].hash).toEqual("d85c124bcfb104934bac7f17c87728d7dd3bcc3e899a461eb89d1ab2ffb2b346");
        expect(flow.kubernetes[3].hash).toEqual("235c26f8d43a7f423a2bd76ab9fb46f047a23cce9ac5ef4243c924a4a6af9065");
      }
    }

    // Close redis connection
    redisCacheDB.instance.quit();
  }, 666000000);
});
