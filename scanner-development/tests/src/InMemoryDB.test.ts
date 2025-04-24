const dotenv = require("dotenv");
dotenv.config();

import redisCacheDB from "../../src/cache/CacheInterface";

describe("In Memory Database", () => {
  it("Test basic in memory functions", async () => {
    redisCacheDB.instance.set("test", "test");
    expect(await redisCacheDB.instance.get("test")).toBe("test");

    redisCacheDB.instance.set("test", "test2");
    expect(await redisCacheDB.instance.get("test")).toBe("test2");

    redisCacheDB.instance.set("test", "test3");
    expect(await redisCacheDB.instance.get("test")).toBe("test3");

    redisCacheDB.instance.multiSet("test1", "test1");
    redisCacheDB.instance.multiSet("test1", "test2");

    expect(await redisCacheDB.instance.multiGet("test1")).toEqual("test1");
    expect(await redisCacheDB.instance.multiGet("test1")).toEqual("test2");
    expect(await redisCacheDB.instance.multiGet("test1")).toEqual(null);

    redisCacheDB.instance.quit();
  }, 666000000);
});
