const dotenv = require("dotenv");
dotenv.config();

import redisCacheDB from "../../src/cache/CacheInterface";

describe("Redis", () => {
  function compareMaps(map1, map2) {
    var testVal;
    if (map1.size !== map2.size) {
      return false;
    }
    for (var [key, val] of map1) {
      testVal = map2.get(key);
      // in cases of an undefined value, make sure the key
      // actually exists on the object so there are no false positives
      if (testVal !== val || (testVal === undefined && !map2.has(key))) {
        return false;
      }
    }
    return true;
  }

  it("test new cache system", async () => {
    expect(redisCacheDB).toBeDefined();

    // Simple test
    {
      redisCacheDB.instance.set("test", "test");

      const value = await redisCacheDB.instance.get("test");
      expect(value).toBe("test");
    }

    // More complex test
    {
      let myMap = new Map([
        ["key1", "value1"],
        ["key2", "value2"],
      ]);

      redisCacheDB.instance.set("testMap", JSON.stringify(Array.from(myMap.entries())));
      const sameMap = new Map(JSON.parse((await redisCacheDB.instance.get("testMap")) as string));

      expect(compareMaps(myMap, sameMap)).toBe(true);
    }

    // Disconnect from redis
    redisCacheDB.instance.quit();

    // Flush all logs and data
    await new Promise(resolve => setTimeout(resolve, 1000));
    expect(true).toBe(true);
  }, 20000);
});
