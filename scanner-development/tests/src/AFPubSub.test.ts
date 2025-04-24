import redisCacheDB from "../../src/cache/CacheInterface";
import afPubSub, { PubSubKey } from "../../src/appmgr/AFPubSub";

describe("App flow pub/sub test", () => {
  it("Simple pub/sub tests", async () => {
    const session = "AppFlowTest";

    let callbackCalled = false;

    const callback = async (object: PubSubKey) => {
      if (object.id === "test") {
        callbackCalled = true;
      }
    };

    const unsubscribe = await afPubSub.instance.subscribe(session, "test", callback);
    expect(callbackCalled).toBe(false);

    //
    // Publish test
    //
    const object = { id: "test" };
    await afPubSub.instance.publish(session, "test", object);
    expect(callbackCalled).toBe(true);

    //
    // Unsubscribe
    //
    unsubscribe();

    //
    // Negative test
    //
    callbackCalled = false;
    await afPubSub.instance.publish(session, "test", object);
    expect(callbackCalled).toBe(false);
  });

  it("delayed pub/sub tests", async () => {
    const session = "AppFlowDelayedTest";
    let callbackCalled = false;

    const callback = async (object: PubSubKey) => {
      if (object.id === "test") {
        callbackCalled = true;
      }
    };

    //
    // Notify before we subscribe
    //
    const object = { id: "test" };
    await afPubSub.instance.publish(session, "test", object);
    expect(callbackCalled).toBe(false);

    //
    // Subscribe and notify
    //
    const unsubscribe = await afPubSub.instance.subscribe(session, "test", callback);
    expect(callbackCalled).toBe(true);

    unsubscribe();
  });

  it("publish after subscribe", async () => {
    const session = "AppFlowPubSubDelayedPublishTest";

    let callbackCalled = false;

    const callback = async (object: PubSubKey) => {
      if (object.id === "test") {
        callbackCalled = true;
      }
    };
    const unsubscribe = await afPubSub.instance.subscribe(session, "test", callback);

    expect(callbackCalled).toBe(false);

    {
      const sessionOther = "AppFlowPubSubDelayedPublishTest";

      const object = { id: "test" };
      await afPubSub.instance.publish(sessionOther, "test", object);
    }
    expect(callbackCalled).toBe(true);

    unsubscribe();
  });

  it("Closing cache", async () => {
    redisCacheDB.instance.quit();

    let session1 = "AppFlowPubSubDelayedPublishTest";
    afPubSub.instance.destroy(session1);
    let length: any = await redisCacheDB.instance.getLen(`${session1}:appFlowArray`);
    expect(length).toBe(null);

    session1 = "AppFlowDelayedTest";
    afPubSub.instance.destroy(session1);
    length = await redisCacheDB.instance.getLen(`${session1}:appFlowArray`);
    expect(length).toBe(0);

    session1 = "AppFlowTest";
    afPubSub.instance.destroy(session1);
    length = await redisCacheDB.instance.getLen(`${session1}:appFlowArray`);
    expect(length).toBe(0);
  });
});
