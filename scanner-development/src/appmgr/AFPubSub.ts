import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();
import redisCacheDB from "../cache/CacheInterface";

export interface PubSubKey {
  id: string;
}

function getAFPubSub() {
  class AFPubSub {
    private subscribers = new Map<string, Function>();
    static instance: AFPubSub = new AFPubSub();
    private constructor() {}

    private async getAppFlowArrays(session) {
      const appFlowArrays = [];

      const length: any = await redisCacheDB.instance.getLen(`${session}:appFlowArray`);

      if (length !== null) {
        for (let i = 0; i < length; i++) {
          const key: any = await redisCacheDB.instance.getIndex(`${session}:appFlowArray`, i);

          //
          // {repo: string, path: string}
          //
          appFlowArrays.push(key);
        }
      }

      return appFlowArrays;
    }

    //
    // {repo: string, path: string}
    //
    private async saveAppFlowArrays(session, object: PubSubKey) {
      await redisCacheDB.instance.multiSet(`${session}:appFlowArray`, object);
    }

    public async subscribe(session: string, topic: string, callback: Function) {
      this.subscribers.set(`${session}:${topic}`, callback);

      const appFlowArrays = await this.getAppFlowArrays(session);

      //
      // Delayed notification
      //
      for (const appFlowArray of appFlowArrays) {
        try {
          if (appFlowArray.id === topic) {
            await callback(appFlowArray);
          }
        } catch (err) {
          logger.error(`Error subscribing to ${topic} with error: ${err}`);
        }
      }

      return () => {
        this.subscribers.delete(`${session}:${topic}`);
      };
    }

    public async publish(session: string, topic: string, message: any) {
      const subscriber = this.subscribers.get(`${session}:${topic}`);

      if (subscriber) {
        await subscriber(message);
      } else {
        await this.saveAppFlowArrays(session, message);
      }
    }

    async destroy(session) {
      logger.info(`AFPubSub: ${session} destroyed`);

      this.subscribers.clear();

      //
      // Clear all appFlowArrays from redis
      //
      for (;;) {
        const temp = await redisCacheDB.instance.multiGet(`${session}:appFlowArray`);

        if (temp === null) {
          break; // We are done!
        }
      }
    }
  }

  return AFPubSub;
}

const afPubSub = getAFPubSub();

export default afPubSub;
