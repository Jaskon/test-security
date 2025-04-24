// crypto lib
const crypto = require("crypto");
import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

function getCacheDB() {
  class RedisCache {
    private cacheMap: Map<string, any>;
    private cacheMultiMap: Map<string, any>;

    private client = null;
    private runOnce: boolean = false;
    private redisConnected = false;

    static instance: RedisCache = new RedisCache();

    private constructor() {
      this.cacheMap = new Map();
      this.cacheMultiMap = new Map();

      const REDIS_PORT = process.env.REDIS_PORT || 6379;
      const REDIS_HOST = process.env.REDIS_HOST || "localhost";

      if (this.client === null) {
        if (typeof REDIS_HOST === "undefined" || REDIS_HOST === null) {
          //logger.info(`Redis Cache: local chosen`);
          //this.client = redis.createClient();
        } else {
          logger.info(`Redis Cache: chosen ${REDIS_HOST}:${REDIS_PORT}`);
          // this.client = redis.createClient({
          //   url: `redis://${REDIS_HOST}:${REDIS_PORT}`,
          // });
        }

        // log the error in case redis is not available
        // this.client.on("error", function (err) {
        //   if (this.runOnce === false) {
        //     logger.error(`Redis Cache error: ${err}`);
        //     this.runOnce = true;
        //   }
        // });

        // this.client.on("connect", () => {
        //   logger.info("Redis Client is connected");
        //   this.redisConnected = true;
        // });
      }
    }

    //
    // Don't use this function on AWS!!!
    //
    public flush() {
      if (this.redisConnected) {
        try {
          this.client.flushdb(function (err, succeeded) {
            if (err) {
              logger.error(`Error while flushing redis cache: ${err}`);
            } else {
              logger.info(`Flush all keys (result: ${succeeded})`); // will be true if successful
            }
          });
        } catch (err) {
          logger.error(`Error while flushing redis cache: ${err}`);
        }
      } else {
        this.cacheMap.clear();
        this.cacheMultiMap.clear();
      }
    }

    public isConnected() {
      return this.redisConnected;
    }

    public quit() {
      try {
        if (this.redisConnected) this.client.quit();
      } catch (err) {
        logger.info(`Error while quitting redis: ${err}`);
      }
    }

    public set(key, value) {
      const hashedKey = crypto.createHash("sha256").update(key).digest("hex");

      if (this.redisConnected) {
        try {
          this.client.set(hashedKey, JSON.stringify(value));
        } catch (err) {
          logger.error(`Error while setting key: ${err}`);
        }
      } else {
        this.cacheMap.set(hashedKey, JSON.stringify(value));
      }
    }

    public setex(key, ex, value) {
      const hashedKey = crypto.createHash("sha256").update(key).digest("hex");

      if (this.redisConnected) {
        try {
          this.client.setex(hashedKey, ex, JSON.stringify(value));
        } catch (err) {
          logger.error(`Error while setting key: ${err}`);
        }
      } else {
        this.cacheMap.set(hashedKey, JSON.stringify(value));
      }
    }

    public getLen(key) {
      return new Promise((resolve, reject) => {
        const hashedKey = crypto.createHash("sha256").update(key).digest("hex");

        if (this.redisConnected) {
          try {
            this.client.llen(hashedKey, (err, data) => {
              if (err) {
                reject(err);
                return;
              }

              if (data !== null) {
                try {
                  resolve(data);
                } catch (err) {
                  resolve(data);
                }
              } else {
                resolve(null);
              }
            });
          } catch (err) {
            logger.error(`Error while getting length: ${err}`);
            resolve(null);
          }
        } else {
          const value = this.cacheMultiMap.get(hashedKey);
          if (value !== undefined) {
            resolve(value.length);
          } else {
            resolve(null);
          }
        }
      });
    }

    public getIndex(key, index) {
      return new Promise((resolve, reject) => {
        const hashedKey = crypto.createHash("sha256").update(key).digest("hex");

        if (this.redisConnected) {
          try {
            this.client.lindex(hashedKey, index, (err, data) => {
              if (err) {
                reject(err);
                return;
              }

              if (data !== null) {
                try {
                  resolve(JSON.parse(data));
                } catch (err) {
                  resolve(data);
                }
              } else {
                resolve(null);
              }
            });
          } catch (err) {
            logger.error(`Error while getting index: ${err}`);
            resolve(null);
          }
        } else {
          const value = this.cacheMultiMap.get(hashedKey);
          if (value !== undefined) {
            resolve(JSON.parse(value[index]));
          } else {
            resolve(null);
          }
        }
      });
    }

    public multiSet(key, value) {
      return new Promise((resolve, reject) => {
        const hashedKey = crypto.createHash("sha256").update(key).digest("hex");

        if (this.redisConnected) {
          try {
            this.client.rpush(hashedKey, JSON.stringify(value), (err, data) => {
              if (err) {
                reject(err);
                return;
              }

              if (data !== null) {
                try {
                  resolve(JSON.parse(data));
                } catch (err) {
                  resolve(data);
                }
              } else {
                resolve(null);
              }
            });
          } catch (err) {
            logger.error(`Error while setting multi key: ${err}`);
            resolve(null);
            return;
          }
        } else {
          if (this.cacheMultiMap.has(hashedKey)) {
            resolve(this.cacheMultiMap.get(hashedKey).push(JSON.stringify(value)));
          } else {
            resolve(this.cacheMultiMap.set(hashedKey, [JSON.stringify(value)]));
          }
        }
      });
    }

    public multiGet(key) {
      return new Promise((resolve, reject) => {
        const hashedKey = crypto.createHash("sha256").update(key).digest("hex");

        if (this.redisConnected) {
          try {
            this.client.lpop(hashedKey, (err, data) => {
              if (err) {
                reject(err);
                return;
              }

              if (data !== null) {
                try {
                  resolve(JSON.parse(data));
                } catch (err) {
                  resolve(data);
                }
              } else {
                resolve(null);
              }
            });
          } catch (err) {
            logger.error(`Error while getting multi key: ${err}`);
            resolve(null);
            return;
          }
        } else {
          const value = this.cacheMultiMap.get(hashedKey);
          if (value !== undefined) {
            if (value.length > 0) {
              this.cacheMultiMap.set(hashedKey, value.slice(1));
              resolve(JSON.parse(value.shift()));
            } else {
              resolve(null);
            }
          } else {
            resolve(null);
          }
        }
      });
    }

    public nonHashedGet(key) {
      return new Promise((resolve, reject) => {
        if (this.redisConnected) {
          try {
            this.client.lpop(key, (err, data) => {
              if (err) {
                reject(err);
                return;
              }

              if (data !== null) {
                try {
                  resolve(JSON.parse(data));
                } catch (err) {
                  resolve(data);
                }
              } else {
                resolve(null);
              }
            });
          } catch (err) {
            logger.error(`Error while getting key: ${err}`);
            resolve(null);
            return;
          }
        } else {
          const value = this.cacheMap.get(key);
          if (value !== undefined) {
            resolve(JSON.parse(value.shift()));
          } else {
            resolve(null);
          }
        }
      });
    }

    public get(key) {
      return new Promise((resolve, reject) => {
        const hashedKey = crypto.createHash("sha256").update(key).digest("hex");

        if (this.redisConnected) {
          try {
            this.client.get(hashedKey, (err, data) => {
              if (err) {
                reject(err);
                return;
              }

              if (data !== null) {
                try {
                  resolve(JSON.parse(data));
                } catch (err) {
                  resolve(data);
                }
              } else {
                resolve(null);
              }
            });
          } catch (err) {
            logger.error(`Error while getting key: ${err}`);
            resolve(null);
          }
        } else {
          const value = this.cacheMap.get(hashedKey);
          if (value !== undefined) {
            resolve(JSON.parse(value));
          } else {
            resolve(null);
          }
        }
      });
    }

    public clean(key) {
      return new Promise((resolve, reject) => {
        const hashedKey = crypto.createHash("sha256").update(key).digest("hex");

        if (this.redisConnected) {
          try {
            this.client.del(hashedKey, (err, data) => {
              if (err) {
                reject(err);
                return;
              }

              if (data !== null) {
                try {
                  resolve(data === 1);
                } catch (err) {
                  resolve(true);
                }
              } else {
                resolve(false);
              }
            });
          } catch (err) {
            logger.error(`Error while cleaning key: ${err}`);
          }
          resolve(false);
        } else {
          resolve(this.cacheMap.delete(hashedKey));
        }
      });
    }
  }

  return RedisCache;
}

const redisCacheDB = getCacheDB();

export default redisCacheDB;
