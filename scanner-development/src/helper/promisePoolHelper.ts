const Queue = require("@supercharge/queue-datastructure");

import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

class PromisePoolHelper {
  boundLimit: number;
  name: string;
  func: any;
  q = new Queue();
  pool = {};

  constructor(boundLimit: number, func: any, name: string) {
    this.boundLimit = boundLimit;
    this.func = func;
    this.name = name;
  }

  async runQueue() {
    try {
      logger.info(`start run queue: ${this.name}`);

      let index = 0;

      while (!this.q.isEmpty() || Object.values(this.pool).length > 0) {
        if (!this.q.isEmpty()) {
          const item = this.pop();
          index++;
          this.pool[index] = this.runFunc(index, item);
        } else {
          await this.sleep(5000);
        }

        if (Object.keys(this.pool).length >= this.boundLimit) {
          const promises = Object.values(this.pool);
          await Promise.race(promises); // wait for one Promise to finish
        }
      }

      logger.info(`finish run queue: ${this.name}`);
    } catch (err) {
      logger.error(`failed run queue: ${this.name}, err: ${err}`);
    }
  }

  async runFunc(id: number, item) {
    try {
      await this.func(item);
      delete this.pool[id]; // remove that Promise from the pool
    } catch (err) {
      logger.error(`failed run queue: ${this.name}, id: ${id}, err: ${err}`);
    }
    return id;
  }

  addRange(items) {
    try {
      items.forEach(i => {
        this.add(i);
      });

      logger.info(`add range to queue: ${this.name}, items count: ${items.length}`);
    } catch (err) {
      logger.error(`failed run add range items to queue: ${this.name}, err: ${err}`);
    }
  }

  add(item) {
    try {
      this.q.enqueue(item);
    } catch (err) {
      logger.error(`failed run add item to queue: ${this.name}, err: ${err}`);
    }
  }

  pop() {
    const item = this.q.dequeue();
    return item;
  }

  async sleep(interval) {
    const delay = (ms: number) => new Promise(res => setTimeout(res, ms));
    await delay(interval);
  }
}

export default PromisePoolHelper;
