import memoryDB from "@oxappsec/ox-memory-db";
import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();

export class RedisHelper {
  private TTL;
  private tableKey: string;

  constructor(tableKey: string, TTL: number) {
    this.tableKey = tableKey;
    this.TTL = TTL;
  }

  private createKey(uniqueKey: string) {
    return `${this.tableKey}_${uniqueKey}`;
  }

  async findOne(uniqueKey: string) {
    try {
      const key = this.createKey(uniqueKey);
      const found = await memoryDB.get.execute(key);
      if (found === null) return null;
      const parsed = JSON.parse(found);
      return parsed;
    } catch (e) {
      logger.error(`unable to find item, uniqueKey: ${uniqueKey}, err: ${e}`);
      return null;
    }
  }

  async setOne(item: any, uniqueKey: string) {
    try {
      const key = this.createKey(uniqueKey);
      const stringified = JSON.stringify(item);
      await memoryDB.set.execute(key, this.TTL, stringified);
      return true;
    } catch (err) {
      logger.error(`unable to set item, uniqueKey: ${uniqueKey}, err: ${err}`);
      return false;
    }
  }

  async setMany(item: any, uniqueKey: string) {
    try {
      const key = this.createKey(uniqueKey);
      const stringified = JSON.stringify(item);
      await memoryDB.rPush.execute(key, stringified);
      return true;
    } catch (e) {
      logger.error(`unable to find many, uniqueKey: ${uniqueKey}, err: ${e}`);
      return false;
    }
  }

  async getMany(uniqueKey: string) {
    const res = [];
    try {
      const key = this.createKey(uniqueKey);

      let safety = 20000;
      while (true || safety != 0) {
        safety--;
        const singleRes = await memoryDB.lPop.execute(key);
        if (!singleRes) {
          break;
        }
        const parsed = JSON.parse(singleRes);
        res.push(parsed);
      }
      if (safety == 0) {
        logger.error(`something happen safety check hit for uniqueKey: ${uniqueKey}`);
      }
      return res;
    } catch (e) {
      logger.error(`unable to set many, uniqueKey: ${uniqueKey}, err: ${e}`);
    }
    return res;
  }
}
