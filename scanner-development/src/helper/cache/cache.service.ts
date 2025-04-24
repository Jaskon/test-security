import { chunk } from "lodash";
import { FilterQuery } from "mongoose";
import { join } from "node:path";
import { AsyncTracker } from "../../async-tracker.service";
import loggerImport from "../../logger";
import MongoConnect from "../../mongo/mongoConnect";
import { checkObjectSize } from "../commonUtils";
import { deflatePromise, inflatePromise } from "../compression/zlib-promise";
import { isDevelopment } from "../envUtils";
import { CacheHelper } from "./cache.helper";
import { Cache, InfectedRepo, InfectedRepoFilter, schemas } from "./cache.types";

const logger = loggerImport.getDebugLogger();

export class CacheService {
  private readonly cacheTestOrgs = [
    "org_0sujGW2twjluoBv3",
    "org_wrc4ONjBqsmbyxf9",
    "org_50BjX8T0nJZrF4sv",
    "org_pzoBHblewSXFtBRh",
    "org_SwxMYJRBZauNrb9p",
  ];
  private readonly CHUNK_SIZE = 50;
  helper = new CacheHelper();

  constructor(private readonly orgId: string, private readonly mongoConnect: MongoConnect) {}

  async get<T>(cacheId: CacheIdentifier, cache: Cache): Promise<T[]> {
    // if ((isDevelopment() || isLocalDevelopment()) && this.orgId === "org_50BjX8T0nJZrF4sv") {
    //   const filePath = this.getCacheFilePath(cacheId);
    //   const startTime = Date.now();
    //   const strFile = await readFile(filePath, { encoding: "utf-8" });
    //   const parsed = JSON.parse(strFile);
    //   if (isDevelopment()) {
    //     logger.info(`[${CacheService.name}] Finished read file ${cache} (${strFile.length}) (${Date.now() - startTime}ms)`);
    //   }
    //   if (this.cacheTestOrgs.includes(this.orgId)) {
    //     return parsed;
    //   }
    // }

    if (!cacheId.idKey || !cacheId.id) {
      logger.error(`fatal -cacheId: ${JSON.stringify(cacheId)}`);
      return [];
    }

    const db = this.mongoConnect.connection.useDb(this.orgId, { useCache: true });
    const model = db.model<T>(cache, schemas[cache], cache);
    const filterQuery: FilterQuery<T> = { [cacheId.idKey]: cacheId.id } as any;
    const results: T[] = [];
    let i = 0;
    const startTime = Date.now();
    while (true) {
      const partialResult = await model
        .find(filterQuery, undefined, { limit: this.CHUNK_SIZE, skip: this.CHUNK_SIZE * i })
        .lean()
        .exec();

      const decompressedPartialResult = await Promise.all(
        partialResult.map(async result =>
          result.compressed ? JSON.parse((await inflatePromise(Buffer.from(result.compressed, "base64"))).toString()) : result,
        ),
      );

      results.push(...decompressedPartialResult);
      if (partialResult.length < this.CHUNK_SIZE) {
        break;
      }
      i++;
    }

    // if (isDevelopment()) {
    //   logger.info(`[${CacheService.name}] Finished read mongo ${cache} (${Date.now() - startTime}ms)`);
    // }

    return results;
  }

  async set<T>(cacheId: CacheIdentifier, items: T[], cache: Cache, compress = false): Promise<void> {
    if (!cacheId.idKey || !cacheId.id) {
      logger.error(`fatal -cacheId: ${JSON.stringify(cacheId)}`);
      return;
    }

    const db = this.mongoConnect.connection.useDb(this.orgId, { useCache: true });
    const model = db.model<T>(cache, schemas[cache], cache);

    const filterQuery: FilterQuery<T> = { [cacheId.idKey]: cacheId.id } as any;
    const startTime = Date.now();
    for (let i = 1; true; i++) {
      const toDelete = await model.find(filterQuery, { _id: 1 }, { limit: 50 });
      if (!toDelete?.length) {
        break;
      }
      await this.execMongoOperation(() => model.deleteMany({ _id: { $in: toDelete.map(d => d._id) } }), cache, "deleteMany", 0, `${i}`);
    }

    const chunks = chunk(items, this.CHUNK_SIZE);
    for (const [i, chunk] of Object.entries(chunks)) {
      await AsyncTracker.runWithAsyncTracker(async () => {
        AsyncTracker.setValue("ox-mongo-collection", cache);
        AsyncTracker.setValue("ox-mongo-db", this.orgId);
        AsyncTracker.setValue("ox-mongo-operation", "insertMany");
        if (compress) {
          const compressedItems = await Promise.all(
            chunk.map(async item => ({ ...filterQuery, compressed: (await deflatePromise(JSON.stringify(item))).toString("base64") })),
          );

          if (isDevelopment()) {
            compressedItems.forEach(i => {
              const s = checkObjectSize(i);
              if (s > 5) {
                logger.error(`huge object: ${s} from: ${cacheId.name}, id: ${cacheId.idKey} for cash`);
              }
            });
          }
          AsyncTracker.setValue("ox-mongo-size", checkObjectSize(compressedItems));
          const startTime = Date.now();

          await model.insertMany(compressedItems, { rawResult: true, lean: true });

          AsyncTracker.setValue("ox-mongo-time", Date.now() - startTime);
        } else {
          const itemToInsert = chunk.map(i => ({ ...i, ...filterQuery }));
          AsyncTracker.setValue("ox-mongo-size", checkObjectSize(itemToInsert));
          const startTime = Date.now();
          await model.insertMany(itemToInsert, { rawResult: true, lean: true });
          AsyncTracker.setValue("ox-mongo-time", Date.now() - startTime);
        }

        // if (isDevelopment()) {
        //   logger.info(`[${CacheService.name}] finished insertMany ${cache} ${this.orgId} ${parseInt(i) + 1}/${chunks.length}`);
        // }
      });
    }

    if (isDevelopment()) {
      logger.info(
        `[${CacheService.name}] Finished write mongo ${cache} for ${cacheId.idKey}: ${cacheId.name}. count: ${items.length} (${
          Date.now() - startTime
        }ms)`,
      );
    }
  }

  private getCacheFilePath(cacheId: CacheIdentifier): string {
    const filePath = join(
      `${process.env.OX_GLOBAL_DATA}/keep/${this.orgId}_DB`,
      `${cacheId.idKey}_${Buffer.from(cacheId.id).toString("base64")}.json`,
    );
    return filePath;
  }

  private async execMongoOperation<T, R>(
    fn: () => R,
    collection: string,
    operation: string,
    size?: number,
    extraLog: string = "",
  ): Promise<R> {
    return await AsyncTracker.runWithAsyncTracker(async () => {
      AsyncTracker.setValue("ox-mongo-collection", collection);
      AsyncTracker.setValue("ox-mongo-db", this.orgId);
      if (size) {
        AsyncTracker.setValue("ox-mongo-size", size);
      }
      AsyncTracker.setValue("ox-mongo-operation", operation);
      const startTime = Date.now();
      const result = await fn();
      AsyncTracker.setValue("ox-mongo-time", Date.now() - startTime);
      // if (isDevelopment()) {
      //   logger.info(`[${CacheService.name}] finished ${operation} ${collection} ${this.orgId} ${extraLog}`);
      // }
      return result;
    });
  }
}

export interface CacheIdentifier {
  id: string;
  idKey: "repoId" | "imageCacheId" | "appId";
  name?: string;
}
