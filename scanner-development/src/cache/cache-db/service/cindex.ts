import loggerImport from "../../../logger";
const logger = loggerImport.getDebugLogger();
import { ClientPromise } from "../cache-db-types";

const cindex = (clientPromise: ClientPromise) => {
  return {
    execute: async (org_id: string, collection: string, indexObj: any, specialOptions: Partial<any> = { unique: true }) => {
      try {
        const client = await clientPromise();
        const db = client.db(org_id);

        const collections = await db.collections();
        const foundCollection = collections.find(dbcollection => {
          return dbcollection.collectionName === collection;
        });

        if (!foundCollection) {
          await db.createCollection(collection);
        }

        const cc = db.collection(collection);

        const indexes = await cc.indexes();
        const found = (indexes.length + specialOptions.expireAfterSeconds ? 1 : 0) >= Object.keys(indexObj).length + 1 ? true : false;

        if (!found) {
          const res = await cc.createIndex(indexObj, specialOptions);
          logger.debug(`Created index on collection ${collection}: ${res}`);
        } else {
          logger.debug(`Index already exists on collection ${collection}`);
        }

        return true;
      } catch (error) {
        logger.error("failed to create index in cache-db", error);

        if (error.code === 85) {
          try {
            const client = await clientPromise();
            const db = client.db(org_id);
            const cc = db.collection(collection);

            await cc.dropIndexes();
            const res = await cc.createIndex(indexObj, specialOptions);
            logger.debug(`Updated index on collection ${collection}: with result: ${res}`);
          } catch (error) {
            logger.error("failed to create index in cache-db", error);
          }
        }

        if (error.code === 11000) {
          try {
            const client = await clientPromise();
            const db = client.db(org_id);
            const cc = db.collection(collection);

            await cc.drop();
          } catch (error) {
            logger.error("failed to create index in cache-db", error);
          }
        }

        return false;
      }
    },
  };
};

export default cindex;
