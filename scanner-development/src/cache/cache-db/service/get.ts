import loggerImport from "../../../logger";
const logger = loggerImport.getDebugLogger();
import { ClientPromise } from "../cache-db-types";

const get = (clientPromise: ClientPromise) => {
  return {
    execute: async <T>(org_id: string, collection: string, data: T) => {
      try {
        logger.debug(`try getting key[${JSON.stringify(data)}] from cache-db`);

        const client = await clientPromise();
        const db = client.db(org_id);
        const cc = db.collection(collection);

        const projection = { _id: 0, __v: 0 }; // Return T
        const record = await cc.find(data).project(projection).toArray();

        if (record.length === 0) {
          logger.debug(`key[${JSON.stringify(data)}] not found in cache-db`);
        } else {
          logger.debug(`key[${JSON.stringify(data)}] found in cache-db`);
        }

        return record; // return T[] due to projection above
      } catch (error) {
        logger.error("failed to get key from cache-db", error);
        return null;
      }
    },
  };
};

export default get;
