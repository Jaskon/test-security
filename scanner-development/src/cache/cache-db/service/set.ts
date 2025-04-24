import loggerImport from "../../../logger";
import { ClientPromise } from "../cache-db-types";
const logger = loggerImport.getDebugLogger();

const set = (clientPromise: ClientPromise) => {
  return {
    execute: async <V>(org_id: string, collection: string, data: V) => {
      try {
        const client = await clientPromise();
        const db = client.db(org_id);
        const cc = db.collection(collection);

        const tempAnyType = data as any;
        delete tempAnyType._id;
        const record: any = await cc.findOne(tempAnyType);

        if (record === null) {
          const record = await cc.insertOne(data);
          return record.insertedId.toString();
        } else {
          if (record && record._id) {
            return record._id.toString();
          } else {
            logger.error(`Record is not null, but missing _id: ${JSON.stringify(record)}`);
          }
        }
      } catch (error) {
        if (error.code === 11000) {
          logger.debug(`Duplicate key error: ${error.message}`);
        } else {
          logger.error("failed to set value in cache-db", error);
        }
        return null;
      }
    },
  };
};

export default set;
