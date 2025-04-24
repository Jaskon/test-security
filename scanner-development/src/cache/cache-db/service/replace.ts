import loggerImport from "../../../logger";
const logger = loggerImport.getDebugLogger();
import { ClientPromise } from "../cache-db-types";

const replace = (clientPromise: ClientPromise) => {
  return {
    execute: async <V>(org_id: string, collection: string, what: V, data: V) => {
      try {
        const client = await clientPromise();
        const db = client.db(org_id);
        const cc = db.collection(collection);

        const tempAnyType = what as any;
        delete tempAnyType._id;
        const record: any = await cc.findOne(tempAnyType);

        if (record === null) {
          const record = await cc.insertOne(data);
          return record.insertedId.toString();
        } else {
          const res = await cc.replaceOne(record, data);

          if (res.modifiedCount === 1) {
            logger.debug(`Entry modified for ${JSON.stringify(what)}`);
          }

          return record._id.toString();
        }
      } catch (error) {
        if (error.code === 11000) {
          logger.debug(`Duplicate key error: ${error.message}`);
        } else {
          logger.error("failed to replace value in cache-db", error);
        }
        return null;
      }
    },
  };
};

export default replace;
