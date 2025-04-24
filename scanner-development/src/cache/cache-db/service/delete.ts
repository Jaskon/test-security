import loggerImport from "../../../logger";
const logger = loggerImport.getDebugLogger();
import { ClientPromise, DeleteResult } from "../cache-db-types";

const del = (clientPromise: ClientPromise) => {
  return {
    execute: async <T>(org_id: string, collection: string, data: T) => {
      try {
        logger.info(`try deleting key[${JSON.stringify(data)}] from cache-db`);

        const client = await clientPromise();
        const db = client.db(org_id);
        const cc = db.collection(collection);

        const ack: DeleteResult = await cc.deleteMany(data);

        return ack.acknowledged;
      } catch (error) {
        logger.error("failed to delete ", error);
        return false;
      }
    },
  };
};

export default del;
