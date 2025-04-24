import { MongoClient, DeleteResult } from "mongodb";

export interface ClientPromise {
  (): Promise<MongoClient>;
}

export { DeleteResult };
