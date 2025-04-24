import { MongoClient } from "mongodb";

export interface ClientPromise {
  (): Promise<MongoClient>;
}
