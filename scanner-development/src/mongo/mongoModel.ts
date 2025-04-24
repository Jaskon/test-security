import { chunk } from "lodash";
import mongoose from "mongoose";
import StatesHelper from "../helper/statesHelper";
import loggerImport from "../logger";
import MongoConnect from "./mongoConnect";
const logger = loggerImport.getDebugLogger();

class MongoModel<T> {
  //General
  firstUpdateHappen: boolean = null;
  lastUpdateTime: number = Date.now();
  alwaysUpdate: boolean = false;
  cachedItems = [];
  //Statistics
  skipped: number = 0;
  total: number = 0;
  totalBatch: number = 0;

  //Connection
  db: mongoose.Connection = null;
  model: mongoose.Model<T> = null;

  constructor(
    public schemaName: string,
    public schemaInfo: any,
    public org: string,
    public uuid: string,
    // if provided, will use this as dbname in verifyConnection instead of `orgId`
    public sharedDatabaseName: string | null = null,
    public useSchemaName: boolean = false,
  ) {}

  async verifyConnection(mongoConnect: MongoConnect) {
    const isConnected = await mongoConnect.verifyConnection();
    if (!isConnected) {
      logger.info(`mongo got disconnected. connection readyState: ${mongoConnect.connection.readyState}`);

      await mongoConnect.setNewConnection();
    }

    const dbName = this.sharedDatabaseName === null ? this.org : this.sharedDatabaseName;
    this.db = mongoConnect.connection.useDb(dbName, { useCache: true });

    this.schemaInfo.forEach(i => {
      if (this.useSchemaName) {
        this.db.model<any>(i.schemaName, i.schema, i.schemaName);
      } else {
        this.db.model<any>(i.schemaName, i.schema);
      }
    });
    this.model = this.db.model<any>(this.schemaName);
  }

  async insertMany(docs: T[], options?: mongoose.InsertManyOptions): Promise<void> {
    if (StatesHelper.Instance.useMongoDBOptimizedQueries) {
      const bulkOperation = this.model.collection.initializeUnorderedBulkOp();
      for (const doc of docs) {
        bulkOperation.insert(new this.model(doc));
      }
      await bulkOperation.execute();
    } else {
      const chunks = chunk(docs, 50);
      for (const chunk of chunks) {
        await this.model.insertMany(chunk, options);
      }
    }
  }

  async deleteMany(filter: mongoose.FilterQuery<T>): Promise<void> {
    for (let i = 1; true; i++) {
      const toDelete = await this.model.find(filter, { _id: 1 }, { limit: 50 });
      if (!toDelete?.length) {
        return;
      }
      await this.model.deleteMany({ _id: { $in: toDelete.map(d => d._id) } });
    }
  }

  getCachedItems() {
    return this.cachedItems;
  }

  clearCachedItems() {
    this.cachedItems = [];
  }

  addCachedItems(items: any[]) {
    this.cachedItems = this.cachedItems.concat(items);
  }
}

export default MongoModel;
