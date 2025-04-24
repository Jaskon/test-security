import mongoose, { Schema } from "mongoose";
import StatesHelper from "../helper/statesHelper";
import loggerImport from "../logger";
import MongoConnect from "./mongoConnect";
import MongoModel from "./mongoModel";
const logger = loggerImport.getDebugLogger();

const activeScan = new Schema(
  {
    scanId: {
      type: String,
      required: true,
    },
    createdAt: {
      type: String,
      required: true,
    },
  },
  { collection: "cancel-scan" },
);

class MongoCancelScan {
  uuid: string;
  org: string;
  mongoConnect: MongoConnect;
  mongoModelCancelScan: MongoModel<any>;

  constructor(uuid: string, orgId: string, mongoConnect: MongoConnect) {
    this.org = orgId;
    this.uuid = uuid;
    this.mongoConnect = mongoConnect;

    this.mongoModelCancelScan = new MongoModel("cancel-scan", [{ schemaName: "cancel-scan", schema: activeScan }], this.org, this.uuid);
  }

  async shouldExist() {
    try {
      await this.mongoModelCancelScan.verifyConnection(this.mongoConnect);

      const scanId = this.uuid;

      const cancelEvents = await this.mongoModelCancelScan.model.find({
        scanId: scanId,
      });

      if (cancelEvents.length == 0) {
        return false;
      }

      const matchedItems = cancelEvents.filter(i => i._doc.scanId === scanId);
      if (matchedItems.length == 0) {
        return false;
      }

      const lastUpdateTime = matchedItems[0]._doc.createdAt;
      logger.info(
        `found cancel command in DB, count: ${cancelEvents.length} for: ${this.uuid}, org: ${this.org}, last update time: ${lastUpdateTime}`,
      );

      return true;
    } catch (error) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;

      const errInfo = `failed check of should cancel scan, err: ${error}`;
      logger.error(errInfo);
    }
    return false;
  }
}

export default MongoCancelScan;
