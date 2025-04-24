import { Schema } from "mongoose";
import StatesHelper from "../helper/statesHelper";
import loggerImport from "../logger";
import MongoConnect from "./mongoConnect";
import MongoModel from "./mongoModel";
const logger = loggerImport.getDebugLogger();

const activeScan = new Schema(
  {
    orgId: {
      type: String,
      required: true,
    },
    scanId: {
      type: String,
      required: true,
    },
    createdAt: {
      type: String,
      required: true,
    },
  },
  { collection: "active-scan" },
);

class MongoActiveScan {
  uuid: string;
  org: string;
  mongoConnect: MongoConnect;
  mongoModelActiveScan: MongoModel<any>;

  constructor(uuid: string, orgName: string, mongoConnect: MongoConnect) {
    this.org = orgName;
    this.uuid = uuid;
    this.mongoConnect = mongoConnect;

    this.mongoModelActiveScan = new MongoModel("active-scan", [{ schemaName: "active-scan", schema: activeScan }], this.org, this.uuid);
  }

  async setDone() {
    try {
      let retry = 4;
      while (retry > 0) {
        try {
          retry--;

          await this.mongoModelActiveScan.verifyConnection(this.mongoConnect);
          const res = await this.mongoModelActiveScan.model.deleteOne({
            scanId: this.uuid,
          });
          if (res.deletedCount != 1) {
            const errInfo = `Remove active scan failed active scan is count is not 1, count: ${res.deletedCount}, uid: ${this.uuid}, org: ${this.org}`;
            logger.error(errInfo);
          } else {
            logger.info(`Remove active scan, count: ${res.deletedCount}, uid: ${this.uuid}, org: ${this.org}`);
          }
          break;
        } catch (error) {
          StatesHelper.Instance.scanInfoStats.mongoErrors++;

          const errInfo = `failed set done for remove active scan, retry: ${retry}, err: ${error}`;
          logger.error(errInfo);
        }
      }
    } catch (error) {
      logger.error(`failed set done for remove active scan, err: ${error}`);
    }
  }
}

export default MongoActiveScan;
