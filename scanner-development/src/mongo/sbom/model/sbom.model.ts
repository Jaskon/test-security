import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import MongoModel from "../../../mongo/mongoModel";
import MongoConnect from "../../mongoConnect";
import { SbomMongoDocument } from "../types";
import { SbomSchema } from "./sbom-schema";
const logger = loggerImport.getDebugLogger();

export class SbomModel {
  private readonly SbomMongoModel: MongoModel<SbomMongoDocument>;
  constructor(private readonly orgId: string, private readonly scanId: string, private readonly mongoConnect: MongoConnect) {
    this.SbomMongoModel = new MongoModel("sboms", [{ schemaName: "sboms", schema: SbomSchema }], orgId, scanId);
  }

  splitToChunks(array, resourceName: string) {
    const chunkSize = 100;
    const chunks = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      const c = array.slice(i, i + chunkSize);
      chunks.push(c);
    }
    return chunks;
  }

  async addSboms(sboms: SbomMongoDocument[]): Promise<null> {
    try {
      await this.SbomMongoModel.verifyConnection(this.mongoConnect);
      await this.SbomMongoModel.insertMany(sboms);
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to add sboms, error: ${e}, orgId: ${this.orgId}`, e);
    }
    return null;
  }

  async getSbomsByAppId(appId: string, appName: string) {
    try {
      await this.SbomMongoModel.verifyConnection(this.mongoConnect);
      const res = await this.SbomMongoModel.model.find({ appId }).exec();
      return res;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed get sboms based on app id: ${appId}, app name: ${appName}, error: ${e}, orgId: ${this.orgId}`, e);
    }
    return [];
  }

  async removeOldSboms() {
    try {
      logger.info(`deleting old sboms, orgId: ${this.orgId}. scanId: ${this.scanId}`);
      await this.SbomMongoModel.verifyConnection(this.mongoConnect);
      //sbom deletion using batch deletions
      logger.info(`sbom deletion using batch deletions: ${this.orgId}. scanId: ${this.scanId}`);
      const batchSize = 1000;
      const delayForBatch = 2000;
      return removeOldSbomsInBatches.call(this, batchSize, delayForBatch).then(result => {
        if (result) {
          logger.info("all sboms successfully deleted in batches.");
        } else {
          logger.info("failed to delete sboms in batches.");
        }
      });
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to removeOldSboms, error: ${e}, orgId: ${this.orgId}`, e);
    }
    return null;
  }
}

async function removeOldSbomsInBatches(batchSize: number, delayForBatch: number) {
  try {
    await this.SbomMongoModel.verifyConnection(this.mongoConnect);
    const sbomsToDelete = await this.SbomMongoModel.model
      .find(
        {
          scanId: { $ne: this.scanId },
        },
        { _id: 1 },
      )
      .limit(batchSize);

    if (sbomsToDelete.length > 0) {
      await this.SbomMongoModel.model.deleteMany({
        _id: { $in: sbomsToDelete.map(sbom => sbom._id) },
      });
      // adding delay between batches
      await new Promise(resolve => setTimeout(resolve, delayForBatch));
      // recursively calling function to delete the next batch
      await removeOldSbomsInBatches.call(this, batchSize, delayForBatch);
    }
    return true;
  } catch (e) {
    StatesHelper.Instance.scanInfoStats.mongoErrors++;
    logger.error(`failed to removeOldSbomsInBatches, error: ${e}, orgId: ${this.orgId}`, e);
    return false;
  }
}
