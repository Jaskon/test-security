import Constant from "../entitis/constant";
import { compress } from "../helper/compression/zStream";
import loggerImport from "../logger";
import MongoModel from "./mongoModel";

const logger = loggerImport.getDebugLogger();

import mongoose from "mongoose";
import MongoConnect from "./mongoConnect";
import StatesHelper from "../helper/statesHelper";

const reportVer = "7.01";

const Schema = mongoose.Schema;
var fs = require("fs");

const reportSchema = new Schema(
  {
    uid: {
      type: String,
      required: true,
    },
    reportJson: {
      type: String,
      required: true,
    },
    done: {
      type: Boolean,
      required: true,
    },
    defaultValues: {
      type: Boolean,
      required: true,
    },
    connections: {
      type: String,
      required: false,
    },
    version: {
      type: String,
      required: true,
    },
    error: {
      type: String,
      required: false,
    },
    createdAt: { type: Date, expires: "365d", default: Date.now },
  },
  { timestamps: true },
);

const reportOverviewStr = "report-overviews";
const reportDiscoveryOverviewStr = "report-discovery-overviews";
const reportStr = "reports";

class MongoDBreportUpdates {
  mongoModels: MongoModel<any>[] = [];
  mongoConnect: MongoConnect;
  uuid: string;
  org: string;

  constructor(uuid: string, orgName: string, mongoConnect: MongoConnect) {
    this.org = orgName;
    this.uuid = uuid;
    this.mongoConnect = mongoConnect;

    const discoveryOverview = new MongoModel(
      reportDiscoveryOverviewStr,
      [{ schemaName: reportDiscoveryOverviewStr, schema: reportSchema }],
      this.org,
      this.uuid,
    );

    this.mongoModels.push(discoveryOverview);

    const overviewReport = new MongoModel(
      reportOverviewStr,
      [{ schemaName: reportOverviewStr, schema: reportSchema }],
      this.org,
      this.uuid,
    );
    overviewReport.alwaysUpdate = true;
    this.mongoModels.push(overviewReport);

    this.mongoModels.push(new MongoModel(reportStr, [{ schemaName: reportStr, schema: reportSchema }], this.org, this.uuid));
  }

  async handleGeneralOverview(reportObj: any, done: boolean, err: string, flowId: string) {
    try {
      const mongoModles: MongoModel<any> = this.getModuleByName(reportOverviewStr);
      const res = await this.handleReport(reportObj, done, err, mongoModles, true, flowId);
      return res;
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed handle ${reportOverviewStr} schema, done: ${done}, err: ${err}`);
    }
    return false;
  }

  async handleDiscoveryOverview(reportObj: any, done: boolean, err: string, flowId: string) {
    try {
      const mongoModels: MongoModel<any> = this.getModuleByName(reportDiscoveryOverviewStr);
      const res = await this.handleReport(reportObj, done, err, mongoModels, false, flowId);
      return res;
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed handle ${reportDiscoveryOverviewStr} schema, done: ${done}, err: ${err}`);
    }
    return false;
  }

  async handleFullReport(reportObj: any, done: boolean, err: string, flowId: string) {
    try {
      const mongoModels: MongoModel<any> = this.getModuleByName(reportStr);
      const res = await this.handleReport(reportObj, done, err, mongoModels, true, flowId);

      return res;
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed handle full report ${reportStr} schema, done: ${done}, err: ${err}`);
    }
    return false;
  }

  getDifferenceInSeconds(date1, date2) {
    const diffInMs = Math.abs(date2 - date1);
    return diffInMs / 1000;
  }

  getModuleByName(name: string) {
    const res = this.mongoModels.find(i => i.schemaName === name.toLowerCase());
    return res;
  }

  async handleReport(reportObj: any, done: boolean, err: string, mongoModel: MongoModel<any>, compress: boolean, flowId: string) {
    try {
      //Check that we didnt get signal and if we did verify the message have err otherwise ignore
      if (process.env.sigTermReceived != undefined) {
        if (err === "") {
          logger.error(`cannot update schema: ${mongoModel.schemaName} due signal exist already set`);
          return false;
        }
      }

      //in case its done(last request) or default(first) dont check diff time
      mongoModel.total++;
      mongoModel.totalBatch++;
      if (!done && !mongoModel.alwaysUpdate && mongoModel.firstUpdateHappen && mongoModel.totalBatch < 10) {
        const diffInM = this.getDifferenceInSeconds(new Date().getTime(), mongoModel.lastUpdateTime);
        if (diffInM < Constant.intevalReportUpdate) {
          mongoModel.skipped++;
          return false;
        }
      } else {
        mongoModel.totalBatch = 0;
      }

      if (done) {
        logger.info(`schema: ${mongoModel.schemaName} total request: ${mongoModel.total}. skipped(optimization): ${mongoModel.skipped}`);
      }

      await mongoModel.verifyConnection(this.mongoConnect);

      mongoModel.lastUpdateTime = new Date().getTime();

      const res = await this.replaceReport(mongoModel, reportObj, done, err, compress, flowId);
      return res;
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errInfo = `failed save ${mongoModel.schemaName} overview.json, flowId: ${flowId}, err: ${err}`;
      logger.error(errInfo);
    }

    return false;
  }

  async replaceReport(mongoModel: MongoModel<any>, reportObj: any, done: boolean, err: string, needToCompress: boolean, flowId: string) {
    try {
      logger.info(`try update schema ${mongoModel.schemaName}, flowId: ${flowId}, uid: ${this.uuid}, org: ${this.org}`);

      let report = JSON.stringify(reportObj);

      if (needToCompress) {
        report = compress(report, true);

        logger.info(
          `finish compress report for update schema ${mongoModel.schemaName}, flowId: ${flowId}, uid: ${this.uuid}, org: ${this.org}`,
        );
      }

      //await this.findReport("");
      const res = await mongoModel.model.replaceOne(
        {
          uid: this.uuid,
        },
        {
          uid: this.uuid,
          reportJson: report,
          done: done,
          version: reportVer,
          connections: "",
          defaultValues: false,
          error: err === "" ? "success" : err,
        },
        { upsert: true },
      );

      mongoModel.firstUpdateHappen = res.upsertedCount == 0;

      logger.info(
        `finish ${mongoModel.firstUpdateHappen ? "update" : "first save"} report for res matched count: ${
          res.matchedCount
        }, first update happen: ${mongoModel.firstUpdateHappen}, schema ${mongoModel.schemaName}, flowId: ${flowId}, uid: ${
          this.uuid
        }, org: ${this.org}`,
      );

      return true;
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      const errInfo = `Failed update schema ${mongoModel.schemaName}, flowId: ${flowId}, org: ${this.org}, err: ${err}`;
      logger.error(errInfo);
    }
    return false;
  }

  async isReportDone() {
    try {
      const mongoModels: MongoModel<any> = this.getModuleByName(reportStr);
      if (mongoModels == null) {
        logger.error(`cannot find schema to check if done for schema: ${reportStr} uuid: ${this.uuid}, org: ${this.org}`);
        return false;
      }

      await mongoModels.verifyConnection(this.mongoConnect);

      const res = await mongoModels.model.find({
        uid: this.uuid,
      });

      if (res.length == 0) {
        logger.error(`cannot find report to check if done for schema: ${reportStr}, ${this.uuid}, org: ${this.org}`);
        return false;
      }

      if (res.length > 1) {
        logger.error(`there are 2 reports for the same ui in schema: ${reportStr}, ${this.uuid}, org: ${this.org}`);
      }

      logger.info(`report for schema: ${reportStr}, ${this.uuid}, org: ${this.org} done: ${res[0].done}`);

      return res[0].done;
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed check if report done, uuid: ${this.uuid}, org: ${this.org}, ${err}`);
    }
    return false;
  }

  async findReports() {
    return new Promise((resolve, reject) => {
      try {
        const mongoModles: MongoModel<any> = this.getModuleByName(reportStr);
        if (mongoModles == null) {
          reject(`cannot use find all reports, failed to find module: ${reportStr}`);
        }

        //TODO REMOVE Promise
        if (mongoose.connection.readyState !== 1) reject(new Error("DB is not connected"));

        mongoModles.model.find((error, data) => {
          if (error) {
            reject(error);
          } else {
            resolve(data);
          }
        });
      } catch (err) {
        StatesHelper.Instance.scanInfoStats.mongoErrors++;
        reject(`Failed to find all reports for module: ${reportStr}, err: ${err}`);
      }
    });
  }
}

export default MongoDBreportUpdates;
