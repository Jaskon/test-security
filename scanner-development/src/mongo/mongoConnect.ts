import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

import mongoose from "mongoose";
import { isDevelopment, isLocalDevelopment, isOnPrem } from "../helper/envUtils";
import { mongoSyncSearchIndex } from "../helper/searchIndexes/searchIndexesHelper";
import { sleep } from "../helper/commonUtils";

const mongoOptions: mongoose.ConnectOptions = {
  retryWrites: true,
  connectTimeoutMS: 360000,
  keepAlive: true,
  maxPoolSize: 30,
  socketTimeoutMS: 360000,
  appName: "ox-scanner-service",
};

class MongoConnect {
  connection: mongoose.Connection = null;
  orgName: string;
  uuid: string;

  constructor(uuid: string, orgName: string) {
    this.orgName = orgName;
    this.uuid = uuid;
  }
  async verifyConnection() {
    try {
      return this.connection.readyState === 1 || this.connection.readyState === 2;
    } catch (e) {
      logger.error(`failed to verify connection, error": ${e}`);
    }
    return false;
  }

  printConnections() {
    try {
      if (this.connection.db == null) {
        return;
      }

      this.connection.db.admin().command({ currentOp: 1 }, function (err, result) {
        if (err) {
          logger.error(`failed get mongo ops, err: ${err}`);
        } else {
          let accumulator = {};
          accumulator["TOTAL_CONNECTION_COUNT"] = 0;
          result.inprog.forEach(i => {
            let appName = i?.appName;
            accumulator["TOTAL_CONNECTION_COUNT"]++;
            if (!appName) {
              appName = "no appName";
            }
            if (accumulator[appName]) {
              accumulator[appName]++;
            } else {
              accumulator[appName] = 1;
            }
          });

          if (accumulator["TOTAL_CONNECTION_COUNT"] > 1000) {
            logger.error(`total mongo connection HIGH, count: ${JSON.stringify(accumulator)}`);
          } else {
            logger.info(`total mongo connection count: ${JSON.stringify(accumulator)}`);
          }
        }
      });
    } catch (err) {
      logger.error(`failed get total mongo connection err: ${err}`);
    }
  }

  async setNewConnection() {
    if (typeof process.env.MONGO_CONN !== "undefined" && process.env.MONGO_CONN !== null) {
      if (process.env.MONGO_CONN === "atlas") {
        logger.info(`try connect to MongoDB atlas, uuid: ${this.uuid}, org id: ${this.orgName}`);
        await this.retryConnectToMongo(`mongodb+srv://${process.env.MONGO_USER}:${process.env.MONGO_PASS}@${process.env.MONGO_HOST}`);
      } else if (process.env.MONGO_CONN === "local") {
        //k8
        logger.info(`try connect to MongoDB local, uuid: ${this.uuid}, org id: ${this.orgName}`);
        await this.retryConnectToMongo(`${process.env.MONGO_URI_CONNECTION}`);
      } else if (process.env.MONGO_CONN === "aws") {
        logger.info(`try connect to MongoDB aws, uuid: ${this.uuid}, org id: ${this.orgName}`);

        await this.retryConnectToMongo(`mongodb+srv://${process.env.MONGO_HOST}`);
      } else {
        throw `wrong mongo server passed: ${process.env.MONGO_CONN},uuid: ${this.uuid}, org id: ${this.orgName}`;
      }
    }

    if (this.connection.readyState === 1 || this.connection.readyState === 2) {
      logger.info(`Connected to MongoDB (${this.connection.readyState}),uuid: ${this.uuid}, org id: ${this.orgName}`);
      return;
    } else {
      const errInfo = `Failed to connect to MongoDB ${this.connection.readyState}`;
      logger.error(errInfo);

      throw errInfo;
    }
  }

  async retryConnectToMongo(connect: string) {
    let retry = 3;

    logger.info(`try connect to mongo db: connect, url info: ${connect}`);

    while (retry > 0) {
      retry--;

      try {
        const res = await this.connectToMongoDB(connect);
        if (res) {
          return;
        }
        await this.sleep();
      } catch (err) {
        const errInfo = `Failed to connect to MongoDB ${connect}, retry: ${retry}`;
        logger.error(errInfo);
      }
    }
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 2);
  }

  async connectToMongoDB(url) {
    return new Promise((resolve, reject) => {
      try {
        this.connection = mongoose.createConnection(url, mongoOptions);

        this.connection.on("open", async () => {
          if (this.orgName === "org_Prkz8geyG1f0uiHG") {
            logger.info(`mongo connection ready state status: ${this.connection.readyState}`);
          }
          try {
            logger.info(`Mongoose connection open`);
            /* for creating search index if collection doesn't exist */
            if (!isOnPrem()) {
              const connection = this.connection.useDb(this.orgName);
              // const isDev = isDevelopment() || isLocalDevelopment();
              // if (isDev && this.orgName === "org_mC72M341wk2b0aL9") {
              //   logger.info(`current issues collection watch init`);
              //   const filter = [
              //     {
              //       $match: {
              //         $and: [
              //           { "ns.coll": "current-issues" },
              //           { operationType: "update" },
              //           { "updateDescription.updatedFields.severity": { $exists: true } },
              //           { "updateDescription.updatedFields.severityChangeReason": { $exists: true } },
              //         ],
              //       },
              //     },
              //   ];
              //   connection.watch(filter).on("change", async change => {
              //     logger.info(`change in mongo current-issues collection: ${JSON.stringify(change)}`);
              //     const severityHistory = {
              //       date: new Date(),
              //       severity: change.updateDescription.updatedFields.severity,
              //       severityChangeReason: change.updateDescription.updatedFields.severityChangeReason,
              //     };

              //     await connection
              //       .collection("current-issues")
              //       .updateOne({ _id: change.documentKey._id }, { $addToSet: { severityHistory } });

              //     logger.info(
              //       `change in mongo current-issues id ${change.documentKey._id} successfully ${JSON.stringify(severityHistory)}`,
              //     );
              //   });
              // }
              let retry = 3;
              while (retry > 0) {
                retry = retry - 1;
                if (connection.readyState === 1) {
                  await mongoSyncSearchIndex(connection, this.orgName, this.uuid);
                  break;
                }
                logger.info(`mongo is still no connected. sleep for 1.5 sec`);
                await sleep(1500);
              }
            }
            resolve(true);
          } catch (err) {
            logger.error(`Mongoose error: ${err} reason: ${err?.reason ? JSON.stringify(err?.reason) : "no reason"}`);
            resolve(false);
          }
        });
        this.connection.on("error", err => {
          logger.error(`Mongoose connection error: ${err} reason: ${err?.reason ? JSON.stringify(err?.reason) : "no reason"}}`);
          resolve(false);
        });
        this.connection.on("close", () => {
          logger.warn(`Mongoose connection close to connection`);
          resolve(false);
        });
        this.connection.on("disconnected", function () {
          logger.warn("MongoDB disconnected! trying to reconnect again");
          mongoose.createConnection(url, mongoOptions);
        });
      } catch (err) {
        logger.error(`Mongoose connection exception error: ${err} reason: ${err?.reason ? JSON.stringify(err?.reason) : "no reason"}}`);
        resolve(false);
      }
    });
  }
}

export default MongoConnect;
