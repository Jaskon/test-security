import StatesHelper from "../helper/statesHelper";
import loggerImport from "../logger";
import { Application } from "../policy/reporting/types";
import MongoConnect from "./mongoConnect";
import MongoModel from "./mongoModel";
import { ApplicationSchema } from "./schemas";
const logger = loggerImport.getDebugLogger();

class MongoDBapplications {
  uuid: string;
  org: string;
  Application: MongoModel<Application>;
  mongoConnect: MongoConnect;

  constructor(uuid: string, orgName: string, mongoConnect: MongoConnect) {
    this.org = orgName;
    this.uuid = uuid;
    this.mongoConnect = mongoConnect;
    this.Application = new MongoModel(
      "applications",
      [
        {
          schemaName: "applications",
          schema: ApplicationSchema,
        },
      ],
      this.org,
      this.uuid,
    );
  }

  async getApplicationsFromDB() {
    try {
      logger.info(`try get applications for org ${this.org}`);

      await this.Application.verifyConnection(this.mongoConnect);
      const applications = await this.Application.model.find();

      return applications.map(i => i.toObject());
    } catch (error) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;

      const errInfo = `failed to get applications, err: ${error}`;
      logger.error(errInfo);

      return [];
    }
  }

  async getApplicationById(id, name = "") {
    try {
      await this.Application.verifyConnection(this.mongoConnect);
      const params = {
        appId: id,
      };
      const application = await this.Application.model.findOne(params);
      if (application) {
        logger.info(`found application by id in database id: ${id} name: ${name} for org ${this.org}`);
      } else {
        logger.info(`didn't find application by id in database id: ${id} name: ${name} for org ${this.org}`);
      }

      return application;
    } catch (error) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;

      const errInfo = `failed get application by id in database id: ${id} name: ${name} for org ${this.org}, err: ${error}`;
      logger.error(errInfo);

      return null;
    }
  }

  async getApplicationByRepoRealName(name) {
    try {
      logger.info(`try get application by repo real name in database name: ${name} for org ${this.org}`);

      await this.Application.verifyConnection(this.mongoConnect);
      const params = {
        repoRealName: name,
      };
      const application = await this.Application.model.findOne(params);
      if (application) {
        logger.info(`found application by repo real name in database name: ${name} for org ${this.org}`);
      } else {
        logger.info(`didn't find application by repo real name in database name: ${name} for org ${this.org}`);
      }

      return application;
    } catch (error) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;

      const errInfo = `failed get application by repo real name in database name: ${name} for org ${this.org}, err: ${error}`;
      logger.error(errInfo);

      return null;
    }
  }
}

export default MongoDBapplications;
