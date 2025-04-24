import StatesHelper from "../helper/statesHelper";
import loggerImport from "../logger";
import { Application } from "../policy/reporting/types";
import MongoConnect from "./mongoConnect";
import MongoModel from "./mongoModel";
import { ApplicationConfigSchema } from "./schemas";
const logger = loggerImport.getDebugLogger();

class MongoDBapplicationsConfigurations {
  uuid: string;
  org: string;
  ApplicationConifg: MongoModel<Application> = null;
  mongoConnect: MongoConnect;

  constructor(uuid: string, orgName: string, mongoConnect: MongoConnect) {
    this.org = orgName;
    this.uuid = uuid;
    this.mongoConnect = mongoConnect;
    this.ApplicationConifg = new MongoModel(
      "applications-configurations",
      [
        {
          schemaName: "applications-configurations",
          schema: ApplicationConfigSchema,
        },
      ],
      this.org,
      this.uuid,
    );
  }

  async getApplicationsFromDB() {
    try {
      logger.info(`try get applications configurations for org ${this.org}`);

      await this.ApplicationConifg.verifyConnection(this.mongoConnect);
      const select = ["appId", "overridePriority", "overrideRelevance", "appOwners", "isOverridingPriority", "pipeline"];
      const applications = await this.ApplicationConifg.model.find().select(select).exec();

      return applications.map(i => i.toObject());
    } catch (error) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;

      const errInfo = `failed to get applications configurations, err: ${error}`;
      logger.error(errInfo);

      return [];
    }
  }
}

export default MongoDBapplicationsConfigurations;
