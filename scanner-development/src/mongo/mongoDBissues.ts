import { ScanErrorName, sendScannerErrorTelemetry } from "../helper/telemetry-utils";
import loggerImport from "../logger";
import MongoConnect from "./mongoConnect";
import MongoModel from "./mongoModel";
import { IssueSchema } from "./schemas";
import { Issue } from "../entitis/issuesTypes";
import StatesHelper from "../helper/statesHelper";
const logger = loggerImport.getDebugLogger();

class MongoDBissues {
  uuid: string;
  org: string;
  Issue: MongoModel<Issue>;
  mongoConnect: MongoConnect;

  constructor(uuid: string, orgName: string, mongoConnect: MongoConnect) {
    this.org = orgName;
    this.uuid = uuid;
    this.mongoConnect = mongoConnect;
    this.Issue = new MongoModel(
      "issues",
      [
        {
          schemaName: "issues",
          schema: IssueSchema,
        },
      ],
      this.org,
      this.uuid,
    );
  }

  async getIssuesFromDB(scanId, appId) {
    try {
      logger.info(`try get issues for org ${this.org}`);

      await this.Issue.verifyConnection(this.mongoConnect);
      const find = { scanId: scanId, appId: appId };
      const issues = await this.Issue.model.find(find);

      return issues.map(i => i.toObject());
    } catch (error) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;

      const errInfo = `failed to get issues, err: ${error}`;
      logger.error(errInfo);
      await sendScannerErrorTelemetry(ScanErrorName.FailedQueryIssues, errInfo, this.org, this.uuid);

      return [];
    }
  }
}

export default MongoDBissues;
