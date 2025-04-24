import cacheDB from "@oxappsec/ox-cache-db";
import { BaseDocument } from "@oxappsec/ox-cache-db/lib/src/cache-db/cache-db-types";
import { IndexDirection } from "mongodb";
import { Session } from "../entitis/ArtifactTypes";
import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

interface indexRequest {
  index: [string, IndexDirection];
  unique: boolean;
}

class MongoHelper<T extends BaseDocument> {
  private indexRequests: indexRequest[] = [];
  private sessionId: Session;
  private runTime: Promise<void>;
  private indexObj: string = "";

  constructor(_indexRequests: indexRequest[], _sessionId: Session, _indexObj: string) {
    this.indexRequests = _indexRequests;
    this.sessionId = _sessionId;
    this.indexObj = _indexObj;
    this.runTime = new Promise(async resolve => {
      resolve(await this.CreateIndex());
    });
  }

  private async CreateIndex() {
    try {
      for (const request of this.indexRequests) {
        logger.debug(`[${process.pid}](${this.sessionId.uuid}) Creating index for ${this.sessionId.orgId}`);
        let res = await cacheDB.cindex.execute(
          this.sessionId.orgId,
          this.indexObj,
          [request.index],
          true, // ignore index length check
          request.unique,
        );
        if (!res) {
          logger.error(`[${process.pid}](${this.sessionId.uuid}) failed to create index for ${this.sessionId.orgId}, trying again`);
          res = await cacheDB.cindex.execute(
            this.sessionId.orgId,
            this.indexObj,
            [request.index],
            true, // ignore index length check
            request.unique,
          );
        }

        logger.debug(`[${process.pid}](${this.sessionId.uuid}) Index created: ${res} for ${this.sessionId.orgId}`);
      }
    } catch (err) {
      logger.error(`Failed to run ${err}`);
    }
  }
}

export default MongoHelper;
