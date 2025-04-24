import { Queue } from "bull";
import { Repo } from "../../entitis/codeRepoTypes";
import loggerImport from "../../logger";
import EnvQueueFactory from "../queue/envQueueFactory";
import Iqueue from "../queue/Iqueue";
import { RedisHelper } from "../redis/redisHelper";
const logger = loggerImport.getDebugLogger();

class VerificationAndStarsHelper {
  verificationAndStarsHelperQ: Iqueue;
  orgName: string;
  uuid: string;
  redisHelper: RedisHelper;
  queue: Queue;

  repos: Repo[] = [];

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.verificationAndStarsHelperQ = queue;
    this.orgName = orgName;
    this.uuid = uuid;
    this.redisHelper = new RedisHelper("verified_stars_cache", 15778800000); // 6 months
    this.queue = EnvQueueFactory.getNewQueue(process.env.OX_SBOM_QUEUE_NAME);
  }

  async setItems(repo: Repo) {
    try {
      if (!repo.unlistedActions.size) {
        return;
      }
      logger.info(`try set ${repo.unlistedActions.size} unlistedActions to redis Q`);

      const msg = [];

      for (const [item, itemInfo] of repo.unlistedActions.entries()) {
        const obj = {
          homepage: "",
          originalHomepage: "",
          orgId: this.orgName,
          libName: "",
          libPkgManager: "",
          libVer: "",
          scanId: this.uuid,

          orgNameToQuery: itemInfo.orgNameToQuery,
          repoNameToQuery: itemInfo.repoNameToQuery,
        };

        const isVerified = await this.redisHelper.findOne(itemInfo.orgNameToQuery);
        const stars = await this.redisHelper.findOne(itemInfo.repoNameToQuery);

        let hasIsVerified = false;
        let hasStars = false;

        if (isVerified !== undefined && isVerified != null) {
          itemInfo.isVerified = isVerified;
          hasIsVerified = true;
        }

        if (stars !== undefined && stars != null) {
          itemInfo.stars = stars;
          hasStars = true;
        }

        if (hasStars && hasIsVerified) {
          //Debug
          //logger.info(`item was found in verified_stars_cache, not sending again, item: ${JSON.stringify(itemInfo)}`);
          continue;
        }
        const job = await this.queue.add(obj);
        logger.info(`VerificationAndStarsHelper, repo: ${repo.fullName}, job.id: ${job.id}, msg: ${JSON.stringify(msg)}`);
      }
    } catch (e) {
      logger.error(`verificationAndStarsHelper setItems failed, repo: ${repo.fullName}, err: ${e}`);
    }
  }

  async getDataFromCache(repo: Repo) {
    try {
      if (!repo.unlistedActions.size) {
        return;
      }

      for (const actionInfo of repo.unlistedActions.values()) {
        try {
          const isVerified = await this.redisHelper.findOne(actionInfo.orgNameToQuery);
          const stars = await this.redisHelper.findOne(actionInfo.repoNameToQuery);

          if (isVerified !== undefined && isVerified != null) {
            actionInfo.isVerified = isVerified;
          }

          if (stars !== undefined && stars != null) {
            actionInfo.stars = stars;
          }
        } catch (e) {
          logger.error(`failed findOne in getDataFromCache err: ${e}, repo: ${repo.fullName}`);
        }
      }
    } catch (e) {
      logger.error(`failed getDataFromCache err: ${e}, repo: ${repo.fullName}`);
    }
  }
}

export default VerificationAndStarsHelper;
