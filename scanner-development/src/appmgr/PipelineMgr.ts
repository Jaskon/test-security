import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

import cacheDB from "@oxappsec/ox-cache-db";
import { IndexDirection } from "mongodb";
import { Session } from "../entitis/ArtifactTypes";
import { runOnce } from "../helper/commonUtils";

export const pipelineStats = "cached-pipeline-stats";

export interface SCMPipeline {
  // pipeline id
  id: string;

  // The pipeline id
  repo_id: string;

  date: any; // Date

  // The jobs inside the pipeline
  jobs: string[];
}

const PipelineMgr = (session: Session) => {
  const createIndexesOnce = runOnce(createIndex);

  async function createIndex() {
    try {
      const createSingleIndex = async (indexRequest: { index: [string, IndexDirection]; unique: boolean }) => {
        logger.debug(`[${process.pid}](${session.uuid}) Creating index for ${session.orgId}`);
        let res = await cacheDB.cindex.execute(
          session.orgId,
          pipelineStats,
          [indexRequest.index],
          true, // ignore index length check
          indexRequest.unique,
        );
        if (!res) {
          logger.error(`[${process.pid}](${session.uuid}) failed to create index for ${session.orgId}, trying again`);
          res = await cacheDB.cindex.execute(
            session.orgId,
            pipelineStats,
            [indexRequest.index],
            true, // ignore index length check
            indexRequest.unique,
          );
        }

        logger.debug(`[${process.pid}](${session.uuid}) Index created: ${res} for ${session.orgId}`);
      };

      const declaredIndexes: {
        index: [string, IndexDirection];
        unique: boolean;
      }[] = [
        { index: ["id", 1], unique: true },
        { index: ["repo_id", 1], unique: false },
        { index: ["date", 1], unique: true },
      ];

      const currentIndexLength = await cacheDB.ilen.execute(session.orgId, pipelineStats);

      // Include default _id of Mongo into account
      const IndexLengthIncludingDefault = (indexLength: number): number => {
        return indexLength + 1;
      };

      if (currentIndexLength < IndexLengthIncludingDefault(declaredIndexes.length)) {
        for (const index of declaredIndexes) {
          await createSingleIndex(index);
        }
      }
    } catch (err) {
      logger.error(`${session.uuid} createIndex: ${err}`);
    }
  }

  logger.debug(`[${process.pid}](${session.uuid}) Pipeline Stats for ${session.orgId}`);

  return {
    update: async (pipeline: SCMPipeline) => {
      let upsertResult;
      logger.debug(`[${process.pid}](${session.uuid}) Updating pipeline stats for ${session.orgId}`);

      await createIndexesOnce;

      const cachedResult = await cacheDB.findOne.execute<SCMPipeline>(session.orgId, pipelineStats, { id: pipeline.id });

      if (cachedResult) {
        logger.debug(`[${process.pid}](${session.uuid}) Pipeline stats updated for ${session.orgId}`);

        const duplicateCachedJobFound = cachedResult.jobs.filter(i => i === pipeline.jobs[0]);
        if (duplicateCachedJobFound.length > 0) {
          logger.debug(`Attempt to cache the same pipeline/action again: ${pipeline.jobs[0]}`);
          return;
        } else {
          cachedResult.jobs.push(...pipeline.jobs);
        }

        upsertResult = await cacheDB.upsertOne.execute<SCMPipeline>(session.orgId, pipelineStats, cachedResult);
      } else {
        upsertResult = await cacheDB.upsertOne.execute<SCMPipeline>(session.orgId, pipelineStats, pipeline);
      }

      if (!upsertResult) {
        logger.error(`Failed to save the pipeline: ${pipeline.id}`);
      }
    },

    get: async (repositoryId: string, diff: number /* Number of days back */) => {
      logger.debug(`[${process.pid}](${session.uuid}) Getting pipeline stats for ${session.orgId}`);

      await createIndexesOnce;

      const pipelineStatsRetrieved = await cacheDB.findAll.execute<SCMPipeline>(session.orgId, pipelineStats, {
        repo_id: repositoryId,
        date: { $gte: new Date(Date.now() - diff * 24 * 60 * 60 * 1000) },
      });

      if (pipelineStatsRetrieved) {
        logger.debug(`[${process.pid}](${session.uuid}) Pipeline stats retrieved for ${session.orgId}`);
      } else {
        logger.error(`[${process.pid}](${session.uuid}) Error rate retrieval failed for ${session.orgId}`);
      }

      return pipelineStatsRetrieved;
    },
  };
};

export default PipelineMgr;
