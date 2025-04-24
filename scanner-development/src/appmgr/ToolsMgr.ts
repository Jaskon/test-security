import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

import { SCM, Session } from "../entitis/ArtifactTypes";
import cacheDB from "../cache/cache-db/service";

export const toolCollection = "tools-stats";
export const parserToolCollection = "ox-parser";
export const database = "ox-tool-stats";

export interface ToolStats {
  id: string; //index
  version: string;
}

const ToolsMgr = (session: Session) => {
  let indexCreated = false;

  async function createIndex() {
    try {
      logger.debug(`[${process.pid}](${session.uuid}) Creating index for ${session.orgId}`);
      indexCreated = await cacheDB.cindex.execute(session.orgId, toolCollection, {
        id: 1,
      });
      if (!indexCreated) {
        logger.error(`[${process.pid}](${session.uuid}) failed to create index for ${session.orgId}, trying again`);
        indexCreated = await cacheDB.cindex.execute(session.orgId, toolCollection, { id: 1 });
      }

      logger.debug(`[${process.pid}](${session.uuid}) Index created: ${indexCreated} for ${session.orgId}`);
    } catch (err) {
      logger.error(`${session.uuid} createIndex: ${err}`);
    }
  }

  logger.info(`[${process.pid}](${session.uuid}) ToolsMgr for ${session.orgId}`);

  return {
    update: async (tool: string, version: string) => {
      logger.info(`[${process.pid}](${session.uuid}) Updating ${tool} version: ${version} for ${session.orgId}`);

      if (indexCreated === false) {
        await createIndex();
      }

      const versionUpdRes = await cacheDB.replace.execute(session.orgId, toolCollection, { id: tool }, { id: tool, version: version });

      if (versionUpdRes === null) {
        logger.error(`[${process.pid}](${session.uuid}) failed to update ${tool} version: ${version} for ${session.orgId}`);
        return false;
      }

      logger.info(`[${process.pid}](${session.uuid}) Updated ${tool} version: ${version} for ${session.orgId}`);
      return true;
    },

    get: async (tool: string) => {
      logger.info(`[${process.pid}](${session.uuid}) Getting ${tool} version for ${session.orgId}`);

      const stats = (await cacheDB.get.execute(session.orgId, toolCollection, {
        id: tool,
      })) as ToolStats[] | null;

      if (stats === null || stats.length === 0) {
        logger.info(`[${process.pid}](${session.uuid}) no version found for ${tool} for ${session.orgId}`);
        return null;
      }

      logger.info(`[${process.pid}](${session.uuid}) version found for ${tool} (${stats[0].version}) for ${session.orgId}`);

      return stats[0].version;
    },

    getParserVersion: async () => {
      logger.debug(`[${process.pid}](${session.uuid}) Getting version for ${session.orgId}`);

      const stats = (await cacheDB.get.execute(database, parserToolCollection, {
        id: session.orgId,
      })) as ToolStats[] | null;

      if (stats === null || stats.length === 0) {
        logger.debug(`[${process.pid}](${session.uuid}) no version found for ${session.orgId}`);
        return null;
      }

      logger.debug(`[${process.pid}](${session.uuid}) Parser version found for (${stats[0].version}) for ${session.orgId}`);

      return stats[0].version;
    },
  };
};

export default ToolsMgr;
