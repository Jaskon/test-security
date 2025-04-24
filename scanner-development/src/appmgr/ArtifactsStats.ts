import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

import cacheDB from "../cache/cache-db/service";
import { SCM, Session } from "../entitis/ArtifactTypes";

export const artifactCollection = "artifacts-stats";

export interface ArtifactStats {
  image: string; //index
  repo_id: string;
  count: number;
  scm_type: string;
  site: string;
}

const ArtifactStats = (session: Session) => {
  let indexCreated = false;

  async function createIndex() {
    try {
      logger.debug(`[${process.pid}](${session.uuid}) Creating index for ${session.orgId}`);
      const indexCreatedInternal = await cacheDB.cindex.execute(session.orgId, artifactCollection, {
        image: 1,
        repo_id: 1,
      });
      if (!indexCreatedInternal) {
        logger.error(`[${process.pid}](${session.uuid}) failed to create index for ${session.orgId}, trying again`);
        await cacheDB.cindex.execute(session.orgId, artifactCollection, { image: 1, repo_id: 1 });
      }

      logger.debug(`[${process.pid}](${session.uuid}) Index created: ${indexCreated} for ${session.orgId}`);
    } catch (err) {
      logger.error(`${session.uuid} createIndex: ${err}`);
    }
  }

  logger.debug(`[${process.pid}](${session.uuid}) ArtifactsStats for ${session.orgId}`);

  return {
    update: async (image: string, scm: SCM) => {
      logger.debug(`[${process.pid}](${session.uuid}) Updating ${image} on repo: ${scm.id} at ${scm.site} for ${session.orgId}`);

      if (indexCreated === false) {
        indexCreated = true;
        await createIndex();
      }

      const stats = (await cacheDB.get.execute(session.orgId, artifactCollection, { image: image })) as ArtifactStats[] | null;

      if (stats === null || stats.length === 0) {
        logger.debug(`[${process.pid}](${session.uuid}) no stats found for ${image}, creating new one`);

        await cacheDB.set.execute(session.orgId, artifactCollection, {
          image: image,
          repo_id: scm.id,
          count: 1,
          scm_type: scm.type,
          site: scm.site,
        });
      } else {
        logger.debug(`[${process.pid}](${session.uuid}) stats found for ${image}, updating`);
        for (const artifactData of stats) {
          if (artifactData.repo_id === scm.id) {
            logger.debug(`[${process.pid}](${session.uuid}): updating stats for ${image} in ${scm.id}`);

            artifactData.count += 1;
            await cacheDB.replace.execute<Partial<ArtifactStats>>(
              session.orgId,
              "artifacts-stats",
              { image: artifactData.image },
              artifactData,
            );
            return;
          }
        }

        logger.debug(`[${process.pid}](${session.uuid}) no stats found for ${image}, creating new one`);
        await cacheDB.set.execute(session.orgId, artifactCollection, {
          image: image,
          repo_id: scm.id,
          count: 1,
          scm_type: scm.type,
          site: scm.site,
        });
      }
    },

    get: async (image: string) => {
      const scm: SCM = {
        id: "",
        type: "",
        site: "",
        token: "",
        scanAll: "false",
      };

      let currentCount = 0;

      logger.info(`[${process.pid}](${session.uuid}) Getting ${image} stats for ${session.orgId}`);

      const stats = (await cacheDB.get.execute(session.orgId, artifactCollection, { image: image })) as ArtifactStats[] | null;

      if (stats === null || stats.length === 0) {
        logger.info(`[${process.pid}](${session.uuid}) no stats found for ${image}`);
        return null;
      }

      for (const artifactData of stats) {
        if (artifactData.count > currentCount) {
          currentCount = artifactData.count;
          scm.id = artifactData.repo_id;
          scm.type = artifactData.scm_type;
          scm.site = artifactData.site;
        }
      }

      logger.info(`[${process.pid}](${session.uuid}) stats found for ${image}`);

      return scm;
    },

    getRepoStats: async (repoId: string) => {
      logger.debug(`[${process.pid}](${session.uuid}) Getting stats for ${repoId} for ${session.orgId}`);

      if (indexCreated === false) {
        indexCreated = true;
        await createIndex();
      }

      const stats = (await cacheDB.get.execute(session.orgId, artifactCollection, { repo_id: repoId })) as ArtifactStats[] | null;

      if (stats === null || stats.length === 0) {
        logger.debug(`[${process.pid}](${session.uuid}) no stats found for ${repoId}`);
        return null;
      }

      logger.debug(`[${process.pid}](${session.uuid}) stats found for ${repoId}`);

      return stats;
    },

    getSCMStats: async (): Promise<SCM[]> => {
      logger.info(`[${process.pid}](${session.uuid}) Getting stats for SCM for ${session.orgId}`);

      if (indexCreated === false) {
        indexCreated = true;
        await createIndex();
      }

      const gitlabGeneralSCM: SCM = {
        type: "gitlab",
        id: "",
        site: "https://gitlab.com",
        token: "",
        scanAll: "true",
      };

      const githubGeneralSCM: SCM = {
        type: "github",
        id: "",
        site: "https://api.github.com",
        token: "",
        scanAll: "true",
      };

      return [gitlabGeneralSCM, githubGeneralSCM];
    },
  };
};

export default ArtifactStats;
