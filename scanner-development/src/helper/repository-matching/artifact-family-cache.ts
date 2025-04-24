import memoryDB from "@oxappsec/ox-memory-db";

import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();

import { Session } from "../../entitis/ArtifactTypes";
import StatesHelper from "../statesHelper";

export type artifactFamily = string;
export type repoId = string;

const afcImpl = () => {
  const initializedSession: Session = {
    uuid: StatesHelper.Instance.uuid,
    orgId: StatesHelper.Instance.orgName,
  };
  const repoIdToNameMap = new Map<string, string>();

  return {
    associateRepoIdToName: (repoId: string, repoName: string) => {
      repoIdToNameMap.set(repoId, repoName);
    },

    getRepoNameFromId: (repoId: string) => {
      return repoIdToNameMap.get(repoId);
    },

    get: async (): Promise<Map<artifactFamily, repoId>> => {
      try {
        const artifactFamilyCache = await memoryDB.queueGet.execute(`${initializedSession.orgId}-artifact-family-cache`);
        if (artifactFamilyCache) {
          const cachedCached = JSON.parse(artifactFamilyCache);
          return new Map(Object.entries(cachedCached));
        }
      } catch (e) {
        logger.error(`Failed to get artifact family cache with error: ${e}`);
      }
      return new Map();
    },
  };
};

let instance: ReturnType<typeof afcImpl>;

const getAFC = () => {
  if (!instance) {
    instance = afcImpl();
    return instance;
  }
  return instance;
};

export default getAFC;
