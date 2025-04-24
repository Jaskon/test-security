import { SbomEvent } from "../../entitis/artifactoryTypes";
import loggerImport from "../../logger";
import MongoConnect from "../../mongo/mongoConnect";
import { isLocalDevelopment } from "../envUtils";
import { ExtendedSbomComponent } from "../sbom/sbomHelper";
import { CacheIdentifier, CacheService } from "./cache.service";
import { Cache, InfectedRepo, InfectedRepoFilter } from "./cache.types";

const logger = loggerImport.getDebugLogger();

export class CacheResolver {
  private readonly cacheService: CacheService;
  constructor(private readonly orgId: string, mongoConnect: MongoConnect) {
    this.cacheService = new CacheService(this.orgId, mongoConnect);
  }

  async getFromCache<T>(cacheId: CacheIdentifier, cache: Cache) {
    try {
      const res = await this.cacheService.get<T>(cacheId, cache);
      if (res === null || !res) {
        return [];
      }

      // logger.info(`get from cache ${cache} length: ${res.length}, ${cacheId.idKey}: ${cacheId.name}`);
      return res;
    } catch (err) {
      logger.error(`failed get from cache ${cache}, ${cacheId.idKey}: ${cacheId.name}, err: ${err}`, err);
    }
    return [];
  }

  async setForCache<T>(cacheId: CacheIdentifier, items: T[], cache: Cache, compress = false) {
    try {
      if (isLocalDevelopment()) {
        return true;
      }

      if (items.length == 0) {
        return true;
      }
      await this.cacheService.set<T>(cacheId, items, cache, compress);
      // logger.info(`set cache ${cache}, length: ${items.length}, ${cacheId.idKey}: ${cacheId.name}`);
      return true;
    } catch (err) {
      logger.error(`failed set cache ${cache}, ${cacheId.idKey}: ${cacheId.name}, err: ${err}`);
    }
    return false;
  }

  async setSbomCache(cacheId: CacheIdentifier, { sbomHelper, ...sbom }: SbomEvent): Promise<boolean> {
    try {
      await this.cacheService.set<SbomEvent>(cacheId, [sbom as SbomEvent], Cache.Sbom, true);
      // logger.info(`Cached sbom for ${cacheId.idKey}: ${cacheId.name}`);
      if (sbomHelper?.extendedSbom?.components?.length) {
        await this.cacheService.set<ExtendedSbomComponent>(cacheId, sbomHelper?.extendedSbom?.components, Cache.ExtendedSbom, true);
      }
      logger.info(
        `Cached extended sboms for ${cacheId.idKey} ${cacheId.name}. Sboms: ${sbomHelper?.extendedSbom?.components?.length ?? 0}`,
      );
      return true;
    } catch (err) {
      logger.error(`Failed caching sboms, ${cacheId.idKey}: ${cacheId.name}, err: ${err}`);
      return false;
    }
  }

  async getSbomCache(cacheId: CacheIdentifier): Promise<SbomEvent[]> {
    try {
      // logger.info(`Fetching sbom from cache for ${cacheId.idKey} ${cacheId.name}`);
      const sbomRes = await this.cacheService.get<SbomEvent>(cacheId, Cache.Sbom);
      const extendedSbomComponents = await this.cacheService.get<ExtendedSbomComponent>(cacheId, Cache.ExtendedSbom);
      if (!sbomRes?.length || !extendedSbomComponents?.length) {
        return [];
      }
      logger.info(`Fetched sbom from cache for ${cacheId.idKey} ${cacheId.name}`);
      return [{ ...sbomRes[0], sbomHelper: { extendedSbom: { ...sbomRes[0].sbom, components: extendedSbomComponents } } }];
    } catch (err) {
      logger.error(`Failed fetching sbom from cache for ${cacheId.idKey}: ${cacheId.name}, err: ${err}`, err);
    }
  }
}
