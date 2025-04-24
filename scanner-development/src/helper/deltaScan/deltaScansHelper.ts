import { PromisePool } from "@supercharge/promise-pool/dist/promise-pool";
import CodeRepoBase from "../../dal/base/codeRepoBase";
import { Relevance } from "../../entitis/codeRepoTypes";
import loggerImport from "../../logger";
import MongoDBApplications from "../../mongo/mongoDBapplications";
import RulesManager from "../../policy/rules/ruleManager";
import StatesHelper from "../statesHelper";
import { isLocalDevelopment } from "../envUtils";
const logger = loggerImport.getDebugLogger();

class DeltaScansHelper {
  uuid: string;
  orgName: string;

  constructor(uuid: string, orgName: string) {
    this.uuid = uuid;
    this.orgName = orgName;
  }

  async markUnchangedApplications(callObj: RulesManager, apiAllRepos, codeRepo: CodeRepoBase) {
    logger.info(`Marking unchanged applications`);

    try {
      // In case we're running a full scan no need to filter applications
      if (StatesHelper.Instance.isFullScan) {
        logger.info(`Running a full scan no need to filter unchanged apps`);
        return apiAllRepos;
      }

      await PromisePool.for(apiAllRepos)
        .withConcurrency(200)
        .process(async (rawRepoFromApi: any) => {
          try {
            if (StatesHelper.Instance.isPipelineScan || StatesHelper.Instance.isCharterBank) {
              rawRepoFromApi.delta = false;
              return;
            }

            //For local debug in case the repo we choose are changing
            if (isLocalDevelopment()) {
              if (process.env.ENFORCE_DELTA_FOR_CHANGED_REPO) {
                rawRepoFromApi.delta = true;
                return;
              }
            }

            const repoId = codeRepo.getCodeRepoId(rawRepoFromApi);
            let dbApplication = await codeRepo.mongoDBApplications.getApplicationById(repoId, rawRepoFromApi.name);

            if (!dbApplication) {
              logger.info(
                `couldn't find the app in the database by id maybe it's a mono repo id: ${repoId} name: ${rawRepoFromApi.name}, try as mono repo by name and not id`,
              );
              // Maybe it's a monorepo so try to get one of the children to check if it changed or not
              dbApplication = await codeRepo.mongoDBApplications.getApplicationByRepoRealName(rawRepoFromApi.name);
              if (!dbApplication) {
                // Couldn't find this repo in the database
                logger.info(
                  `running app, is overwrite as relevant so we, couldn't find the app in the database maybe it's a new repo id: ${repoId} name: ${rawRepoFromApi.name}.`,
                );
                StatesHelper.Instance.scanInfoStats.nonDeltaApps++;
                return;
              }
            }

            const appOverrideRelevance = codeRepo.isAppOverrideRelevance(repoId);
            if (appOverrideRelevance === Relevance.RELEVANT) {
              logger.info(
                `running app, application ${rawRepoFromApi.name}, repoId: ${repoId} is overwrite as relevant so we need to scan it`,
              );
              StatesHelper.Instance.scanInfoStats.nonDeltaApps++;
              return;
            }

            // If we did find it check if it needs to be re scanned
            rawRepoFromApi.lastCodeChange = await codeRepo.getCodeBaseLastCodeChange(rawRepoFromApi); //Can be null

            const codebaseApplicationLastCodeChange = rawRepoFromApi.lastCodeChange ? rawRepoFromApi.lastCodeChange.getTime() : "";

            const dbApplicationLastCodeChange = new Date(dbApplication.lastCodeChange).getTime();
            if (!dbApplicationLastCodeChange || !codebaseApplicationLastCodeChange) {
              logger.info(
                `running app, couldn't get code change times for ${dbApplication.appName}. dbApplicationLastCodeChange: ${dbApplicationLastCodeChange}, codebaseApplicationLastCodeChange: ${codebaseApplicationLastCodeChange}.`,
              );
              StatesHelper.Instance.scanInfoStats.nonDeltaApps++;
              return;
            }
            if (dbApplicationLastCodeChange < codebaseApplicationLastCodeChange) {
              // It changed so it needs to be scanned therefore we don't need it in the unchanged apps
              logger.info(
                `running app, application ${dbApplication.appName} changed so we need to scan it. dbApplicationLastCodeChange: ${dbApplicationLastCodeChange}, codebaseApplicationLastCodeChange: ${codebaseApplicationLastCodeChange}.`,
              );
              StatesHelper.Instance.scanInfoStats.nonDeltaApps++;
              return;
            }
            logger.info(
              `not executing app, application ${rawRepoFromApi.name} didn't change, marking it as delta. dbApplicationLastCodeChange: ${dbApplicationLastCodeChange}, codebaseApplicationLastCodeChange: ${codebaseApplicationLastCodeChange}.`,
            );

            rawRepoFromApi.delta = true;
            StatesHelper.Instance.scanInfoStats.deltaApps++;
          } catch (err) {
            StatesHelper.Instance.scanInfoStats.nonDeltaApps++;
            logger.error(`failed check is delta, err: ${err}`);
          }
        });
    } catch (error) {
      logger.error(`Error Marking unchanged applications ${error}`);
      return apiAllRepos;
    }
  }
}

export default DeltaScansHelper;
