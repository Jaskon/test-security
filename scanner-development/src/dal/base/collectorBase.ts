import { SbomEvent } from "../../entitis/artifactoryTypes";
import { RegistryName, Repo, SecurityEvent } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { Resource } from "../../entitis/orgPolicyTypes";
import { Connector } from "../../entitis/service/connector-message-types";
import { getSelectedRepos } from "../../helper/commonUtils";
import { PerformanceTelemetry } from "../../helper/decorators/PerformanceTelemetry";
import FileHelper from "../../helper/IO/fileHlper";
import JsonHelper from "../../helper/jsonHelper";
import Iqueue from "../../helper/queue/Iqueue";
import RateLimitHelper from "../../helper/rateLimitHelper";
import { GoogleOpenSourceInsightsHelper } from "../../helper/sbom/googleOpenSourceInsightsHelper";
import AlertRecommendationHelper from "../../helper/service/alertRecommendationHelper";
import BlameHelper from "../../helper/service/blameHelper";
import LightBlameHelper from "../../helper/service/lightBlameHelper";
import SecretValidationHelper from "../../helper/service/secretValidationHelper";
import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";
import MongoConnect from "../../mongo/mongoConnect";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import Artifactory from "../../policy/reporting/fakeCollectorsData/Artifactory.json";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../policy/rules/ruleManager";
import { ImageScanInfo } from "./artifactoryBase";

const logger = loggerImport.getDebugLogger();

abstract class CollectorBase {
  token: Token;
  uuid: string;
  orgName: string;
  resourceType: string;
  funcNames = new Set();
  orgPolicyParser: OrgPolicyParser;
  jsonHelper: JsonHelper;
  jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview;

  //Stats
  uniqueRequestAPIs = new Map<string, number>();

  //Handle execution of cloud and code security open source tools
  securityToolsQueue: Iqueue;
  mongoConnect: MongoConnect;
  executionOrder: number;
  userSelectedRepos: Connector = null;

  //handle clonerService communication
  clonerQueue: Iqueue;

  //Rate Limit Helper
  rateLimitHelper: RateLimitHelper;

  //Severity for connectors that used as sec tools
  fileHelper: FileHelper;

  //Helpers
  blameHelper: BlameHelper;
  lightBlameHelper: LightBlameHelper;
  secretValidationHelper: SecretValidationHelper;
  alertRecommendationHelper: AlertRecommendationHelper;
  googleOpenSourceInsightsHelper: GoogleOpenSourceInsightsHelper;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    resourceType: string,
    orgPolicyParser: OrgPolicyParser,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    this.token = token;
    this.uuid = uuid;
    this.orgName = orgName;
    this.resourceType = resourceType.toLowerCase();
    this.fileHelper = new FileHelper(this.uuid);
    this.orgPolicyParser = orgPolicyParser == undefined ? null : orgPolicyParser;
    this.jsonHelper = new JsonHelper(this.uuid);
    this.jsonApplicationDiscoveryOverview = jsonApplicationDiscoveryOverview;
    this.executionOrder = token.executionOrder;

    this.printToken();
    this.setFuncNames();
  }

  //To implemented
  abstract collect(resources: Resource[], callback: RulesManager): Promise<boolean[]>;

  setCommunicationChanel(securityToolsQueue: Iqueue, clonerQueue: Iqueue) {
    this.clonerQueue = clonerQueue;
    this.securityToolsQueue = securityToolsQueue;
  }

  getTokenPassword(): string {
    return this.token.password;
  }

  getUniqueKeyForDB(): string {
    return this.resourceType + "_" + this.uuid;
  }

  printStatsOfRateLimitInfo() {
    try {
      const relevantRequests = [...this.uniqueRequestAPIs.entries()].reduce((acc, [key, value]) => {
        if (value >= 1) {
          acc[key] = value;
        }
        return acc;
      }, {} as Record<string, number>);

      logger.info(`stats of api for: ${this.token.name}, stats: ${JSON.stringify(relevantRequests)}`);

      if (!this.rateLimitHelper) {
        return;
      }
      this.rateLimitHelper.printStats();
    } catch (err) {
      logger.error(`failed print state of rate limit info, token: ${this.token.name}, err: ${err}`);
    }
  }

  @PerformanceTelemetry()
  async setArtifactSecurityEventForFakeApp(securityAlerts: SecurityEvent[], sbomData: SbomEvent[], imageScanInfo: ImageScanInfo) {
    try {
      if (process.env.DEBUG) {
        return;
      }

      const startTime = new Date().getTime();

      const ArtifactoryCopy: Repo = JSON.parse(JSON.stringify(Artifactory));
      ArtifactoryCopy.type = "artifactory";
      ArtifactoryCopy.realRepo = false;
      ArtifactoryCopy.id = `*${imageScanInfo.imageObj.image.name}`;
      ArtifactoryCopy.name = `*${imageScanInfo.imageObj.image.name}`;
      ArtifactoryCopy.fullName = `*${imageScanInfo.imageObj.image.name}`;
      ArtifactoryCopy.realRepo = false;
      ArtifactoryCopy.noneRelevantRepo = false;

      const proms = [];
      if (securityAlerts.length > 0) {
        if (StatesHelper.Instance.useLightBlame) {
          //First dp blame
          await this.blameHelper.extendBlameSecurityEventsForSingleApp(
            securityAlerts,
            ArtifactoryCopy,
            "container security events",
            imageScanInfo.imageObj.image.name,
          );
        } else {
          //First dp blame
          await this.blameHelper.extendBlameSecurityEventsForSingleApp(
            securityAlerts,
            ArtifactoryCopy,
            "container security events",
            imageScanInfo.imageObj.image.name,
          );
        }

        logger.info(
          `try set artifact security events for image: ${imageScanInfo.imageObj.image.name}, securityAlerts count: ${securityAlerts.length}`,
        );
        const p1 = this.alertRecommendationHelper.setAlertRecommendation(securityAlerts, ArtifactoryCopy);
        const p2 = this.secretValidationHelper.validateSecrets(securityAlerts, ArtifactoryCopy, "artifact");
        proms.push(p1);
        proms.push(p2);
      }

      if (sbomData.length > 0) {
        const p4 = this.googleOpenSourceInsightsHelper.setApplicationSbomData(ArtifactoryCopy, sbomData);
        proms.push(p4);
      }

      if (proms.length == 0) {
        return;
      }

      await Promise.all(proms);

      const elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));

      logger.info(
        `finish set artifact security events, elapsedTime: ${elapsedTime} for image: ${imageScanInfo.imageObj.image.name}, securityAlerts count: ${securityAlerts.length}`,
      );
    } catch (err) {
      logger.error(`Failed set artifact security events, for image: ${imageScanInfo.imageObj.image.name} err ${err}`);
    }
  }

  repoSelectedByUser(repoId: string, repoName: string, createdAt: string, connectorName?: RegistryName) {
    try {
      if (!this.userSelectedRepos || this.userSelectedRepos === null) {
        logger.debug(`The repo ${repoName}, repoId: ${repoId} was selected by user, userSelectedRepos is undefined`);
        return true;
      }

      //BC support
      if (this.userSelectedRepos.monitorAllResources === undefined) {
        logger.debug(`The repo ${repoName}, repoId: ${repoId} was selected by user, monitorAllResources is undefined`);
        return true;
      }

      //Means we need to filter specific repos
      if (this.userSelectedRepos.monitorAllResources === null || !this.userSelectedRepos.monitorAllResources) {
        if (this.userSelectedRepos.monitoredResources === null) {
          logger.info(`The repo ${repoName} was selected by user, monitoredResources is null, repoId: ${repoId}`);
          return true;
        }

        const res = this.userSelectedRepos.monitoredResources.hasOwnProperty(repoId);

        let resInclude = false;

        if (connectorName && connectorName === RegistryName.gcr) {
          for (const image in this.userSelectedRepos.monitoredResources) {
            if (image.split("/").pop() === repoId) {
              resInclude = true;
              logger.info(`image match: ${image},repoId: ${repoId}, resInclude is true`);
            }
          }
        }

        if (res || resInclude) {
          logger.debug(`The repo ${repoName} was selected by user, repoId: ${repoId}`);
          return true;
        }

        try {
          //For new repos
          if (this.userSelectedRepos.monitorAllNewlyCreatedResources && createdAt) {
            const createdAtDate: Date = new Date(createdAt);
            if (createdAtDate.getTime() > this.userSelectedRepos.monitorAllNewlyCreatedResources) {
              logger.info(
                `The repo ${repoName} was selected by user by date, from connector: ${this.userSelectedRepos.monitorAllNewlyCreatedResources.toString()} from repo: ${createdAtDate.toString()}, repoId: ${repoId}`,
              );
              return true;
            }
          }
        } catch (err) {
          logger.error(
            `failed check if to monitor by newly create for repo ${repoName} from connector: ${this.userSelectedRepos.monitorAllNewlyCreatedResources.toString()} from repo: ${createdAt}, repoId: ${repoId}, err: ${err}`,
          );
          return false;
        }

        //The only way to remove repo and return false is if user didn't sleeted it
        logger.info(`The repo ${repoName} was not selected by user, repoId: ${repoId}`);
        return false;
      }

      //Monitor then all
      const monitorAllResourcesRes = this.userSelectedRepos.monitorAllResources;
      if (monitorAllResourcesRes) {
        logger.debug(`The repo ${repoName} was selected by user, monitorAllResourcesRes: ${monitorAllResourcesRes}`);
        return true;
      }

      logger.info(`The repo ${repoName} was not selected by user: ${monitorAllResourcesRes}`);
    } catch (err) {
      logger.error(`failed to get the monitored repos selected by user for repo: ${repoName}, repoId: ${repoId}, err: ${err}`);
    }
    return true;
  }

  initSelectedRepos(ruleManager: RulesManager) {
    logger.info(`try find selected apps by user for: ${this.token.name}`);

    try {
      let name = this.token.name.toLowerCase();
      if (this.token.type === "citool") {
        if (name.endsWith("ci")) {
          name = name.substring(0, name.length - "ci".length);
          const exist = ruleManager.collectorManager.collectors.filter(i => i.token.name === name);
          if (exist.length === 0) {
            name = "";
          } else {
            logger.info(
              `found citool which related to code repo for token name: ${exist[0].token.name}, going to try select specific repos`,
            );
          }
        }
      }

      if (!name) {
        logger.error(`failed init selected repos for: ${this.token.name}, name is empty`);
        return;
      }
      const res = getSelectedRepos(name, ruleManager.collectorManager.body);
      if (res) {
        this.userSelectedRepos = res;
      }
    } catch (e) {
      logger.warn(`failed in select apps by user for: ${this.token.name} ${e}`);
    }
  }

  updateToolResults(msgJson: any) {
    try {
      if (msgJson.body.uuid != this.uuid) return;
      if (msgJson.body.orgID != this.orgName) return;
    } catch (err) {
      logger.error(`uuid: ${this.uuid}, failed to update tools with results, msg: ${JSON.stringify(msgJson, null, 4)}, err: ${err}`);
    }
  }

  private printToken() {
    try {
      if (!this.token.password) {
        return;
      }
      if (this.token.password.length > 3) {
        logger.info(`${this.token.name} using token: ${this.token.password.substr(0, 3)} `);
      } else {
        logger.warn(`cannot print ${this.token.name} token due to: size is to small`);
      }
    } catch (err) {
      logger.error(`failed to print token, err: ${err}`);
    }
  }

  private setFuncNames() {
    try {
      logger.debug(`try to set object func names in collector: ${this.token.name}`);

      const allFuncNames = this.getAllFuncs(this);
      allFuncNames.forEach(i => this.funcNames.add(i));

      logger.debug(`finish set object func names in collector: ${this.token.name}`);
    } catch (err) {
      logger.error(`failed to set object func names in collector: ${this.token.name}, err: ${err}`);
    }
  }

  private getAllFuncs(toCheck) {
    const props = [];
    let obj = toCheck;
    do {
      props.push(...Object.getOwnPropertyNames(obj));
    } while ((obj = Object.getPrototypeOf(obj)));

    return props.sort().filter((e, i, arr) => {
      if (e != arr[i + 1] && typeof toCheck[e] == "function") return true;
    });
  }
}

export default CollectorBase;
