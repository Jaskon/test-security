import CollectorBase from "./collectorBase";
import { ResourceType, Token } from "../../entitis/collectorEntitisTypes";
import loggerImport from "../../logger";
import { Resource } from "../../entitis/orgPolicyTypes";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import { CICD, CICDJob, CICDRepo } from "../../entitis/cicidRepoTypes";
import RulesManager from "../../policy/rules/ruleManager";
import PromisePool from "@supercharge/promise-pool/dist";
import { millisToMinutesAndSeconds, ScanPhaseTime, sendScannerPhaseTimeTelemetry } from "../../helper/telemetry-utils";
import { CicdRepoTypes } from "../../entitis/cicdTypes";
import StatesHelper from "../../helper/statesHelper";
import { Session } from "../../entitis/ArtifactTypes";
import { versionUtils } from "../../helper/versionUtils";
import ToolsMgr from "../../appmgr/ToolsMgr";
import ArtifactStats from "../../appmgr/ArtifactsStats";
import { ApplicationManager } from "../../appmgr/AppManager";

const Timeout = require("await-timeout");
const logger = loggerImport.getDebugLogger();

abstract class CIToolBase extends CollectorBase {
  totalFinish: number = 0;

  session: Session;
  artifactsStatsMgr;
  toolManager: ReturnType<typeof ToolsMgr>;
  appMgr: ApplicationManager;
  indexCreated: boolean = false;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, ResourceType[ResourceType.citool], policyConfiguration, jsonApplicationDiscoveryOverview);
  }

  //Should be collected regardless to the policy resources
  mandatoryResources: CicdRepoTypes[] = [CicdRepoTypes.repositories, CicdRepoTypes.jobs];

  abstract initLib(): Promise<void>;
  abstract getAllcicsTools(callObj: RulesManager): Promise<CICDRepo[]>;

  async initCicd(callObj) {
    this.appMgr = new ApplicationManager(this.uuid);
    this.session = {
      uuid: this.uuid,
      orgId: this.orgName,
    };

    this.session = {
      uuid: this.uuid,
      orgId: this.orgName,
    };
    this.artifactsStatsMgr = ArtifactStats(this.session);
    this.toolManager = ToolsMgr(this.session);

    await this.initLib();
    this.initSelectedRepos(callObj);
  }

  async repositories(cicdTool: CICDRepo): Promise<any> {
    return cicdTool;
  }

  async collect(resources: Resource[], callObj: RulesManager): Promise<boolean[]> {
    if (StatesHelper.Instance.isPipelineScan) {
      logger.info(`will not collect for cicd ${this.token.name} since a pipeline scan is running`);
      return [];
    }

    logger.info(`try set cicd repos for: ${this.token.name}, url: ${this.token.host}`);

    const startTime = new Date().getTime();

    try {
      this.setAndExtendWithMandatoryResources(resources);

      await this.initCicd(callObj);
      let cicdToolsFromApi = await this.getAllcicsTools(callObj);

      logger.info(
        `${this.token.name} start promisees poll to collect all ${resources.length} resources, cicd tools count: ${cicdToolsFromApi.length}`,
      );

      // cicdToolsFromApi = cicdToolsFromApi.slice(2, 3);
      // cicdToolsFromApi = cicdToolsFromApi.filter((i) =>
      //   i.repoName.includes("plat-service-connectors")
      // );

      await this.runInBatch(cicdToolsFromApi, callObj, resources);

      const elapsedTime = Math.floor((new Date().getTime() - startTime) / (1000 * 60));

      await sendScannerPhaseTimeTelemetry(ScanPhaseTime.ScanCicdPhaseTime, this.orgName, this.uuid, Number(elapsedTime));

      logger.info(`${this.token.name} promisees poll finish collect all resource for cicd, execution time in minutes: ${elapsedTime}`);

      StatesHelper.Instance.scanInfoStats.cicdScanTime = `${elapsedTime} minutes, ${new Date().toTimeString()}`;
    } catch (err) {
      const errInfo = `${this.token.name} failed collect all resources for cicd, err: ${err}`;
      logger.error(errInfo);
    }
    return [];
  }

  async runInBatch(cicdToolsFromApi, callObj, resources) {
    let defaultTimeoutPerApp = 1000 * 60 * 60;
    const timeoutBasedOnApi = StatesHelper.Instance.getTimeoutForProcessRepoBasedOnAPIlimits();
    if (timeoutBasedOnApi) {
      defaultTimeoutPerApp = timeoutBasedOnApi;
      logger.info(`set default timeout to process: ${this.token.name} from API is: ${defaultTimeoutPerApp}`);
    } else {
      logger.info(`set default timeout to process: ${this.token.name} is: ${defaultTimeoutPerApp}`);
    }

    const { results, errors } = await PromisePool.for(cicdToolsFromApi)
      .withConcurrency(StatesHelper.Instance.concurrentRepoScans)
      .process(async (cicdRepo: CICDRepo) => {
        try {
          let cicdInfo = {};

          const startTimeProcessRepo = new Date().getTime();

          logger.info(`start process cicd for: ${cicdRepo.repoName}, total finish: ${this.totalFinish} from: ${cicdToolsFromApi?.length}`);

          await Timeout.wrap(this.processCicd(cicdInfo, resources, callObj, cicdRepo), defaultTimeoutPerApp, `timeout process cicd`);
          let elapsedTimeProcessRepo = millisToMinutesAndSeconds(new Date().getTime() - startTimeProcessRepo);

          this.totalFinish++;
          logger.info(
            `finish process cicd for: ${cicdRepo.repoName} in ${elapsedTimeProcessRepo} minutes, total finish: ${this.totalFinish} from: ${cicdToolsFromApi?.length}`,
          );

          return true;
        } catch (err) {
          StatesHelper.Instance.scanInfoStats.failedProcessSingleCICD++;

          logger.error(`failed collect cicd resources for repo: ${cicdRepo.repoName}, total finish: ${this.totalFinish}, err: ${err}`);
          return false;
        }
      });
  }

  async processCicd(cicdInfo: any, resources: Resource[], callObj: RulesManager, cicdRepo: CICDRepo) {
    const typeStr = ResourceType[ResourceType.citool];

    cicdInfo["uuid"] = this.uuid;
    cicdInfo["uniqueID"] = this.token.type + "_" + this.uuid + "_" + this.token.name;
    cicdInfo["resourceType"] = typeStr;
    cicdInfo[typeStr] = cicdRepo;

    const apisProms = resources.map(resource => this.addFirstLevelItemToCicd(cicdRepo, cicdInfo, resource));
    await Promise.all(apisProms);

    //Set typed object
    const cicd: CICD = new CICD();
    cicd.citool = cicdRepo;
    cicd.repositories = cicdInfo[CicdRepoTypes[CicdRepoTypes.repositories]];
    cicd.jobs = cicdInfo[CicdRepoTypes[CicdRepoTypes.jobs]];

    if (cicd?.jobs?.length) {
      if (cicd?.jobs?.length === 0) {
        return;
      }
    } else {
      return;
    }

    await callObj.applicationsManager.updateAppMangerCICDItem(cicd);
  }

  async addFirstLevelItemToCicd(repoApi: CICDRepo, cicdObj: any, resource: Resource) {
    let data = [];

    try {
      if (this.funcNames.has(resource.name)) {
        data = await this[resource.name](repoApi);
        cicdObj[resource.name] = data;
      }

      return true;
    } catch (err) {
      logger.error(`failed collect resources: ${resource.name}, err: ${err}`);
    }
    return false;
  }

  private setAndExtendWithMandatoryResources(resources: Resource[]) {
    try {
      for (const cicdRepoTypes of this.mandatoryResources) {
        if (resources.some(i => i.name === CicdRepoTypes[cicdRepoTypes])) {
          continue;
        }

        let resource: Resource = new Resource();
        resource.name = CicdRepoTypes[cicdRepoTypes].toLowerCase();
        resource.type = this.resourceType;
        resource.global = false;
        resources.push(resource);
      }
    } catch (err) {
      logger.error(`failed extend with mandatory resources, err: ${err}`);
    }
  }
}

export default CIToolBase;
