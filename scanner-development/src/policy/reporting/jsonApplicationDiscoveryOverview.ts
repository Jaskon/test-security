import loggerImport from "../../logger";
import { Repo } from "../../entitis/codeRepoTypes";
import { ResourceType } from "../../entitis/collectorEntitisTypes";
import MongoDBreportUpdates from "../../mongo/mongoDBreportUpdates";
import MongoConnect from "../../mongo/mongoConnect";
import {
  ScanMetric,
  ScanPhaseTime,
  sendScannerPhaseTimeTelemetry,
  sendScannerTimeTelemetry,
  millisToMinutesAndSeconds,
} from "../../helper/telemetry-utils";

const logger = loggerImport.getDebugLogger();

class JsonApplicationDiscoveryOverview {
  uuid: string;
  orgName: string;
  finaJs: any;
  mongoDBreportUpdates: MongoDBreportUpdates;
  done: boolean = false;
  startTime = null;

  constructor(uuid: string, orgName: string, mongoConnect: MongoConnect) {
    this.uuid = uuid;
    this.orgName = orgName;

    this.mongoDBreportUpdates = new MongoDBreportUpdates(this.uuid, orgName, mongoConnect);

    const finaJs = {
      jsonVersion: "3.00",
      usage: "Used to show continuous progress in the Connectors page during a policy evaluation scan's discovery phase",
      systemsWithCreds: 3,
      discoveryDone: false,
      total: 0,
      scanned: 0,
      progressEvent: {
        type: "",
        label: "Devop systems discovery initiated",
      },
      systems: [
        {
          systemType: ResourceType[ResourceType.code_repo],
          progress: [],
        },
      ],
    };

    this.finaJs = finaJs;

    this.startTime = new Date().getTime();
  }

  setDescriptionFromRepo(repo: Repo) {
    try {
      const label = `${repo.name} repo discovered`;
      this.finaJs.progressEvent.label = label;
      this.finaJs.progressEvent.type = repo.type;
    } catch (err) {
      logger.error(`failed get description from repo: ${repo.name} for application discovery json, err: ${err}`);
    }
  }

  async updateInitState(totalRepos: number) {
    try {
      this.finaJs.total = totalRepos;

      await this.mongoDBreportUpdates.handleDiscoveryOverview(this.finaJs, false, "", "init state");
    } catch (err) {
      logger.error(`failed update default application discovery json, err: ${err}`);
    }
  }

  async updateReposItem(repo: Repo) {
    try {
      if (this.done) {
        return;
      }

      this.finaJs.scanned++;

      if (this.finaJs.scanned == 1) {
        let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - this.startTime);
        await sendScannerTimeTelemetry(ScanMetric.FirstDiscoveryItemTime, this.orgName, this.uuid, Number(elapsedTime));

        logger.info(`first update for discovery, execution time in minutes: ${elapsedTime}`);
      }

      this.setDescriptionFromRepo(repo);

      const reposSystem = this.finaJs.systems.find(i => i.systemType === ResourceType[ResourceType.code_repo]);
      if (reposSystem === undefined) {
        logger.error(`failed find system type ${ResourceType[ResourceType.code_repo]}`);
        return;
      }

      const repoItem = reposSystem.progress.find(i => i.type === repo.type);
      if (repoItem === undefined) {
        reposSystem.progress.push({
          type: repo.type,
          label: "1 repository discovered",
          count: 1,
        });
      } else {
        repoItem.count++;
        repoItem.label = `${repoItem.count} repository discovered`;
      }

      await this.mongoDBreportUpdates.handleDiscoveryOverview(this.finaJs, false, "", repo.fullName);
    } catch (err) {
      logger.error(`failed update application discovery json, err: ${err}`);
    }
  }

  async setErrAndDone(err: string) {
    try {
      await this.mongoDBreportUpdates.handleDiscoveryOverview("", true, err, "err");
    } catch (err) {
      logger.error(`failed set err for application discovery json, err: ${err}`);
    }
  }

  async setDone() {
    try {
      if (this.done) {
        return;
      }
      this.done = true;

      logger.info(`try update set done for application discovery json`);

      this.finaJs.scanned = this.finaJs.total;

      this.finaJs.discoveryDone = true;
    } catch (err) {
      logger.error(`failed update set done for application discovery json, err: ${err}`);
    }

    this.sleep();

    let retry = 4;
    let resUpdate = false;
    while (retry > 0) {
      retry--;

      resUpdate = await this.mongoDBreportUpdates.handleDiscoveryOverview(this.finaJs, true, "", "set done");

      if (resUpdate) {
        break;
      }
    }

    if (!resUpdate) {
      const errInfo = `failed update set done for application discovery json after 4 retry`;
      logger.error(errInfo);
    } else {
      let elapsedTime = millisToMinutesAndSeconds(new Date().getTime() - this.startTime);
      await sendScannerPhaseTimeTelemetry(ScanPhaseTime.ScanDiscoveryPhaseTime, this.orgName, this.uuid, Number(elapsedTime));

      logger.info(`finish update set done for application discovery json, execution time in minutes: ${elapsedTime}`);
    }
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 2);
  }
}

export default JsonApplicationDiscoveryOverview;
