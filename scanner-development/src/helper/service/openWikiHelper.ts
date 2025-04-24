const util = require("util");
const exec = util.promisify(require("child_process").exec);
import { Application } from "../../appmgr/application";
import { Repo, repoType, VCSType } from "../../entitis/codeRepoTypes";
import { OpenWikiTypesRequest, OpenWikiTypesResponse } from "../../entitis/service/openWikiTypes";
import loggerImport from "../../logger";
import { isK8Mode } from "../envUtils";
import { replaceAll } from "../generalUtils";
import Iqueue from "../queue/Iqueue";
import { RedisHelper } from "../redis/redisHelper";
import StatesHelper from "../statesHelper";

const onSast = process.env.MONGO_CONN === "atlas";
const isk8 = isK8Mode();
const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();
const globalDir = process.env.OX_GLOBAL_DATA === "undefined" ? "/var/global-data" : process.env.OX_GLOBAL_DATA;

class OpenWikiHelper {
  openWikiHelperQ: Iqueue;
  uuid: string;
  orgName: string;

  repos: Repo[] = [];
  redisHelper: RedisHelper;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.openWikiHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.redisHelper = new RedisHelper("open_wiki", 0);
  }

  //Called during scan
  async addOpenWikiRequest(app: Application, repo: Repo) {
    try {
      const repo: Repo = app?.appInfo?.repo?.code_repo;
      if (!repo) {
        return;
      }

      if (!repo.privateVisability && repo.type.toLowerCase() === repoType.github.toLowerCase() && repo.hasWiki && !repo.noneRelevantRepo) {
        const uniqueKey = `${this.orgName}-${repo.type.toLowerCase()}-${repo.repoId}`;
        const responseFromRedis = (await this.redisHelper.findOne(uniqueKey)) as any;
        if (responseFromRedis && responseFromRedis != null) {
          this.updateSecurityAlertsWithOpenWikiInfo(responseFromRedis, repo);
          return;
        }

        StatesHelper.Instance.scanInfoStats.wikiReposNotFound++;
        this.repos.push(repo);
        if (this.repos.length >= 50) {
          const reposCopy = JSON.parse(JSON.stringify(this.repos));
          this.repos = [];
          await this.setOpenWikiItems(reposCopy);
        }
      }
    } catch (err) {
      logger.error(`failed handel open wiki for single app: ${repo.fullName}, err: ${err}`);
    }
  }

  //Called at finalizing state
  async setAllOpenWikiForRepos(apps: Application[]) {
    try {
      logger.info(`try set all open Wiki at finalizing for: ${apps.length} repos`);

      //Set reminding app if needed
      if (this.repos.length > 0) {
        await this.setOpenWikiItems(this.repos);
        this.repos = [];
      }

      logger.info(`finish set all open Wiki at finalizing for: ${apps.length} repos`);
    } catch (err) {
      logger.error(`failed set all open Wiki for repos, err: ${err}`);
    }
  }

  private async setOpenWikiItems(allRepos: Repo[]) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      let requests: OpenWikiTypesRequest[] = [];
      allRepos.forEach(i => {
        try {
          if (i.vcsType === VCSType.tfvc) {
            return;
          }

          const openWikiTypesRequest: OpenWikiTypesRequest = new OpenWikiTypesRequest();
          openWikiTypesRequest.analysisUid = this.uuid;
          openWikiTypesRequest.orgId = this.orgName;
          openWikiTypesRequest.repoUrl = i.link;
          openWikiTypesRequest.uid = i.openWikiRequestId;
          openWikiTypesRequest.repoName = i.fullName;
          openWikiTypesRequest.repoId = i.repoId;
          openWikiTypesRequest.sourceControl = i.type.toLowerCase();
          requests.push(openWikiTypesRequest);
        } catch (err) {
          logger.error(`failed create open wiki requests for repo: ${i.fullName}`);
        }
      });

      requests = requests.filter(i => i);
      if (requests.length == 0) {
        return;
      }

      logger.info(`try set open wiki requests: ${requests.length}`);

      const chunks = this.splitToChunks(requests);
      const proms = chunks.map(c => {
        return this.sendWithoutWaitForRes(c as OpenWikiTypesRequest[]);
      });
      await Promise.all(proms);

      logger.info(`finish set open wiki for requests: ${requests.length}`);
    } catch (err) {
      logger.error(`failed set all open wiki for apps, err: ${err}`);
    }
  }

  private updateSecurityAlertsWithOpenWikiInfo(openWikiItemRes: OpenWikiTypesResponse, repo: Repo) {
    try {
      if (!openWikiItemRes.isSuccess) {
        logger.error(`error from wiki service for response: ${JSON.stringify(openWikiItemRes)}`);
        StatesHelper.Instance.scanInfoStats.failedOpenWiki++;
        return;
      }

      if (openWikiItemRes.isOpen) {
        repo.openWiki = openWikiItemRes.isOpen;
        logger.info(`found repo: ${repo.fullName} with open wiki, response: ${JSON.stringify(openWikiItemRes)}`);
      }
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.failedOpenWiki++;
      logger.error(`fail open wiki for response: ${JSON.stringify(openWikiItemRes)} repo: ${repo.fullName}, err: ${err}`);
    }
  }

  private async sendWithoutWaitForRes(items: OpenWikiTypesRequest[]) {
    const openWikiDir = `${globalDir}/${this.orgName}/scan_${replaceAll(this.uuid, "-", "_")}/openWiki`;
    const uniqueId = uuid.v4();

    try {
      if (items.length == 0) {
        return null;
      }

      logger.info(`sending request to open wiki service, requests: ${items.length}, uniqueId: ${uniqueId}`);

      let url = onSast ? process.env.OPENWIKI_SERVICE_SQS_URL : process.env.OPENWIKI_SERVICE_QUEUE_KEY;
      if (isk8) {
        url = process.env.OPENWIKI_SERVICE_QUEUE_KEY;
      }

      const dirToPutRes = `${openWikiDir}/${uniqueId}`;
      const filePathRes = `${dirToPutRes}/openWiki.json`;
      const doneFilePath = `${filePathRes}.done`;

      const msg = {
        resultPath: filePathRes,
        doneFilePath: doneFilePath,
        items: items,
        dirToPutRes: dirToPutRes,
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(
        `about to send msg to queue for open wiki, uniqueId: ${uniqueId}, num of requests: ${items.length}, msg: ${JSON.stringify(msg)}`,
      );

      //From SAST(sqs)
      const reqRes = await this.openWikiHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        logger.error(
          `failed enter item to open wiki Q, uniqueId: ${uniqueId}, num of requests: ${items.length}, msg: ${JSON.stringify(msg)}`,
        );
        return;
      }
    } catch (err) {
      let errInfo = `failed to send batch of open wiki batch request, uniqueId: ${uniqueId}, err: ${err}`;
      logger.error(`${errInfo}`);
    }
    StatesHelper.Instance.scanInfoStats.failedOpenWiki++;
  }

  splitToChunks(array) {
    const chunkSize = process.env.DEBUG ? 20000 : 5000;
    const chunks: any[] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      const c = array.slice(i, i + chunkSize);
      chunks.push(c);
    }
    return chunks;
  }
}

export default OpenWikiHelper;
