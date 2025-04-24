import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import {
  AttackGraph,
  AttackGraphMongo,
  AttackPathhRes,
  AttackPathInputCategoryName,
  AttackPathInputCodeLocation,
  AttackPathInputSecurityEvents,
  AttackPathJSON,
  AttackPathNode,
  AttackPathSeverityFactor,
  attackPathSeverityFactors,
} from "../../entitis/attackPathTypes";
import { Repo, VCSType } from "../../entitis/codeRepoTypes";
import { OXtools } from "../../entitis/constant";
import { ExtraInfo, Issue, IssueAttackPath, SeverityChangeReason } from "../../entitis/issuesTypes";
import loggerImport from "../../logger";
import { AggItem } from "../../mongo/schemas";
import { ChangeReason, severityReasons } from "../../package-index";
import ResultsHandler from "../../policy/reporting/ResultsHandler";
import { copyToolInfo, escapeCharsFromPath, getLinkToFile, sleep } from "../commonUtils";
import { DotGraph, DotNode } from "../dotGraph";
import { replaceAll } from "../generalUtils";
import FileHelper from "../IO/fileHlper";
import { addSeverityChangedReasonToIssue } from "../policy/severityHelper";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
import { ToolError, ToolsExecutionStats } from "../toolExecutionStats";
import { unionBy } from "lodash";
import { isDefined } from "../typeguards";
import { CacheResolver } from "../cache/cache.resolver";
import { Cache } from "../cache/cache.types";
import { CacheIdentifier } from "../cache/cache.service";

const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();
const sharedDir = process.env.OX_SHARED_DATA === "undefined" ? "/var/shared-data" : process.env.OX_SHARED_DATA;

class AttackPathHelper {
  serviceHelperQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;
  appName: string;
  repo?: Repo;

  constructor(queue: Iqueue, uuid: string, orgName: string) {
    this.serviceHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
    this.appName = "";
  }

  async generateAttackPath(repo: Repo, attackPathInput: AttackPathJSON) {
    try {
      this.repo = repo;
      this.appName = repo.fullName;

      if (StatesHelper.Instance.isWalmart) {
        return;
      }

      if (!StatesHelper.Instance.isAttackPathEnable) {
        return;
      }

      if (repo.isDelta) {
        logger.info(`[${AttackPathHelper.name}] skipping isDelta, repo:${repo.fullName}`);
        return;
      }

      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      const attackPathDir = `${sharedDir}/${this.orgName}/scan_${replaceAll(this.uuid, "-", "_")}/attackPath`;
      const uniqueId = uuid.v4();
      const dirToPutRes = `${attackPathDir}/${uniqueId}`;
      fs.mkdirSync(dirToPutRes, { recursive: true });

      const inputFileName = `${dirToPutRes}/attackPathInput.json`;
      const attackPathInputJASONdata = JSON.stringify(attackPathInput);
      fs.writeFileSync(inputFileName, attackPathInputJASONdata);
      copyToolInfo(repo.name, inputFileName, AttackPathHelper.name, this.uuid);

      StatesHelper.Instance.scanInfoStats.numberOfToolsCalls++;
      logger.info(`[${AttackPathHelper.name}] Start, repo:${this.appName}`);
      const attackPathResFile = await this.sendAndWaitForRes(repo, inputFileName, dirToPutRes, uniqueId);
      logger.info(`[${AttackPathHelper.name}] End, repo:${this.appName}`);

      fs.unlinkSync(inputFileName);

      return attackPathResFile;
    } catch (err) {
      logger.error(`[${AttackPathHelper.name}] Failed, repo:${repo.fullName}, err: ${err}`);
    }
  }

  private async sendAndWaitForRes(repo: Repo, inputFileName: string, dirToPutRes: string, uniqueId: string) {
    logger.info(`[${AttackPathHelper.name}] calling service for: repo:${repo.fullName}`);

    try {
      let url = process.env.ATTACK_PATH_QUEUE_KEY;
      if (!url && !process.env.DEBUG) {
        return null;
      }

      const filePathRes = `${dirToPutRes}/attackPath.json`;

      let command = this.getCommand(dirToPutRes, inputFileName);
      command = escapeCharsFromPath(command);

      const msg = {
        MessageId: uniqueId,
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "attack-path",
        repoName: repo.fullName,
        resultPath: filePathRes,
        timeout: 1800000,
        orgDisplayName: process.env["companyName"],
        cloneDir: "",
        copyType: CopyType.LeanCodeOnly,
        toolCopyDestination: "",
        isMonoRepoChild: "",
        monoRepoChildSubfolder: "",
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: "",
        putInQueueTime: new Date().getTime(),
        shouldSkipLocalCopy: true,
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(
        `[${AttackPathHelper.name}] about to send msg to queue, repo:${repo.fullName}, uniqueId: ${uniqueId}, msg: ${JSON.stringify(msg)}`,
      );

      if (process.env.DEBUG) {
        //const reqRes = await runShell(repo.name, msg.localCommand, AttackPathHelper.name);
        //await sleep(10 * 1000);
        //await sleep(10 * 1000);
        return filePathRes;
      }

      const reqRes = await this.serviceHelperQ.sendQueueMessage(info);
      if (!reqRes) {
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.attackPath,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          -1,
          ToolError.SendToQueue,
        );

        repo.addFailedSecurityTools(OXtools.attackPath);
        return null;
      }

      logger.info(
        `[${AttackPathHelper.name}] about to start waiting for requests, uniqueId: ${uniqueId} repo:${repo.fullName}, msg: ${JSON.stringify(
          msg,
        )}`,
      );

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromAttackPath = false;

      const startProcessTime = new Date().getTime();

      let counter = 6 * 30; // 60 seconds * 30 = 30 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.attackPath,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.Timeout,
          );

          StatesHelper.Instance.scanInfoStats.failedAttackPathTimeout++;
          StatesHelper.Instance.scanInfoStats.failedAttackPathTimeoutRepoNames.push(repo.name);

          repo.addFailedSecurityTools(OXtools.attackPath);
          return null;
        }

        //Failed from Attack Path
        if (fs.existsSync(failedFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          ToolsExecutionStats.addExecutionStateOnFail(
            uniqueId,
            OXtools.attackPath,
            repo.fullName,
            repo.id,
            "repo",
            dirToPutRes,
            elapsedTimeProcessTime,
            ToolError.ResFileNotFound,
          );

          StatesHelper.Instance.scanInfoStats.failedAttackPathBatches++;
          StatesHelper.Instance.scanInfoStats.failedAttackPathBatchesNames.push(repo.name);

          repo.addFailedSecurityTools(OXtools.attackPath);
          return null;
        }

        //Done from Attack Path
        if (fs.existsSync(doneFilePath)) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `[${AttackPathHelper.name}] done file discovered from response, uniqueId: ${uniqueId}, repo:${repo.fullName}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromAttackPath = true;
          break;
        }

        //10 seconds
        await sleep(10 * 1000);
        counter--;
      }

      await sleep(10 * 1000);
      if (!fs.existsSync(filePathRes)) {
        let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
        ToolsExecutionStats.addExecutionStateOnFail(
          uniqueId,
          OXtools.attackPath,
          repo.fullName,
          repo.id,
          "repo",
          dirToPutRes,
          elapsedTimeProcessTime,
          ToolError.ResFileNotFound,
        );

        StatesHelper.Instance.scanInfoStats.failedAttackPathBatches++;
        repo.addFailedSecurityTools(OXtools.attackPath);
        return null;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      copyToolInfo(repo.name, filePathRes, AttackPathHelper.name, this.uuid);

      const failed = new Set<string>();
      ToolsExecutionStats.addToExecutionStatsFromFile(
        doneFilePath,
        uniqueId,
        OXtools.attackPath,
        repo.fullName,
        repo.id,
        "repo",
        repo.cloneDir,
        failed,
      );
      if (failed.size > 0) {
        return null;
      }

      logger.info(
        `[${AttackPathHelper.name}] finish waiting, repo: ${repo.fullName}, uniqueId: ${uniqueId}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, counter: ${counter}`,
      );

      return filePathRes;
    } catch (err) {
      ToolsExecutionStats.addExecutionStateOnFail(
        uniqueId,
        OXtools.attackPath,
        repo.fullName,
        repo.id,
        "repo",
        dirToPutRes,
        -1,
        ToolError.Generic,
      );

      logger.error(
        `[${AttackPathHelper.name}] failed to send batch of request, repo: ${repo.fullName}, uniqueId: ${uniqueId}, err: ${err}`,
      );
      repo.addFailedSecurityTools(OXtools.attackPath);
      StatesHelper.Instance.scanInfoStats.failedAttackPathBatches++;
    }
  }

  getCommand(outputDir: string, inputFilePath: string) {
    let exec_path: string | undefined = "/src/attack-path.py";
    if (process.env.DEBUG) {
      exec_path = process.env.ATTACK_PATH_PATH;
    }
    //return `python ${exec_path} --source ${repoDir} --output-dir ${outputDir} --events-path ${inputFilePath}`;
    return `python ${exec_path} --output-dir ${outputDir} --events-path ${inputFilePath}`;
  }

  getReachableByApiBranchesExtraInfo(attackPathNode: DotNode<AttackPathNode>, dotGraph: DotGraph<AttackPathNode>): ExtraInfo[] {
    try {
      const callBranches = dotGraph.findAllBranchesRecursively(attackPathNode?.id, 100, false);
      if (!callBranches.length) {
        logger.error(`${AttackPathHelper.name}] failed to get call branch for ${attackPathNode?.id}, repo:${this.appName}`);
        return [];
      }

      return callBranches.map(branch => this.getReachableByApiBranchExtraInfo(attackPathNode, branch)).filter(isDefined);
    } catch (err) {
      logger.error(`[${AttackPathHelper.name}] Failed to handleReachableByAPISF, repo:${this.appName}, err: ${err}`, err);
      return [];
    }
  }

  getReachableByApiBranchExtraInfo(attackPathNode: DotNode<AttackPathNode>, callBranch: string[]): ExtraInfo | undefined {
    try {
      const branch: string[] = callBranch?.slice(1);
      const apiInfo = AttackPathHelper.extractInfoFromFuncNodeName(branch[0]);
      const codeLocationInfo = AttackPathHelper.extractInfoFromFuncNodeName(branch[branch.length - 1]);

      let extraInfoKey = `\nAPI Endpoint - ${attackPathNode.endPoint}\nAPI Method - ${attackPathNode.method}`;
      extraInfoKey += `\nAPI Function - ${apiInfo?.functionName} path: ${apiInfo?.filePath} line: ${apiInfo?.line}`;
      extraInfoKey += `\nIssue Location -  path: ${codeLocationInfo?.filePath} line: ${codeLocationInfo?.line}`;
      extraInfoKey += `\nVulnerable API Call Path -  ${branch.join("  ->  ")}`;

      const repoDir = this.repo.getRepoForToolsBasedOnEnv();
      let filePath = codeLocationInfo?.filePath;
      if (filePath && filePath.startsWith(repoDir)) {
        filePath = filePath.slice(repoDir.length + 1);
      }

      return {
        key: extraInfoKey,
        link: getLinkToFile(this.repo, filePath, codeLocationInfo?.line?.toString()),
        callBranch,
      };
    } catch (err) {
      logger.error(`[${AttackPathHelper.name}] Failed to handleReachableByAPISFBranch, repo:${this.appName}, err: ${err}`, err);
    }
  }

  //extract function name + file path + line number from the following format example submit_order@/src/app.py#77
  static extractInfoFromFuncNodeName(funcNodeName: string) {
    try {
      let functionName = "";
      let filePath = "";
      let line = -1;
      let index = funcNodeName.indexOf("@");
      if (index > 0) {
        functionName = funcNodeName.slice(0, index);
        funcNodeName = funcNodeName.slice(index + 1);
      }
      index = funcNodeName.indexOf("#");
      if (index > 0) {
        filePath = funcNodeName.slice(0, index);
        line = parseInt(funcNodeName.slice(index + 1));
      }
      return { functionName: functionName, filePath: filePath, line: line };
    } catch (err) {
      logger.error(`[${AttackPathHelper.name}] Failed to extractInfoFromFuncNodeName, err: ${err}`, err);
    }
  }

  handleSeverityFactor(
    attackPathSeverityFactor: AttackPathSeverityFactor,
    attackPathNode: DotNode<AttackPathNode>,
    dotGraph: DotGraph<AttackPathNode>,
  ): { extraInfo: ExtraInfo[] } | undefined {
    try {
      const extraInfo = this.issueIsExposedByApi(attackPathNode, attackPathSeverityFactor)
        ? this.getReachableByApiBranchesExtraInfo(attackPathNode, dotGraph)
        : [];

      return { extraInfo };
    } catch (err) {
      logger.error(`[${AttackPathHelper.name}] Failed to handleSeverityFactor, repo:${this.appName}, err: ${err}`, err);
    }
  }

  static prepareCodeSecurityIssue(aggItems: AggItem[], issue: Issue) {
    try {
      if (!aggItems || !(aggItems.length > 0)) {
        logger.info(`[${AttackPathHelper.name}] issue does no contain aggItems ${issue?.iid} : ${issue?.categoryDisplayName}`);
        return;
      }

      let item: AttackPathInputSecurityEvents = new AttackPathInputSecurityEvents();
      item.uid = issue?.issueId;
      item.securityAlertType = AttackPathInputCategoryName[issue?.categoryId];
      item.locations = [];
      for (const aggItem of aggItems) {
        let location: AttackPathInputCodeLocation = new AttackPathInputCodeLocation();
        if (aggItem["startLine"] !== undefined) {
          location.startLineNumber = aggItem["startLine"];
        }
        if (aggItem["endLine"] !== undefined) {
          location.endLineNumber = aggItem["endLine"];
        }
        if (aggItem["filePath"]) {
          location.filePath = aggItem["filePath"];
        }
        item.locations.push(location);
      }
      //BC
      if (item?.locations.length > 0) {
        item.fileName = item?.locations[0]?.filePath;
        item.filePath = item?.locations[0]?.filePath;
        item.startLineNumber = item?.locations[0]?.startLineNumber;
        item.endLineNumber = item?.locations[0]?.endLineNumber;
      }

      return item;
    } catch (err) {
      logger.error(`[${AttackPathHelper.name}] Failed to prepareCodeSecurityIssue, repo:${issue?.iid}, err: ${err}`, err);
    }
  }

  static prepareSCAIssue(issue: Issue) {
    try {
      if (issue?.severityChangedReason && issue.severityChangedReason.length > 0) {
        const changeReason = issue.severityChangedReason.find(
          changeReason => changeReason.shortName === severityReasons.packageUsed.shortName,
        );
        if (!changeReason) {
          return;
        }

        if (changeReason?.extraInfo && changeReason.extraInfo.length > 0) {
          let item: AttackPathInputSecurityEvents = new AttackPathInputSecurityEvents();
          item.uid = issue?.issueId;
          item.securityAlertType = AttackPathInputCategoryName[issue?.categoryId];
          item.locations = [];
          for (const codeLocation of changeReason.extraInfo) {
            let location: AttackPathInputCodeLocation = new AttackPathInputCodeLocation();
            location.startLineNumber = codeLocation?.snippet?.snippetLineNumber;
            location.endLineNumber = -1;
            location.filePath = codeLocation?.snippet?.fileName;
            item.locations.push(location);
          }
          //BC
          if (item?.locations.length > 0) {
            item.fileName = item?.locations[0]?.filePath;
            item.filePath = item?.locations[0]?.filePath;
            item.startLineNumber = item?.locations[0]?.startLineNumber;
            item.endLineNumber = item?.locations[0]?.endLineNumber;
          }
          return item;
        }
      }
    } catch (err) {
      logger.error(`[${AttackPathHelper.name}] Failed to prepareSCAIssue, repo:${issue?.iid}, err: ${err}`, err);
    }
  }

  async saveAttackGraphs(
    attackPathResFile: string,
    issueIdToIssue: Map<string, Issue>,
    resultsHandler: ResultsHandler,
    cacheResolver: CacheResolver,
  ) {
    try {
      const data = fs.readFileSync(attackPathResFile, "utf8");

      //Delete file after reading
      this.fileHelper.deleteFile(attackPathResFile);

      const attackPathResults: AttackPathhRes[] = JSON.parse(data);
      if (attackPathResults.length == 0) {
        logger.error(`${AttackPathHelper.name}] attackPathRes.length == 0, repo:${this.appName}`);
        return;
      }

      const attackGraphs: AttackGraph[] = [];
      const issueAttackPathCacheItems: Omit<IssueAttackPath, "repoId">[] = [];
      for (const attackPathRes of attackPathResults) {
        if (!attackPathRes.success) continue;

        if (attackPathRes.type === "global") {
          try {
            const dotGraph = await DotGraph.decodeAndParseGraph<AttackPathNode>(attackPathRes.dot);
            const attackGraph: AttackGraphMongo = {
              issues: null,
              type: attackPathRes.type,
              graph: {
                nodes: dotGraph?.nodes,
                edges: dotGraph?.edges,
              },
              scanId: StatesHelper.Instance.uuid,
              createdAt: new Date(),
              appId: this?.repo?.id,
            };
            attackGraphs.push(attackGraph);
          } catch (err) {
            logger.error(`[${AttackPathHelper.name}] Failed to save global graph, err: ${err}`, err);
          }
        }

        if (attackPathRes.type !== "issueResult") continue;

        const issuesIds = attackPathRes.uid;
        const dotGraph = await DotGraph.decodeAndParseGraph<AttackPathNode>(attackPathRes.dot);
        try {
          // add new attackpath severity factors to issues
          if (dotGraph) {
            for (const attackPathNode of dotGraph?.nodes) {
              if (!attackPathNode?.severityFactors) {
                continue;
              }
              const attackPathSeverityFactor = attackPathSeverityFactors.find(
                item => item.name.toLocaleLowerCase() === attackPathNode.severityFactors?.toLocaleLowerCase(),
              );
              if (!attackPathSeverityFactor) {
                logger.error(
                  `${AttackPathHelper.name}] failed to match severity factor:${attackPathNode.severityFactors}, repo:${this.appName}`,
                );
                continue;
              }

              const { extraInfo } = this.handleSeverityFactor(attackPathSeverityFactor, attackPathNode, dotGraph) ?? {};
              for (const uid of issuesIds) {
                const issue = issueIdToIssue.get(uid);
                if (!issue) {
                  logger.error(`${AttackPathHelper.name}] failed to found issue for uid:${uid}, repo:${this.appName}`);
                  continue;
                }

                logger.info(
                  `[${AttackPathHelper.name}] Adding severity factor: ${attackPathSeverityFactor.severityReason.shortName}, to issue ${issue?.issueId}, repo:${this.appName}`,
                );

                addSeverityChangedReasonToIssue(attackPathSeverityFactor.severityReason, issue, extraInfo);
                if (this.issueIsExposedByApi(attackPathNode, attackPathSeverityFactor) && attackPathNode.uuid) {
                  this.markIssueAsExposedByApi(issue, attackPathNode.uuid, extraInfo);

                  issueAttackPathCacheItems.push({
                    issueId: issue.issueId,
                    newSeverity: {
                      changedReason: attackPathSeverityFactor.severityReason,
                      extraInfo,
                    },
                    exposedByApiItems: issue.exposedByApiItems,
                    exposedByApiIds: issue.exposedByApiIds,
                  });
                }
              }
            }
          }
        } catch (err) {
          logger.error(`[${AttackPathHelper.name}] Failed to save severity factors, repo:${this.appName}, err: ${err}`, err);
        }
        const attackGraph: AttackGraphMongo = {
          issues: issuesIds,
          type: attackPathRes.type,
          graph: {
            nodes: dotGraph?.nodes,
            edges: dotGraph?.edges,
          },
          scanId: StatesHelper.Instance.uuid,
          createdAt: new Date(),
          appId: this?.repo?.id,
        };
        attackGraphs.push(attackGraph);
      }

      logger.info(
        `[${AttackPathHelper.name}] saveAttackGraphs, attackGraphs lenght: ${attackGraphs?.length}, res lenght ${attackPathResults?.length}`,
      );
      await resultsHandler.mongoDBreport.addAttackGraphs(attackGraphs, StatesHelper.Instance.uuid, this?.repo?.id);

      await AttackPathHelper.saveCache(this.repo!, issueAttackPathCacheItems, cacheResolver);
    } catch (err) {
      logger.error(`[${AttackPathHelper.name}] Failed to saveAttackGraphs, repo:${this.appName}, err: ${err}`, err);
    }
  }

  static async setAttackPathToIssuesFromCache(repo: Repo, issues: Issue[], cacheResolver: CacheResolver) {
    const cache = await cacheResolver.getFromCache<IssueAttackPath>(AttackPathHelper.getCacheKey(repo), Cache.issueAttackPath);
    for (const issueAttackPath of cache) {
      const issue = issues.find(({ issueId }) => issueId === issueAttackPath.issueId);

      if (issue) {
        issue.exposedByApiIds = issueAttackPath.exposedByApiIds;
        issue.exposedByApiItems = issueAttackPath.exposedByApiItems;

        addSeverityChangedReasonToIssue(issueAttackPath.newSeverity.changedReason, issue, issueAttackPath.newSeverity.extraInfo);
      }
    }
  }

  private static async saveCache(repo: Repo, items: Omit<IssueAttackPath, "repoId">[], cacheResolver: CacheResolver) {
    await cacheResolver.setForCache(AttackPathHelper.getCacheKey(repo), items, Cache.issueAttackPath);
  }

  private markIssueAsExposedByApi(issue: Issue, apiItemUuid: string, extraInfo: ExtraInfo[] = []) {
    const newCodeLocations = extraInfo
      .map(item => ({ link: item.link, callBranch: item.callBranch }))
      .filter(codeLocation => isDefined(codeLocation.link)) as {
      link: string;
      callBranch: string[];
    }[];

    const existingApiItem = issue.exposedByApiItems?.find(({ apiId }) => apiItemUuid === apiId);
    if (existingApiItem) {
      existingApiItem.codeLocations = unionBy(existingApiItem.codeLocations, newCodeLocations, "link");
    } else {
      issue.exposedByApiItems = [
        ...(issue.exposedByApiItems ?? []),
        {
          apiId: apiItemUuid,
          codeLocations: newCodeLocations,
        },
      ];
    }

    if (!issue.exposedByApiIds) {
      issue.exposedByApiIds = [apiItemUuid];
      return;
    }
    if (issue.exposedByApiIds.includes(apiItemUuid)) {
      return;
    }
    issue.exposedByApiIds.push(apiItemUuid);
  }

  private issueIsExposedByApi(attackPathNode: DotNode<AttackPathNode>, attackPathSeverityFactor: AttackPathSeverityFactor) {
    return attackPathNode.node_type === "API" && attackPathSeverityFactor.severityReason === severityReasons.codeExposedByAPI;
  }

  private static getCacheKey(repo: Repo): CacheIdentifier {
    return { id: repo.id, idKey: "appId" };
  }
}

export default AttackPathHelper;
