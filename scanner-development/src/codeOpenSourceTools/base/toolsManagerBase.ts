import { SecurityEvent } from "../../entitis/codeRepoTypes";
import Iqueue from "../../helper/queue/Iqueue";
import StatesHelper from "../../helper/statesHelper";
import { ResourceType, ToolError, ToolsExecutionStats } from "../../helper/toolExecutionStats";
import loggerImport from "../../logger";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import SecurityToolBase from "./securityToolsBase";
import ToolProgressBase from "./toolProgressBase";
import ToolsCreatorBase from "./toolsCreatorBase";

const Timeout = require("await-timeout");
const fs = require("fs");
const logger = loggerImport.getDebugLogger();

let runViaShell = process.env.DEBUG != undefined && !process.env.RUN_TOOLS_LOCALLY;

class ToolsManagerBase {
  uuid: string;
  type: ResourceType;
  orgPolicyParser: OrgPolicyParser;
  orgName: string;
  securityToolsQueue: Iqueue;
  toolResource: any;
  resultsDir: string;
  toolsExecutionState: Record<string, boolean> = {};
  allToolFinishedEventStr: string;
  toolsCount: number = 0;
  allDone: boolean = false;
  onPremRequestToTools: any = null;

  toolProgressBase: ToolProgressBase;
  resourceId: string;
  resourceName: string;

  //Tools info
  securityTools: SecurityToolBase[] = [];
  failedTools = new Set<string>();

  constructor(
    uuid: string,
    orgPolicyParser: OrgPolicyParser,
    orgName: string,
    resultsDir: string,
    filterMessage: string,
    toolResource: any,
    securityToolsQueue: Iqueue,
    toolsCreator: ToolsCreatorBase,
    allToolFinishedEventStr: string,
    type: ResourceType,
    toolProgressBase: ToolProgressBase,
    id: string,
  ) {
    this.uuid = uuid;
    this.orgPolicyParser = orgPolicyParser;
    this.orgName = orgName;
    this.securityToolsQueue = securityToolsQueue;
    this.resultsDir = resultsDir;
    this.securityTools = toolsCreator.securityTools;
    this.resourceName = filterMessage;
    this.toolResource = toolResource;
    this.allToolFinishedEventStr = allToolFinishedEventStr;
    this.type = type;
    this.toolProgressBase = toolProgressBase;
    this.resourceId = id;
  }

  get securityToolNamesLowercase(): string[] {
    return this.securityTools.map(t => t.toolConfig.name).map(t => t.toLowerCase());
  }

  printErr(message, msg) {}

  getRequestId(toolName: string): string | undefined {
    return this.securityTools.find(secTool => secTool.toolConfig.name.toLowerCase() === toolName.toLowerCase())?.requestId;
  }

  async sendAlertToShell() {
    logger.info(`start to wait for security tools based on shell from repo ${this.resultsDir}`);
    this.onPremRequestToTools = this.securityTools.map(i => i.runViaShell(this.toolResource));
    this.toolsCount = this.onPremRequestToTools.length;
    logger.info(`finish to wait for security tools based on shell from repo ${this.resultsDir}`);
  }

  async sendAlertsToQueue() {
    if (this.securityTools.length === 0) {
      this.toolsCount = 0;
      return;
    }

    //First set tool list state to pending request
    this.securityTools.forEach(i => (this.toolsExecutionState[i.toolConfig.name.toLowerCase()] = false));

    StatesHelper.Instance.scanInfoStats.numberOfToolsCalls += this.toolsCount;

    //Send all request
    const noNeedToRunTools: SecurityToolBase[] = [];
    const failedExecute: SecurityToolBase[] = [];

    let msgRequestsProms = this.securityTools.map(i => i.runViaSQS(this.toolResource, i, noNeedToRunTools, failedExecute));
    let msgRequests = await Promise.all(msgRequestsProms);

    //Set failed operation
    failedExecute.forEach(i => {
      this.failedTools.add(i.toolConfig.name.toLowerCase());
      ToolsExecutionStats.addExecutionStateOnFail(
        this.getRequestId(i.toolConfig.name),
        i.toolConfig.name,
        this.resourceName,
        this.resourceId,
        this.type,
        this.resultsDir,
        -1,
        ToolError.SendToQueue,
      );
    });

    //Remove requests that should't be waited for
    //and in case no need to wait just return
    msgRequests = msgRequests.filter(i => i != null);

    noNeedToRunTools.forEach(i => {
      const toolNameToLower = i.toolConfig.name.toLowerCase();
      this.toolsExecutionState[toolNameToLower] = true;
      logger.info(`setting no need to run tools for tool: ${toolNameToLower}, repo ${this.resultsDir}`);
    });

    this.toolsCount = msgRequests.length;

    if (msgRequests.length == 0) {
      logger.info(`not waiting for security all request to Q failed null, repo ${this.resultsDir}`);
      this.toolsExecutionState = {};
      this.toolsCount = 0;
      return;
    }
  }

  async sendScanRequest() {
    try {
      return runViaShell ? await this.sendAlertToShell() : await this.sendAlertsToQueue();
    } catch (err) {
      logger.error(`failed get extended alerts repo ${this.resultsDir} err ${err}`);
    }
  }

  async waitForAlerts() {
    try {
      if (runViaShell) {
        await this.waitToolsRunToFinishOnPrem();
      } else {
        await this.waitToolsRunToFinishPupSub();
      }
    } catch (err) {
      logger.error(`failed wait for alerts, repo ${this.resultsDir} err: ${err}`);
    }
  }

  async collectAlerts() {
    try {
      await this.waitForAlerts();

      const securityResultsProms = this.securityTools.map(i => i.createSecurityEvents(this.toolResource));

      const securityResults = await Promise.all(securityResultsProms);
      const flatten = securityResults.flat();

      return flatten;
    } catch (err) {
      logger.error(`failed collect alerts, repo ${this.resultsDir} err: ${err}`);
    }
    return [];
  }

  async collectAlertsWithoutWait() {
    try {
      const securityResultsProms = this.securityTools.map(i => i.createSecurityEvents(this.toolResource));

      const securityResults = await Promise.all(securityResultsProms);
      const flatten = securityResults.flat();

      logger.info(`finish collect alert. repo: ${this.resultsDir}, count: ${flatten.length}`);
      return flatten;
    } catch (err) {
      logger.error(`failed collect alerts, repo ${this.resultsDir} err: ${err}`);
    }
    return [];
  }

  async collectSbom() {
    try {
      const sbomResultsProms = this.securityTools.map(i => i.createSbomEvents(this.toolResource));
      const sbomData = await Promise.all(sbomResultsProms);
      return sbomData.filter(i => i != null);
    } catch (err) {
      logger.error(`failed collect sbom alerts, repo ${this.resultsDir} err: ${err}`);
    }
    return [];
  }

  async collectComplianceAlerts() {
    try {
      const complianceAlerts = this.securityTools.map(i => i.createComplianceAlerts(this.toolResource));

      const ComplianceData = await Promise.all(complianceAlerts);
      const filteredData = ComplianceData.filter(i => i != null);
      return filteredData.flat() as SecurityEvent[];
    } catch (err) {
      logger.error(`Failed to collect compliance alerts, ${err}`);
    }
    return [];
  }

  async collectAppSecurity() {
    try {
      const applicationSecurityAlerts = this.securityTools.map(i => i.applicationSecurity(this.toolResource));
      const res = await Promise.all(applicationSecurityAlerts);
      return res.flat();
    } catch (err) {
      logger.error(`Failed to collect aApp security alerts, ${err}`);
    }
    return [];
  }

  async waitToolsRunToFinishOnPrem() {
    let loopCount = 1;

    try {
      //Wait for all states to be true which means we receive all notification for them
      logger.info(
        `start to wait on prem for security tools count ${this.toolsCount} repo ${this.resultsDir}, interval: ${this.toolProgressBase.intervalToWaitFromLastUpdate}`,
      );

      let finishWithoutTimeout = true;
      try {
        await Timeout.wrap(
          Promise.all(this.onPremRequestToTools),
          this.toolProgressBase.intervalToWaitFromLastUpdateInMilli,
          `timeout security tools on prem`,
        );

        this.toolProgressBase.updateLastProgressTime(this.resultsDir, this.allToolFinishedEventStr);
      } catch (err) {
        finishWithoutTimeout = false;

        logger.info(`get timeout, repo ${this.resultsDir}, first timeout of 10 m`);
      }

      if (!finishWithoutTimeout) {
        while (true) {
          try {
            await Timeout.wrap(Promise.all(this.onPremRequestToTools), 1000 * 60 * 1, `timeout security tools on prem`);

            this.toolProgressBase.updateLastProgressTime(this.resultsDir, this.allToolFinishedEventStr);
          } catch (err) {
            if (this.toolProgressBase.continueToWait(this.resultsDir, this.allToolFinishedEventStr, loopCount)) {
              loopCount++;
              continue;
            }

            logger.error(`get timeout, repo ${this.resultsDir}, loopCount ${loopCount}, err: ${err}`);
          }
          //Exist
          break;
        }
      }
    } catch (err) {
      logger.error(`get timeout, repo ${this.resultsDir} err: ${err}`);
    }

    logger.info(`finish to wait on prem for security tools count ${this.toolsCount} loopCount: ${loopCount} repo ${this.resultsDir}`);
  }

  async waitToolsRunToFinishPupSub() {
    let loopCount = 1;

    try {
      if (this.toolsCount == 0) {
        logger.info(
          `not needed to wait tool count ${this.toolsCount} repo ${this.resultsDir}, interval: ${this.toolProgressBase.intervalToWaitFromLastUpdate}`,
        );
        return;
      }

      //All done before wait
      if (this.allDone) {
        logger.info(`finish to wait pupS allDone is true for security tools count ${this.toolsCount} repo ${this.resultsDir}`);
        return;
      }

      logger.info(`start to wait pupS object for security tools count ${this.toolsCount} done ${this.allDone} repo ${this.resultsDir}`);

      while (true) {
        await this.sleep();

        this.tryPullResultsFromDiskAndCheckIfDone();
        if (this.allDone) {
          logger.info(`all message arrive, repo ${this.resultsDir}`);
          break;
        }

        if (this.toolProgressBase.continueToWait(this.resultsDir, this.allToolFinishedEventStr, loopCount)) {
          loopCount++;
        } else {
          try {
            for (const [toolName, state] of Object.entries(this.toolsExecutionState)) {
              if (!state) {
                this.failedTools.add(toolName.toLowerCase());
                ToolsExecutionStats.addExecutionStateOnFail(
                  this.getRequestId(toolName),
                  toolName,
                  this.resourceName,
                  this.resourceId,
                  this.type,
                  this.resultsDir,
                  -1,
                  ToolError.NeverReturnFromQueue,
                );
              }
            }
          } catch (err) {
            //Do nothing
          }
          break;
        }
      }
    } catch (err) {
      logger.error(`failed wait for ${this.allToolFinishedEventStr}, security results, repo ${this.resultsDir} err: ${err}`);
    }

    logger.info(
      `finish to wait pupS object security tools count ${this.toolsCount} done ${this.allDone}, toolsExecutionState: ${JSON.stringify(
        this.toolsExecutionState,
      )} loopCount ${loopCount} repo ${this.resultsDir}`,
    );
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 5);
  }

  tryPullResultsFromDiskAndCheckIfDone() {
    try {
      for (const securityTool of this.securityTools) {
        try {
          let resFile = "";
          if (
            securityTool.toolConfig.type === "code" ||
            securityTool.toolConfig.type === "artifactoryDownload" ||
            securityTool.toolConfig.type === "artifactory"
          ) {
            resFile = `${this.resultsDir}/${securityTool.toolConfig.fileNameOutput}.done`;
          } else {
            resFile = `${this.resultsDir}.done`;
          }

          const toolNameToLower = securityTool.toolConfig.name.toLowerCase();

          //Results file not exist yet continue
          if (!fs.existsSync(resFile)) {
            continue;
          }
          //Some error, tool not exist
          if (this.toolsExecutionState[toolNameToLower] == undefined) {
            logger.error(
              `scanner output res problem, ${toolNameToLower} not exist in list: ${Object.values(this.toolsExecutionState).toString()}`,
            );
            continue;
          }
          //Already set to true ignore
          if (this.toolsExecutionState[toolNameToLower]) {
            continue;
          }

          this.toolsExecutionState[toolNameToLower] = true;

          ToolsExecutionStats.addToExecutionStatsFromFile(
            resFile,
            this.getRequestId(toolNameToLower),
            toolNameToLower,
            this.resourceName,
            this.resourceId,
            this.type,
            this.resultsDir,
            this.failedTools,
          );

          this.toolProgressBase.updateLastProgressTime(this.resultsDir, this.allToolFinishedEventStr);
        } catch (err) {
          logger.error(`failed to pull results for single tool: ${securityTool.toolConfig.name} command ${this.resultsDir}`);
        }
      }

      //Check before overwrite
      if (this.allDone) {
        return;
      }

      this.allDone = Object.values(this.toolsExecutionState).every(i => i);
    } catch (err) {
      logger.error(`failed to pull for all for command ${this.resultsDir}`);
    }
  }
}

export default ToolsManagerBase;
