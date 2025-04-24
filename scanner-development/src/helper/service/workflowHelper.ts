import { Job, Queue } from "bull";
import loggerImport from "../../logger";
import { isK8Mode } from "../envUtils";
import { ShardFolderUtils } from "../sharedFolderUtils";
import StatesHelper from "../statesHelper";
import { Issue } from "../../entitis/issuesTypes";
import { existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "fs";
import { ScanType } from "../../entitis/service/connector-message-types";
import { JobTypeEnum } from "@oxappsec/policy-workflow-service";
import { isPipelineWorkflowsFeatureEnabledForOrg } from "../featureFlags/isPipelineWorkflowsFeatureEnabledForOrg";

const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();
const sharedDir = process.env.OX_SHARED_DATA === "undefined" ? "/var/shared-data" : process.env.OX_SHARED_DATA;

type WorkflowJob = {
  scanId: string;
  orgId: string;
  doneFilePath: string;
  scanType: ScanType;
  jobType: JobTypeEnum;
};

class WorkflowHelper {
  workflowHelperQ: Queue<WorkflowJob>;
  uuid: string;
  orgName: string;

  constructor(queue: Queue<WorkflowJob>, uuid: string, orgName: string) {
    this.workflowHelperQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
  }

  async setWorkflowInfo() {
    try {
      await this.sendAndWaitForRes();
    } catch (err) {
      logger.error(`failed set workflow`);
    }
  }

  private async sendAndWaitForRes() {
    try {
      const uniqueId = uuid.v4();
      const scanSharedFolderPath = ShardFolderUtils.getScanSharedFolderPath(this.orgName, this.uuid);
      const dirToPutRes = `${scanSharedFolderPath}/${uniqueId}/workflow`;
      const doneFilePath = `${dirToPutRes}/workflow.done`;

      logger.info(`workflow creating dir: ${dirToPutRes}`);
      mkdirSync(dirToPutRes, { recursive: true });

      const { WORKFLOW_MANAGER_JOBS_NAME } = process.env;
      if (!WORKFLOW_MANAGER_JOBS_NAME) {
        logger.warn(`[WorkflowHelper] will not to add job to queue, WORKFLOW_MANAGER_JOBS_NAME: ${WORKFLOW_MANAGER_JOBS_NAME}`);
        return;
      }

      const { isPipelineScan } = StatesHelper.Instance;
      const jobType = isPipelineScan ? JobTypeEnum.PIPELINE : JobTypeEnum.SCAN;

      const isPipelineScanWithFeatureEnabled = isPipelineScan && (await isPipelineWorkflowsFeatureEnabledForOrg.isEnabled(this.orgName));
      const shouldSendJob = !isPipelineScan || isPipelineScanWithFeatureEnabled;
      if (!shouldSendJob) {
        logger.warn(`[WorkflowHelper] will not to add job to queue, isPipelineScanWithFeatureEnabled: ${isPipelineScanWithFeatureEnabled}`);
        return;
      }

      const jobPayload = {
        scanId: this.uuid,
        orgId: this.orgName,
        doneFilePath: doneFilePath,
        dirPath: dirToPutRes,
        scanType: StatesHelper.Instance.scanType,
        jobType,
      };

      logger.info(
        `[WorkflowHelper] adding job to queue, appName: ${this.orgName}, jobId: ${this.uuid}, payload: ${JSON.stringify(jobPayload)}`,
      );

      const queueJob = await this.workflowHelperQ.add(WORKFLOW_MANAGER_JOBS_NAME, jobPayload);

      if (isPipelineScanWithFeatureEnabled) {
        await this.waitForDone(queueJob, doneFilePath, this.orgName);
      }
    } catch (err) {
      logger.error(`[WorkflowHelper] failed, err: ${err}`);
    }
  }

  private async waitForDone(job: Job<WorkflowJob>, doneFilePath: string, appName: string): Promise<void> {
    const startTime = Date.now();

    logger.info(`[WorkflowHelper] starting to wait for job completion workflow, appName: ${appName}, jobId: ${job.id}`);

    for (let i = 0; i < 150; i++) {
      // Wait 2 seconds
      await new Promise(resolver => setTimeout(resolver, 2000));

      if (await job.isCompleted()) {
        logger.info(`[WorkflowHelper] Job completed (${Date.now() - startTime})ms. appName: ${appName}, jobId: ${job.id}`);
      } else {
        continue;
      }

      // Check if done file is present
      if (existsSync(doneFilePath)) {
        const doneFile = readFileSync(doneFilePath, { encoding: "utf-8" });
        const doneResult = JSON.parse(doneFile);
        if (doneResult.success) {
          //do something
          return;
        } else {
          StatesHelper.Instance.scanInfoStats.failedOpenSource++;
          StatesHelper.Instance.scanInfoStats.failedOpenSourceRepoNames.push(appName);
          logger.error(`[WorkflowHelper] Job done failed file. appName: ${appName}, jobId: ${job.id}`);
        }
      } else {
        StatesHelper.Instance.scanInfoStats.failedOpenSource++;
        StatesHelper.Instance.scanInfoStats.failedOpenSourceRepoNames.push(appName);
        logger.warn(`[WorkflowHelper] Job missing done file. appName: ${appName}, jobId: ${job.id}`);
      }
    }
    StatesHelper.Instance.scanInfoStats.timeoutOpenSource++;
    StatesHelper.Instance.scanInfoStats.timeoutOpenSourceRepoNames.push(appName);
    logger.error(`[WorkflowHelper] Job waiting timeout (${Date.now() - startTime})ms.. appName: ${appName}, jobId: ${job.id}`);
  }
  private splitToChunks(array, fullName: string) {
    const chunkSize = process.env.DEBUG ? 20000 : 5000;
    const chunks: any[] = [];
    for (let i = 0; i < array.length; i += chunkSize) {
      const c = array.slice(i, i + chunkSize);
      chunks.push(c);
    }
    return chunks;
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 10);
  }
}

export default WorkflowHelper;
