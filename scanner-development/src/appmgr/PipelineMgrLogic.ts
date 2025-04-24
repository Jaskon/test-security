import loggerImport from "../logger";
import { SCMPipeline } from "./PipelineMgr";
import { GitHub } from "../entitis/connectorsSpecific/GitHubTypes";
const logger = loggerImport.getDebugLogger();

export type CachedJob = string;
type WorkflowNames = string;
type WorkflowCapNumber = number;

//export const MAX_CICD_DEPTH = process.env.CICD_DEPTH ? parseInt(process.env.CICD_DEPTH) : 1;

export function isWorkflowTooOld(date: string): boolean {
  return Math.round(Math.abs(new Date().getTime() - new Date(date).getTime()) / (1000 * 60 * 60 * 24)) > 30;
}

export const getWorkflowsByActions = (actions: GitHub.GitHubActions[]): Map<WorkflowNames, GitHub.WorkflowRun[]> => {
  const result = [];

  const workflows = new Map<WorkflowNames, GitHub.WorkflowRun[]>();

  try {
    for (const action of actions) {
      for (const job of action.workflow_runs) {
        const mappedWorkflow = workflows.get(job.name);

        if (mappedWorkflow) {
          mappedWorkflow.push(job);
        } else {
          workflows.set(job.name, [job]);
        }
      }
    }
  } catch (err) {
    logger.error(`getWorkflowsByActions failed with error ${err}`);
  }

  return workflows;
};

export const getLatestActions = (actions: any, max_cicd_depth: number): any => {
  const result = [];

  const workflowCap = new Map<WorkflowNames, WorkflowCapNumber>();

  try {
    //
    // Take the last max_cicd_depth workflows from all actions
    //
    for (const action of actions) {
      for (const job of action.workflow_runs) {
        let currentCap = workflowCap.get(job.name) as number;

        const jobRunTime = job.updated_at ? job.updated_at : job.run_started_at;

        if (currentCap) {
          if (currentCap < max_cicd_depth) {
            if (!isWorkflowTooOld(jobRunTime)) {
              workflowCap.set(job.name, ++currentCap);
              result.push(job);
            }
          }
        } else {
          if (!isWorkflowTooOld(jobRunTime)) {
            workflowCap.set(job.name, 1);
            result.push(job);
          }
        }
      }
    }
  } catch (err) {
    logger.error(`getLatestActions failed with error ${err}`);
  }

  return result;
};
