import { AppFlowOrchestrator } from "./applicationsFlowTypes";
import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

export class Orchestrator {
  orchestratorsAppFlow: AppFlowOrchestrator[] = [];
}

export enum OrchestratorSystem {
  Unknown = "",
  Ansible = "Ansible",
  Terraform = "Terraform",
  TerraformPlan = "Terraform-Plan",
  Helm = "Helm",
}

export function getOrchestratorSystem(type: string) {
  const lower = type.toLowerCase();
  const keys = Object.values(OrchestratorSystem);
  const i = keys.find(k => lower === k.toLowerCase());
  if (i) {
    if (i === OrchestratorSystem.TerraformPlan) {
      return OrchestratorSystem.Terraform;
    }
    return i;
  }
  return OrchestratorSystem.Unknown;
}

export class OrchestratorFile {
  type: string;
  name: string;
  size: string;
  hashType: string;
  hash: string;
  fileName: string;
  link: string;
}
