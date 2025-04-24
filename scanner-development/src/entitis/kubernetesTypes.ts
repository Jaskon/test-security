import { AppFlowKubernetes } from "./applicationsFlowTypes";
import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

export class Kubernetes {
  kubernetesAppFlow: AppFlowKubernetes[] = [];
}

export enum KubernetesSystem {
  Unknown = "General",
  Pod = "Pod",
  Deployment = "Deployment",
  Service = "Service",
  ServiceAccount = "Service Account",
  Secret = "Secret",
  PersistentVolume = "Persistent Volume",
  Ingress = "Ingress",
  CronJob = "Cron Job",
  Cluster = "Cluster",
  ConfigMap = "Config Map",
  PersistentVolumeClaim = "Persistent Volume Claim",
  ClusterRole = "Cluster Role",
  ClusterRoleBinding = "Cluster Role Binding",
  Role = "Role",
  RoleBinding = "Role Binding",
  PriorityClass = "Priority Class",
  ScaledJob = "Scaled Job",
  ScaledObject = "Scaled Object",
  DaemonSet = "Daemon Set",
}

export function getKubernetesSubSystem(type: string) {
  const lower = type.toLowerCase();
  const keys = Object.keys(KubernetesSystem);
  const i = keys.find(k => lower === k.toLowerCase());
  if (i) {
    return i;
  }
  logger.error(`failed get kubernetes sub system for repo info, subType: ${type}`);
  return KubernetesSystem.Unknown;
}

export class KubernetesFile {
  type: string;
  subType: string;
  name: string;
  size: string;
  hashType: string;
  hash: string;
  fileName: string;
  link: string;
}
