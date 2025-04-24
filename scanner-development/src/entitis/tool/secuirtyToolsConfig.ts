export interface ToolConfig {
  fileNameAutomaticallyCreated?: string;
  name: string;
  oxToolName: string;
  fileNameOutput: string;
  command: string;
  severityConfigName: string;
  nameForExternalService: string;
  disableByOx: boolean;
  localSshToolName: string;
  env_sqs_url: string;
  env_redis_url: string;
  monoRepoCommand: string;
  injectToCommand: string;
  critical: boolean;
  supportedTypes: string[];
  defaultSeverity: string;
  onPrem: string;
  onPremMonoRepo: string;
  envPort: string;
  envHost: string;
  defaultType: string;
  dynamicIdentifyType: boolean;
  timeout: number;
  scanGitHistory: boolean;
  pullingFromDisk: boolean;
  enableAlways: boolean;
  type: string;
  /** Always send full code, and not leanCode */
  fullCodeOverride?: boolean;
}

export interface ToolCommand {
  jsonVersion: string;
  usage: string;
  tools: ToolConfig[];
}
