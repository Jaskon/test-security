export interface ScannerMessage {
  uuid: string;
  orgID: string;
  orgDisplayName: string;
  command: string;
  localCommand: string;
  rawCommand: string;
  url: string;
  toolName: string;
  repoName: string;
  resultPath: string;
  cloneDir: string;
  timeout: number;
  putInQueueTime: number;
  MessageId?: string;
  copyType: CopyType;
  toolCopyDestination: string;
  isMonoRepoChild: boolean;
  monoRepoChildSubfolder: string;
  shouldAdditionallyScanRootFiles: boolean;
  ignoredSubfolders: string[] | null;
  shouldSkipActiveScanCheck?: boolean;
  shouldSkipLocalCopy?: boolean;
  shouldSkipSSH?: boolean;
  overrideTopic?: string;
}

export enum CopyType {
  All = "all",
  CodeOnly = "code_only",
  GitOnly = "git_only",
  DockerImage = "docker_image",
  LeanCodeOnly = "lean_code_only",
  LeanCodeWithDotGit = "lean_code_and_git",
  LeanCodeDependencyToolsOnly = "lean_code_dependency_tools_only",
  None = "none",
}

export interface ReturnStatus {
  stdout: string;
  stderr: string;
  execErrorCode: number;
  scanStatus: string;
}

export interface ParsingRequest {
  id: string; // Should be 'oxparser'
  uuid: string; // Unique identifier of the parsing collection
  logs: string[]; // Should be "12345678" key set
}
