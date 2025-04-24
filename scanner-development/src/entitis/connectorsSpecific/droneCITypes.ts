export interface DroneCIClient {
  getToken(): Promise<unknown>;
  getSelf(): Promise<DroneUser>;
  recentBuilds(): Promise<unknown>;
  syncRepos(): Promise<unknown>;
  updateSelf(): Promise<unknown>;
  selfRepos(params?: { latest?: boolean }): Promise<DroneRepo[]>;
  getRepos(): Promise<unknown>;
  getRepo(): Promise<unknown>;
  enableRepo(): Promise<unknown>;
  disableRepo(): Promise<unknown>;
  chownRepo(): Promise<unknown>;
  repairRepo(): Promise<unknown>;
  updateRepo(): Promise<unknown>;
  incompleteBuilds(): Promise<unknown>;
  getBuilds(owner: string, repo: string, page?: number, limit?: number): Promise<DroneBaseBuild[]>;
  purgeBuilds(): Promise<unknown>;
  latestBuild(): Promise<unknown>;
  getBuild(owner: string, repo: string, number: number): Promise<DroneExtendedBuild>;
  retryBuild(): Promise<unknown>;
  cancelBuild(): Promise<unknown>;
  promoteBuild(): Promise<unknown>;
  rollbackBuild(): Promise<unknown>;
  declineBuild(): Promise<unknown>;
  approveBuild(): Promise<unknown>;
  triggerBuild(): Promise<unknown>;
  getLogs(owner: string, repo: string, number: number, stage: number, step: number): Promise<DroneBuildStepLog[]>;
  deleteLogs(): Promise<unknown>;
  getSecrets(): Promise<unknown>;
  getSecret(): Promise<unknown>;
  deleteSecret(): Promise<unknown>;
  updateSecret(): Promise<unknown>;
  createSecret(): Promise<unknown>;
  encryptSecret(): Promise<unknown>;
  signConfig(): Promise<unknown>;
  getCrons(): Promise<unknown>;
  getCron(): Promise<unknown>;
  executeCron(): Promise<unknown>;
  deleteCron(): Promise<unknown>;
  updateCron(): Promise<unknown>;
  createCron(): Promise<unknown>;
  getCollaborators(): Promise<unknown>;
  getCollaborator(): Promise<unknown>;
  deleteCollaborator(): Promise<unknown>;
  getUsers(): Promise<unknown>;
  getUser(): Promise<unknown>;
  deleteUser(): Promise<unknown>;
  updateUser(): Promise<unknown>;
  createUser(): Promise<unknown>;
  userRepos(): Promise<unknown>;
  getAllGlobalSecrets(): Promise<unknown>;
  getGlobalSecrets(): Promise<unknown>;
  getGlobalSecret(): Promise<unknown>;
  deleteGlobalSecret(): Promise<unknown>;
  updateGlobalSecret(): Promise<unknown>;
  createGlobalSecret(): Promise<unknown>;
  getQueue(): Promise<unknown>;
  resumeQueue(): Promise<unknown>;
  pauseQueue(): Promise<unknown>;
  getSystemStats(): Promise<unknown>;
}

export interface DroneUser {
  login: string;
  email: string;
  avatar: string;
  machine: boolean;
  admin: boolean;
  active: boolean;
  syncing: boolean;
  synced: number; // unix timestamp
  created: number; // unix timestamp
  updated: number; // unix timestamp
  last_login: number; // unix timestamp
}

export interface DroneRepo {
  active: boolean;
  archived: boolean;
  auto_cancel_pull_requests: boolean;
  auto_cancel_pushes: boolean;
  auto_cancel_running: boolean;
  config_path: string;
  counter: number;
  created: number; // unix timestamp
  default_branch: string;
  git_http_url: string;
  git_ssh_url: string;
  id: number;
  ignore_forks: boolean;
  ignore_pull_requests: boolean;
  link: string;
  name: string;
  namespace: string;
  private: boolean;
  protected: boolean;
  scm: string;
  slug: string;
  synced: number; // unix timestamp
  timeout: number;
  trusted: boolean;
  uid: string;
  user_id: number;
  version: number;
  updated: number; // unix timestamp
  visibility: string;
}

export interface DroneBaseBuild {
  id: number;
  repo_id: number;
  trigger: string;
  number: number;
  parent: number;
  status: "success" | "failure";
  event: string;
  action: string;
  link: string;
  timestamp: number;
  message: string;
  before: string; // commit sha before the build was triggered
  after: string; // commit sha that triggered the build
  ref: string;
  source_repo: string;
  source: string;
  target: string;
  author_login: string;
  author_name: string;
  author_email: string;
  author_avatar: string;
  sender: string;
  started: number; // unix timestamp
  finished: number; // unix timestamp
  created: number; // unix timestamp
  updated: number; // unix timestamp
  version: number;
}

export interface DroneBuildStep {
  id: number;
  step_id: number;
  number: number;
  name: string;
  status: "success" | "failure" | "skipped";
  exit_code: number;
  started: number;
  stopped: number;
  version: number;
  image: string;
  depends_on: string[];
}

export interface DroneBuildStage {
  id: number;
  repo_id: number;
  build_id: number;
  number: number;
  name: string;
  kind: string;
  type: string;
  status: string;
  errignore: boolean;
  exit_code: number;
  machine: string;
  os: string;
  arch: string;
  started: number;
  stopped: number;
  created: number;
  updated: number;
  version: number;
  on_success: boolean;
  on_failure: boolean;
  steps: DroneBuildStep[];
}

export interface DroneExtendedBuild extends DroneBaseBuild {
  stages: DroneBuildStage[];
}

export interface DroneBuildStepLog {
  pos: number;
  out: string;
  time: number;
}
