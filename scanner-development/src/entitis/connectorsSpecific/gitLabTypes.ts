export interface GitLabBlame {
  commit: GitLabBlameCommit;
  lines: string[];
}

export interface GitLabBlameCommit {
  id: string;
  parent_ids: string[];
  message: string;
  authored_date: string;
  author_name: string;
  author_email: string;
  committed_date: string;
  committer_name: string;
  committer_email: string;
}

export interface GitLabPipeline {
  id: number;
  project_id: number;
  sha: string;
  ref: string;
  status: string;
  source: string;
  created_at: string;
  updated_at: string;
  web_url: string;
}

export interface GitLabSecurityVulnerability {
  id: any;
  report_type: string;
  name: string;
  severity: string;
  confidence: string;
  scanner: Scanner;
  identifiers: Identifier[];
  project_fingerprint: string;
  uuid: string;
  create_jira_issue_url: any;
  false_positive: boolean;
  create_vulnerability_feedback_issue_path: string;
  create_vulnerability_feedback_merge_request_path: string;
  create_vulnerability_feedback_dismissal_path: string;
  project: Project;
  dismissal_feedback: any;
  issue_feedback: any;
  merge_request_feedback: any;
  description: string;
  links: any[];
  location: Location;
  remediations: any[];
  solution: any;
  evidence: any;
  request: any;
  response: any;
  evidence_source: any;
  supporting_messages: any[];
  assets: any[];
  details: Details;
  state: string;
  scan: Scan;
  blob_path: string;
}

export interface Details {}

export interface Identifier {
  external_type: string;
  external_id: string;
  name: string;
  url: string;
}

export interface Location {
  file: string;
  start_line: number;
  end_line: number;
}

export interface Project {
  id: number;
  name: string;
  full_path: string;
  full_name: string;
}

export interface Scan {
  type: string;
  status: string;
  start_time: string;
  end_time: string;
}

export interface Scanner {
  external_id: string;
  name: string;
  vendor: string;
}

//
// Gitlab Repo definition
//
export interface GitlabRepository {
  id: number;
  description: string;
  name: string;
  name_with_namespace: string;
  path: string;
  path_with_namespace: string;
  created_at: string;
  default_branch: string;
  tag_list: any[];
  topics: any[];
  ssh_url_to_repo: string;
  http_url_to_repo: string;
  web_url: string;
  readme_url: string;
  avatar_url: null;
  forks_count: number;
  star_count: number;
  last_activity_at: string;
  namespace: Namespace;
  container_registry_image_prefix: string;
  _links: Links;
  packages_enabled: boolean;
  empty_repo: boolean;
  archived: boolean;
  visibility: string;
  resolve_outdated_diff_discussions: boolean;
  container_expiration_policy: ContainerExpirationPolicy;
  issues_enabled: boolean;
  merge_requests_enabled: boolean;
  wiki_enabled: boolean;
  jobs_enabled: boolean;
  snippets_enabled: boolean;
  container_registry_enabled: boolean;
  service_desk_enabled: boolean;
  service_desk_address: string;
  can_create_merge_request_in: boolean;
  issues_access_level: string;
  repository_access_level: string;
  merge_requests_access_level: string;
  forking_access_level: string;
  wiki_access_level: string;
  builds_access_level: string;
  snippets_access_level: string;
  pages_access_level: string;
  operations_access_level: string;
  analytics_access_level: string;
  container_registry_access_level: string;
  security_and_compliance_access_level: string;
  emails_disabled: null;
  shared_runners_enabled: boolean;
  lfs_enabled: boolean;
  creator_id: number;
  import_url: null;
  import_type: null;
  import_status: string;
  open_issues_count: number;
  ci_default_git_depth: number;
  ci_forward_deployment_enabled: boolean;
  ci_job_token_scope_enabled: boolean;
  public_jobs: boolean;
  build_timeout: number;
  auto_cancel_pending_pipelines: string;
  build_coverage_regex: null;
  ci_config_path: string;
  shared_with_groups: any[];
  only_allow_merge_if_pipeline_succeeds: boolean;
  allow_merge_on_skipped_pipeline: null;
  restrict_user_defined_variables: boolean;
  request_access_enabled: boolean;
  only_allow_merge_if_all_discussions_are_resolved: boolean;
  remove_source_branch_after_merge: boolean;
  printing_merge_request_link_enabled: boolean;
  merge_method: string;
  squash_option: string;
  enforce_auth_checks_on_uploads: boolean;
  suggestion_commit_message: null;
  merge_commit_template: null;
  squash_commit_template: null;
  auto_devops_enabled: boolean;
  auto_devops_deploy_strategy: string;
  autoclose_referenced_issues: boolean;
  keep_latest_artifact: boolean;
  runner_token_expiration_interval: null;
  approvals_before_merge: number;
  mirror: boolean;
  external_authorization_classification_label: string;
  marked_for_deletion_at: null;
  marked_for_deletion_on: null;
  requirements_enabled: boolean;
  requirements_access_level: string;
  security_and_compliance_enabled: boolean;
  compliance_frameworks: any[];
  issues_template: null;
  merge_requests_template: null;
  merge_pipelines_enabled: boolean;
  merge_trains_enabled: boolean;
  permissions: Permissions;
}

export interface Links {
  self: string;
  issues: string;
  merge_requests: string;
  repo_branches: string;
  labels: string;
  events: string;
  members: string;
  cluster_agents: string;
}

export interface ContainerExpirationPolicy {
  cadence: string;
  enabled: boolean;
  keep_n: number;
  older_than: string;
  name_regex: string;
  name_regex_keep: null;
  next_run_at: string;
}

export interface Namespace {
  id: number;
  name: string;
  path: string;
  kind: string;
  full_path: string;
  parent_id: number;
  avatar_url: null;
  web_url: string;
}

export interface Permissions {
  project_access: null;
  group_access: null;
}

//
// Gitlab Job type
//
export interface GitLabJob {
  id: number;
  status: string;
  stage: string;
  name: string;
  ref: string;
  tag: boolean;
  coverage: null;
  allow_failure: boolean;
  created_at: string;
  started_at: string;
  finished_at: string;
  duration: number;
  queued_duration: number;
  user: User;
  commit: Commit;
  pipeline: Pipeline;
  failure_reason?: string;
  web_url: string;
  artifacts: Artifact[];
  runner: Runner;
  artifacts_expire_at: null;
  tag_list: any[];
}

export interface Artifact {
  file_type: string;
  size: number;
  filename: string;
  file_format: null;
}

export interface Commit {
  id: string;
  short_id: string;
  created_at: string;
  parent_ids: string[];
  title: string;
  message: string;
  author_name: string;
  author_email: string;
  authored_date: string;
  committer_name: string;
  committer_email: string;
  committed_date: string;
  trailers: Trailers;
  web_url: string;
}

export interface Trailers {}

export interface Pipeline {
  id: number;
  iid: number;
  project_id: number;
  sha: string;
  ref: string;
  status: string;
  source: string;
  created_at: string;
  updated_at: string;
  web_url: string;
}

export interface Runner {
  id: number;
  description: string;
  ip_address: string;
  active: boolean;
  paused: boolean;
  is_shared: boolean;
  runner_type: string;
  name: string;
  online: boolean;
  status: string;
}

export interface User {
  id: number;
  username: string;
  name: string;
  state: string;
  avatar_url: string;
  web_url: string;
  created_at: string;
  bio: string;
  location: null;
  public_email: string;
  skype: string;
  linkedin: string;
  twitter: string;
  website_url: string;
  organization: null;
  job_title: string;
  pronouns: null;
  bot: boolean;
  work_information: null;
  followers: number;
  following: number;
  local_time: string;
}

//
// Gitlab Job type
//
export interface GitLabJob {
  id: number;
  status: string;
  stage: string;
  name: string;
  ref: string;
  tag: boolean;
  coverage: null;
  allow_failure: boolean;
  created_at: string;
  started_at: string;
  finished_at: string;
  duration: number;
  queued_duration: number;
  user: User;
  commit: Commit;
  pipeline: Pipeline;
  failure_reason?: string;
  web_url: string;
  artifacts: Artifact[];
  runner: Runner;
  artifacts_expire_at: null;
  tag_list: any[];
}

export interface Artifact {
  file_type: string;
  size: number;
  filename: string;
  file_format: null;
}

export interface Commit {
  id: string;
  short_id: string;
  created_at: string;
  parent_ids: string[];
  title: string;
  message: string;
  author_name: string;
  author_email: string;
  authored_date: string;
  committer_name: string;
  committer_email: string;
  committed_date: string;
  trailers: Trailers;
  web_url: string;
}

export interface Trailers {}

export interface Pipeline {
  id: number;
  iid: number;
  project_id: number;
  sha: string;
  ref: string;
  status: string;
  source: string;
  created_at: string;
  updated_at: string;
  web_url: string;
}

export interface Runner {
  id: number;
  description: string;
  ip_address: string;
  active: boolean;
  paused: boolean;
  is_shared: boolean;
  runner_type: string;
  name: string;
  online: boolean;
  status: string;
}

export interface User {
  id: number;
  username: string;
  name: string;
  state: string;
  avatar_url: string;
  web_url: string;
  created_at: string;
  bio: string;
  location: null;
  public_email: string;
  skype: string;
  linkedin: string;
  twitter: string;
  website_url: string;
  organization: null;
  job_title: string;
  pronouns: null;
  bot: boolean;
  work_information: null;
  followers: number;
  following: number;
  local_time: string;
}

export declare namespace GitLab {
  export interface MergeRequest {
    state: string; //"merged"
    created_at: string;
    merged_by: Author;
    author: Author;
    reviewers: Author[];
    sha: string;
    merge_commit_sha: string;
    squash_commit_sha: string;
    web_url: string;
    id: string;
    iid: string;
    description: string;
    title: string;
    merged_at: string;
    merge_user: Author;
    source_branch: string;
    target_branch: string;
  }

  export interface Author {
    id: number;
    username: string;
    name: string;
  }

  export interface MergeRequestDetailed extends MergeRequest {
    changes_count: string;
  }

  export interface CompareRequestDiff {
    old_path: string;
    new_path: string;
    a_mode: string;
    b_mode: string;
    diff: string;
    new_file: boolean;
    renamed_file: boolean;
    deleted_file: boolean;
  }
}
