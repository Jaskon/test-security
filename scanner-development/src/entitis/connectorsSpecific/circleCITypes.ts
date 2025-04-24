// Example of CircleCI Projects
// [
// 	{
// 		"reponame": "ForensicsCollector",
// 		"username": "kostya253",
// 		"vcs_type": "github",
// 		"vcs_url": "https://github.com/kostya253/ForensicsCollector",
// 		"default_branch": "master"
// 	},
// 	{
// 		"reponame": "NodeFun",
// 		"username": "kostya253",
// 		"vcs_type": "github",
// 		"vcs_url": "https://github.com/kostya253/NodeFun",
// 		"default_branch": "master"
// 	}
// ]

export interface CircleCIProjects {
  reponame: string;
  username: string;
  vcs_type: string;
  vcs_url: string;
  branch: string;
}

// {
//     "compare": null,
//     "previous_successful_build": null,
//     "build_parameters": {},
//     "oss": true,
//     "all_commit_details_truncated": false,
//     "committer_date": "2021-10-28T05:26:38.000Z",
//     "body": "Add .circleci/config.yml",
//     "usage_queued_at": "2021-10-28T05:26:40.005Z",
//     "context_ids": [],
//     "fail_reason": null,
//     "retry_of": null,
//     "reponame": "ForensicsCollector",
//     "ssh_users": [],
//     "build_url": "https://circleci.com/gh/kostya253/ForensicsCollector/2",
//     "parallel": 1,
//     "failed": false,
//     "branch": "master",
//     "username": "kostya253",
//     "author_date": "2021-10-28T05:26:38.000Z",
//     "why": "github",
//     "user": {
//         "is_user": true,
//         "login": "kostya253",
//         "avatar_url": "https://avatars.githubusercontent.com/u/14079798?v=4",
//         "name": "Kostya Zhuruev",
//         "vcs_type": "github",
//         "id": 14079798
//     },
//     "vcs_revision": "464565333eb5d3048ad1d5fe0968cbe9bf51a440",
//     "workflows": {
//         "job_name": "say-hello",
//         "job_id": "da4009ed-0eb0-4399-ad5b-9204aa1635e3",
//         "workflow_id": "7d6503da-d815-4199-bb06-1f6bf772fe20",
//         "workspace_id": "7d6503da-d815-4199-bb06-1f6bf772fe20",
//         "upstream_job_ids": [],
//         "upstream_concurrency_map": {},
//         "workflow_name": "say-hello-workflow"
//     },
//     "vcs_tag": null,
//     "build_num": 2,
//     "infrastructure_fail": false,
//     "committer_email": "noreply@github.com",
//     "has_artifacts": true,
//     "previous": null,
//     "status": "success",
//     "committer_name": "GitHub",
//     "retries": null,
//     "subject": "Merge pull request #1 from kostya253/circleci-project-setup",
//     "vcs_type": "github",
//     "timedout": false,
//     "dont_build": null,
//     "lifecycle": "finished",
//     "stop_time": "2021-10-28T05:26:45.419Z",
//     "ssh_disabled": false,
//     "build_time_millis": 2795,
//     "picard": null,
//     "circle_yml": null,
//     "messages": [],
//     "is_first_green_build": false,
//     "job_name": null,
//     "start_time": "2021-10-28T05:26:42.624Z",
//     "canceler": null,
//     "all_commit_details": [
//         {
//             "committer_date": "2021-10-24T13:39:00.000Z",
//             "body": "",
//             "branch": "master",
//             "author_date": "2021-10-24T13:39:00.000Z",
//             "committer_email": "kostya253@gmail.com",
//             "commit": "279473eb4255ad1cd4466b1c2757fa5cc3132a61",
//             "committer_login": "kostya253",
//             "committer_name": "Kostya Zhuruev",
//             "subject": "Add .circleci/config.yml",
//             "commit_url": "https://github.com/kostya253/ForensicsCollector/commit/279473eb4255ad1cd4466b1c2757fa5cc3132a61",
//             "author_login": "kostya253",
//             "author_name": "Kostya Zhuruev",
//             "author_email": "kostya253@gmail.com"
//         },
//         {
//             "committer_date": "2021-10-28T05:26:38.000Z",
//             "body": "Add .circleci/config.yml",
//             "branch": "master",
//             "author_date": "2021-10-28T05:26:38.000Z",
//             "committer_email": "noreply@github.com",
//             "commit": "464565333eb5d3048ad1d5fe0968cbe9bf51a440",
//             "committer_login": "web-flow",
//             "committer_name": "GitHub",
//             "subject": "Merge pull request #1 from kostya253/circleci-project-setup",
//             "commit_url": "https://github.com/kostya253/ForensicsCollector/commit/464565333eb5d3048ad1d5fe0968cbe9bf51a440",
//             "author_login": "kostya253",
//             "author_name": "Kostya Zhuruev",
//             "author_email": "kostya253@gmail.com"
//         }
//     ],
//     "platform": "1.0",
//     "outcome": "success",
//     "vcs_url": "https://github.com/kostya253/ForensicsCollector",
//     "author_name": "Kostya Zhuruev",
//     "node": null,
//     "queued_at": "2021-10-28T05:26:40.100Z",
//     "canceled": false,
//     "author_email": "kostya253@gmail.com"
// }

export interface CircleCIJobs {
  compare: null;
  previous_successful_build: null;
  build_parameters: BuildParameters;
  oss: boolean;
  all_commit_details_truncated: boolean;
  committer_date: null | string;
  body: null | string;
  usage_queued_at: string;
  context_ids: any[];
  fail_reason: null;
  retry_of: null;
  reponame: string;
  ssh_users: any[];
  build_url: string;
  parallel: number;
  failed: boolean;
  branch: string;
  username: string;
  author_date: null | string;
  why: string;
  user: User;
  vcs_revision: string;
  workflows: Workflows;
  vcs_tag: null;
  build_num: number;
  infrastructure_fail: boolean;
  committer_email: null | string;
  has_artifacts: boolean;
  previous: Previous | null;
  status: string;
  committer_name: null | string;
  retries: null;
  subject: null | string;
  vcs_type: string;
  timedout: boolean;
  dont_build: null;
  lifecycle: string;
  stop_time: string;
  ssh_disabled: boolean;
  build_time_millis: number;
  picard: null;
  circle_yml: null;
  messages: any[];
  is_first_green_build: boolean;
  job_name: null;
  start_time: string;
  canceler: null;
  all_commit_details: { [key: string]: string }[];
  platform: string;
  outcome: string;
  vcs_url: string;
  author_name: null | string;
  node: null;
  queued_at: string;
  canceled: boolean;
  author_email: null | string;
}

export interface BuildParameters {}

export interface Previous {
  build_num: number;
  status: string;
  build_time_millis: number;
}

export interface User {
  is_user: boolean;
  login: string;
  avatar_url: string;
  name: string;
  vcs_type: string;
  id: number;
}

export interface Workflows {
  job_name: string;
  job_id: string;
  workflow_id: string;
  workspace_id: string;
  upstream_job_ids: any[];
  upstream_concurrency_map: BuildParameters;
  workflow_name: string;
}
