export interface GetAllPullRequestsRes {
  getAllPullRequests: {
    prs: PullRequest[];
  };
}
export interface PullRequest {
  issueId: string;
  prId: string;
  prURL: string;
  createdBy: string;
}
export interface PRDeatils {
  sourceControlType: string;
  issueId: string;
  appId: string;
  repo: string;
  prId: string;
  prURL: string;
  prBranchName: string;
  commitMessage?: string;
  commiter?: string;
  comment?: string;
  date?: Date;
  prTitle?: string;
  prBody?: string;
  prStatus?: string;
  prApprover?: string;
  prReviewer?: string;
  prMergeTime?: Date;
}
