export interface GetPullsResponse {
  repository: Repository;
}

export interface Repository {
  pullRequests: PullRequests;
}

export interface PullRequests {
  pageInfo: PageInfo;
  totalCount: number;
  nodes: PullRequestNode[];
}

export interface PageInfo {
  endCursor: string | null;
}

export interface PullRequestNode {
  createdAt: string;
  updatedAt: string;
  mergedAt: string;
  url: string;
  body: string;
  title: string;
  number: number;
  baseRefName: string;
  baseRefOid: string;
  headRefName: string;
  headRefOid: string;
  author: Author;
  mergeCommit: MergeCommit;
  headRepositoryOwner: HeadRepositoryOwner;
  reviews: PullReqiestReviewNodes;
}

export interface Author {
  login: string;
}

export interface MergeCommit {
  oid: string;
}

export interface HeadRepositoryOwner {
  id: string;
  login: string;
}

export interface PullReqiestReviewNodes {
  nodes: PullRequestReviewNode[];
}

export interface PullRequestReviewNode {
  state: string;
  author: Author;
}
