import { gql, GraphQLClient } from "graphql-request";
import { isDevelopment } from "../../helper/envUtils";
import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";
import { GetPullsResponse, PullRequestNode } from "./github-graphql.types";
import { GithubRateLimiter } from "./github-rate-limiter";

const logger = loggerImport.getDebugLogger();

export class GithubGraphQL {
  private readonly client: GraphQLClient;
  private readonly rateLimiter: GithubRateLimiter;
  private readonly PR_TIME_LIMIT_MS = isDevelopment() ? 1000 * 60 * 60 * 24 * 365 : 1000 * 60 * 60 * 24 * 30 * 60; // 1 year in dev, otherwise 6 months

  constructor(githubToken: string) {
    this.client = new GraphQLClient("https://api.github.com/graphql", {
      headers: { authorization: `Bearer ${githubToken}` },
      timeout: 1000 * 60 * 45,
    });
    this.rateLimiter = new GithubRateLimiter();
  }

  async getPullsAndReviews(
    { owner, repository, defaultBranch }: PullsAndReviewsInput,
    nextPage: string | null = null,
    retry = 0,
  ): Promise<PullRequestNode[]> {
    try {
      const pullRequests: PullRequestNode[] = [];
      const { data } = await this.rateLimiter.runRateLimitedQuery(() =>
        this.client.rawRequest<GetPullsResponse>(pullsAndReviewsQuery, { owner, repository, defaultBranch, nextPage }),
      );
      StatesHelper.Instance.scanInfoStats.githubGraphqlQueries++;
      const sixMonthsAgo = new Date(Date.now() - this.PR_TIME_LIMIT_MS);
      const pulls = data.repository?.pullRequests?.nodes?.filter(pull => new Date(pull.updatedAt) > sixMonthsAgo) || [];
      pullRequests.push(...pulls);
      if (pulls.length < 100) {
        return pullRequests;
      }
      const nextCursor = data.repository.pullRequests.pageInfo.endCursor;
      if (nextCursor) {
        const otherPullRequests = await this.getPullsAndReviews({ owner, repository, defaultBranch }, nextCursor);
        pullRequests.push(...otherPullRequests);
      }
      return pullRequests;
    } catch (err) {
      retry = retry + 1;
      if (err.code === "ECONNRESET" && retry < 3) {
        return this.getPullsAndReviews({ owner, repository, defaultBranch }, nextPage, retry);
      }
      logger.error(`Failed to get pulls for ${repository}: ${JSON.stringify(err)} (${retry})`);
      return [];
    }
  }

  async getAlerts({ owner, repository }: RepoInput, nextPage: string | null = null, retry = 0): Promise<any[]> {
    try {
      const allAlerts: any[] = [];
      const { data } = await this.rateLimiter.runRateLimitedQuery(() =>
        this.client.rawRequest<any>(getDependabotAlertsQuery, {
          owner,
          repository,
          nextPage,
        }),
      );
      const alerts = data.repository.vulnerabilityAlerts.nodes || [];
      allAlerts.push(...alerts);
      const nextCursor = data.repository.vulnerabilityAlerts.pageInfo.endCursor;
      if (nextCursor) {
        const otherAlerts = await this.getAlerts({ owner, repository }, nextCursor);
        allAlerts.push(...otherAlerts);
      }
      return allAlerts;
    } catch (err) {
      if (err.code === "ECONNRESET" && retry < 3) {
        return this.getAlerts({ owner, repository }, nextPage, retry + 1);
      }
      logger.error(`Failed to get alerts for ${repository}: ${JSON.stringify(err)} (${retry})`);
      return [];
    }
  }

  async getOpenPullRequestForBranches(
    owner: string,
    repository: string,
    sourceBranch: string,
    targetBranch: string,
  ): Promise<Pick<PullRequestNode, "number" | "url"> | null> {
    try {
      const { data } = await this.rateLimiter.runRateLimitedQuery(() =>
        this.client.rawRequest<GetPullsResponse>(getOpenPullRequestForBranchesQuery, { owner, repository, sourceBranch, targetBranch }),
      );
      StatesHelper.Instance.scanInfoStats.githubGraphqlQueries++;
      return data.repository?.pullRequests?.nodes[0] ?? null;
    } catch (err) {
      logger.error(`[getOpenPullRequestForBranches] failed for ${repository}: ${JSON.stringify(err)}`);
      return null;
    }
  }
}

interface RepoInput {
  owner: string;
  repository: string;
}

interface PullsAndReviewsInput extends RepoInput {
  defaultBranch: string;
}

const pullsAndReviewsQuery = gql`
  query GetPulls($owner: String!, $repository: String!, $defaultBranch: String!, $nextPage: String) {
    repository(owner: $owner, name: $repository) {
      pullRequests(
        first: 100
        states: MERGED
        after: $nextPage
        baseRefName: $defaultBranch
        orderBy: { direction: DESC, field: UPDATED_AT }
      ) {
        pageInfo {
          endCursor
        }
        totalCount
        nodes {
          createdAt
          updatedAt
          mergedAt
          url
          body
          title
          number
          baseRefName
          baseRefOid
          headRefName
          headRefOid
          author {
            login
          }
          mergeCommit {
            oid
          }
          headRepositoryOwner {
            id
            login
          }
          reviews(first: 100, states: [APPROVED, CHANGES_REQUESTED]) {
            nodes {
              state
              author {
                login
              }
            }
          }
        }
      }
    }
  }
`;

const getOpenPullRequestForBranchesQuery = gql`
  query GetOpenPullRequestForBranches($owner: String!, $repository: String!, $sourceBranch: String!, $targetBranch: String!) {
    repository(owner: $owner, name: $repository) {
      pullRequests(
        first: 1
        states: OPEN
        baseRefName: $targetBranch
        headRefName: $sourceBranch
        orderBy: { direction: DESC, field: UPDATED_AT }
      ) {
        totalCount
        nodes {
          url
          number
          title
          baseRefName
          headRefName
        }
      }
    }
  }
`;

const getDependabotAlertsQuery = gql`
  query GetDependabotAlerts($owner: String!, $repository: String!, $nextPage: String) {
    repository(owner: $owner, name: $repository) {
      vulnerabilityAlerts(first: 100, after: $nextPage) {
        pageInfo {
          endCursor
        }
        nodes {
          state
          createdAt
          dismissedAt
          dismissReason
          number
          vulnerableManifestFilename
          vulnerableManifestPath
          vulnerableRequirements
          dismisser {
            email
          }
          securityVulnerability {
            firstPatchedVersion {
              identifier
            }
            package {
              name
              ecosystem
            }
            advisory {
              description
              cvss {
                score
                vectorString
              }
              cwes(first: 10) {
                nodes {
                  cweId
                  name
                  description
                }
              }
              origin
              permalink
              severity
              summary
              updatedAt
              withdrawnAt
              identifiers {
                type
                value
              }
            }
            vulnerableVersionRange
            updatedAt
            severity
          }
        }
      }
    }
  }
`;
