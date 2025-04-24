import { gql } from "graphql-request";
import { UniqueIssue } from "./get-unique-issues-query";

export const getRawIssuesQuery = gql`
  query GetRawIssues($orgId: String) {
    getRawIssues(orgId: $orgId) {
      issueId
      createdAt
      aggregatedItemsId
    }
  }
`;

export interface GetRawIssuesRes {
  getRawIssues: UniqueIssue[];
}
