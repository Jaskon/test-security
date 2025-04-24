import { gql } from "graphql-request";
import { UniqueIssue } from "./get-unique-issues-query";

export const getCurrentFullScanIssuesIds = gql`
  query GetCurrentFullScanIssuesIds($orgId: String, $appId: String) {
    getRawIssues(orgId: $orgId, appId: $appId) {
      issueId
    }
  }
`;

export interface GetCurrentFullScanIssuesIds {
  getRawIssues: UniqueIssue[];
}
