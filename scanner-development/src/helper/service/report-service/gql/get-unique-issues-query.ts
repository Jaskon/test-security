import { gql } from "graphql-request";

export const getUniqueIssuesQuery = gql`
  query GetUniqueIssues($orgId: String) {
    getUniqueIssues(orgId: $orgId) {
      issueId
      createdAt
      aggregatedItemsId
      comment
      severity
      overrideSeverity
      originalSeverity
      isFalsePositive
      aggFileNames
      lastIssueSeenDate
      sDate
      aggregationsCount
      increasedAt
      decreasedAt
      newDate
      prevSeverity
    }
  }
`;

export interface GetUniqueIssuesRes {
  getUniqueIssues: UniqueIssue[];
}

export interface UniqueIssue {
  originalSeverity: number;
  overrideSeverity: boolean;
  issueId: string;
  newDate: Date;
  createdAt?: string;
  aggregatedItemsId?: string;
  comment?: string;
  severity?: number;
  isFalsePositive?: boolean;
  aggFileNames?: string[];
  lastIssueSeenDate?: Date;
  sDate?: Date;
  aggregationsCount?: number;
  increasedAt?: Date;
  decreasedAt?: Date;
  prevSeverity?: number;
}
