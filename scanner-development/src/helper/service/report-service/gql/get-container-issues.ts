import { gql } from "graphql-request";

// query GetIssues($getIssuesInput: IssuesInput) {
//   getIssues(getIssuesInput: $getIssuesInput) {
//       issues {
//           issueId
//           policy {
//               name
//           }
//           aggregations {
//               items {
//                   sha
//               }
//           }

//       }
//       totalIssues totalFilteredIssues totalResolvedIssues offset
//   }
// }

export const getContainerIssuesQuery = gql`
  query GetIssues($getIssuesInput: IssuesInput) {
    getIssues(getIssuesInput: $getIssuesInput) {
      issues {
        issueId
        policy {
          name
        }
        aggregations {
          items {
            sha
          }
        }
      }
      totalIssues
      totalFilteredIssues
      totalResolvedIssues
      offset
    }
  }
`;

export interface GetIssuesRes {
  issues: SingleUniqueIssue[];
}

export interface SingleUniqueIssue {
  issueId: string;
}
