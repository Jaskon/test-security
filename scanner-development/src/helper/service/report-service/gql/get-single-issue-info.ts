import { gql } from "graphql-request";

export const getSingleIssueQuery = gql`
  query GetSingleIssueInfo($getSingleIssueInput: SingleIssueInput) {
    getSingleIssueInfo(getSingleIssueInput: $getSingleIssueInput) {
      policy {
        name
      }
      aggregations {
        type
        items {
          sha
        }
      }
    }
  }
`;
