import { gql } from "graphql-request";
export const getAllPrs = gql`
  query GetAllPullRequests {
    getAllPullRequests {
      prs {
        issueId
        prId
        prURL
        # createdBy // to be added after slack deployed
      }
    }
  }
`;
