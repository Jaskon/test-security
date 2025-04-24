import { gql } from "graphql-request";

export const getAllGPTQuery = gql`
  query GetAll($orgId: String) {
    getAll(orgId: $orgId) {
      gpts {
        createdBy
        issueId
        response
        createdAt
      }
    }
  }
`;
