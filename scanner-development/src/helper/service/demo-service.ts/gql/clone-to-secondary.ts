import { gql } from "graphql-request";

export default gql`
  query CloneToSecondary($orgId: String, $scanId: String!) {
    cloneToSecondary(orgId: $orgId, scanId: $scanId) {
      db
      scanId
    }
  }
`;
