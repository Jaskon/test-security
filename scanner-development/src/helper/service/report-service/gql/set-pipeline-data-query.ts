import { gql } from "graphql-request";

export default gql`
  mutation SetPipelineData($orgId: String, $appId: String!, $setPipelineDataInput: SetPipelineDataInput!) {
    setPipelineData(appId: $appId, setPipelineDataInput: $setPipelineDataInput, orgId: $orgId) {
      appId
      acknowledged
    }
  }
`;
