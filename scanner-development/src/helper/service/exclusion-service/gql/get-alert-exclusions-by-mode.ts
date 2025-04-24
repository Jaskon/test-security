import { gql } from "graphql-request";

export default gql`
  query GetAlertExclusionsByMode($orgId: String, $exclusionMode: ExclusionMode) {
    getAlertExclusionsByMode(orgId: $orgId, exclusionMode: $exclusionMode) {
      exclusions {
        exclusionType
        exclusionId
        exclusionScope
        appName
        appId
        policyId
        exclusionMode
        expiredAt
        isActive
        oxIssueId
        match {
          key
          value
          level
        }
      }
    }
  }
`;
