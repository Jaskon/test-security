import { gql } from "graphql-request";
import { Policy } from "../types";
export const getPipelinePoliciesByAppIdQuery = gql`
  query GetPipelinePoliciesByAppId($appId: String, $orgId: String) {
    getPipelinePoliciesByAppId(appId: $appId, orgId: $orgId) {
      id
      policyId
      ruleId
      name
      categoryId
      catId
      system
      description
      detailedDescription
      severity
      selected
      functionName
      exclusionCategory
      displayIssueSeverity
      oscarId
      cwe
      defaultSeverity
      ignoreResolve
      compliance {
        control
        description
        category
        standard
        controlLink
      }
      args {
        id
        name
        label
        tooltip
        type
        value
        range
        multiSelect
        visible
      }
      resources {
        id
        name
        type
      }
      exclusions
      appInclusions
      newIssuesPipelineOptionId
      oldIssuesPipelineOptionId
      countRule
      ignoreMonoRepoChild
    }
  }
`;

export interface GetPipelinePoliciesByAppIdRes {
  getPipelinePoliciesByAppId: Policy[];
}
