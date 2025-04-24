import { gql } from "graphql-request";

export default gql`
  query GetSelectedPoliciesForActiveProfile {
    getSelectedPoliciesForActiveProfile {
      policies {
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
        dataRangeInDays
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
          global
        }
        exclusions
        appInclusions
        countRule
        ignoreMonoRepoChild
      }
    }
  }
`;
