import { gql } from "graphql-request";

export const updateDevelopersCount = gql`
  mutation UpdateDevelopersCount($updateDevelopersCountInput: UpdateDevelopersCountInput!, $orgId: String) {
    updateDevelopersCount(updateDevelopersCountInput: $updateDevelopersCountInput, orgId: $orgId)
  }
`;
