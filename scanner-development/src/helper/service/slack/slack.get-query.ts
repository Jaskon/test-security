import { gql } from "graphql-request";

export const getSlackQuery = gql`
  query Get($orgId: String) {
    res: get(orgId: $orgId) {
      notifications {
        issueId
        channelName
        timestamp
        # user // to be added after slack deployed
        # createdBy // to be added after slack deployed
      }
    }
  }
`;
