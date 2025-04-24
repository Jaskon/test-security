import { gql } from "graphql-request";

export const getAllTicketsQueryDevFlag = gql`
  query GetAllTickets($orgId: String) {
    getAllTickets(orgId: $orgId) {
      id
      ticketId
      link
      issueId
      provider
      key
      aggItemsIds
    }
  }
`;
