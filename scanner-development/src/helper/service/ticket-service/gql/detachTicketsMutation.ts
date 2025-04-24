import { gql } from "graphql-request";

export const detachTicketsMutation = gql`
  mutation DetachTickets($orgId: String, $ticketsIds: [String!]!) {
    detachTickets(orgId: $orgId, ticketsIds: $ticketsIds) {
      acknowledge
    }
  }
`;
