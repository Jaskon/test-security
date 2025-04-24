import { gql } from "graphql-request";
import { Ticket } from "../types";

export const getAllTicketsQuery = gql`
  query GetAllTickets($orgId: String) {
    getAllTickets(orgId: $orgId) {
      id
      ticketId
      link
      issueId
      provider
      key
      aggItemsIds
      detach
      # createdBy // to be added after ticket deployed
    }
  }
`;

export interface GetAllTicketsRes {
  getAllTickets: Ticket[];
}
