import loggerImport from "../../../../logger";
import { ServiceBase } from "../../serviceBase";
import { detachTicketsMutation, getAllTicketsQuery, GetAllTicketsRes } from "../gql";
import { Ticket } from "../types";
const logger = loggerImport.getDebugLogger();
const TICKET_SERVICE_HOST_URL = process.env.TICKET_SERVICE_HOST_URL || "";

export class TicketService extends ServiceBase {
  private isFetchedTickets = false;
  private tickets: Ticket[] = [];

  private constructor() {
    super(TICKET_SERVICE_HOST_URL);

    logger.info(`ticket service URL :${TICKET_SERVICE_HOST_URL}`);
  }

  private static _instance: TicketService;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  async getAllTickets(orgId: string) {
    try {
      if (this.isFetchedTickets) {
        return this.tickets;
      }
      this.isFetchedTickets = true;

      await this.setAuthHeader();
      logger.info(`getting tickets orgId: ${orgId}`);
      const res = await this.gqlClient.request<GetAllTicketsRes>(getAllTicketsQuery, { orgId });
      this.tickets = res.getAllTickets;
      logger.info(`finish getting tickets, orgId: ${orgId}`);
      return this.tickets;
    } catch (e) {
      logger.error(`failed to get all tickets: ${orgId}`, e);
    }
    return [];
  }
  async detachedTickets(orgId: string, ticketsIds: string[]) {
    try {
      logger.info(`about to detach tickets: ${JSON.stringify(ticketsIds)}, orgId: ${orgId}`);
      await this.setAuthHeader();
      await this.gqlClient.request(detachTicketsMutation, { orgId, ticketsIds });
      logger.info(`finish to detach tickets, orgId: ${orgId}`);
      return true;
    } catch (e) {
      logger.error(`failed to detach tickets: ${orgId} error: ${e}`);
    }
    return false;
  }
}
