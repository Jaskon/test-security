export enum Provider {
  Jira = "jira",
  Monday = "monday",
}

export interface Ticket {
  id: string;
  ticketId: string;
  link: string;
  issueId: string;
  provider: Provider;
  key: string;
  createdBy: string;
  aggItemsIds: string[];
  detach?: boolean;
}
