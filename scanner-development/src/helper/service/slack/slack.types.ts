export interface SlackNotification {
  issueId: string;
  channelName: string;
  timestamp: string;
  user: string;
  createdBy: string
}
export interface getSlackNotificationsRes {
  res: {
    notifications: SlackNotification[];
  };
}
