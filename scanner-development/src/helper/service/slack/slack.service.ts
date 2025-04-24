import loggerImport from "../../../logger";
import { ServiceBase } from "../serviceBase";
import { getSlackQuery } from "./slack.get-query";
import { getSlackNotificationsRes } from "./slack.types";

const logger = loggerImport.getDebugLogger();
const SLACK_SERVICE_HOST_URL = process.env.SLACK_SERVICE_HOST_URL || "";

export class SlackService extends ServiceBase {
  constructor() {
    super(SLACK_SERVICE_HOST_URL);
  }

  private static _instance: SlackService;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  async getSlackNotifications(orgId: string) {
    try {
      await this.setAuthHeader();
      logger.info(`slack service URL :${SLACK_SERVICE_HOST_URL}`);
      logger.info(`getting slack orgId: ${orgId}`);
      const slackRes = await this.gqlClient.request<getSlackNotificationsRes>(getSlackQuery, {
        orgId,
      });

      return slackRes.res.notifications;
    } catch (e) {
      logger.error(`failed to get slack notifications: ${orgId}`, e);
    }
    return [];
  }
}
