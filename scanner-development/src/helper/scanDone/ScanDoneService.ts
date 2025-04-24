import { ScanStatus } from "../../entitis/commonTypes";
import loggerImport from "../../logger";
import { ScanType } from "../../entitis/service/connector-message-types";
import { publisherService, PubsubMessage } from "@oxappsec/ox-unified-pubsub";
import { ScanDoneMsg } from "./types";
const logger = loggerImport.getDebugLogger();

export class ScanDoneService {
  private static _instance: ScanDoneService;

  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  public async publishScanDoneMessage(scanId: string, orgId: string, scanType: ScanType, scanStatus: ScanStatus) {
    try {
      const { publisher } = publisherService((pubSubMsg: PubsubMessage) => process.env.SCAN_DONE_TOPIC, process.env.SCAN_DONE_TOPIC);
      const scanDoneMsg: ScanDoneMsg = {
        orgId,
        scanId,
        scanType,
        scanStatus,
      };
      await publisher.send(scanDoneMsg);
    } catch (e) {
      logger.error(`failed to publish scan done message, orgId: ${orgId}, error: ${e}, scanStatus: ${status}, scanType: ${scanType}`);
    }
  }
}
