import { ScanStatus } from "../../entitis/commonTypes";
import { ScanType } from "../../entitis/service/connector-message-types";

export interface ScanDoneMsg {
  orgId: string;
  scanId: string;
  scanType?: ScanType;
  scanStatus?: ScanStatus;
}
