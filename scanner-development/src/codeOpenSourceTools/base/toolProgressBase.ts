import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";

const logger = loggerImport.getDebugLogger();

class ToolProgressBase {
  uuid: string;
  lastUpdateTime = null;
  lastUpdateTimeWasChanged = false;
  intervalToWaitFromLastUpdate = 35 * 1000 * 60;
  intervalToWaitFromLastUpdateInMilli = this.intervalToWaitFromLastUpdate;
  lastUpdateType: string;
  lastUpdateResource: string;

  constructor(uuid: string) {
    this.uuid = uuid;

    this.intervalToWaitFromLastUpdate = this.intervalToWaitFromLastUpdate / (60 * 1000);

    logger.info(`interval to wait from last update set to ${this.intervalToWaitFromLastUpdate} minutes`);
  }

  continueToWait(resource: string, type: string, loopCount: number) {
    try {
      if (this.lastUpdateTime == null) {
        if (this.lastUpdateTimeWasChanged) {
          logger.error(`interval to wait from last update is null after it already was set`);
          StatesHelper.Instance.scanInfoStats.timeoutForAllTools++;
          return false;
        } else {
          logger.info(`interval to wait from last update is null, waiting for first update`);
          return true;
        }
      }

      this.lastUpdateTimeWasChanged = true;

      const diffInM = this.getDifferenceInMinutes(new Date().getTime(), this.lastUpdateTime);

      if (diffInM > this.intervalToWaitFromLastUpdate) {
        StatesHelper.Instance.scanInfoStats.timeoutForAllTools++;
        return false;
      } else {
        return true;
      }
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.timeoutForAllTools++;
      logger.error(`failed to check if tool should continue to wait for results, err: ${err}`);
    }
    return false;
  }

  updateLastProgressTime(resource: string, type: string) {
    try {
      this.lastUpdateTime = new Date().getTime();
      this.lastUpdateResource = resource;
      this.lastUpdateType = type;
    } catch (err) {
      logger.error(`failed to update last tool time update, err: ${err}`);
    }
  }

  getDifferenceInMinutes(dateNow, date2) {
    const diffInMs = dateNow - date2;
    const seconds = diffInMs / 1000;
    return seconds / 60;
  }
}

export default ToolProgressBase;
