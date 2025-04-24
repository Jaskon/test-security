import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

class TimeHelper {
  uuid: string;

  constructor(uuid: string) {
    this.uuid = uuid;
  }

  static getTime() {
    const currentDate = new Date();
    const month = currentDate.getUTCMonth() + 1; //months from 1-12
    const day = currentDate.getUTCDate();
    const year = currentDate.getUTCFullYear();

    return year + "-" + `${month}`.padStart(2, "0") + "-" + `${day}`.padStart(2, "0");
  }

  // returns either a valid date or null
  static isoDateStringToDate(input: string): Date | null {
    const maybeValidDate = new Date(input);
    return isNaN(Number(maybeValidDate)) ? null : maybeValidDate;
  }

  getTimeIntervalFronNowInDays(timeStr: string, abs: boolean = false) {
    try {
      if (!timeStr) return -1;

      let openTime = new Date(timeStr);
      const openTimeInfo = openTime.getTime();
      const seconds = abs ? Math.abs(new Date().getTime() - openTimeInfo) / 1000 : (new Date().getTime() - openTimeInfo) / 1000;
      const openTimeInHours = seconds / 3600;
      const days = Math.trunc(openTimeInHours / 24);

      const isN = isNaN(days);
      if (isN) {
        logger.warn(`failed to parse time str to epoch, str ${timeStr}, is not number`);
        return -1;
      }

      return days;
    } catch (err) {
      logger.error(`failed to parse time str to epoch, str ${timeStr}, err: ${err}`);
    }

    return -1;
  }

  getTimeIntervalFronNowInHours(timeStr: string, abs: boolean = false) {
    try {
      if (timeStr == "") return -1;

      let openTime = new Date(timeStr);
      const openTimeInfo = openTime.getTime();
      const seconds = abs ? Math.abs(new Date().getTime() - openTimeInfo) / 1000 : (new Date().getTime() - openTimeInfo) / 1000;
      const openTimeInHours = seconds / 3600;
      return openTimeInHours;
    } catch (err) {
      logger.error(`failed to parse time str to epoch, str ${timeStr}, err: ${err}`);
    }
    return -1;
  }

  getDiffFromNowInMilliSeconds(reset) {
    const t: TimeHelper = new TimeHelper("");
    const d: Date = new Date(0);
    d.setUTCSeconds(reset);

    let longTimeToWait = t.getTimeIntervalFronNowInMili(d.toLocaleString());
    longTimeToWait = Math.abs(longTimeToWait);
    return longTimeToWait;
  }

  getTimeIntervalFronNowInMili(timeStr: string) {
    try {
      if (!timeStr) return -1;

      let openTime = new Date(timeStr);
      const openTimeInfo = openTime.getTime();
      const mili = new Date().getTime() - openTimeInfo;
      return mili;
    } catch (err) {
      logger.error(`failed to parse time str to epoch, str ${timeStr}, err: ${err}`);
    }

    return -1;
  }

  getTimeIntervalFromNowInDaysFromEpoch(epoch) {
    try {
      const seconds = (new Date().getTime() - epoch) / 1000;
      const openTimeInHours = seconds / 3600;
      const days = Math.trunc(openTimeInHours / 24);
      return days;
    } catch (err) {
      logger.error(`failed to covert epoch time to days, str ${epoch}, err: ${err}`);
    }

    return -1;
  }

  getTimeIntervalFromNowInMonths(startDate) {
    try {
      const endDate = new Date();
      startDate = new Date(startDate);
      return endDate.getMonth() - startDate.getMonth() + 12 * (endDate.getFullYear() - startDate.getFullYear());
    } catch (e) {
      logger.error(`failed to convert getTimeIntervalFromNowInMonths, date ${startDate}, err: ${e}`);
    }
  }
  // returns new Date, does not mutate the original
  addDaysToDate(date: Date, days: number) {
    return new Date(date.getTime() + days * 24 * 60 * 60 * 1000);
  }
}

export function waitFor(conditionFunction: Function, counter = 600 /* 5 min */): Promise<void> {
  const poll = resolve => {
    if (conditionFunction() || !counter--) resolve();
    else setTimeout(_ => poll(resolve), 500);
  };

  return new Promise(poll);
}

export default TimeHelper;
