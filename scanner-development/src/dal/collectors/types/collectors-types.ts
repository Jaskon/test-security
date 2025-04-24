import loggerImport from "../../../logger";

export const logger = loggerImport.getDebugLogger();
export const MAX_RETRY_ATTEMPTS = 3;

export const urlRegex = /<a\s+(?:[^>]*?\s+)?href=(['"])(.*?)\1/g;

export const TIME_UNITS = {
  SEC: 1000,
  MIN: 60 * 1000,
};

export const TIME_OUTS = {
  SHORT: 10 * TIME_UNITS.SEC,
  MEDIUM: 50 * TIME_UNITS.SEC,
  LONG: 2 * TIME_UNITS.MIN,
};
