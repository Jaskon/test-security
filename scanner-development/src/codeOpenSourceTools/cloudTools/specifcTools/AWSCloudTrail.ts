import loggerImport from "../../../logger";
const logger = loggerImport.getDebugLogger();

const AWSCloudTrail = () => {
  return {
    parseDateFromCloudTrailEvent: (event: string) => {
      try {
        const trail = JSON.parse(event) as any;
        if ("eventTime" in trail) {
          const eventTime = trail.eventTime;
          return eventTime;
        }
      } catch (e) {
        logger.error(`Failed to parse date from CloudTrailEvent: ${e}`);
      }
      return null;
    },
  };
};

export default AWSCloudTrail;
