import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

const localToolRunner = () => {
  const configuredToRunToolsLocally = process.env.RUN_TOOLS_LOCALLY && !process.env.DOCKER_DEBUG;

  return {
    ifConfiguredToRunToolsLocallyThen: () => {
      if (configuredToRunToolsLocally) {
        return localToolRunner();
      } else {
        return {
          updateToolRunnerMessage: (msg: any) => {},
          isConfiguredToRunToolsLocally: () => {
            return false;
          },
          updatePath: (path: string) => {},
          updateMntPath: (path: string) => {},
        };
      }
    },

    isConfiguredToRunToolsLocally: () => {
      return configuredToRunToolsLocally;
    },
    updateToolRunnerMessage: (msg: any) => {
      try {
        msg["shouldSkipLocalCopy"] = true;
        msg["resultPath"] = msg.resultPath.replaceAll(process.env.OX_SHARED_DATA, "/var/shared-data");
      } catch (e) {
        logger.error(`updateToolRunnerMessage: ${e}`);
      }
    },
    updatePath: (path: string) => {
      return path.replaceAll(process.env.OX_SHARED_DATA, "/var/shared-data");
    },
    updateMntPath: (path: string) => {
      return path.replaceAll("/mnt/scratch", "/var/shared-data");
    },
  };
};

export default localToolRunner;
