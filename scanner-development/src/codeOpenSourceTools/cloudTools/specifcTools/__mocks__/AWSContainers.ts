import * as fs from "fs";

const AWSContainers = (accessKey: string | undefined, secretKey: string | undefined, sessionToken: string | undefined) => {
  return {
    fetchRunningTasksDefinitions: async () => {
      // eslint-disable-next-line no-async-promise-executor
      return new Promise(async (resolve, reject) => {
        const runningImageData = fs.readFileSync("./tests/src/AWSMockData/AWSImageData.json", "utf8");
        const parsedRunningImageData = JSON.parse(JSON.parse(runningImageData)[7]);
        const map = new Map<string, any>(parsedRunningImageData);
        resolve(map);
      });
    },
  };
};

export default AWSContainers;
