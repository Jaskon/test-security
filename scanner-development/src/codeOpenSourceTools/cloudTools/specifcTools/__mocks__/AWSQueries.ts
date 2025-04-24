import * as fs from "fs";

const AWSQueries = (accessKey: string | undefined, secretKey: string | undefined, sessionToken: string | undefined) => {
  return {
    describeRegions: async () => {
      return new Promise((resolve, reject) => {
        resolve(fs.readFileSync("./tests/src/AWSMockData/MockRegions", "utf8"));
      });
    },

    queryECSTasksDefinitions: (region: string) => {
      return {
        getAllDefinitions: async () => {
          return new Promise((resolve, reject) => {
            resolve(fs.readFileSync("./tests/src/AWSMockData/MockTasksDefinitions", "utf8"));
          });
        },

        getDefinitionData: async (taskDefinitionArn: string) => {
          return new Promise((resolve, reject) => {
            resolve(fs.readFileSync("./tests/src/AWSMockData/BetaappDefinition", "utf8"));
          });
        },
      };
    },

    awsLambda: (region: string) => {
      return {
        getFunctions: async () => {
          return new Promise(resolve => {
            resolve(JSON.parse(fs.readFileSync("./tests/src/AWSMockData/MockLambdaList", "utf8")));
          });
        },
      };
    },
  };
};

export default AWSQueries;
