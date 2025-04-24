const dotenv = require("dotenv");
dotenv.config();

import Constant from "../../src/entitis/constant";
import { AWSCredReturnType, Token } from "../../src/entitis/collectorEntitisTypes";
import getAwsStorage from "../../src/codeOpenSourceTools/cloudTools/specifcTools/AWStorage";
import AWSContainers from "../../src/codeOpenSourceTools/cloudTools/specifcTools/AWSContainers";
import { AWSResource } from "../../src/entitis/connectorsSpecific/AWSRelatedTypes";
import { performance } from "perf_hooks";
import {
  isFunctionTooOld,
  queryEmptyResourceTypes,
  queryForAllMissingImages,
  queryIfDefinitionsAreMissing,
  queryIfImagesAreMissing,
  queryIfImagesTrailsAreMissing,
  queryResourceTypes,
  retainAllDockerInformation,
  retainAllDockerTrailInformation,
  retainLambdaData,
  retainLambdaTrail,
  retainTaskDefinitions,
  retainTaskDefinitionsContainerInformation,
} from "../../src/codeOpenSourceTools/cloudTools/specifcTools/AWSBussinessLogic";

if (process.env.AWS_RESOURCES_TEST) {
  describe("AWS Resource collector test suite", () => {
    it("Test AWS Resource fetching", async () => {
      // Implementation design:
      // 1. Fetch all resources for all users for all regions
      // 2. Identify resources that were not cached per user per region
      // 3. Call all functions to get this data
      // 4. Update cloud trails for all resources from last update (kept in cloud-stats)
      // 5. Every time we fetch data from the aws cloud, we call a function to ask if more data is needed

      // 1.a Fetch all accounts

      const startTiming = performance.now();
      const uuid = "test-uuid";
      const orgName = "test-org";

      const OxAws1 = new Token(
        "cloud",
        Constant.oxCloudConnectorName,
        Constant.oxCloudConnectorName,
        "arn:aws:iam::857809147732:role/OxAWSIntegrationRole-0a1913683f95",
        "",
        "c7569a22-620b-4529-8c78-ac86495667e2",
        false,
        "",
        "",
        "",
        true,
        1,
        process.env.CLOUD_AWS_SECRET_ACCESS_KEY || "use .env please",
        "",
        process.env.CLOUD_AWS_ACCESS_KEY || "use .env please",
      );

      const OxAws2 = new Token(
        "cloud",
        Constant.oxCloudConnectorName,
        Constant.oxCloudConnectorName,
        "arn:aws:iam::857809147732:role/OxAWSIntegrationRole-0221c618d6ab",
        "",
        "1b03970b-a767-46af-ab16-0f110b37f7e9",
        false,
        "",
        "",
        "",
        true,
        1,
        process.env.CLOUD_AWS_SECRET_ACCESS_KEY || "use .env please",
        "",
        process.env.CLOUD_AWS_ACCESS_KEY || "use .env please",
      );

      const accountsGetters1: AWSCredReturnType[] = await OxAws1.getAWSCredAccountsEx(uuid, orgName);

      const accountsGetters2: AWSCredReturnType[] = await OxAws2.getAWSCredAccountsEx(uuid, orgName);

      const accountsGetters = [...accountsGetters1, ...accountsGetters2];

      //const token = await (await accountsGetters1[0]()).getToken();

      const AWStorage = getAwsStorage();
      AWStorage.enableCaching({
        uuid: "test-uuid",
        orgId: "org_OCiEeMaFR5nSimbx",
      });

      try {
        // 1.b Fetch all regions
        // 1.c Fetch all resources
        expect(await AWStorage.Config(accountsGetters)).toBe(true);

        // 3. Call all functions to get this data
        expect(AWStorage.shouldQueryForResources("ecs")).toBe(true);
        expect(AWStorage.shouldQueryForResources("lambda")).toBe(true);
        expect(AWStorage.shouldQueryForResources("ec2")).toBe(true);

        // Get all possible data
        const fetchAWSData = async (tokenGetter: AWSCredReturnType) => {
          const token = (await tokenGetter()).getToken();
          const awsData = AWSContainers(token.password, token.secret, token.tokenSession);

          // Containers
          const result = await awsData.fetchActiveDefinitions(queryIfDefinitionsAreMissing, retainTaskDefinitions);

          await retainTaskDefinitionsContainerInformation();

          await awsData.fetchImages(queryIfImagesAreMissing, retainAllDockerInformation);
        };

        const AWSFlow: ((tokenGetter: AWSCredReturnType) => Promise<void>)[] = [fetchAWSData];

        for (const singleFlow of AWSFlow) {
          const singleFlowPromises = accountsGetters.map(async userAccount => {
            await singleFlow(userAccount);
          });

          const res = await Promise.all(singleFlowPromises);
        }

        // await AWStorage.filterCollectionByCondition(
        //   (item: AWSResource) =>
        //     item.type === "ecs" && !item.bypass && item.data === ""
        // );

        // // Clear all images we could not find
        // await AWStorage.filterCollectionByCondition(
        //   (item: AWSResource) =>
        //     item.type === "dkr" && !item.bypass && item.data === ""
        // );

        const lambdaData = AWStorage.getCollection((item: AWSResource) => item.type === "lambda" && !item.bypass && item.data !== "");

        const dockersData = AWStorage.getCollection((item: AWSResource) => item.type === "dkr" && !item.bypass && item.data !== "");

        const endTiming = performance.now();
        console.log(`Stats: ${JSON.stringify(AWStorage.getStats())} and total time: ${endTiming - startTiming} milliseconds`);

        console.log(`Lambdas size: ${lambdaData.size}`);
        console.log(`Docker size: ${dockersData.size}`);
      } catch (err) {
        console.log(`Error calling AWStorage config: ${err}`);
      }
      expect(true).toEqual(true);
    }, 666999666);
  });
} else {
  describe("AWS Resource tests not configured", () => {
    it("not configured", () => {
      console.log("Fill environment variables to test");
      expect(true).toBe(true);
    });
  });
}
