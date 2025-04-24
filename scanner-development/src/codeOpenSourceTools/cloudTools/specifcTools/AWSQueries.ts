import { DescribeRegionsCommand, EC2Client } from "@aws-sdk/client-ec2";
import {
  DescribeImagesCommand,
  DescribeImagesCommandInput,
  DescribeRepositoriesCommand,
  DescribeRepositoriesCommandInput,
  ECRClient,
  ImageDetail,
  Repository,
} from "@aws-sdk/client-ecr";
import {
  DescribeTaskDefinitionCommand,
  ECSClient,
  ListTaskDefinitionFamiliesCommand,
  ListTaskDefinitionFamiliesCommandInput,
} from "@aws-sdk/client-ecs";
import { GetResourcesCommand, GetResourcesCommandInput, ResourceGroupsTaggingAPIClient } from "@aws-sdk/client-resource-groups-tagging-api";
import { AWSResources } from "../../../entitis/connectorsSpecific/AWSRelatedTypes";
import loggerImport from "../../../logger";

const logger = loggerImport.getDebugLogger();

const AWSQueries = (accessKey: string | undefined, secretKey: string | undefined, sessionToken: string | undefined) => {
  return {
    fetchAllResources: async (region: string): Promise<AWSResources> => {
      try {
        const client = new ResourceGroupsTaggingAPIClient({
          region: region,
          credentials: { accessKeyId: accessKey, secretAccessKey: secretKey, sessionToken: sessionToken },
        });

        const params: GetResourcesCommandInput = { PaginationToken: undefined, ResourcesPerPage: 100 };
        const result: AWSResources = { ResourceTagMappingList: [] };

        do {
          const data = await client.send(new GetResourcesCommand(params));
          if (data?.ResourceTagMappingList) {
            result.ResourceTagMappingList = result.ResourceTagMappingList.concat(data.ResourceTagMappingList);
            params.PaginationToken = data.PaginationToken;
          } else {
            params.PaginationToken = undefined;
          }
        } while (params.PaginationToken);

        return result;
      } catch (error) {
        logger.error(`FetchAllResources Failed`, error);
      }
      return { ResourceTagMappingList: [] };
    },

    describeRegions: async () => {
      try {
        logger.debug(`try fetch regions`);
        const ec2 = new EC2Client({
          region: process.env.REGION,
          credentials: { accessKeyId: accessKey, secretAccessKey: secretKey, sessionToken: sessionToken },
        });
        try {
          const data = await ec2.send(new DescribeRegionsCommand({}));
          return JSON.stringify(data);
        } catch (err) {
          logger.debug(`try fetch regions failed: ${err}`);
          throw err;
        }
      } catch (err) {
        logger.error(`Error in AWSQueries.describeRegions`, err);
        throw err;
      }
    },

    queryECSTasksDefinitions: (region: string) => {
      return {
        getAllDefinitions: async () => {
          try {
            logger.debug(`try fetch active task definitions for region: ${region}`);

            const ecs = new ECSClient({
              region,
              credentials: { accessKeyId: accessKey, secretAccessKey: secretKey, sessionToken: sessionToken },
            });

            const params: ListTaskDefinitionFamiliesCommandInput = { nextToken: undefined, status: "ACTIVE", maxResults: 100 };
            const taskDefinitionFamilies: string[] = [];

            do {
              const data = await ecs.send(new ListTaskDefinitionFamiliesCommand(params));
              taskDefinitionFamilies.push(...(data.families || []));
              params.nextToken = data.nextToken;
            } while (params.nextToken);

            logger.debug(`fetch active task definitions for region: ${region} success (done)`);
            if (taskDefinitionFamilies.length) {
              logger.info(`[AWS ECS] found ${taskDefinitionFamilies.length} TaskDefinitions for region ${region}`);
            }
            return JSON.stringify(taskDefinitionFamilies);
          } catch (err) {
            logger.error(`[AWS ECS] Error in AWSQueries.describeECSTasksDefinitions`, err);
            throw err;
          }
        },

        getDefinitionData: async (taskDefinitionFamily: string) => {
          try {
            logger.debug(`[AWS ECS] try fetch task definition data for task definition: ${taskDefinitionFamily}`);
            const ecs = new ECSClient({
              region,
              credentials: { accessKeyId: accessKey, secretAccessKey: secretKey, sessionToken: sessionToken },
            });
            return await ecs.send(new DescribeTaskDefinitionCommand({ taskDefinition: taskDefinitionFamily }));
          } catch (err) {
            logger.error(`[AWS ECS] Error in AWSQueries.describeECSTasksDefinitions`, err);
            throw err;
          }
        },
      };
    },

    awsECR: (region: string) => {
      return {
        getRepositoriesEx: async () => {
          try {
            logger.debug(`[AWS ECR] try fetch repositories for region: ${region}`);
            const ecr = new ECRClient({
              region: region,
              credentials: { accessKeyId: accessKey, secretAccessKey: secretKey, sessionToken: sessionToken },
            });
            const params: DescribeRepositoriesCommandInput = { nextToken: undefined };
            const repositories: Repository[] = [];
            do {
              const data = await ecr.send(new DescribeRepositoriesCommand(params));
              repositories.push(...(data.repositories || []));
              params.nextToken = data.nextToken;
            } while (params.nextToken);

            return repositories;
          } catch (err) {
            logger.error(`[AWS ECR] Error in AWSQueries.awsECR.getRepositories`, err);
            throw err;
          }
        },

        getImagesEx: async (repositoryName: string, limitNumberOfImages = 2, limitPagesTo = Infinity) => {
          try {
            logger.info(`[AWS ECR] try fetch images for repository ${repositoryName} and region ${region}}`);

            const ecr = new ECRClient({
              region: region,
              credentials: { accessKeyId: accessKey, secretAccessKey: secretKey, sessionToken: sessionToken },
            });

            const params: DescribeImagesCommandInput = { repositoryName, maxResults: 1000, nextToken: undefined };
            const images: ImageDetail[] = [];
            let limitCounter = limitPagesTo;
            let factor = 1; // backoff factor as prescribed by AWS documentation

            do {
              try {
                const data = await ecr.send(new DescribeImagesCommand(params));
                images.push(...(data.imageDetails || []));
                params.nextToken = data.nextToken;
              } catch (e) {
                if (`${e}`.includes("ThrottlingException")) {
                  logger.info(`[AWS ECR] ThrottlingException handled in getImagesEx(${repositoryName})`);
                  const delay = ms => new Promise(res => setTimeout(res, ms));
                  await delay(1000 * 65 * factor++);
                  continue;
                }
                throw e;
              }
            } while (params.nextToken && limitCounter-- > 0);

            logger.info(`[AWS ECR] fetched total image count: ${images.length}, for repository: ${repositoryName} and region ${region}`);

            return images;
          } catch (err) {
            logger.error(`[AWS ECR] Error in AWSQueries.awsECR.getImages`, err);
            throw err;
          }
        },
      };
    },
  };
};

export default AWSQueries;
