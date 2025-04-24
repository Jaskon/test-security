import { DescribeRegionsCommandOutput } from "@aws-sdk/client-ec2";
import { ImageDetail, Repository } from "@aws-sdk/client-ecr";
import { TaskDefinition } from "@aws-sdk/client-ecs";
import FeatureFlags from "@oxappsec/ox-feature-flag";
import { AsyncTracker } from "../../../async-tracker.service";
import { SettingsService } from "../../../helper/service/scan-settings-service/service/settings-service";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import AWSQueries from "./AWSQueries";

const logger = loggerImport.getDebugLogger();
const MONTH_IN_MILLISECONDS = 1000 * 60 * 60 * 24 * 30;

const AWSContainers = (accessKey: string | undefined, secretKey: string | undefined, sessionToken: string | undefined) => {
  const regionsSet = new Set<string>();
  const regionTaskDefinitionsMap = new Map<string, string>();
  const awsECRRepositoriesEx = new Map<string, Repository[]>();

  const fetchAllRepositoriesEx = async () => {
    try {
      logger.info(`[AWS ECR] Start repositories fetching for all regions`);
      const awsQueries = AWSQueries(accessKey, secretKey, sessionToken);

      if (regionsSet.size === 0) {
        const regions = await awsQueries.describeRegions();
        const regionArray: DescribeRegionsCommandOutput = JSON.parse(regions);
        for (const region of regionArray.Regions) {
          regionsSet.add(region.RegionName);
        }
      }

      for (const region of regionsSet.values()) {
        await AsyncTracker.runWithAsyncTracker(async () => {
          AsyncTracker.setValue("ox-aws-region", region);
          logger.info(`[AWS ECR] Start repositories fetching for region`);
          try {
            const repositories = await awsQueries.awsECR(region).getRepositoriesEx();
            if (repositories.length) {
              logger.info(`[AWS ECR] Found total repositories count: ${repositories.length} inside region`);
            } else {
              logger.info(`[AWS ECR] No repositories found inside region`);
            }
            awsECRRepositoriesEx.set(region, repositories);
          } catch (e) {
            logger.error(`[AWS ECR] fetchAllRepositories failed`, e);
          }
        });
      }

      logger.info(`[AWS ECR] all repositories fetched successfully`);
      return awsECRRepositoriesEx;
    } catch (err) {
      logger.error(`[AWS ECR] fetchAllRepositories failed`, err);
      throw err;
    }
  };

  return {
    fetchActiveDefinitions: async (
      queryIfDefinitionsAreMissing: () => boolean,
      resourceFiller: (taskDefinition: TaskDefinition) => Promise<boolean>,
    ): Promise<boolean> => {
      const imageIrrelevantTimeInMonths = SettingsService.Instance.irrelevantImageTimeInMonths();
      try {
        if (!queryIfDefinitionsAreMissing()) return true;

        const awsQueries = AWSQueries(accessKey, secretKey, sessionToken);

        if (regionsSet.size === 0) {
          const regions = await awsQueries.describeRegions();
          const regionArray: DescribeRegionsCommandOutput = JSON.parse(regions);

          for (const region of regionArray.Regions) {
            regionsSet.add(region.RegionName);
          }
        }

        if (regionsSet.size !== 0) {
          for (const region of regionsSet.values()) {
            const definitions = await awsQueries.queryECSTasksDefinitions(region).getAllDefinitions();
            regionTaskDefinitionsMap.set(region, definitions);
          }

          const imageMap = new Map<string, TaskDefinition[]>();
          for (const [region, value] of regionTaskDefinitionsMap.entries()) {
            const taskDefinitionFamilies: string[] = JSON.parse(value);

            for (const taskDefinitionFamily of taskDefinitionFamilies) {
              try {
                const taskDefinition = await awsQueries.queryECSTasksDefinitions(region).getDefinitionData(taskDefinitionFamily);
                if (
                  Date.now() - new Date(taskDefinition.taskDefinition.registeredAt || 0).getTime() >
                  MONTH_IN_MILLISECONDS * imageIrrelevantTimeInMonths
                ) {
                  // Ignore task definitions older than 6 months
                  continue;
                }
                // Build a map of images used by task definitions
                for (const containerDefinition of taskDefinition.taskDefinition.containerDefinitions) {
                  const imageName = containerDefinition.image.split(":")[0];
                  if (!imageMap.has(imageName)) {
                    imageMap.set(imageName, []);
                  }
                  imageMap.get(imageName).push(taskDefinition.taskDefinition);
                }
                logger.info(
                  `[AWS ECR] Found active task definition for region ${region} - ${taskDefinition.taskDefinition.family}:${
                    taskDefinition.taskDefinition.revision
                  }, running images [${taskDefinition.taskDefinition.containerDefinitions.map(cf => cf.image).join(",")}]`,
                );
              } catch (err) {
                if (`${err}`.includes("ThrottlingException")) {
                  const delay = ms => new Promise(res => setTimeout(res, ms));
                  await delay(1000 * 65);
                  continue;
                }
              }
            }
          }
          for (const [image, taskDefinitions] of imageMap.entries()) {
            // For every image repository, we want to retain the 2 latest task definitions
            for (const taskDefinition of taskDefinitions.sort((a, b) => b.registeredAt.getTime() - a.registeredAt.getTime()).slice(0, 2)) {
              const resourceRetentionResult = await resourceFiller(taskDefinition);
              if (!resourceRetentionResult) {
                // No need to retain anymore
                return true;
              }
            }
          }
        }

        return true;
      } catch (err) {
        logger.error(`[AWS ECR] Failed in fetchActiveDefinitions`, err);
        throw err;
      }
    },

    fetchImages: async (queryIfImagesAreMissing: () => boolean, resourceFiller: (arn: string, image: ImageDetail) => Promise<boolean>) => {
      try {
        // Check if we need to fetch any containers
        if (!queryIfImagesAreMissing()) return true;

        const awsQueries = AWSQueries(accessKey, secretKey, sessionToken);
        const isContainerScanLimited = await FeatureFlags.isFeatureEnabled.execute(
          StatesHelper.Instance.orgName,
          "limit-container-scans-to-eu-west-1",
          true,
        );

        // Fetch all ECT repositories
        await fetchAllRepositoriesEx();

        for (const [region, repositories] of awsECRRepositoriesEx) {
          if (isContainerScanLimited && region !== process.env.REGION) {
            logger.info(`[AWS ECR] skip fetch images for region: ${region} and isContainerScanLimited: ${isContainerScanLimited}`);
            continue;
          }

          for (const repo of repositories) {
            const images = await awsQueries.awsECR(region).getImagesEx(repo.repositoryName);

            for (const image of images) {
              let arnName = "";

              if (image.imageTags && image.imageTags.length > 0) {
                for (const tag of image.imageTags) {
                  arnName = `${image.registryId}.dkr.ecr.${region}.amazonaws.com/${image.repositoryName}:${tag}`;

                  if (!(await resourceFiller(arnName, image))) {
                    return true;
                  }
                }
              } else {
                arnName = `${image.registryId}.dkr.ecr.${region}.amazonaws.com/${image.repositoryName}`;

                if (!(await resourceFiller(arnName, image))) {
                  return true;
                }
              }
            }
          }
        }

        return true;
      } catch (err) {
        logger.error(`[AWS ECR] Failed to fetch all images`, err);
        throw err;
      }
    },
  };
};

export default AWSContainers;
