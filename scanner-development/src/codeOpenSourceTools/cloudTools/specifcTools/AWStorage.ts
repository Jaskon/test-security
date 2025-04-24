import { DescribeRegionsCommandOutput } from "@aws-sdk/client-ec2";
import { AssumeRoleCommandOutput } from "@aws-sdk/client-sts";
import { AsyncTracker } from "../../../async-tracker.service";
import { AWSCredReturnType } from "../../../entitis/collectorEntitisTypes";
import {
  AWSDataTrailType,
  AWSRegion,
  AWSResource,
  AWSResourceId,
  AWSResources,
  AWSResourcesStatistics,
  AWSResourceType,
  AWSResourceTypeData,
} from "../../../entitis/connectorsSpecific/AWSRelatedTypes";
import loggerImport from "../../../logger";
import AWSQueries from "./AWSQueries";

const logger = loggerImport.getDebugLogger();

const AWStorage = () => {
  let cloudStats;
  const regionsSet = new Set<AWSRegion>();
  const resourceMap = new Map<AWSResourceId, AWSResource>();

  const resourceStats: AWSResourcesStatistics = {
    resourceCount: 0,
    resourcesWithData: 0,
    resourcesWithTrails: 0,
    resourcesFiltered: 0,
    resourceNotFound: 0, // resources not found by tagging engine
    resourcesCached: 0,
    resourcesWithMultipleAccounts: 0,
  };

  const fetchRegions = async (assumedRole: AssumeRoleCommandOutput) => {
    const awsQueries = AWSQueries(
      assumedRole.Credentials?.AccessKeyId,
      assumedRole.Credentials?.SecretAccessKey,
      assumedRole.Credentials?.SessionToken,
    );
    const regions = await awsQueries.describeRegions();
    const regionArray: DescribeRegionsCommandOutput = JSON.parse(regions);

    for (const region of regionArray.Regions) {
      regionsSet.add(region.RegionName);
    }
  };

  const identityResource = (arn: string): AWSResourceTypeData | null => {
    const dkrRegEx = /(\d+).dkr.ecr.([^:]+?).amazonaws.com\/([a-zA-Z0-9:\-_]+)/;
    const ec2RegEx = /arn:aws:ec2:([^:]+?):(\d+):instance\/(i-[a-zA-Z0-9]+)/;
    const ecsRegEx = /arn:aws:ecs:([^:]+?):(\d+):task-definition\/([a-zA-Z0-9:\-_]+)/;
    const lambdaRegEx = /arn:aws:lambda:([^:]+?):(\d+):function:([a-zA-Z0-9:\-_]+)/;

    if (arn.startsWith("arn:aws:lambda")) {
      const match = lambdaRegEx.exec(arn);
      if (match) {
        return {
          id: "lambda",
          account: match[2],
          region: match[1],
          resourceArn: `arn:aws:lambda:${match[1]}:*:function:${match[3]}`,
        };
      }
    } else if (arn.startsWith("arn:aws:ecs:")) {
      const match = ecsRegEx.exec(arn);
      if (match) {
        return {
          id: "ecs",
          account: match[2],
          region: match[1],
          resourceArn: `arn:aws:ecs:${match[1]}:*:task-definition/${match[3]}`,
        };
      }
    } else if (arn.includes(".dkr.ecr.")) {
      const match = dkrRegEx.exec(arn);
      if (match) {
        return {
          id: "dkr",
          account: match[1],
          region: match[2],
          resourceArn: arn,
        };
      }
    } else if (arn.startsWith("arn:aws:ec2:")) {
      const match = ec2RegEx.exec(arn);
      if (match) {
        return {
          id: "ec2",
          account: match[2],
          region: match[1],
          resourceArn: `arn:aws:ec2:${match[1]}:*:instance/${match[3]}`,
        };
      }
    }

    return null;
  };

  const fetchResources = async (assumedRole: AssumeRoleCommandOutput) => {
    const awsQueries = AWSQueries(
      assumedRole.Credentials?.AccessKeyId,
      assumedRole.Credentials?.SecretAccessKey,
      assumedRole.Credentials?.SessionToken,
    );

    //
    // Fetch all resources ids and build AWSResource
    //
    for (const region of regionsSet) {
      try {
        const resources: AWSResources = await awsQueries.fetchAllResources(region);
        if (!resources) continue;

        for (const resource of resources.ResourceTagMappingList) {
          const identifiedResource = identityResource(resource.ResourceARN ?? "");
          if (!identifiedResource) continue;

          const accountId = identifiedResource.account;

          // Check if we have the resource already in our map
          if (resourceMap.has(identifiedResource.resourceArn)) {
            const currentResource = resourceMap.get(identifiedResource.resourceArn);
            if (currentResource) {
              const matchedAccount = currentResource.accounts.filter(account => account === identifiedResource.account);

              if (matchedAccount.length === 0) {
                currentResource.accounts.push(identifiedResource.account);
                resourceMap.set(identifiedResource.resourceArn, currentResource);

                resourceStats.resourcesWithMultipleAccounts++;
              }
            }

            continue; // Next resource
          }
          // if the resource is not in Mongo create a new one, with default values
          resourceMap.set(identifiedResource.resourceArn, {
            id: identifiedResource.resourceArn,
            type: identifiedResource.id,
            trail: "",
            data: "",
            accounts: [accountId],
            region: region,
            lastUpdateTime: `${new Date()}`,
            bypass: false,
          });
          resourceStats.resourceCount++;
        }
      } catch (error) {
        logger.error(`Fetching resources failed with error: ${error}`);
      }
    }
  };

  return {
    Config: async (accounts: AWSCredReturnType[]): Promise<boolean> => {
      try {
        for (const account of accounts) {
          await AsyncTracker.runWithAsyncTracker(async () => {
            // Getting an account can result in an exception, therefore
            try {
              const assumedRole = (await account(false)).getAssumedRole();
              await fetchRegions(assumedRole);
              await fetchResources(assumedRole);
            } catch (error) {
              logger.error(`Error getting an account: ${error}`);
            }
          });
        }

        return true;
      } catch (err) {
        logger.error(`Failed in AWStorage.Config: ${err}`);
      }

      return false;
    },

    shouldQueryForResources: (type: AWSResourceType, onlyDataSuffice = false) => {
      let requireAdditionalQueryForResources = false;

      function traverseAllResources(visitor: (item: AWSResource) => boolean) {
        for (const [key, value] of resourceMap) {
          if (visitor(value)) break;
        }
      }

      traverseAllResources((item: AWSResource) => {
        if (type != item.type) return false;

        if (item.bypass) return false;

        if (onlyDataSuffice && item.data) return false;

        if (item.data && item.trail) return false;

        // We need to
        requireAdditionalQueryForResources = true;
        return true;
      });

      return requireAdditionalQueryForResources;
    },

    populateMap: (id: AWSResourceId, resource: AWSResource) => {
      // Testing only
      if (process.env.CLOUD_DEBUG !== undefined) {
        resourceMap.set(id, resource);
      }
    },

    populateResource: async (resource: AWSResourceId, what: AWSDataTrailType, data: string, bypass = false) => {
      const sanitizedResource = identityResource(resource);

      if (sanitizedResource) {
        if (resourceMap.has(sanitizedResource.resourceArn)) {
          const currentResource = resourceMap.get(sanitizedResource.resourceArn);
          if (currentResource) {
            if (bypass) {
              currentResource.bypass = true;
              resourceStats.resourcesFiltered++;
            } else {
              currentResource.bypass = false;
            }

            if (currentResource[what]) {
              logger.info(`We already have data for this resource: ${resource}`);
            }

            switch (what) {
              case "data":
                resourceStats.resourcesWithData++;
                break;
              case "trail":
                resourceStats.resourcesWithTrails++;
                break;
            }

            currentResource[what] = data;
            resourceMap.set(sanitizedResource.resourceArn, currentResource);
          }
        } else {
          logger.debug(`${resource} is missing from ResourceMap`);

          const currentResource: AWSResource = {
            id: sanitizedResource.resourceArn,
            type: sanitizedResource.id,
            trail: "",
            data: "",
            accounts: [sanitizedResource.account],
            region: sanitizedResource.region,
            lastUpdateTime: `${new Date()}`,
            bypass: false,
          };

          currentResource[what] = data;

          resourceMap.set(sanitizedResource.resourceArn, currentResource);
          resourceStats.resourceNotFound++;
        }
      }
    },

    getResource: async (resource: AWSResourceId): Promise<AWSResource | null> => {
      const sanitizedResource = identityResource(resource);

      if (sanitizedResource) {
        if (resourceMap.has(sanitizedResource.resourceArn)) {
          const currentResource = resourceMap.get(sanitizedResource.resourceArn);
          if (currentResource) {
            return currentResource;
          }
        } else {
          logger.debug(`${resource} is missing from ResourceMap`);
        }
      }

      return null;
    },

    getCollection: (condition: (item: AWSResource) => boolean) => {
      return new Map([...resourceMap].filter(([k, v]) => condition(v)));
    },
  };
};

let instance: ReturnType<typeof AWStorage>;

const getAwsStorage = () => {
  if (!instance) {
    instance = AWStorage();
    return instance;
  }
  return instance;
};

export default getAwsStorage;
