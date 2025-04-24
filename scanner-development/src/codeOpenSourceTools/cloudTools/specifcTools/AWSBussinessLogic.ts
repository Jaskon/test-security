import { ImageDetail } from "@aws-sdk/client-ecr";
import { TaskDefinition } from "@aws-sdk/client-ecs";
import { Credentials } from "@aws-sdk/types/dist-types/credentials";
import { AWSCredReturnType, Token } from "../../../entitis/collectorEntitisTypes";
import { AWSResource, AWSResourceType } from "../../../entitis/connectorsSpecific/AWSRelatedTypes";
import { isDevelopment, isLocalDevelopment } from "../../../helper/envUtils";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
import AWSContainers from "./AWSContainers";
import getAwsStorage from "./AWStorage";

const logger = loggerImport.getDebugLogger();

//
// AWS keeps trail data for 90 days, everything else dropped
//
export function isFunctionOrImageTooOld(date: string): boolean {
  //Run all on dev
  const shouldRun = isLocalDevelopment() || isDevelopment() || StatesHelper.Instance.isContainerEnable;
  if (shouldRun) {
    return false;
  }

  return Math.round(Math.abs(new Date().getTime() - new Date(date).getTime()) / (1000 * 60 * 60 * 24)) > 30;
}

export function isNewerUpdate(leftDate: string | undefined, rightDate: string | undefined) {
  return new Date(leftDate ?? "1970-01-01T00:00:00Z").getTime() < new Date(rightDate ?? "1970-01-01T00:00:00Z").getTime();
}

export function getImageAndTagData(dockerString: string): [
  string, // Image name
  string, // Tag
] {
  try {
    if (dockerString) {
      const tokens = dockerString.split(":");

      if (tokens.length === 2) {
        return [tokens[0], tokens[1]];
      }
    }
  } catch (e) {
    logger.error(`Failed to parse image and tag information in getImageAndTagData`, e);
  }

  return ["", ""];
}

export function generateContainerLink(inputDockerName: string) {
  try {
    if (inputDockerName.includes(".dkr.ecr.")) {
      const image = inputDockerName.split(":")[0];
      const dkr = image.split(".");

      if (dkr.length === 6 && dkr[1] === "dkr" && dkr[2] === "ecr" && dkr[5].startsWith("com/")) {
        return `https://${dkr[3]}.console.aws.amazon.com/ecr/repositories/private/${dkr[0]}/${dkr[5].split("/")[1]}?region=${dkr[3]}`;
      }
    }
  } catch (e) {
    //...
  }

  return inputDockerName;
}

export async function retainTaskDefinitions(task: TaskDefinition): Promise<boolean> {
  const AWStorage = getAwsStorage();

  if (AWStorage.shouldQueryForResources("ecs", true /* skip trail, we need data only */)) {
    // Skip if we have the task cached (Don't update it)
    const cachedTask = await AWStorage.getResource(task?.taskDefinitionArn ?? "");
    if (cachedTask && cachedTask.data) return true;

    const taskRegistrationDate = task?.registeredAt?.toISOString() ?? "1970-01-01T00:00:00Z";
    if (!isFunctionOrImageTooOld(taskRegistrationDate)) {
      await AWStorage.populateResource(task?.taskDefinitionArn ?? "", "data", JSON.stringify(task));

      await AWStorage.populateResource(task?.taskDefinitionArn ?? "", "lastUpdateTime", taskRegistrationDate);
    } else {
      // kyz TODO: does not make sense that this is not important!!!
      await AWStorage.populateResource(
        task?.taskDefinitionArn ?? "",
        "data",
        JSON.stringify(task),
        true, // bypass
      );
    }
  } else {
    return false;
  }

  return true;
}

export async function retainTaskDefinitionsContainerInformation() {
  const AWStorage = getAwsStorage();

  const activeECSResources = AWStorage.getCollection((item: AWSResource) => item.type === "ecs" && !item.bypass && item.data !== "");

  for (const [resourceId, resource] of activeECSResources) {
    if (resource.data) {
      const ecsData = JSON.parse(resource.data) as TaskDefinition;

      for (const container of ecsData.containerDefinitions ?? []) {
        if (container.image) {
          const cachedResource = await AWStorage.getResource(container.image);
          if (!cachedResource) {
            // add only if missing
            await AWStorage.populateResource(container.image ?? "", "data", "");
          }
        }
      }
    }
  }
}

export function queryIfDefinitionsAreMissing(ignoreTrails = true): boolean {
  const AWStorage = getAwsStorage();
  return AWStorage.shouldQueryForResources("ecs", ignoreTrails);
}

export async function retainAllDockerInformation(arn: string, image: ImageDetail): Promise<boolean> {
  const AWStorage = getAwsStorage();
  await AWStorage.populateResource(arn, "data", JSON.stringify(image));

  return true;
}

export function queryResourceTypes(
  queryTypes: AWSResourceType[],
  conditionTypes: string[],
  queryFunction: (collectionFound: Map<string, AWSResource>) => void,
  ignoreBypass = false,
) {
  const AWStorage = getAwsStorage();

  queryFunction(
    AWStorage.getCollection((item: AWSResource) => {
      if (!ignoreBypass && item.bypass) return false;

      for (const singleQueryType of queryTypes) {
        if (singleQueryType == item.type) {
          for (const singleConditionType of conditionTypes) {
            if (item[singleConditionType] === "") return false;
          }
          return true;
        }
      }

      return false;
    }),
  );
}

export function queryEmptyResourceTypes(
  queryTypes: AWSResourceType[],
  conditionTypes: string[],
  queryFunction: (collectionFound: Map<string, AWSResource>) => void,
  ignoreBypass = false,
) {
  const AWStorage = getAwsStorage();

  queryFunction(
    AWStorage.getCollection((item: AWSResource) => {
      if (!ignoreBypass && item.bypass) return false;

      for (const singleQueryType of queryTypes) {
        if (singleQueryType == item.type) {
          for (const singleConditionType of conditionTypes) {
            if (item[singleConditionType] !== "") return false;
          }

          return true;
        }
      }

      return false;
    }),
  );
}

export const refreshedAWSCredentialsFromToken = async (token: AWSCredReturnType): Promise<Credentials> => {
  const currentToken = (await token(true)).getToken();

  return {
    accessKeyId: currentToken.password,
    secretAccessKey: currentToken.secret,
    sessionToken: currentToken.tokenSession,
  };
};

const fetchContainerInformationImpl = async (token: Credentials): Promise<void> => {
  const awsData = AWSContainers(token.accessKeyId, token.secretAccessKey, token.sessionToken);

  await awsData.fetchImages(() => true, retainAllDockerInformation);

  try {
    await awsData.fetchActiveDefinitions(queryIfDefinitionsAreMissing, retainTaskDefinitions);
  } catch (e) {
    logger.error(`[AWS ECS] Failed to fetch Active Definition information. ${e}`);
  }

  await retainTaskDefinitionsContainerInformation();
};

export const fetchAWSData = async (tokenGetter: AWSCredReturnType) => {
  let AWSCollectionFlow: ((token: Credentials, tokenDetails: Token) => Promise<void>)[];

  AWSCollectionFlow = [fetchContainerInformationImpl];

  for (const singleFlow of AWSCollectionFlow) {
    logger.info(`Running AWS Collection flow: ${singleFlow.name} with refreshed token`);

    const token = await refreshedAWSCredentialsFromToken(tokenGetter);
    const tokenDetails = (await tokenGetter(true)).getToken();
    await singleFlow(token, tokenDetails);
  }
};

export const getEC2CpuAsString = (cpuStr: string): string => {
  try {
    switch (cpuStr) {
      case "256":
        return ".25 vCPU";
      case "512":
        return ".5 vCPU";
      case "1024":
        return "1 vCPU";
      case "2048":
        return "2 vCPU";
      case "4096":
        return "4 vCPU";
      case "8192":
        return "8 vCPU";
      case "16374":
        return "16 vCPU";
      case "32768":
        return "32 vCPU";
    }
  } catch (e) {
    logger.error(`getEC2CpuAsString failed with error: ${e}`);
  }

  return cpuStr;
};
