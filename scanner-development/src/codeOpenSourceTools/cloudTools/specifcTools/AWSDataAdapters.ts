import { ImageDetail as EcrImageDetail } from "@aws-sdk/client-ecr";
import { TaskDefinition } from "@aws-sdk/client-ecs";
import { FunctionArn, FunctionConfiguration, FunctionList } from "aws-sdk/clients/lambda";
import {
  AWSEcrRepositoryName,
  AWSLambdaTrailData,
  AWSRegion,
  AWSResource,
  ContainerImageName,
  ImageName,
  Instances,
  OXAWSImageTrailData,
} from "../../../entitis/connectorsSpecific/AWSRelatedTypes";
import getAwsStorage from "./AWStorage";

export const populateRegionsFromResourcesData = (regions: Set<AWSRegion>) => {
  const awsStorage = getAwsStorage();

  const allResources = awsStorage.getCollection((item: AWSResource) => !item.bypass && item.data !== "");

  for (const [id, resource] of allResources) {
    regions.add(resource.region);
  }
};

export const populateECRRegistryImages = (
  awsECRRepositories: Map<AWSRegion, EcrImageDetail[]>,
  awsECRImages: Map<AWSEcrRepositoryName, { imageDetails: EcrImageDetail[] }>,
) => {
  const awsStorage = getAwsStorage();

  const allDockers = awsStorage.getCollection((item: AWSResource) => item.type === "dkr" && !item.bypass && item.data !== "");

  for (const [id, resource] of allDockers) {
    const ecrImageRepositoryUri = id.split(":")[0];
    const imageDetail: EcrImageDetail = JSON.parse(resource.data);

    if (awsECRRepositories.has(resource.region)) {
      const currentImageList = awsECRRepositories.get(resource.region);
      if (currentImageList) {
        currentImageList.push(imageDetail);
      }
    } else {
      awsECRRepositories.set(resource.region, [imageDetail]);
    }

    if (awsECRImages.has(ecrImageRepositoryUri)) {
      const currentImageList = awsECRImages.get(ecrImageRepositoryUri);
      if (currentImageList) {
        currentImageList.imageDetails.push(imageDetail);
      }
    } else {
      awsECRImages.set(ecrImageRepositoryUri, {
        imageDetails: [imageDetail],
      });
    }
  }
};

// kyz: why any :(
export const associateContainerToTaskDefinition = (containerMap: Map<ContainerImageName, any>) => {
  const awsStorage = getAwsStorage();

  const allTaskDefinitions = awsStorage.getCollection((item: AWSResource) => item.type === "ecs" && !item.bypass && item.data !== "");

  for (const [id, resource] of allTaskDefinitions) {
    const taskDefinition = JSON.parse(resource.data) as TaskDefinition;

    if (taskDefinition.containerDefinitions) {
      for (const container of taskDefinition.containerDefinitions) {
        if (container.image) {
          containerMap.set(container.image, {
            image: container.image,
            container: container as any,
            region: resource.region,
            taskDefinition: [taskDefinition as any],
          });
        }
      }
    }
  }
};

export const associateImagesWithTrails = (
  imageAuditTrails: Map<ImageName, OXAWSImageTrailData>,
  containerMap: Map<ContainerImageName, any>,
) => {
  const awsStorage = getAwsStorage();

  const allDockersWithTrails = awsStorage.getCollection(
    (item: AWSResource) => item.type === "dkr" && !item.bypass && item.data !== "" && item.trail !== "",
  );

  for (const [id, resource] of allDockersWithTrails) {
    const imageDetail = JSON.parse(resource.data);
    const containerImage = containerMap.get(id);

    if (containerImage) {
      imageAuditTrails.set(imageDetail.imageDigest, {
        region: resource.region,
        containerImage: containerImage.container as any,
        trailEvents: {
          CloudTrailEvent: resource.trail,
        },
      });
    }
  }
};

export const placeLambdaFunctionsInRegionBins = (lambdaFunctions: Map<AWSRegion, FunctionList>) => {
  const awsStorage = getAwsStorage();

  const lambdaFunctionsCollection = awsStorage.getCollection(
    (item: AWSResource) => item.type === "lambda" && !item.bypass && item.data !== "",
  );

  for (const [id, resource] of lambdaFunctionsCollection) {
    if (lambdaFunctions.has(resource.region)) {
      const currentFunction = lambdaFunctions.get(resource.region);
      if (currentFunction) {
        currentFunction.push(JSON.parse(resource.data));
      }
    } else {
      lambdaFunctions.set(resource.region, [JSON.parse(resource.data)]);
    }
  }
};

export const associateLambdaFunctionToTrails = (lambdaAuditTrails: Map<FunctionArn, AWSLambdaTrailData>) => {
  const awsStorage = getAwsStorage();

  const lambdaFunctionsTrailsCollection = awsStorage.getCollection(
    (item: AWSResource) => item.type === "lambda" && !item.bypass && item.data !== "" && item.trail !== "",
  );

  for (const [id, resource] of lambdaFunctionsTrailsCollection) {
    // region: string;
    // lambda: FunctionConfiguration;
    // trailEvents: EventsList;
    const lambdaFunctionConfiguration = JSON.parse(resource.data) as FunctionConfiguration;
    lambdaAuditTrails.set(lambdaFunctionConfiguration.FunctionName ?? "", {
      region: resource.region,
      lambda: lambdaFunctionConfiguration,
      trailEvents: [{ CloudTrailEvent: resource.trail }],
    });
  }
};

export const fetchEC2InstancesFromStorage = (instances: Instances) => {
  const awsStorage = getAwsStorage();

  const ec2Collection = awsStorage.getCollection((item: AWSResource) => item.type === "ec2" && !item.bypass && item.data !== "");

  for (const [id, resource] of ec2Collection) {
    const instance = id.split("/");

    if (instance.length === 2) {
      instances[instance[1]] = JSON.parse(resource.data);
    }
  }
};
