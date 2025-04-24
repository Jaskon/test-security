import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import { IssueOwner, Repo } from "../../../entitis/codeRepoTypes";
import { AppOwnerRole } from "../../reporting/types";
import { CloudTypes, ImageContainerDetail } from "../../../entitis/cloudTypes";
import { Severity } from "../../../entitis/reportTypes";
import Constant from "../../../entitis/constant";
import StatesHelper from "../../../helper/statesHelper";
import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
const logger = loggerImport.getDebugLogger();

class PolicyNoMatchHashBetweenCICDandRuntimeCloud extends PolicyRulesBase {
  async eval(jsonData) {
    if (StatesHelper.Instance.isContainerEnrichmentDisabled) {
      return [];
    }

    const res = [];

    const fetchUserFromTrail = (input: string): string => {
      try {
        if (input) {
          const trail = JSON.parse(input);
          if (trail.userIdentity && trail.userIdentity.userName) return trail.userIdentity.userName;
        }
      } catch (e) {
        return "";
      }
      return "";
    };

    const owners = this.getAppOwners(jsonData);

    let byHash;
    const alertSeverityFromArgs = this.getValueFromRuleArgs("type")[0];
    let containerImages: ImageContainerDetail[] = [];
    if (alertSeverityFromArgs === "hash") {
      containerImages = jsonData.containerImage.filter(
        containerImage => !containerImage.cicdFoundByHash && !containerImage.cicdFoundByName,
      );
      byHash = true;
    } else if (alertSeverityFromArgs === "name") {
      containerImages = jsonData.containerImage.filter(containerImage => !containerImage.cicdFoundByHash && containerImage.cicdFoundByName);
      byHash = false;
    } else {
      return [];
    }

    const countBeforeReduction = containerImages.length;
    containerImages = containerImages.filter(i => i.imageDetail.imagePushedAtInDays != undefined && i.imageDetail.imagePushedAtInDays < 22);
    const countAfterReduction = containerImages.length;
    if (countBeforeReduction != countAfterReduction) {
      logger.info(
        `${this.policyRuleMetadata.name}, countBeforeReduction: ${countBeforeReduction}, countAfterReduction: ${countAfterReduction}`,
      );
    }

    if (containerImages.length == 0) {
      return [];
    }

    let issueOwners = owners.map(owner => {
      const issueOwner: IssueOwner = {
        name: owner.name,
        email: owner.email,
      };
      return issueOwner;
    });

    for (const containerImage of containerImages) {
      try {
        if (containerImage.containerImageInfo == null) {
          continue;
        }

        let imagePushedBy = containerImage.auditTrail?.Username ?? "";

        const resourceTemp =
          containerImage.taskDefinition.capacityProviderName == undefined
            ? containerImage.taskDefinition.launchType
            : containerImage.taskDefinition.capacityProviderName;

        let resource = resourceTemp ? `${resourceTemp.toLowerCase().replace("_", " ")} task` : "Lambda function";
        let mainTitle;
        let violationInfo;

        let severity = this.policyRuleMetadata.severity;

        if (containerImage.cluster) {
          resource = "ECS Task";
          imagePushedBy = fetchUserFromTrail(containerImage.auditTrail?.CloudTrailEvent);
          if (byHash) {
            mainTitle = `${containerImage.cloudEnv} cloud ECS image (${containerImage.imageNameWithoutTag}) does not match a build artifact via name or hash`;
            violationInfo = `The task ${containerImage.taskDefinition.family} running as an ECS Task is using image ${containerImage.imageNameWithoutTag} whose sha256 (${containerImage.imageDigestWithoutPrefix}) was not correlated to any known artifact from the build system. This image was first utilized on ${containerImage.taskDefinition.registeredAt}`;
          } else {
            mainTitle = `${containerImage.cloudEnv} cloud ECS image (${containerImage.imageNameWithoutTag}) matches name but not build artifact hash`;
            violationInfo = `The task ${containerImage.taskDefinition.family} running as a ECS Task is using image ${containerImage.imageNameWithoutTag} whose sha256 (${containerImage.imageDigestWithoutPrefix}) was not correlated to any known artifact from the build system. However, this image corresponds to an artifact name built from your pipeline. This image was first utilized on ${containerImage.taskDefinition.registeredAt}`;
            severity = Severity.MEDIUM;
          }
        }

        if (imagePushedBy != undefined && imagePushedBy !== "") {
          violationInfo += ` the image pushed by: ${imagePushedBy}`;

          if (imagePushedBy.includes("@")) {
            const name = imagePushedBy.split("@")[0];
            const email = imagePushedBy.split("@")[1];

            issueOwners = [
              {
                name: name,
                email: imagePushedBy,
              },
            ];
          }
        }

        const learnMoreLink = containerImage.link;

        let Recommendation = "";
        let additionalInfo = "";
        let additionalInfoEx = [];

        if (containerImage.imageDetail != null) {
          Recommendation = `Please validate that the ECS Task with service ${containerImage.taskDefinition.family} running in the ${containerImage.region} region was authorized to utilize image with sha256 (${containerImage.imageDigestWithoutPrefix})`;
          additionalInfo = `Current status - active`;

          additionalInfoEx = [
            {
              key: "Current status",
              value: "active",
            },
            {
              key: "Task name",
              value: `${containerImage.taskDefinition.family}`,
            },
            { key: "Region", value: containerImage.region },
            { key: "Image", value: containerImage.imageNameWithoutTag },
            { key: "Image type", value: "ECS Task" },
            { key: "SHA256", value: containerImage.imageDigestWithoutPrefix },
            { key: "Memory", value: containerImage.taskDefinition.memory },
            { key: "CPU", value: containerImage.taskDefinition.cpu },
          ];
        } else {
          // Lambda
          if (containerImage.objType === CloudTypes.lambda) {
            const isLambdaCodeVisible =
              containerImage.taskDefinition.Handler === "index.handler" &&
              containerImage.taskDefinition.PackageType === "Zip" &&
              containerImage.taskDefinition.CodeSize < 3145728; // 3MB

            const isLambdaDockerized = containerImage.taskDefinition.PackageType === "Image";

            if (isLambdaCodeVisible) {
              mainTitle = `${containerImage.cloudEnv} Lambda code (${containerImage.containerImageInfo.name}) was uploaded directly`;
            } else if (isLambdaDockerized) {
              mainTitle = `${containerImage.cloudEnv} Lambda docker (${containerImage.containerImageInfo.name}) does not match any build artifact`;
            } else {
              mainTitle = `${containerImage.cloudEnv} Lambda zip (${containerImage.containerImageInfo.name}) does not match any build artifact`;
            }

            violationInfo = `The service ${containerImage.containerImageInfo.name} running as a ${resource} is using image ${containerImage.containerImageInfo.image} whose sha256 (${containerImage.imageDigestWithoutPrefix}) was not correlated to any known artifact from the build system. The lambda was last modified on ${containerImage.taskDefinition.LastModified}`;

            imagePushedBy = fetchUserFromTrail(containerImage.auditTrail?.CloudTrailEvent);

            if (imagePushedBy != undefined && imagePushedBy !== "") {
              violationInfo += ` the image pushed by: ${imagePushedBy}`;

              if (imagePushedBy.includes("@")) {
                const name = imagePushedBy.split("@")[0];
                const email = imagePushedBy.split("@")[1];

                issueOwners = [
                  {
                    name: name,
                    email: imagePushedBy,
                  },
                ];
              }
            }
            const lambdaPkgType = isLambdaDockerized ? "Docker" : "Zip";
            Recommendation = `Please validate that the ${resource} with the arn ${containerImage.containerImageInfo.image} deployed in the ${containerImage.region} region was authorized to utilize ${lambdaPkgType} image type with sha256 (${containerImage.imageDigestWithoutPrefix})`;
            additionalInfo = `Current status - ${containerImage.containerImageInfo.lastStatus.toLowerCase()}, Function ARN - ${
              containerImage.taskDefinition.FunctionArn
            }, Runtime platform - ${containerImage.taskDefinition.Runtime}, Memory - ${containerImage.taskDefinition.MemorySize} MB`;

            additionalInfoEx = [
              {
                key: "Current status",
                value: containerImage.containerImageInfo.lastStatus.toLowerCase(),
              },
              {
                key: "Service name",
                value: containerImage.containerImageInfo.name,
              },
              { key: "Region", value: containerImage.region },
              { key: "Image", value: containerImage.containerImageInfo.image },
              { key: "Image type", value: resource },
              { key: "SHA256", value: containerImage.imageDigestWithoutPrefix },
              {
                key: "Function ARN",
                value: containerImage.taskDefinition.FunctionArn,
              },
              {
                key: "Runtime platform",
                value: containerImage.taskDefinition.Runtime,
              },
              {
                key: "Memory",
                value: `${containerImage.taskDefinition.MemorySize} MB`,
              },
            ];
          }

          // EC2
          if (containerImage.objType === CloudTypes.EC2) {
            const resource = "docker image on an EC2 Instance";
            const resourceForRecommendation = "docker image on the EC2 Instance";
            let dockerHubInfo = [];
            if (byHash) {
              logger.info(
                `${containerImage.cloudEnv} EC2 docker image (${containerImage.containerImageInfo.image}) does not match a build artifact via name or hash`,
              );
              mainTitle = `${containerImage.cloudEnv} EC2 docker image (${containerImage.containerImageInfo.image}) does not match a build artifact via name or hash`;
              violationInfo = `The service ${containerImage.containerImageInfo.name} running as a ${resource} is using image ${containerImage.containerImageInfo.image} whose sha256 (${containerImage.imageDigestWithoutPrefix}) was not correlated to any known artifact from the build system.`;
            } else if (containerImage.cicdFoundInDockerHub == true) {
              // If it was found in docker hub
              logger.info(
                `${containerImage.cloudEnv} EC2 docker image (${containerImage.containerImageInfo.image}) found in Docker Hub but not in CICD`,
              );
              mainTitle = `${containerImage.cloudEnv} EC2 docker image (${containerImage.containerImageInfo.image}) found in Docker Hub but not in CICD`;
              violationInfo = `The service ${containerImage.containerImageInfo.name} running as a ${resource} is using image ${containerImage.containerImageInfo.image} whose sha256 (${containerImage.imageDigestWithoutPrefix}) was not correlated to any known artifact from the build system by name or hash. However, this image corresponds to an image we found in DockerHub so it is likely safe.`;
              severity = Severity.INFO;

              const imageCreatedDate = new Date(containerImage.taskDefinition?.created);
              const manifestImageCreatedDate = new Date(containerImage.taskDefinition?.dockerHubManifestImagePushDate);
              if (imageCreatedDate) {
                dockerHubInfo.push({
                  key: "Image creation date",
                  value: imageCreatedDate || "",
                });
              }
              if (manifestImageCreatedDate) {
                dockerHubInfo.push({
                  key: "Image creation date in Docker Hub",
                  value: manifestImageCreatedDate || "",
                });
              }
              dockerHubInfo.push({
                key: "Library badge",
                value: containerImage.taskDefinition?.badge,
              });
              dockerHubInfo.push({
                key: "Library pull count",
                value: containerImage.taskDefinition?.pull_count,
              });
              dockerHubInfo.push({
                key: "Library star count",
                value: containerImage.taskDefinition?.star_count,
              });
              if (containerImage.taskDefinition?.namespace != "library") {
                dockerHubInfo.push({
                  key: "Library namespace",
                  value: containerImage.taskDefinition?.namespace,
                });
              }

              // Keeping here in case needed in the future
              // if (containerImage.taskDefinition?.manifestSha) {
              //   dockerHubInfo.push({
              //     key: "Local Manifest SHA256",
              //     value: containerImage.taskDefinition?.manifestSha || "",
              //   });
              // }
              // if (containerImage.taskDefinition?.dockerHubManifestSha) {
              //   dockerHubInfo.push({
              //     key: "Docker Hub Manifest SHA256",
              //     value:
              //       containerImage.taskDefinition?.dockerHubManifestSha || "",
              //   });
              // }

              // Changing the severity based on manifest sha match
              // if (
              //   containerImage.taskDefinition?.dockerHubManifestSha !=
              //   containerImage.taskDefinition?.manifestSha
              // ) {
              //   severity += 1;
              // }

              // Changing the severity based on created
              if (Math.abs(imageCreatedDate.getTime() - manifestImageCreatedDate.getTime()) > 10800000 /* 3 hours in milliseconds */) {
                severity += 1;
              }
              // Changing the severity based on docker hub tag status active
              if (!containerImage.taskDefinition?.active) {
                severity += 1;
              }
            } else {
              // if it was found by name
              logger.info(
                `${containerImage.cloudEnv} EC2 docker image (${containerImage.containerImageInfo.image}) matches name but not build artifact hash`,
              );
              mainTitle = `${containerImage.cloudEnv} EC2 docker image (${containerImage.containerImageInfo.image}) matches name but not build artifact hash`;
              violationInfo = `The service ${containerImage.containerImageInfo.name} running as a ${resource} is using image ${containerImage.containerImageInfo.image} whose sha256 (${containerImage.imageDigestWithoutPrefix}) was not correlated to any known artifact from the build system. However, this image corresponds to an artifact name built from your pipeline.`;
              severity = Severity.MEDIUM;
            }
            Recommendation = `Please validate that the ${resourceForRecommendation} named ${containerImage.containerImageInfo.image} deployed in the ${containerImage.region} region was authorized to utilize the image with sha256 (${containerImage.imageDigestWithoutPrefix})`;

            additionalInfoEx = [
              {
                key: "Current status",
                value: containerImage.containerImageInfo.lastStatus.toLowerCase(),
              },
              {
                key: "Service name",
                value: containerImage.containerImageInfo.name,
              },
              { key: "Region", value: containerImage.region },
              { key: "Image", value: containerImage.containerImageInfo.image },
              { key: "Image type", value: resource },
              { key: "SHA256", value: containerImage.imageDigestWithoutPrefix },
              {
                key: "EC2 Instance ID",
                value: containerImage.taskDefinition?.instanceId,
              },
              {
                key: "Docker Image ID",
                value: containerImage.taskDefinition?.imageId,
              },
            ];
            additionalInfoEx = [...additionalInfoEx, ...dockerHubInfo];
          }
        }

        const item = this.generateItemForReport(
          true,
          mainTitle,
          violationInfo,
          violationInfo,
          Recommendation,
          containerImage.containerImageInfo.name ?? containerImage.imageNameWithoutTag,
          resource,
          [],
          additionalInfo,
          true,
          "",
          [],
          [SourceToolType["Artifact Integrity"]],
          ["UNKNOWN"],
          additionalInfoEx,
          this.getCustomIssueId(containerImage.containerImageInfo.name ?? containerImage.imageNameWithoutTag),
          issueOwners,
          learnMoreLink,
          "",
          [],
          "",
          [],
          severity,
        );

        res.push(item);
      } catch (err) {
        logger.error(`failed add single item for Policy no match hash between CICD cloud err: ${err}`);
      }
    }

    return res;
  }

  getAppOwners(jsonData) {
    try {
      const repo = jsonData.code_repo as Repo;
      const { appOwners } = repo;
      if (appOwners) {
        if (appOwners.length === 0) return [];
        const devOwners = appOwners.filter(owner => owner.roles.includes(AppOwnerRole.Dev));
        if (devOwners.length > 0) {
          return devOwners;
        }
        const secOwners = appOwners.filter(owner => owner.roles.includes(AppOwnerRole.Security));
        if (secOwners.length > 0) {
          return secOwners;
        }
        return [];
      }
    } catch (e) {
      logger.error(`failed to get issue owners, error: ${e}`);
    }
    return [];
  }
}

export default PolicyNoMatchHashBetweenCICDandRuntimeCloud;
