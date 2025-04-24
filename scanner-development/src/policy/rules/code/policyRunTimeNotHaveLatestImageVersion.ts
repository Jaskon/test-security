import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";
import CicdHelper from "../../../helper/connectorsSpecific/cicdHelper";
import OrgPolicyParser from "../../org/ruleConfigParser";
import { AlertSeverity, IssueOwner, Repo } from "../../../entitis/codeRepoTypes";
import { AppOwnerRole } from "../../reporting/types";
import Constant from "../../../entitis/constant";
import { SourceToolType } from "@oxappsec/ox-consolidated-categories";

const logger = loggerImport.getDebugLogger();

class PolicyRunTimeNotHaveLatestImageVersion extends PolicyRulesBase {
  async eval(jsonData) {
    if (jsonData.containerImage.length == 0) {
      return [];
    }

    const daysFromFromArgs = this.getValueFromRuleArgs("daysFrom");
    if (isNaN(daysFromFromArgs)) {
      throw `daysFromFromArgs, is not number type, daysFromFromArgs: ${daysFromFromArgs}`;
    }
    const owners = this.getOwnersFromAppOwnersConfig(jsonData);

    const issueOwners = owners.map(owner => {
      const issueOwner: IssueOwner = {
        name: owner.name,
        email: owner.email,
      };
      return issueOwner;
    });

    const res = [];
    for (const containerImage of jsonData.containerImage) {
      try {
        if (containerImage.lastImageAvailableInRegistry == null || containerImage.imageDetail == null) {
          continue;
        }

        if (containerImage.lastImageAvailableInRegistry.imagePushedAt === containerImage.imageDetail.imagePushedAt) {
          continue;
        }

        if (
          containerImage.imageDetail.imagePushedAtInDays - containerImage.lastImageAvailableInRegistry.imagePushedAtInDays <
          daysFromFromArgs
        ) {
          continue;
        }

        const resourceTemp =
          containerImage.taskDefinition.capacityProviderName == undefined
            ? containerImage.taskDefinition.launchType
            : containerImage.taskDefinition.capacityProviderName;

        const resource = `${resourceTemp.toLowerCase().replace("_", " ")} task`;

        const mainTitle = `${containerImage.cloudEnv} service is not utilizing the latest image version`;
        const imageTags = containerImage.lastImageAvailableInRegistry.imageTags.join(",");

        const imageInfo = containerImage.containerImageInfo.image.split(":");
        const tag = imageInfo[1];

        const secondTitle = `The service ${containerImage.containerImageInfo.name} running as a ${resource} is using image ${
          containerImage.containerImageInfo.image
        } with tag: ${tag} built on ${containerImage.imageDetail.imagePushedAt} (${
          containerImage.imageDetail.imagePushedAtInDays == 0 ? "today" : `${containerImage.imageDetail.imagePushedAtInDays} days ago`
        }). This image is not the latest version in the registry. The latest version available was build on ${containerImage.lastImageAvailableInRegistry.imagePushedAt.replace(
          "Z",
          "",
        )} (${
          containerImage.lastImageAvailableInRegistry.imagePushedAtInDays == 0
            ? "today"
            : `${containerImage.lastImageAvailableInRegistry.imagePushedAtInDays} days ago`
        }) with tag ${imageTags}`;

        const imageName = containerImage.containerImageInfo.image.split(":")[0];

        const Recommendation = `Please validate that the ${resource} with service ${
          containerImage.containerImageInfo.name
        } running in the ${containerImage.region} region has the latest image ${`${imageName}:${imageTags} (tag: ${imageTags})`}`;

        const additionalInfo = `SHA256 - ${
          containerImage.imageDigestWithoutPrefix
        }, Current status - ${containerImage.containerImageInfo.lastStatus.toLowerCase()}, Cluster Arn - ${
          containerImage.taskDefinition.clusterArn
        }, Runtime platform - ${containerImage.taskDefinition.platformFamily}, CPU - ${containerImage.taskDefinition.cpu}, Memory - ${
          containerImage.taskDefinition.memory
        }`;

        const additionalInfoEx = [
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
            key: "Cluster Arn",
            value: containerImage.taskDefinition.clusterArn,
          },
          {
            key: "Runtime platform",
            value: containerImage.taskDefinition.platformFamily,
          },
          { key: "Memory", value: containerImage.taskDefinition.memory },
          { key: "CPU", value: containerImage.taskDefinition.cpu },
        ];

        const fixLink = "";

        const item = this.generateItemForReport(
          true,
          mainTitle,
          secondTitle,
          secondTitle,
          Recommendation,
          containerImage.containerImageInfo.name,
          resource,
          [],
          additionalInfo,
          true,
          fixLink,
          [],
          [SourceToolType["Artifact Integrity"]],
          ["UNKNOWN"],
          additionalInfoEx,
          this.getGeneralIssueId(),
          issueOwners,
        );

        res.push(item);
      } catch (err) {
        logger.error(`failed add single item for policy run time not have latest image version err: ${err}`);
      }
    }

    return res;
  }
}

export default PolicyRunTimeNotHaveLatestImageVersion;
