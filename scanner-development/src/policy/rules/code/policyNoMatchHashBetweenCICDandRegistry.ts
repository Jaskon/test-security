import { SourceToolType } from "@oxappsec/ox-consolidated-categories";
import { ImageInfo } from "../../../entitis/artifactoryTypes";
import Constant from "../../../entitis/constant";
import { AggregatedContainerData, AggregatedInfoForExclusion } from "../../../entitis/service/exclusionTypes";
import StatesHelper from "../../../helper/statesHelper";
import StringHelper from "../../../helper/stringHelper";
import loggerImport from "../../../logger";
import PolicyRulesBase from "./policyRulesBase";

const logger = loggerImport.getDebugLogger();

class PolicyNoMatchHashBetweenCICDandRegistry extends PolicyRulesBase {
  async eval(jsonData) {
    if (StatesHelper.Instance.isContainerEnrichmentDisabled) {
      return [];
    }

    const res = [];

    const imagesInfo: ImageInfo[] = jsonData.registryImage;

    if (imagesInfo.length == 0) {
      return [];
    }

    const alertSeverityFromArgs = this.getValueFromRuleArgs("type")[0];

    let byHash = null;

    if (alertSeverityFromArgs.toLowerCase() === "hash") {
      byHash = true;
    } else if (alertSeverityFromArgs.toLowerCase() === "name") {
      byHash = false;
    }

    if (byHash == null) {
      return [];
    }

    let images: ImageInfo[] = [];
    if (byHash) {
      images = imagesInfo.filter(imageInfo => !imageInfo.image.cicdFoundByHash && !imageInfo.image.cicdFoundByName);
    } else {
      images = imagesInfo.filter(imageInfo => !imageInfo.image.cicdFoundByHash && imageInfo.image.cicdFoundByName);
    }

    const countBeforeReduction = images.length;
    images = images.filter(i => i.image.imagePushedAtInDays != undefined && i.image.imagePushedAtInDays < 22);
    const countAfterReduction = images.length;
    if (countBeforeReduction != countAfterReduction) {
      logger.info(
        `${this.policyRuleMetadata.name}, countBeforeReduction: ${countBeforeReduction}, countAfterReduction: ${countAfterReduction}`,
      );
    }

    if (images.length == 0) {
      return [];
    }

    const aggregatedInfo = this.getKeyValueMapByRuleIdAndData(images);

    for (const events of Object.values(aggregatedInfo) as any) {
      try {
        if (events.length == 0) {
          continue;
        }

        const image = events.topLevel as any;
        let mainTitle;
        let violationInfo = `The following build artifacts ${image.repositoryName}@${image.imageDigest} from ${image.repositoryName} registry were not correlated to any known artifact from the build system`;

        if (byHash) {
          mainTitle = `${image.cloudEnv ?? "AWS"} artifactory image (${
            image.repositoryName
          }) does not match a build artifact via name or hash`;
        } else {
          mainTitle = `${image.cloudEnv ?? "AWS"} artifactory image (${image.repositoryName}) matches name but not build artifact hash`;
        }

        const Recommendation = `Please validate that the artifacts in the registry: ${
          image.name ?? image.repositoryName
        } were legitimately uploaded by your organization`;

        let additionalInfo = "";
        let additionalInfoEx = [];

        if (image.lastRecordedPullTime) {
          additionalInfo = `Last pull time from registry ${image.repositoryName} - ${image.lastRecordedPullTime}`;
          additionalInfoEx = [
            {
              key: `Image pushed at:`,
              value: `${image.imagePushedAt}`,
            },
          ];
        }

        const aggregated = {
          aggregatedItems: this.sortEvents(events.aggregated),
          columns: "policyNoMatchHashBetweenCICDandArtifactory",
          violationInfo,
        };

        const item = this.generateItemForReport(
          true,
          mainTitle,
          violationInfo,
          violationInfo,
          Recommendation,
          image.repositoryName,
          "Image",
          [],
          additionalInfo,
          true,
          "",
          aggregated,
          [SourceToolType["Artifact Integrity"]],
          ["UNKNOWN"],
          additionalInfoEx,
          this.getCustomIssueId(`${image.repositoryName}@${image.imageDigest}`),
        );

        res.push(item);
      } catch (err) {
        logger.error(`failed add single item for policy no match hash between CICD cloud err: ${err}`);
      }
    }

    return res;
  }

  sortEvents(images: PolicyNoMatchHashBetweenCICDandRegistryAggItem[]) {
    try {
      const res = images.sort((a, b) => a.imagePushedAtInDays - b.imagePushedAtInDays);
      return res;
    } catch (err) {
      logger.error(`failed sort ${this.policyRuleMetadata.name}, err: ${err}`);
    }
    return images;
  }

  getKeyValueMapByRuleIdAndData(images: ImageInfo[]) {
    let aggregatedItems = {};
    for (const imageInfo of images) {
      const image = imageInfo.image;

      const singleItem: PolicyNoMatchHashBetweenCICDandRegistryAggItem = new PolicyNoMatchHashBetweenCICDandRegistryAggItem();

      singleItem.image = image.name || "";
      singleItem.tag = image.imageTags.length > 0 ? `${image.imageTags.join(",")}` : "";
      singleItem.sha = image.imageDigestWithoutPrefix || "";
      singleItem.region = image.region || "";
      singleItem.filePath = "";
      singleItem.size = (image.imageSizeInBytes / (1024 * 1024)).toFixed(1).toString();
      singleItem.imageCreatedAt = `${image.imagePushedAt} (${
        image.imagePushedAtInDays == 0 ? "today" : `${image.imagePushedAtInDays} days ago`
      })`;
      singleItem.pushedAt = singleItem.imageCreatedAt;
      singleItem.imagePushedAtInDays = image.imagePushedAtInDays;
      singleItem.link = image.link;
      singleItem.setAggId();

      const unique = `${image.repositoryName}`;

      if (aggregatedItems.hasOwnProperty(unique)) {
        let info = aggregatedItems[unique];
        info.aggregated.push(singleItem);
      } else {
        const info = {
          topLevel: image,
          aggregated: [],
        };
        info.aggregated.push(singleItem);
        aggregatedItems[unique] = info;
      }
    }
    return aggregatedItems;
  }
}

export class PolicyNoMatchHashBetweenCICDandRegistryAggItem extends AggregatedInfoForExclusion {
  image: string;
  tag: string;
  sha: string;
  region: string;
  pushedAt: string;
  size: string;
  imageCreatedAt: string;
  link: string;
  imagePushedAtInDays: number;
  filePath: string;

  getExclusionObj() {
    const i: AggregatedContainerData = new AggregatedContainerData();
    i.image = this.image;
    i.sha = this.sha;
    return i;
  }

  setAggId() {
    this.aggId = StringHelper.combineStrings(this.sha, this.image);
    this.hashAggId = StringHelper.hashMd5(this.aggId);
  }
}

export default PolicyNoMatchHashBetweenCICDandRegistry;
