const util = require("util");
const exec = util.promisify(require("child_process").exec);
import ApplicationsManager from "../../appmgr/applicationsManager";
import { CopyType } from "../../appmgr/OXParserToolHandlerTypes";
import { ImageInfo } from "../../entitis/artifactoryTypes";
import { CloudGraphNode, CloudGraphRes, k8SupportedTypes, CloudImageId, CloudGraphInput } from "../../entitis/CloudGraphTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { ChangeReason, SeverityFactorType, severityReasons } from "../../entitis/service/blameTypes";
import loggerImport from "../../logger";
import { escapeCharsFromPath, fullyDecodeURI, copyToolInfo } from "../commonUtils";
import { DotNode, DotGraph } from "../dotGraph";
import { isDevelopment, isLocalDevelopment, isOnPrem } from "../envUtils";
import { replaceAll } from "../generalUtils";
import FileHelper from "../IO/fileHlper";
import Iqueue from "../queue/Iqueue";
import StatesHelper from "../statesHelper";
import { millisToMinutesAndSeconds } from "../telemetry-utils";
import { ExtraInfo } from "../../entitis/issuesTypes";
import { addSeverityChangedReason } from "../../entitis/codeRepoTypes";
import { staticConnectors } from "../connectorsSpecific/tokensHelper";
import { ConnectorName, CredentialsType } from "../../entitis/service/connector-message-types";
import Constant from "../../entitis/constant";
import { ImageDetail, WorkloadInfo } from "../../entitis/cloudTypes";
import { addSeverityChangedReasonToImage } from "../policy/severityHelper";
import { PerformanceTelemetry } from "../decorators/PerformanceTelemetry";
import { ShardFolderUtils } from "../sharedFolderUtils";

const uuid = require("uuid");
const fs = require("fs");

const logger = loggerImport.getDebugLogger();

class CloudGraphHelper {
  cloudGraphQ: Iqueue;
  uuid: string;
  orgName: string;
  fileHelper: FileHelper;
  appsManager: ApplicationsManager;

  constructor(queue: Iqueue, uuid: string, orgName: string, appsManager: ApplicationsManager) {
    this.cloudGraphQ = queue;
    this.uuid = uuid;
    this.orgName = orgName;
    this.fileHelper = new FileHelper(this.uuid);
    this.appsManager = appsManager;
  }

  async setCloudGraph(token: Token) {
    try {
      if (!StatesHelper.Instance.isEKSEnabled) {
        return;
      }

      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }

      if (isOnPrem()) {
        logger.info(`[CloudGraph] OnPrem - not running`);
        return;
      }

      logger.info(`[CloudGraph] try set set cloud graph accountName: ${token.accountName}`);

      const res = await this.sendReq(token);
      if (res) {
        this.appsManager.cloudGraphs.push(res);
      }
      logger.info(`[CloudGraph] finish set set AWS info`);
    } catch (err) {
      logger.error(`[CloudGraph] failed setCloudGraph, err: ${err}`);
    }
  }

  private async sendReq(token: Token): Promise<CloudGraphRes | undefined> {
    try {
      const scanSharedFolderPath = ShardFolderUtils.getScanSharedFolderPath(this.orgName, this.uuid);
      const dirToPutRes = `${scanSharedFolderPath}/${replaceAll(uuid.v4(), "-", "_")}/cloudGraph`;
      fs.mkdirSync(dirToPutRes, { recursive: true });

      const filePathRes = `${dirToPutRes}/cloudGraph.json`;
      const inputFile = `${dirToPutRes}/cloudGraphInput.json`;
      if ((await this.setInputInfo(token, inputFile)) === false) {
        return;
      }

      let url = process.env.CLOUD_GRAPH_QUEUE_KEY;

      let command = this.getCommand(token, dirToPutRes, inputFile);
      command = escapeCharsFromPath(command);

      const msg = {
        uuid: this.uuid,
        orgID: this.orgName,
        command: command, // for on-prem
        localCommand: command,
        url: url,
        toolName: "cloudGraph",
        repoName: "",
        resultPath: filePathRes,
        timeout: 1800000,
        orgDisplayName: process.env["companyName"],
        cloneDir: "",
        copyType: CopyType.LeanCodeOnly,
        toolCopyDestination: "",
        isMonoRepoChild: "",
        monoRepoChildSubfolder: "",
        shouldAdditionallyScanRootFiles: false,
        ignoredSubfolders: null,
        putInQueueTime: new Date().getTime(),
        shouldSkipLocalCopy: true,
        isPipelineScan: StatesHelper.Instance.isPipelineScan,
      };

      const info = {
        url: url,
        msg: msg,
      };

      logger.info(`[CloudGraph] about to send msg to queue for cloud graph, msg: ${JSON.stringify(msg)}`);

      const doneFilePath = `${filePathRes}.done`;
      const failedFilePath = `${dirToPutRes}/.fail`;
      let doneFromCloudGraph = false;

      if (process.env.DEBUG) {
        const reqRes = await this.runShell("aws", msg.localCommand);
        return;
      }

      const reqRes = await this.cloudGraphQ.sendQueueMessage(info);
      if (!reqRes) {
        logger.error(`[CloudGraph] failed enter item to cloud graph Q, msg: ${JSON.stringify(msg)}`);
        return null;
      }

      logger.info(`[CloudGraph] about to start waiting for cloud graph, msg: ${JSON.stringify(msg)}`);

      const startProcessTime = new Date().getTime();

      let counter = 6 * 30; // 60 seconds * 30 = 30 m
      while (true) {
        //Timeout
        if (counter <= 0) {
          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          let errInfo = `[CloudGraph] failed wait for cloud graph due to timeout, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`;
          logger.error(`${errInfo}`);
          StatesHelper.Instance.scanInfoStats.failedCloudGraphBatches++;

          return;
        }

        //Failed from cloud graph
        if (fs.existsSync(failedFilePath)) {
          //setToolInfoFromDoneFile(doneFilePath, this.orgName, this.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          let errInfo = `[CloudGraph] failed file discovered from cloud graph service for cloud graph response, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`;
          logger.error(`${errInfo}`);
          StatesHelper.Instance.scanInfoStats.failedCloudGraphBatches++;

          return;
        }

        //Done from cloud graph
        if (fs.existsSync(doneFilePath)) {
          //setToolInfoFromDoneFile(doneFilePath, this.orgName, this.uuid);

          let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
          logger.info(
            `[CloudGraph] done file discovered from cloud graph response, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}`,
          );
          doneFromCloudGraph = true;
          break;
        }

        //10 seconds
        await this.sleep();
        counter--;
      }

      if (!fs.existsSync(filePathRes)) {
        let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
        let errInfo = `[CloudGraph] response file from cloud graph not exist on disk, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, done from cloud graph: ${doneFromCloudGraph}, dirToPutRes: ${dirToPutRes}`;
        logger.error(`${errInfo}`);
        StatesHelper.Instance.scanInfoStats.failedCloudGraphBatches++;

        return;
      }

      let elapsedTimeProcessTime = millisToMinutesAndSeconds(new Date().getTime() - startProcessTime);
      const data = fs.readFileSync(filePathRes, "utf8");
      copyToolInfo("cloudGraph", filePathRes, "cloudGraph", this.uuid);
      const cloudGraphRes: CloudGraphRes = JSON.parse(data);

      //Delete after reading
      this.fileHelper.deleteFile(filePathRes);
      this.fileHelper.deleteFile(inputFile);

      logger.info(
        `[CloudGraph] finish waiting for cloud graph items: ${data.length}, elapsedTimeProcessTime: ${elapsedTimeProcessTime}, dirToPutRes: ${dirToPutRes}, cloud graph size: ${cloudGraphRes.dot.length}, counter: ${counter}`,
      );

      return cloudGraphRes;
    } catch (err) {
      logger.error(`[CloudGraph] error in cloud graph: ${err}`);
    }
    StatesHelper.Instance.scanInfoStats.failedCloudGraphBatches++;

    return;
  }

  async sleep() {
    const delay = ms => new Promise(res => setTimeout(res, ms));
    await delay(1000 * 10);
  }

  async setInputInfo(token: Token, inputFile: string) {
    try {
      let graphInput: CloudGraphInput = new CloudGraphInput();
      if (token.name === Constant.oxCloudConnectorName) {
        const eksConnector = staticConnectors.find(connector => connector.name.toLowerCase() === ConnectorName.EKS.toLowerCase());
        if (eksConnector) {
          graphInput.monitorAll = eksConnector?.monitorAllResources;
          graphInput.monitorNewDate = eksConnector?.monitorAllNewlyCreatedResources;
          if (eksConnector?.monitoredResources) {
            const clusters = Object.keys(eksConnector?.monitoredResources);
            if (clusters.length > 0) {
              graphInput.monitorResources = clusters;
            }
          }

          // no specific resources were choosen, scan all
          if (graphInput.monitorResources.length === 0) {
            graphInput.monitorAll = true;
          } else {
            graphInput.monitorAll = false;
          }

          if (graphInput.monitorNewDate === undefined) {
            graphInput.monitorNewDate = null;
          }

          if (eksConnector?.credentials && eksConnector?.credentials.length > 0) {
            logger.info(`[CloudGraph] EKS cred type: ${eksConnector?.credentials[0].credentialsType}`);
            if (eksConnector?.credentials[0].credentialsType === CredentialsType.AWSEKS) {
              graphInput.eksConnection = CredentialsType.AWSEKS;
            } else if (eksConnector?.credentials[0].credentialsType === CredentialsType.AWSEKSDirect) {
              graphInput.eksConnection = CredentialsType.AWSEKSDirect;
            } else if (eksConnector?.credentials[0].credentialsType === CredentialsType.AWSEKSPrivateLink) {
              graphInput.eksConnection = CredentialsType.AWSEKSPrivateLink;
            }
          }
        }
      }

      const jsonData = JSON.stringify(graphInput);
      fs.writeFileSync(inputFile, jsonData, "utf8");
      copyToolInfo("cloudGraph", inputFile, "cloudGraph", this.uuid);
      logger.info(`[CloudGraph] input file: ${jsonData}`);
      return true;
    } catch (err) {
      logger.error(`[CloudGraph] failed to setInputInfo, err: ${err}`);
      return false;
    }
  }

  getCommand(token: Token, dirToPutRes: string, inputFile: string) {
    let exec_path: string | undefined = "/src/cloud_graph.py";
    if (process.env.DEBUG) {
      exec_path = process.env.CLOUD_GRAPH_PATH;
    }

    return `OX_RESEARCH_BUCKET=${process.env.OX_RESEARCH_BUCKET} ox_customer_AWS_ACCESS_KEY_ID=${token.password} ox_customer_AWS_SECRET_ACCESS_KEY=${token.secret} ox_customer_AWS_SESSION_TOKEN=${token.tokenSession} python ${exec_path} --output-dir ${dirToPutRes} --customer-id ${this.orgName}_${StatesHelper.Instance.companyName} --input-file ${inputFile}`;
  }

  async runShell(requesterName: string, command: string) {
    try {
      await this.shell(requesterName, command);
      return true;
    } catch (err) {
      logger.error(`[CloudGraph] failed run shell command: ${command} to run err: ${err}`);
    }
    return false;
  }

  async shell(requesterName, command: string) {
    try {
      logger.info(`[CloudGraph] try run from shell, repo: ${requesterName}: cmd: ${command}`);

      const { stdout, stderr } = await exec(command, {
        maxBuffer: 1024 * 1024 * 10,
        env: { ...process.env, FOO: "ah" },
      });
      logger.debug(`[CloudGraph] stdout:, ${JSON.stringify(stdout, null, 4)}`);
      logger.debug(`[CloudGraph] stderr:, ${JSON.stringify(stderr, null, 4)}`);
    } catch (err) {
      logger.error(
        `[CloudGraph] uuid: ${this.uuid} shell command: ${command} failed to run error: ${err} stdout: ${err.stdout + "\n"} stderr: ${
          err.stderr + "\n"
        }`,
      );

      logger.info(`[CloudGraph] finish run from shell, requester name: ${requesterName} cmd: ${command}`);
    }
  }

  static decodeImageId(imageId: string): CloudImageId[] {
    let cloudImageIds: CloudImageId[] = [];

    //sometimes we get images with such begining, issue in cloudgraph tool
    let imageName = imageId;
    if (imageName.startsWith(", ")) {
      imageName = imageName.slice(2);
    }

    decodeURIComponent(imageName)
      .split(", ")
      .forEach(imageIdWithTag => {
        try {
          let cloudImageId: CloudImageId = new CloudImageId();
          let imageAndSha = imageIdWithTag.split("@");
          cloudImageId.name = imageAndSha[0];
          if (imageAndSha.length > 1) {
            cloudImageId.hash = imageAndSha[1];
            cloudImageId.hash = cloudImageId.hash?.startsWith("sha256:") ? cloudImageId.hash?.substring(7) : cloudImageId.hash;
          }
          let imageAndTag = imageAndSha[0].split(":");
          if (imageAndTag.length > 1) {
            cloudImageId.name = imageAndTag[0];
            cloudImageId.tag = imageAndTag[1].split("@")[0];
          }
          cloudImageIds.push(cloudImageId);
        } catch (err) {
          logger.error(`[CloudGraph] decodeURIComponent single node ImageID: ${imageIdWithTag} error: ${err}`, err);
        }
      });
    return cloudImageIds;
  }

  static getArtifactsMap(allImagesFromRegistry: ImageInfo[]): Map<string, ImageInfo[]> {
    const artifactMap = allImagesFromRegistry.reduce((map, imageInfo) => {
      const imageName = imageInfo.image.imageId.split("_").slice(0, -1).join("_");
      if (!map.has(imageName)) {
        map.set(imageName, []);
      }
      map.get(imageName).push(imageInfo);
      return map;
    }, new Map());
    return artifactMap;
  }

  static getPotentialImages(
    artifactsMap: Map<string, ImageInfo[]>,
    imageName: string,
    hash: string,
    tag: string,
  ): [images: ImageInfo[], specificMatch: boolean] {
    const images: ImageInfo[] = artifactsMap.get(imageName);
    if (!images || images.length < 1) {
      return [[], false];
    }

    const hashFoundImages: ImageInfo[] = images.filter(obj => obj.image.imageDigestWithoutPrefix === hash);
    if (hashFoundImages && hashFoundImages.length > 0) {
      return [hashFoundImages, true];
    }

    const tagFoundImages: ImageInfo[] = images.filter(obj => obj.image.imageTags.includes(tag));
    if (tagFoundImages && tagFoundImages.length > 0) {
      return [tagFoundImages, true];
    }

    return [images, false];
  }

  static extendImageDetails(image: ImageInfo, node: DotNode<CloudGraphNode>, consoleLink: string) {
    if (!image.image?.workloadInfo) {
      image.image.workloadInfo = [];
    }

    if (image.image.workloadInfo.find(info => info?.cluster === node?.cluster && info?.region === node?.region)) {
      logger.info(
        `[CloudGraph] workflow info already exist for image: ${image?.image?.name}, cluster: ${node?.cluster} region: ${node?.region}`,
      );
      return;
    }

    let workloadInfo: WorkloadInfo = new WorkloadInfo();
    workloadInfo.cluster = node?.cluster;
    workloadInfo.region = node?.region;
    workloadInfo.type = node?.type;
    workloadInfo.k8sType = node?.platform;
    workloadInfo.consoleLink = consoleLink || "";
    image.image.workloadInfo.push(workloadInfo);

    image.image.imageRunningInCloud = true;
  }

  static addCloudItemToArtifactManager(node: DotNode<CloudGraphNode>, consoleLink: string, hash: string, awsAccount: string) {}

  static addSeverityFactorsToArtifact(
    image: ImageInfo,
    dotGraph: DotGraph<CloudGraphNode>,
    node: DotNode<CloudGraphNode>,
    imageName: string,
    consoleLink: string,
  ) {
    let severityFactors: ChangeReason[] = [];
    if (node?.severity_factors) {
      severityFactors = node.severity_factors
        ? decodeURIComponent(node.severity_factors)
            ?.split(", ")
            .map(factor => severityReasons[factor])
            .filter(Boolean)
        : [];
    }

    if (severityFactors.length == 0) {
      logger.info(`[CloudGraph] no severity factors found for image: ${imageName}, node.severity_factors: ${node?.severity_factors}`);
    }

    if (image.securityEvents.length == 0) {
      logger.info(`[CloudGraph] no securityEvents found for image: ${imageName}`);
    }

    const extraInfo: ExtraInfo[] = [];
    const exposedAPIExtraInfo: ExtraInfo[] = [];

    const extraInfoKey = imageName + "  Type: " + node?.type + "  Region: " + node?.region + "  Cluster: " + node?.cluster;
    if (consoleLink) {
      extraInfo.push({
        key: extraInfoKey,
        link: consoleLink,
      });
    }

    if (node?.type === k8SupportedTypes.service && consoleLink) {
      try {
        const allBranches = dotGraph.findAllBranchesRecursively(node?.id, 10, true);
        if (allBranches.length > 0) {
          const longestBranch = allBranches.reduce((max, branch) => (branch.length > max.length ? branch : max), []);
          exposedAPIExtraInfo.push({
            key:
              extraInfoKey +
              `\nExternal Traffic Routing Flow:  ${longestBranch
                .reverse()
                .map(str => str.slice(str.lastIndexOf("_") + 1))
                .join("  ->  ")}`,
            link: consoleLink,
          });
        }
      } catch (err) {
        logger.error(`[CloudGraph] Failed to calc External Traffic Routing Flow: ${err}`, err);
      }
    }

    //we might have many jobs running at once, we would like to have only one as evidence
    let compareKey = false;
    if (node?.type === k8SupportedTypes.job || node?.type === k8SupportedTypes.cronJob) {
      compareKey = true;
    }

    //add severity factors to image, later will propogate to all repo issues
    addSeverityChangedReasonToImage(severityReasons.runningInCloud, image, extraInfo, compareKey);
    for (const severityFactor of severityFactors) {
      severityFactor.severityFactorType = SeverityFactorType.Cloud;
      const sevExtraInfo =
        exposedAPIExtraInfo.length > 0 && severityFactor.shortName === severityReasons.internetdExposedAPI.shortName
          ? exposedAPIExtraInfo
          : extraInfo;
      addSeverityChangedReasonToImage(severityFactor, image, sevExtraInfo, compareKey);
    }

    for (const secEvent of image.securityEvents) {
      addSeverityChangedReason(severityReasons.runningInCloud, secEvent, undefined, extraInfo, compareKey);
      for (const severityFactor of severityFactors) {
        /*if (isDevelopment()) {
          logger.info(
            `[CloudGraph] adding severity factor ${severityFactor.shortName} to imageId: ${image?.image?.imageId} for issue ${secEvent.title}`,
          );
        }*/
        severityFactor.severityFactorType = SeverityFactorType.Cloud;
        const sevExtraInfo =
          exposedAPIExtraInfo.length > 0 && severityFactor.shortName === severityReasons.internetdExposedAPI.shortName
            ? exposedAPIExtraInfo
            : extraInfo;
        addSeverityChangedReason(severityFactor, secEvent, undefined, sevExtraInfo, compareKey);
      }
    }
  }

  @PerformanceTelemetry()
  static async attachCloudGraphInfo(allImagesFromRegistry: ImageInfo[], cloudGraphs: CloudGraphRes[]) {
    try {
      if (StatesHelper.Instance.isPipelineScan) {
        return;
      }
      const shouldRun = isDevelopment() || isLocalDevelopment() || StatesHelper.Instance.isEKSEnabled;
      if (!shouldRun) {
        return;
      }
      if (isLocalDevelopment()) {
        const pathToDot = "/Users/itai/Documents/cloudGraph.json";
        const rawdata = fs.readFileSync(pathToDot, "utf-8");
        if (!rawdata) {
          return null;
        }
        const dotGraph = JSON.parse(rawdata) as any;
        cloudGraphs.push(dotGraph);

        let image: ImageInfo = new ImageInfo();
        image.image = new ImageDetail();
        image.image.imageId = "203043666164.dkr.ecr.eu-west-1.amazonaws.com/bank-website_AWS";
        image.image.imageTags = ["v1"];
        image.image.imageDigestWithoutPrefix = "c336f1b2db5f5132e345ce8976f6d5870b5a5b875cbd3118e3ab7751474c688b";
        image.image.repositoryName = "bank-website";
        image.image.workloadInfo = [];
        image.image.imageRunningInCloud = false;

        allImagesFromRegistry.push(image);
      }

      //fetch all artifacts in a map format, key is image name
      const artifactsMap: Map<string, ImageInfo[]> = CloudGraphHelper.getArtifactsMap(allImagesFromRegistry);
      if (!artifactsMap || artifactsMap.size < 1) {
        logger.info("[CloudGraph] artifacts were not found");
        return;
      }

      logger.info(`[CloudGraph] cloudGraphs lenght: ${cloudGraphs?.length}`);
      const k8SupportedItems = Object.values(k8SupportedTypes).map(value => value.toString());
      for (const cloudGraph of cloudGraphs) {
        try {
          let missingNodes = 0;
          let noImageData = 0;
          let imageMatches = 0;
          const alreadyAnalyzedImagesWithHashes = new Set();
          const dotGraph = await DotGraph.decodeAndParseGraph<CloudGraphNode>(cloudGraph?.dot);
          if (!dotGraph?.nodes) {
            logger.error(`[CloudGraph] dotGraph.nodes empty, aws_account: ${cloudGraph?.aws_account}`);
            missingNodes++;
            continue;
          }
          const totalFilteredNodes = dotGraph.nodes.filter(i => k8SupportedItems.includes(i?.type));
          logger.info(`[CloudGraph] total ks supported nodes: ${totalFilteredNodes?.length}`);
          if (!totalFilteredNodes) {
            continue;
          }

          totalFilteredNodes.forEach(node => {
            try {
              if (!k8SupportedItems.includes(node?.type) || !node?.image_id?.length) {
                //logger.error(`[CloudGraph] node doesn't have image id, type: ${node?.type}`);
                return;
              }

              let cloudImageIds: CloudImageId[] = CloudGraphHelper.decodeImageId(node?.image_id);
              for (const cloudImageId of cloudImageIds) {
                if (!cloudImageId?.name) {
                  logger.error(`[CloudGraph] Failed to get image name, imageId: ${node?.image_id}`);
                  noImageData++;
                  continue;
                }

                //logger.info(`[CloudGraph] imageName: ${cloudImageId?.name} sha: ${cloudImageId?.hash}, tag: ${cloudImageId?.tag}`);

                let [potentialImages, specificMatch] = CloudGraphHelper.getPotentialImages(
                  artifactsMap,
                  cloudImageId.name,
                  cloudImageId.hash,
                  cloudImageId.tag,
                );
                if (!potentialImages || potentialImages.length < 1) {
                  //logger.info(`[CloudGraph] no image found for ${cloudImageId?.name})`);
                  continue;
                }

                //if we failed to match by tag or hash, just use one random image to add SF to
                if (!specificMatch) {
                  potentialImages = [potentialImages[0]];
                }

                imageMatches++;
                for (const potentialImage of potentialImages) {
                  logger.info(`[CloudGraph] found image for ${cloudImageId.name} (${cloudImageId.hash}) (${cloudImageId.tag})`);

                  let consoleLink = fullyDecodeURI(node?.console_url);
                  consoleLink = consoleLink == "undefined" ? "" : consoleLink;

                  const imageKey: string =
                    cloudImageId.name +
                    "_" +
                    (cloudImageId.hash || "") +
                    "_" +
                    (node?.cluster || "") +
                    "_" +
                    (node?.region || "") +
                    "_" +
                    (node?.platform || "");
                  if (cloudImageId.hash && specificMatch && !alreadyAnalyzedImagesWithHashes.has(imageKey)) {
                    alreadyAnalyzedImagesWithHashes.add(imageKey);
                    CloudGraphHelper.addCloudItemToArtifactManager(node, consoleLink, cloudImageId.hash, cloudGraph?.aws_account);
                  }

                  CloudGraphHelper.extendImageDetails(potentialImage, node, consoleLink);
                  CloudGraphHelper.addSeverityFactorsToArtifact(potentialImage, dotGraph, node, cloudImageId.name, consoleLink);
                }
              }
            } catch (err) {
              logger.error(`[CloudGraph]: Failed to process node: ${err}`, err);
            }
          });

          logger.info(
            `[CloudGraph] finish get total data: ${cloudGraphs?.length}, missingNodes: ${missingNodes}, noImageData: ${noImageData}
            dotGraph.nodes: ${dotGraph?.nodes?.length}, totalFiltereNodes: ${totalFilteredNodes?.length}, imageMatches: ${imageMatches}`,
          );
        } catch (err) {
          logger.error(`[CloudGraph] Failed to parse cloud graph: ${err}`, err);
        }
      }
    } catch (err) {
      logger.error(`[CloudGraph] failed attachCloudGraphInfo, err:${err}`, err);
    }
  }
}

export default CloudGraphHelper;
