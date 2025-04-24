import { Application } from "../../appmgr/application";
import {
  AppFlowArtifacts,
  AppFlowCICD,
  AppFlowCloud,
  AppFlowKubernetes,
  AppFlowOrchestrator,
  AppFlowType,
  FoundByItem,
  FoundLocation,
  HahsType,
} from "../../entitis/applicationsFlowTypes";
import {
  Artifactory,
  ArtifactorySecEventSystem,
  ArtifactorySecEventType,
  guessArtifactSystem,
  guessArtifactType,
} from "../../entitis/ArtifactTypes";
import { CICD, CICDJob, getCICDProvider, getCICDType } from "../../entitis/cicidRepoTypes";
import { AWSserviceTypes, CloudProviderType, getCloudProviderSubType, getCloudProviderType } from "../../entitis/cloudTypes";
import { Repo } from "../../entitis/codeRepoTypes";
import Constant from "../../entitis/constant";
import { getKubernetesSubSystem } from "../../entitis/kubernetesTypes";
import { getOrchestratorSystem, OrchestratorSystem } from "../../entitis/orchestratorTypes";
import { EvalRepoPolicyRes } from "../../entitis/reportTypes";
import loggerImport from "../../logger";
import { isDevelopment, isLocalDevelopment } from "../envUtils";
import { getHashType } from "../hash";
import StatesHelper from "../statesHelper";
const path = require("path");
const logger = loggerImport.getDebugLogger();

export function mergeCICDForAppFlow(app: Application) {
  try {
    //Set default
    app.appInfo.cicd.cicdAppFlow = [];

    const repo: Repo = app.appInfo.repo.code_repo;
    //Set default with what we found in repo based on files
    app.appInfo.cicd.cicdAppFlow = repo.cicdInfo;
    const existingCICDtools: AppFlowCICD[] = app.appInfo.cicd.cicdAppFlow;

    if (app.appInfo.cicd.repositories) {
      const system = getCICDProvider(app.appInfo.cicd.repositories.toolName);
      //Check if Gitlab\Github already there
      let item = existingCICDtools.find(i => i.system.toLowerCase() === system.toLowerCase());
      if (!item) {
        item = new AppFlowCICD();
        item.system = system;
        existingCICDtools.push(item);
      }

      const sortedJobsByPipeline: CICDJob[] = app.appInfo.cicd.jobs.sort((a, b) => a.pipelineDiffInTime - b.pipelineDiffInTime);

      if (sortedJobsByPipeline.length > 0) {
        const c: FoundLocation = new FoundLocation();
        c.foundBy = getCICDType("Pipeline");
        c.foundIn = sortedJobsByPipeline[0].pipelineId
          ? `${Constant.PipelineName} - ${sortedJobsByPipeline[0].pipelineId}`
          : Constant.PipelineName;

        c.link = sortedJobsByPipeline[0].pipelineLink ? sortedJobsByPipeline[0].pipelineLink : "";
        c.runBy = sortedJobsByPipeline[0].username ? `${sortedJobsByPipeline[0].username}` : "";

        item.lastMonthJobCount = getLastMonthJobsCount(app.appInfo.cicd.jobs).length.toString();
        item.latestDate = sortedJobsByPipeline[0].startTime ? sortedJobsByPipeline[0].startTime : "Not Executed";
        item.location.push(c);
      }
    }

    if (existingCICDtools.length > 1) {
      //Remove generic if there are other cicd
      const newCICDTools = [];
      existingCICDtools.forEach(i => {
        if (i.system.toLowerCase() !== "generic") {
          newCICDTools.push(i);
        } else {
          logger.debug(`removing generic cicd from app flow for app: ${app.appInfo.repo.code_repo.fullName}`);
        }
      });

      if (newCICDTools.length > 0) {
        app.appInfo.cicd.cicdAppFlow = newCICDTools;
      }
    }

    app.appInfo.cicd.cicdAppFlow =
      app.appInfo.cicd.cicdAppFlow.length > 10 ? app.appInfo.cicd.cicdAppFlow.slice(0, 10) : app.appInfo.cicd.cicdAppFlow;
  } catch (err) {
    logger.error(`failed merge CICD for app flow, err: ${err}`);
  }
}

export function mergeOrchestratorAppFlow(app: Application) {
  let repo: Repo;
  try {
    //Set default
    app.appInfo.orchestrator.orchestratorsAppFlow = [];

    const jobs: CICDJob[] = app.appInfo.cicd.jobs;
    repo = app.appInfo.repo.code_repo;

    //From repo files
    repo.orchestrator.forEach(i => {
      try {
        const system = getOrchestratorSystem(i.name);
        if (!system) {
          logger.error(`failed get orchestrator sub system for repo info, system: ${i.name}`);
          return;
        }

        const appFlowOrchestrator: AppFlowOrchestrator = new AppFlowOrchestrator();
        appFlowOrchestrator.system = system;
        appFlowOrchestrator.hash = "";
        appFlowOrchestrator.size = i.size ? Number(i.size) : 0;
        if (isNaN(appFlowOrchestrator.size)) {
          appFlowOrchestrator.size = 0;
        }
        appFlowOrchestrator.hashType = "";
        appFlowOrchestrator.name = i.name;
        appFlowOrchestrator.date = "";

        const foundLocation: FoundLocation = new FoundLocation();
        foundLocation.foundIn = `${Constant.DeploymentFile} - ${i.fileName}`;
        foundLocation.link = i.link.replace("sha256:", "");
        foundLocation.foundBy = FoundByItem.File;
        appFlowOrchestrator.location.push(foundLocation);
        app.appInfo.orchestrator.orchestratorsAppFlow.push(appFlowOrchestrator);
      } catch (err) {
        logger.error(`failed merge single orchestrator for app flow, repo: ${repo.fullName}, item: ${JSON.stringify(i)} err: ${err}`);
      }
    });

    //From CICD(Without helm)
    const jobsWithArtifacts = jobs.filter(i => i.parsedArtifacts.length > 0);
    const lastJobsWithArtifact = jobsWithArtifacts.sort((a, b) => a.pipelineDiffInTime - b.pipelineDiffInTime);

    const singleJobArtifact = [];
    if (lastJobsWithArtifact.length > 0) {
      singleJobArtifact.push(lastJobsWithArtifact[0]);
    }
    singleJobArtifact.forEach(job => {
      try {
        job.parsedArtifacts.forEach(artifact => {
          try {
            if (artifact.type.toLowerCase() === AppFlowType.Kubernetes.toLowerCase()) {
              return;
            }
            //No need to put log hear not all artifacts are orchestrators
            const system = getOrchestratorSystem(artifact.type);
            if (!system) {
              return;
            }
            //Ignore helm in this case
            if (system === OrchestratorSystem.Helm) {
              return;
            }

            if (!job.buildName || !job.buildUrl) {
              logger.error(
                `failed get build name: ${job.buildName} or build url: ${job.buildUrl} for artifact type: ${artifact.type}, repo: ${app.appInfo.repo.code_repo.fullName}`,
              );
              return;
            }

            //Add file name to cicd
            const appFlowOrchestrator: AppFlowOrchestrator = new AppFlowOrchestrator();
            appFlowOrchestrator.system = system;
            appFlowOrchestrator.hash = "";
            appFlowOrchestrator.size = artifact.size ? Number(artifact.size) : 0;
            if (isNaN(appFlowOrchestrator.size)) {
              appFlowOrchestrator.size = 0;
            }
            appFlowOrchestrator.date = job.startTime;

            const foundLocation: FoundLocation = new FoundLocation();
            foundLocation.foundIn = `${Constant.BuildName} - ${job.buildName}`;
            foundLocation.link = job.buildUrl;
            foundLocation.runBy = job.username ? `${job.username}` : "";
            foundLocation.foundBy = FoundByItem.Pipeline;
            appFlowOrchestrator.location.push(foundLocation);
            app.appInfo.orchestrator.orchestratorsAppFlow.push(appFlowOrchestrator);
          } catch (err) {
            logger.error(
              `failed merge single orchestrator in artifact for app flow, repo: ${repo.fullName}, item: ${JSON.stringify(
                artifact,
              )} err: ${err}`,
            );
          }
        });
      } catch (err) {
        logger.error(
          `failed merge single orchestrator in job for app flow, repo: ${repo.fullName}, item: ${JSON.stringify(job)} err: ${err}`,
        );
      }
    });

    app.appInfo.orchestrator.orchestratorsAppFlow =
      app.appInfo.orchestrator.orchestratorsAppFlow.length > 10
        ? app.appInfo.orchestrator.orchestratorsAppFlow.slice(0, 10)
        : app.appInfo.orchestrator.orchestratorsAppFlow;
  } catch (err) {
    logger.error(`failed merge orchestrator for app flow, repo: ${repo.fullName} err: ${err}`);
  }
}

export function mergeKubernetesAppFlow(app: Application) {
  let repo: Repo;
  try {
    //Set default
    app.appInfo.kubernetes.kubernetesAppFlow = [];

    repo = app.appInfo.repo.code_repo;

    const unique = new Set();

    //From repo files
    repo.kubernetes.forEach(i => {
      try {
        //Skip duplication
        if (unique.has(i.subType)) {
          return;
        }
        const subType = getKubernetesSubSystem(i.subType);
        if (!subType) {
          return;
        }

        const appFlowKubernetes: AppFlowKubernetes = new AppFlowKubernetes();
        appFlowKubernetes.system = AppFlowType.Kubernetes;
        appFlowKubernetes.hash = i.hash;
        appFlowKubernetes.hashType = i.hashType;
        appFlowKubernetes.name = i.name;
        appFlowKubernetes.date = "";
        appFlowKubernetes.subType = subType;
        appFlowKubernetes.size = i.size ? Number(i.size) : 0;
        if (isNaN(appFlowKubernetes.size)) {
          appFlowKubernetes.size = 0;
        }

        const foundLocation: FoundLocation = new FoundLocation();
        foundLocation.foundIn = `${Constant.DeploymentFile} - ${path.basename(i.fileName)}`;
        foundLocation.link = i.link;
        foundLocation.foundBy = FoundByItem.File;
        appFlowKubernetes.location.push(foundLocation);
        app.appInfo.kubernetes.kubernetesAppFlow.push(appFlowKubernetes);
      } catch (err) {
        logger.error(`failed merge single kubernetes for app flow, repo: ${repo.fullName}, item: ${JSON.stringify(i)} err: ${err}`);
      }
    });

    app.appInfo.kubernetes.kubernetesAppFlow =
      app.appInfo.kubernetes.kubernetesAppFlow.length > 10
        ? app.appInfo.kubernetes.kubernetesAppFlow.slice(0, 10)
        : app.appInfo.kubernetes.kubernetesAppFlow;
  } catch (err) {
    logger.error(`failed merge kubernetes for app flow, repo: ${repo.fullName} err: ${err}`);
  }
}

export function mergeArtifactsForAppFlow(app: Application) {
  try {
    const cicd: CICD = app.appInfo.cicd;
    const artifactory: Artifactory = app.appInfo.artifactory;
    const repo: Repo = app.appInfo.repo.code_repo;

    if (repo.artifacts.length > 0) {
      artifactory.artifactsAppFlow = repo.artifacts;
      return;
    }

    //Set default
    artifactory.artifactsAppFlow = [];

    const uniqueArtifacts = new Set();

    //From registry
    for (const image of artifactory.registryImage) {
      try {
        const unique = image.image.imageDigest ? image.image.imageDigest : image.image.name;
        if (!unique) {
          continue;
        }
        //Remove duplicates
        if (uniqueArtifacts.has(unique)) {
          continue;
        }
        uniqueArtifacts.add(unique);

        const appFlowArtifacts: AppFlowArtifacts = new AppFlowArtifacts();
        appFlowArtifacts.subType = ArtifactorySecEventType.Docker;
        appFlowArtifacts.system = guessArtifactSystem(image.image.name);
        if (!appFlowArtifacts.subType) {
          logger.error(
            `failed get subType or system for image (system)name: ${image.image.name}, (subType)artifactMediaType: ${image.image.artifactMediaType}, repo: ${app.appInfo.repo.code_repo.fullName}`,
          );
          continue;
        }

        if (appFlowArtifacts.system === ArtifactorySecEventSystem.Generic) {
          appFlowArtifacts.system = getArtifactSystem(image.image.name);
        }

        appFlowArtifacts.name = image.image.name;
        appFlowArtifacts.size = image.image.imageSizeInBytes;
        if (isNaN(appFlowArtifacts.size)) {
          appFlowArtifacts.size = 0;
        }
        appFlowArtifacts.hashType = HahsType.sha256;
        appFlowArtifacts.hash = image.image.imageDigestWithoutPrefix;
        appFlowArtifacts.date = image.image.imagePushedAt;

        const foundLocation: FoundLocation = new FoundLocation();
        foundLocation.link = image.image.link;
        foundLocation.foundBy = FoundByItem.Registry;
        foundLocation.foundIn = image.image.repositoryName
          ? `${image.image.cloudEnv} Registry Name - ${image.image.repositoryName}`
          : "Registry";
        foundLocation.runBy = "";
        appFlowArtifacts.location.push(foundLocation);

        artifactory.artifactsAppFlow.push(appFlowArtifacts);
      } catch (err) {
        logger.error(
          `failed merge single artifact for app flow by image: ${image.image.name}, repo: ${app.appInfo.repo.code_repo.fullName} err: ${err}`,
        );
      }
    }

    //From Security Event
    let totalAddedFromSecEvents = 0;
    for (const securityEvent of artifactory.securityEvents) {
      try {
        if (!securityEvent.artifacts) {
          continue;
        }

        const unique = securityEvent.artifacts.sha ? securityEvent.artifacts.sha : securityEvent.artifacts.dockerFileInRunTime;
        if (!unique) {
          continue;
        }
        //Remove duplicates
        if (uniqueArtifacts.has(unique) && uniqueArtifacts.has(`sha256:${unique}`)) {
          continue;
        }
        if (uniqueArtifacts.has(unique)) {
          uniqueArtifacts.add(unique);
        }
        if (uniqueArtifacts.has(`sha256:${unique}`)) {
          uniqueArtifacts.add(`sha256:${unique}`);
        }

        const appFlowArtifacts: AppFlowArtifacts = new AppFlowArtifacts();
        appFlowArtifacts.system = securityEvent.artifacts.system;
        appFlowArtifacts.subType = securityEvent.artifacts.subType;

        if (appFlowArtifacts.system === ArtifactorySecEventSystem.Generic) {
          continue;
        }

        if (!appFlowArtifacts.subType || !appFlowArtifacts.system) {
          logger.error(
            `failed get subType or system for sec alert, dockerFileInRunTime: ${securityEvent.artifacts.dockerFileInRunTime}, system: ${securityEvent.artifacts.system}, sub type: ${securityEvent.artifacts.subType}`,
          );
          continue;
        }

        appFlowArtifacts.name = securityEvent.artifacts.dockerFileInRunTime;
        appFlowArtifacts.hash = securityEvent.artifacts.sha;
        appFlowArtifacts.size = 0;

        if (appFlowArtifacts.hash) {
          appFlowArtifacts.hashType = getHashType(appFlowArtifacts.hash);
        }
        appFlowArtifacts.date = securityEvent.artifacts.imageCreatedAt;

        const foundLocation: FoundLocation = new FoundLocation();
        foundLocation.link = securityEvent.artifacts.linkToRegistry;
        foundLocation.foundBy = FoundByItem.SecurityEvent;
        foundLocation.foundIn = `Security Provider - ${securityEvent.securityProvider}`;
        foundLocation.runBy = "";
        appFlowArtifacts.location.push(foundLocation);

        artifactory.artifactsAppFlow.push(appFlowArtifacts);
        totalAddedFromSecEvents++;
      } catch (err) {
        logger.error(
          `failed merge single artifact for app flow by sec event: ${JSON.stringify(securityEvent)}, repo: ${
            app.appInfo.repo.code_repo.fullName
          } err: ${err}`,
        );
      }
    }

    app.appInfo.artifactory.artifactsAppFlow =
      app.appInfo.artifactory.artifactsAppFlow.length > 10
        ? app.appInfo.artifactory.artifactsAppFlow.slice(0, 10)
        : app.appInfo.artifactory.artifactsAppFlow;
  } catch (err) {
    logger.error(`failed merge artifacts for app flow, err: ${err}`);
  }
}

export function mergeCloudAppFlow(app: Application) {
  const repo: Repo = app.appInfo.repo.code_repo;

  try {
    const unique = new Set();

    //Set default
    app.appInfo.cloud.cloudAppFlow = [];

    //From Artifacts
    const added = createAppFlowsForImages(app);
    //if (added) {
    //  return;
    //}

    //From Runtime
    for (const cloudResource of app.appInfo.cloud.containerImage) {
      try {
        const type = getCloudProviderType(cloudResource.cloudEnv);
        const subType = getCloudProviderSubType(cloudResource.objTypeStr);
        if (!subType || !type) {
          // logger.warn(
          //   `failed to find type: ${type} for ${cloudResource.cloudEnv} or sub type: ${cloudResource.objTypeStr} in cloud runtime findings, repo: ${repo.fullName}`,
          // );
          continue;
        }

        let name = "";
        if ("containerImageInfo" in cloudResource) {
          name = `${cloudResource.containerImageInfo.name}`;
        } else if (subType === AWSserviceTypes.lambda) {
          name = `${cloudResource["imageNameWithoutTag"]}`;
        }

        if (!name) {
          logger.error(`failed to find name: ${name} in cloud runtime findings, repo: ${repo.fullName}`);
          continue;
        }

        const appFlowCloud: AppFlowCloud = new AppFlowCloud();
        appFlowCloud.type = type;
        appFlowCloud.system = type;
        appFlowCloud.subType = subType;
        appFlowCloud.name = name;
        if (!cloudResource.imageDigestWithoutPrefix) {
          appFlowCloud.hashType = getHashType(cloudResource.imageDigestWithoutPrefix);
          appFlowCloud.hash = cloudResource.imageDigestWithoutPrefix;
        }

        const foundLocation: FoundLocation = new FoundLocation();
        foundLocation.foundIn = `${FoundByItem.RunTime} - ${appFlowCloud.name}`;
        foundLocation.link = cloudResource.link.replace("sha256:", "");
        foundLocation.foundBy = FoundByItem.RunTime;
        appFlowCloud.location.push(foundLocation);

        unique.add(appFlowCloud.subType);
        app.appInfo.cloud.cloudAppFlow.push(appFlowCloud);
      } catch (err) {
        logger.error(
          `failed merge single cloud resource for app flow, repo: ${repo.fullName}, item: ${JSON.stringify(cloudResource)} err: ${err}`,
        );
      }
    }

    //From Repo
    for (const prop in repo.cloudDeployments) {
      try {
        const c = repo.cloudDeployments as any;
        if (!c[prop].length) {
          continue;
        }
        if (c[prop].length == 0) {
          continue;
        }

        const items = c[prop];
        items.forEach(item => {
          try {
            const type = getCloudProviderType(item.type);
            const subType = getCloudProviderSubType(item.subType);
            if (!subType || !type) {
              // logger.warn(
              //   `failed to find type: ${type} for ${item.type} or sub type: ${subType} for: ${item.subType} in repo cloud findings, repo: ${repo.fullName}`,
              // );
              return;
            }
            if (!item.name || !item.link) {
              logger.error(`failed to find name: ${item.name} or link: ${item.link} in repo cloud findings, repo: ${repo.fullName}`);
              return;
            }
            if (unique.has(subType)) {
              return;
            }

            const appFlowCloud: AppFlowCloud = new AppFlowCloud();
            appFlowCloud.type = type;
            appFlowCloud.system = type;
            appFlowCloud.subType = subType;
            appFlowCloud.name = item.name;

            const foundLocation: FoundLocation = new FoundLocation();
            foundLocation.foundIn = `${Constant.DeploymentFile} - ${path.basename(item.link)}`;
            foundLocation.link = item.link;
            foundLocation.foundBy = FoundByItem.File;
            appFlowCloud.location.push(foundLocation);
            app.appInfo.cloud.cloudAppFlow.push(appFlowCloud);
          } catch (err) {
            logger.error(
              `failed merge single cloud from repo for app flow, repo: ${repo.fullName}, item: ${JSON.stringify(item)} err: ${err}`,
            );
          }
        });
      } catch (err) {
        logger.error(`failed merge all cloud from repo for app flow, repo: ${repo.fullName} err: ${err}`);
      }
    }

    //From security findings
    for (const cloudResource of app.appInfo.cloud.cloud) {
      try {
        const type = getCloudProviderType(cloudResource.cloudEnv);
        const subType = getCloudProviderSubType(cloudResource.cloudService);
        if (!subType || !type) {
          //Debug
          // logger.warn(
          //   `failed to find type: ${type} for ${cloudResource.cloudEnv} or sub type: ${subType} for: ${cloudResource.cloudService} in cloud resource findings, repo: ${repo.fullName}`,
          // );
          continue;
        }
        const name = `${cloudResource.region} ${cloudResource.resource}`;
        if (!name) {
          logger.error(`failed to find name: ${name} in cloud resource findings, repo: ${repo.fullName}`);
          continue;
        }
        if (unique.has(subType)) {
          continue;
        }

        const appFlowCloud: AppFlowCloud = new AppFlowCloud();
        appFlowCloud.type = type;
        appFlowCloud.system = type;
        appFlowCloud.subType = subType;
        appFlowCloud.name = name;
        appFlowCloud.account = cloudResource.account;

        const foundLocation: FoundLocation = new FoundLocation();
        foundLocation.foundIn = `${FoundByItem.RunTime} - ${name}`;
        foundLocation.foundBy = FoundByItem.RunTime;
        appFlowCloud.location.push(foundLocation);

        unique.add(appFlowCloud.subType);
        app.appInfo.cloud.cloudAppFlow.push(appFlowCloud);
      } catch (err) {
        logger.error(
          `failed merge single cloud resource for app flow, repo: ${repo.fullName}, item: ${JSON.stringify(cloudResource)} err: ${err}`,
        );
      }
    }

    app.appInfo.cloud.cloudAppFlow =
      app.appInfo.cloud.cloudAppFlow.length > 10 ? app.appInfo.cloud.cloudAppFlow.slice(0, 10) : app.appInfo.cloud.cloudAppFlow;
  } catch (err) {
    logger.error(`failed set all flows cloud for repo: ${repo.fullName}, err: ${err}`);
  }
}

export function getArtifactSystem(name: string) {
  const index = name.indexOf("/");
  if (index != -1) {
    const res = name.substring(0, index);
    return res;
  } else {
    return name;
  }
}

function createAppFlowsForImages(app: Application) {
  let added = false;

  const shouldRun = isDevelopment() || isLocalDevelopment() || StatesHelper.Instance.isEKSEnabled;
  if (!shouldRun) {
    return false;
  }

  try {
    const artifactory: Artifactory = app.appInfo.artifactory;

    //From registry
    const unique = new Set();
    for (const image of artifactory.registryImage) {
      try {
        if (!image.image.imageRunningInCloud) {
          continue;
        }

        if (!image.image?.workloadInfo || image.image.workloadInfo.length === 0) {
          continue;
        }

        let u = image.image.imageDigestWithoutPrefix;
        if (!u) {
          image.image.name;
        }

        if (unique.has(u)) {
          continue;
        }
        unique.add(u);

        for (const workloadInfo of image.image.workloadInfo) {
          if (!workloadInfo?.k8sType) {
            logger.warn(`failed find k8sType: ${workloadInfo.k8sType} for image: ${image.image.name}`);
          }
          const type = getCloudProviderType(CloudProviderType.AWS);
          const subType = getCloudProviderSubType(workloadInfo?.k8sType.toLowerCase());
          if (!subType || !type) {
            logger.warn(`failed to find type: ${type} sub type: ${subType} for image: ${image.image.name}`);
            continue;
          }
          const appFlowCloud: AppFlowCloud = new AppFlowCloud();
          appFlowCloud.type = type;
          appFlowCloud.imageName = image.image.name;
          appFlowCloud.system = type;
          appFlowCloud.subType = subType;
          appFlowCloud.cluster = workloadInfo?.cluster;
          appFlowCloud.region = workloadInfo?.region;
          appFlowCloud.k8sType = workloadInfo?.k8sType;
          appFlowCloud.hash = image.image.imageDigestWithoutPrefix;
          appFlowCloud.date = image.image.imagePushedAt;
          appFlowCloud.hashType = HahsType.sha256;

          const foundLocation: FoundLocation = new FoundLocation();
          foundLocation.foundIn = `${FoundByItem.RunTime} - ${appFlowCloud?.k8sType}`;
          foundLocation.link = workloadInfo?.consoleLink;
          foundLocation.foundBy = FoundByItem.RunTime;

          if (!appFlowCloud?.k8sType) {
            foundLocation.foundIn = `${FoundByItem.RunTime}`;
          }

          appFlowCloud.location.push(foundLocation);
          app.appInfo.cloud.cloudAppFlow.push(appFlowCloud);
          added = true;
        }
      } catch (err) {
        logger.error(
          `failed merge single cloud for app flow by image: ${image.image.name}, repo: ${app.appInfo.repo.code_repo.fullName} err: ${err}`,
        );
      }
    }
  } catch (err) {
    logger.error(`failed merge all cloud, repo: ${app.appInfo.repo.code_repo.fullName} err: ${err}`);
  }

  return added;
}

export function getAppFlow(app: EvalRepoPolicyRes) {
  //Expect to get array
  const res = {
    cloudDeployments: app.cloud.cloudAppFlow,
    repository: app.repository.repoAppFlow,
    artifacts: app.artifacts.artifactsAppFlow,
    orchestrators: app.orchestrator.orchestratorsAppFlow,
    kubernetes: app.kubernetes.kubernetesAppFlow,
    cicdInfo: app.cicd.cicdAppFlow,
  };
  return res;
}

function getLastMonthJobsCount(jobs: CICDJob[]) {
  try {
    const month = 1000 * 60 * 60 * 24 * 30;
    const lastMonthJobs = jobs.filter(i => i.diffTime < month);
    return lastMonthJobs;
  } catch (err) {
    logger.error(`failed get last month jobs, err: ${err}`);
  }
  return [];
}
