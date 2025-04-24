import { Application } from "../../appmgr/application";
import cacheDB from "../../cache/cache-db/service";
import { AzureCI, RepoType } from "../../entitis/cicdTypes";
import { File, getTFSRepo, getTFSRepoNameFromBranch, Repo, SecurityEvent } from "../../entitis/codeRepoTypes";
import { SecInfra } from "../../entitis/reportTypes";
import { getStringFromEnumSecInfra, ToolNameForUI } from "../../entitis/tool/toolsTypes";
import loggerImport from "../../logger";
import { AppToolCoverage, AppToolCoverageSource, AppToolCoverageSourceType } from "../../policy/reporting/types";
import SecurityToolsHelper from "../tools/securityToolsHelper";

const fs = require("fs");

const logger = loggerImport.getDebugLogger();

export class CheckmarxToolSecEvent {
  toolType: string;
  toolName: string;
  link: string;
}

export class ImportedSecTemplate {
  text: string;
  project: string;
}

class CheckmarxCLIparser {
  private static _instance: CheckmarxCLIparser;
  public static get Instance() {
    return this._instance || (this._instance = new this());
  }

  private constructor() {}

  //
  // Cache related data
  //
  orgName: string = "";
  collectionName = "azureci";

  checmarxProject = new Map<string, AzureCI[]>();
  projectToRepoName = new Map<string, string>();

  repoNameToSecurityApp = new Map<string, AppToolCoverage[]>();

  regexToExtractCheckmarxProject = new RegExp("\\$\\(build\\.sourcesdirectory\\) -n (.+) -p");
  regexToExtractCheckmarxProjectJob = new RegExp("-n (.+) -p");
  regexToExtractCheckmarxProjectProjectName = new RegExp("projectname: '(.+)'");
  regexToExtractCheckmarxProjectFromLocalRepo = new RegExp("checkmarx-project-name\\s*[\\r\\n]+\\s*value:\\s*(.+)[\\r\\n]");

  fileNameToYamlSec = new Map<string, ImportedSecTemplate>();
  regexToExtractSecYmlFile = new RegExp("template:(.+)@");
  noRepoProject = {};

  scanOrgs: string[] = [];

  private getCache() {
    if (this.orgName === "") {
      const cantUseCache = async () => {
        logger.debug(`Please call associateCheckmarxCLIToOrgName to use cache`);
      };

      return {
        createIndex: cantUseCache,
        set: cantUseCache,
        replace: cantUseCache,
        get: cantUseCache,
      };
    }
    return {
      createIndex: async () => {
        try {
          let indexCreated = await cacheDB.cindex.execute(this.orgName, this.collectionName, {
            repoId: 1,
            repoName: 1,
          });
          if (indexCreated) {
            logger.warn(`CheckmarxCLIparser: failed to create index, trying again`);
            indexCreated = await cacheDB.cindex.execute(this.orgName, this.collectionName, { repoId: 1, repoName: 1 });
          }
          if (!indexCreated) {
            logger.error(`CheckmarxCLIparser: failed to create index after retry`);
          }
        } catch (err) {
          logger.error(`CheckmarxCLIparser: failed to create index, err: ${err}`);
        }
      },

      set: async (az: AzureCI) => {
        try {
          await cacheDB.set.execute<AzureCI>(this.orgName, this.collectionName, az);
        } catch (err) {
          logger.error(`CheckmarxCLIparser cache set failed: ${err}`);
        }
      },

      get: async (repoName: string) => {
        try {
          return await cacheDB.get.execute<Partial<AzureCI>>(this.orgName, "job-info", {
            repoName: repoName,
          });
        } catch (err) {
          logger.error(`CheckmarxCLIparser cache get failed: ${err}`);
        }

        return null;
      },
    };
  }

  async associateCheckmarxCLIToOrgName(orgName: string) {
    this.orgName = orgName;
    await this.getCache().createIndex();
  }

  initCheckmarxCLI(repos: Repo[]) {
    try {
      logger.info(`checkmarx, projects based on cicd ${JSON.stringify(this.checmarxProject)}`);

      logger.info(
        `checkmarx, repoName to security count: ${Object.keys(this.repoNameToSecurityApp).length} app ${JSON.stringify(
          this.repoNameToSecurityApp,
        )}`,
      );

      this.examineSecDeploymentRepo(repos);

      for (const repo of repos) {
        try {
          for (const file of repo.deploymentFilesYmls) {
            try {
              //Found possible file where connection for alerts can be done
              const text = fs.readFileSync(file.path, "utf8").toLowerCase();
              const fileNameToLower = file.fileNameWithoutDisk.toLowerCase();

              //Example --> template: security_and_config_casino_game_rise_of_the_pharaohs_extreme_reels.yml@templates
              const r = text.match(this.regexToExtractSecYmlFile);
              if (r) {
                repo.importSecurityTemplateYml[r[1].trim()] = {
                  file: file,
                  text: text,
                };
              }

              for (const [name, entry] of Object.entries(this.fileNameToYamlSec)) {
                const e: ImportedSecTemplate = entry;
                if (text.includes(name.toLowerCase()) && this.fileNameToYamlSec[fileNameToLower] == undefined) {
                  repo.importSecurityTemplateYml[e.project] = {
                    file: file,
                    text: text,
                    importedText: e.text,
                  };
                }
              }
            } catch (err) {
              logger.error(
                `checkmarx, failed add single file: ${file.path} in single repo: ${repo.fullName} in init checkmarx CLI parser, err: ${err}`,
              );
            }
          }

          if (Object.values(repo.importSecurityTemplateYml).length > 0) {
            this.addProjectNameToRepoCollection(repo);
          }
        } catch (err) {
          logger.error(`checkmarx, failed add single repo: ${repo.fullName} in init checkmarx CLI parser, err: ${err}`);
        }
      }
    } catch (err) {
      logger.error(`checkmarx, failed init checkmarx CLI parser, err: ${err}`);
    }
  }

  async tryParseSingleAzureBuildLog(buildContent: string, build: any, project: any) {
    try {
      if (buildContent.includes("checkmarx")) {
        const projectName = this.getProjectNameFromText(buildContent).trim();
        if (projectName) {
          const index = projectName.indexOf("-p");
          if (index != -1) {
            const p = projectName.substring(0, index).trim();
            await this.setCheckmarxRepo(p, build, buildContent);
          } else {
            await this.setCheckmarxRepo(projectName, build, buildContent);
          }
        } else {
          const index = buildContent.indexOf("project name:");
          if (index != -1) {
            const sub = buildContent.substring(index + "project name:".length, buildContent.length);
            const index2 = sub.indexOf(",");
            if (index2 != -1) {
              const projectName = sub.substring(0, index2).trim();
              await this.setCheckmarxRepo(projectName, build, buildContent);
            }
          } else {
            const index = buildContent.indexOf("projectname:");
            if (index != -1) {
              const sub = buildContent.substring(index + "projectname:".length, buildContent.length);
              const index2 = sub.indexOf(",");
              if (index2 != -1) {
                const projectName = sub.substring(0, index2).trim();
                await this.setCheckmarxRepo(projectName, build, buildContent);
              }
            }
          }
        }
      }
      return buildContent;
    } catch (err) {
      logger.error(`failed get single AzureCI logs for single build, project: ${project.name} err: ${err}`);
    }
    return null;
  }

  //Attach to app for filters
  attachTemplateSecurityForAllApps(apps: Application[]) {
    const stats = {
      added: new Set(),
      notAdded: new Set(),
    };

    apps.forEach(app => this.attachTemplateSecurity(app, stats));

    logger.info(
      `finish attach all templates security to all app, stats: added ${stats.added.size}, not added: ${
        stats.notAdded.size
      }, add info: ${Array.from(stats.added).join(", ")}, not add info: ${Array.from(stats.notAdded).join(", ")}`,
    );
  }

  getAppToolCoverageFromAlerts(app: Application) {
    const possibleNewItems: AppToolCoverage[] = [];
    try {
      const securityEvents: SecurityEvent[] = app?.appInfo?.repo?.securityEvents;
      if (!securityEvents) {
        return [];
      }

      const sast: SecurityEvent = securityEvents.find(i => i.securityProvider.toLowerCase() === ToolNameForUI.cxsast.toLowerCase());
      if (sast) {
        const appToolCoverage: AppToolCoverage = new AppToolCoverage();
        appToolCoverage.coverage = true;
        appToolCoverage.oxDelivered = false;
        appToolCoverage.toolName = ToolNameForUI.cxsast;
        appToolCoverage.type = SecInfra.SAST.toLowerCase();
        const source: AppToolCoverageSource = new AppToolCoverageSource();
        source.match = "";
        source.type = AppToolCoverageSourceType.Alert;
        appToolCoverage.sources.push(source);

        if (appToolCoverage.validateInfo()) {
          possibleNewItems.push(appToolCoverage);
        }
      }

      const sca: SecurityEvent = securityEvents.find(i => i.securityProvider.toLowerCase() === ToolNameForUI.cxsca.toLowerCase());
      if (sca) {
        const appToolCoverage: AppToolCoverage = new AppToolCoverage();
        appToolCoverage.coverage = true;
        appToolCoverage.oxDelivered = false;
        appToolCoverage.toolName = ToolNameForUI.cxsca;
        appToolCoverage.type = SecInfra.SCA.toLowerCase();
        const source: AppToolCoverageSource = new AppToolCoverageSource();
        source.match = "";
        source.type = AppToolCoverageSourceType.Alert;
        appToolCoverage.sources.push(source);

        if (appToolCoverage.validateInfo()) {
          possibleNewItems.push(appToolCoverage);
        }
      }
    } catch (err) {}
    return possibleNewItems;
  }

  attachTemplateSecurity(app: Application, stats: any) {
    let repoNameToLowerCase = "";
    try {
      const repo: Repo = app.appInfo.repo.code_repo;
      repoNameToLowerCase = repo.fullName.toLowerCase();

      if (!repo.realRepo) {
        return;
      }

      let possibleNewItems: AppToolCoverage[] = [];
      const possibleNewItemsFromAlerts: AppToolCoverage[] = this.getAppToolCoverageFromAlerts(app);

      const possibleNewItemsFromYml: AppToolCoverage[] = this.repoNameToSecurityApp[repoNameToLowerCase];
      if (possibleNewItemsFromYml) {
        possibleNewItems = [...possibleNewItemsFromAlerts, ...possibleNewItemsFromYml];
      } else {
        possibleNewItems = possibleNewItemsFromAlerts;
      }

      let added = false;
      possibleNewItems.forEach(possibleNewItem => {
        const res = SecurityToolsHelper.addToToolCoverage(repo.toolsCoverage, possibleNewItem);
        if (res) {
          added = true;
        }
      });

      if (added) {
        stats.added.add(repo.fullName);
      } else {
        stats.notAdded.add(repo.fullName);
      }

      let neededToAddedNot = true;
      for (const t of repo.toolsCoverage) {
        for (const source of t.sources) {
          if (source.type === AppToolCoverageSourceType.CICD || source.type === AppToolCoverageSourceType.MentionInFile) {
            neededToAddedNot = false;
            break;
          }
        }
      }

      if (neededToAddedNot) {
        logger.info(`added fake info for app: ${repo.fullName}`);

        const appToolCoverageSAST: AppToolCoverage = new AppToolCoverage();
        appToolCoverageSAST.coverage = true;
        appToolCoverageSAST.oxDelivered = false;
        appToolCoverageSAST.toolName = "None";
        appToolCoverageSAST.type = "tools";
        const sourceSAST: AppToolCoverageSource = new AppToolCoverageSource();
        sourceSAST.match = "";
        sourceSAST.type = AppToolCoverageSourceType.MissingCoverageButHaveCICD;
        appToolCoverageSAST.sources.push(sourceSAST);
        repo.toolsCoverage.push(appToolCoverageSAST);

        const appToolCoverageSCA: AppToolCoverage = new AppToolCoverage();
        appToolCoverageSCA.coverage = true;
        appToolCoverageSCA.oxDelivered = false;
        appToolCoverageSCA.toolName = "None";
        appToolCoverageSCA.type = "tools";
        const sourceSCA: AppToolCoverageSource = new AppToolCoverageSource();
        sourceSCA.match = "";
        sourceSCA.type = AppToolCoverageSourceType.MissingCoverageButHaveCICD;
        appToolCoverageSAST.sources.push(sourceSCA);
        repo.toolsCoverage.push(appToolCoverageSAST);
      }
    } catch (err) {
      logger.error(`failed attach all templates security to app: ${repoNameToLowerCase} err: ${err}`);
      stats.notAdded.add(repoNameToLowerCase);
    }
  }

  async updateSecEventsRepoInfo(securityEvents: SecurityEvent[]) {
    let notFoundCount = 0;
    let connectedCount = 0;
    let masterBranch = 0;
    let devBranch = 0;
    let unknownBranch = 0;
    let notFoundFromCICD = new Set();

    try {
      const projectThatNotHaveRepo = new Set();
      const projectThatHaveRepo = new Set();

      for (const securityEvent of securityEvents) {
        try {
          if (
            !securityEvent.securityProvider.toLowerCase().includes("cxsast") &&
            !securityEvent.securityProvider.toLowerCase().includes("cxsca")
          ) {
            continue;
          }

          const repoFullNameToLowerCase = securityEvent.repoFullName.toLowerCase();

          //Init
          let possibleRepoName: string = this.projectToRepoName[repoFullNameToLowerCase];
          let repoName = "";
          if (possibleRepoName) {
            repoName = possibleRepoName;
          }

          const secondTryRepoName: AzureCI[] = this.checmarxProject[repoFullNameToLowerCase];

          if (secondTryRepoName == undefined) {
            //try cache also
            const az = await this.getCache().get(repoFullNameToLowerCase);
            if (az) this.checmarxProject[repoFullNameToLowerCase] = [...az];
          }

          //Take first from cicd
          if (secondTryRepoName != undefined) {
            repoName = secondTryRepoName[0].repoName;
            logger.info(`checkmarx, found a project from cicd, repository name before: ${securityEvent.repoFullName}, after: ${repoName}`);
            if (secondTryRepoName.find(i => i.isMaster) != undefined) {
              masterBranch++;
            } else {
              devBranch++;
            }
          } else {
            //Take from file system
            if (repoName) {
              logger.info(
                `checkmarx, found a project from files, repository name before: ${securityEvent.repoFullName}, after: ${repoName}`,
              );
              notFoundFromCICD.add(repoName);
              unknownBranch++;
            }
          }

          if (!repoName) {
            notFoundCount++;
            projectThatNotHaveRepo.add(securityEvent.repoFullName);
            continue;
          }

          connectedCount++;
          securityEvent.repoFullName = repoName;
          projectThatHaveRepo.add(securityEvent.repoFullName);
        } catch (err) {
          logger.error(`checkmarx, failed to check if repo related to project for single alert, err: ${err}`);
        }
      }

      logger.info(
        `checkmarx finish attach events: attached ${connectedCount}, not attached: ${notFoundCount}, project not found: ${Array.from(
          projectThatNotHaveRepo,
        ).join(", ")} project that have repo: $$$$$$$$$$$$$$$$$, ${Array.from(projectThatHaveRepo).join(
          ", ",
        )} $$$$$$$$$$$$$$$$$, project to repo name: ${JSON.stringify(
          this.projectToRepoName,
        )} $$$$$$$$$$$$ not found from CICD: ${Array.from(notFoundFromCICD).join(
          ", ",
        )}, devBranch: ${devBranch}, masterBranch: ${masterBranch}, unknownBranch: ${unknownBranch}`,
      );
    } catch (err) {
      logger.error(`checkmarx, failed to check if repo related to project for all alerts: ${securityEvents.length}, err: ${err}`);
    }
    return connectedCount > 0;
  }

  getProjectNameFromText(text: string) {
    const r = text.match(this.regexToExtractCheckmarxProjectJob);
    if (r) {
      return r[1].trim();
    }
    return "";
  }

  private examineSecDeploymentRepo(repos: Repo[]) {
    try {
      for (const repo of repos) {
        try {
          for (const file of repo.deploymentFilesYmls) {
            try {
              //Found possible matches to project
              const text = fs.readFileSync(file.path, "utf8").toLowerCase();
              if (!text.includes("checkmarx")) {
                continue;
              }

              //Example --> script: '/home/ado/scaresolver/ScaResolver -a 888Holdings -u build.scanner -s $(Build.SourcesDirectory) -n poker_web_app -p thriver-S8wR3ZSx2B --log-level Debug --ignore-dev-dependencies'
              const fileNameToLower = file.fileNameWithoutDisk.toLowerCase();

              const r = text.match(this.regexToExtractCheckmarxProject);
              if (r) {
                const projectName = r[1].trim();
                const e: ImportedSecTemplate = new ImportedSecTemplate();
                e.project = projectName;
                e.text = text.toLowerCase();
                this.fileNameToYamlSec[fileNameToLower] = e;
              }

              const r2 = text.match(this.regexToExtractCheckmarxProjectProjectName);
              if (r2) {
                const projectName = r2[1].trim();
                const e: ImportedSecTemplate = new ImportedSecTemplate();
                e.project = projectName;
                e.text = text.toLowerCase();
                this.fileNameToYamlSec[fileNameToLower] = e;
              }

              //Example --> value: free2play_service_core, direct connection to repo
              const r3 = text.match(this.regexToExtractCheckmarxProjectFromLocalRepo);
              if (r3) {
                const projectName = r3[1].trim();
                this.setAppToolCoverage(
                  repo.fullName,
                  text,
                  `${repo.fileLink}/${file.fileNameWithoutDisk}`,
                  AppToolCoverageSourceType.MentionInFile,
                );

                this.projectToRepoName[projectName] = repo.fullName;
              }
            } catch (err) {
              logger.error(
                `checkmarx, failed add single file: ${file.fileNameWithoutDisk} in single repo: ${repo.fullName} in examine sec deployment repo checkmarx CLI parser, err: ${err}`,
              );
            }
          }
        } catch (err) {
          logger.error(
            `checkmarx, failed add single repo: ${repo.fullName} in examine sec deployment repo checkmarx CLI parser, err: ${err}`,
          );
        }
      }
    } catch (err) {
      logger.error(`checkmarx, failed examine sec deployment repo checkmarx CLI parser, err: ${err}`);
    }
  }

  async setCheckmarxRepo(projectName: string, build: any, buildLog: string) {
    if (!projectName) {
      return;
    }

    if (projectName.startsWith("'") && projectName.endsWith("'")) {
      projectName = projectName.substring(1, projectName.length - 1);
    }

    if (this.checmarxProject[projectName] == undefined) {
      this.checmarxProject[projectName] = [];
    }

    const azureCI: AzureCI = new AzureCI();
    azureCI.linkToBuild = build?._links?.web?.href;
    azureCI.reason = build.reason;
    azureCI.startTime = build.startTime;
    if (build.requestedBy) {
      azureCI.requestedBy = build.requestedBy.displayName;
      azureCI.requestedByMail = build.requestedBy.uniqueName;
    }
    azureCI.project = build.project.name;
    azureCI.buildNumber = build.buildNumber;

    const azureCIitems: AzureCI[] = this.checmarxProject[projectName];

    if (build.repository.type === "TfsVersionControl") {
      azureCI.isMaster = true;
      azureCI.branch = build.sourceBranch;
      azureCI.tfsSubFolder = getTFSRepo(build.sourceBranch);
      azureCI.repoId = build.repository.id;
      azureCI.repoName = getTFSRepoNameFromBranch(build.sourceBranch);
      azureCI.type = RepoType.TFS;
    } else {
      azureCI.isMaster = build.sourceBranch.toLowerCase().includes("master");
      azureCI.branch = build.sourceBranch;
      azureCI.repoId = build.repository.id;
      azureCI.repoName = build.repository.name;
      azureCI.type = RepoType.GIT;
    }

    if (!azureCI.repoName) {
      azureCI.repoName = build.definition.name;
      if (!this.noRepoProject[projectName]) {
        logger.warn(`no repo name for project: ${projectName}, using task definition data for build info: ${JSON.stringify(build)}`);
      }
      this.noRepoProject[projectName] = build;
    }

    this.setAppToolCoverage(azureCI.repoName, buildLog, azureCI.linkToBuild, AppToolCoverageSourceType.CICD);

    if (azureCIitems.find(i => i.repoName === azureCI.repoName && i.isMaster === azureCI.isMaster) === undefined) {
      await this.getCache().set(azureCI);
      azureCIitems.push(azureCI);
    }
  }

  private setAppToolCoverage(repoFullName: string, buildLog: string, link: string, source: AppToolCoverageSourceType) {
    const repoNameToLowerCase = repoFullName.toLowerCase();

    let appToolCoverage: AppToolCoverage[] = this.repoNameToSecurityApp[repoNameToLowerCase];
    //Set default
    if (!appToolCoverage) {
      appToolCoverage = [];
      this.repoNameToSecurityApp[repoNameToLowerCase] = appToolCoverage;
    }

    const sca = getStringFromEnumSecInfra(SecInfra.SCA);
    const sast = getStringFromEnumSecInfra(SecInfra.SAST);

    if (!sca || !sast) {
      logger.error(`failed get string from enum sec infra for repo: ${repoFullName}, sca: ${sca}, sast: ${sast}`);
      return;
    }

    const appToolCoverageSource: AppToolCoverageSource = new AppToolCoverageSource();
    appToolCoverageSource.match = link;
    appToolCoverageSource.type = source;

    if (!buildLog.includes("enabledependencyscan") && !buildLog.includes("enablesastscan")) {
      return;
    }

    const enableSca = buildLog.includes("enabledependencyscan: true");
    const enableSast = buildLog.includes("enablesastscan: true");

    if (!enableSca && !enableSast) {
      logger.info(`cannot set appTool coverage for repo: ${repoFullName}, build log: ${buildLog}`);
      return;
    }

    if (enableSca) {
      const item: AppToolCoverage = new AppToolCoverage();
      item.toolName = ToolNameForUI.cxsca;
      item.coverage = true;
      item.oxDelivered = false;
      item.type = sca;
      item.sources.push(appToolCoverageSource);

      SecurityToolsHelper.addToToolCoverage(appToolCoverage, item);
    }
    if (enableSast) {
      const item: AppToolCoverage = new AppToolCoverage();
      item.toolName = ToolNameForUI.cxsast;
      item.coverage = true;
      item.oxDelivered = false;
      item.type = sast;
      item.sources.push(appToolCoverageSource);

      SecurityToolsHelper.addToToolCoverage(appToolCoverage, item);
    }
  }

  private addProjectNameToRepoCollection(repo: Repo) {
    for (const [name, entry] of Object.entries(repo.importSecurityTemplateYml)) {
      try {
        const fileNameToLower = name.toLowerCase();
        const item: ImportedSecTemplate = this.fileNameToYamlSec[fileNameToLower];
        if (item == undefined) {
          continue;
        }

        const data = entry as any;

        const file: File = data.file as File;

        this.setAppToolCoverage(
          repo.fullName,
          item.text,
          `${repo.fileLink}/${file.fileNameWithoutDisk}`,
          AppToolCoverageSourceType.MentionInFile,
        );

        this.projectToRepoName[item.project] = repo.fullName;
      } catch (err) {
        logger.error(
          `checkmarx, failed add single file: ${name} in single repo: ${repo.fullName} in add repo to project name collection, err: ${err}`,
        );
      }
    }
  }

  getRepoNameInCheckmarxFormat(repoFullName: string, repoName: string) {
    try {
      //let repoNameHandelDotsForCheckmarx = "";
      const repoNameToLower = repoName.toLowerCase();

      // //Example: d10x.proxymity.report.service
      // for (const scanOrg of this.scanOrgs) {
      //   const projectNameToLower = scanOrg.toLowerCase();

      //   const indexOfProjectName = repoNameToLower.indexOf(projectNameToLower);
      //   if (indexOfProjectName != -1) {
      //     //Example: d10x.proxymity.report.service
      //     const repoNameWithoutProjectName = repoNameToLower
      //       .substring(
      //         indexOfProjectName + projectNameToLower.length,
      //         repoNameToLower.length
      //       )
      //       .trim();
      //     const indexOfDot = repoNameWithoutProjectName.indexOf(".");
      //     if (indexOfDot != -1) {
      //       //Example report.service
      //       repoNameHandelDotsForCheckmarx =
      //         repoNameWithoutProjectName.substring(
      //           indexOfDot + ".".length,
      //           repoNameWithoutProjectName.length
      //         );
      //       //Example report-service
      //       repoNameHandelDotsForCheckmarx = this.replaceAll(
      //         repoNameHandelDotsForCheckmarx,
      //         "\\.",
      //         "-"
      //       ).toLowerCase();
      //       repoNameHandelDotsForCheckmarx = this.replaceAll(
      //         repoNameHandelDotsForCheckmarx,
      //         "_",
      //         "-"
      //       ).toLowerCase();

      //       repoNameHandelDotsForCheckmarx = "sdasda-dasdsad dasdsad";
      //       let wordsCount = repoNameHandelDotsForCheckmarx.split('-').length;
      //       wordsCount += repoNameHandelDotsForCheckmarx.split(' ').length;
      //       if(wordsCount > 1){
      //         return repoNameHandelDotsForCheckmarx;
      //       }
      //     }
      //   }
      // }

      let repo = repoNameToLower;
      repo = repo.replaceAll("\\.", "-").toLowerCase();
      repo = repo.replaceAll("_", "-").toLowerCase();
      return repo;
    } catch (err) {
      logger.error(`checkmarx, get repo name in checkmarx format, repo: ${repoFullName}, err: ${err}`);
    }
    return "";
  }
}

export default CheckmarxCLIparser;
