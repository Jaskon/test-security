import loggerImport from "../../logger";
import { CicdTool, OrgCicdTool } from "../../entitis/cicdTypes";
import { Webhook, Workflow, File, Repo, repoType } from "../../entitis/codeRepoTypes";
import { Constant, ArtifactoryPushCmd } from "../../entitis/constant";
import { severityReasons } from "../../entitis/service/blameTypes";
import { ExtraInfo } from "../../entitis/issuesTypes";
import { handleFileNameReplace } from "../commonUtils";
import FileHelper from "../IO/fileHlper";

const fs = require("fs");

const logger = loggerImport.getDebugLogger();

class CicdHelper {
  orgCicdTools: CicdTool[];
  uuid: string;
  idForLogs: string;
  repoType: string;
  deploymentFiles: string[] = [];
  containerFiles: string[] = [];
  cloudDeployments: Object[] = [];
  artifactory: string[] = [];
  activeOrgCicdTools: OrgCicdTool[] = [];
  disableOrgCicdTools: OrgCicdTool[] = [];
  fileHelper: FileHelper;

  constructor(uuid: string, idForLogs: string, repoType: string, orgCicdTools: CicdTool[], policyTools: string[]) {
    this.uuid = uuid;
    this.idForLogs = idForLogs;
    this.repoType = repoType;
    this.orgCicdTools = orgCicdTools;
    this.fileHelper = new FileHelper(uuid);

    if (policyTools != null)
      this.orgCicdTools = orgCicdTools.filter(orgTool => policyTools.some(i => i.toLowerCase() === orgTool.name.toLowerCase()));
  }

  getContainerFiles(files: File[]) {
    try {
      const res = files.filter(i => Constant.dockerRegex.exec(i.path) != null);
      const conterFiles = res;
      return conterFiles.map(i => i.path);
    } catch (err) {
      logger.error(`failed get container files based on files for ${this.idForLogs}, err: ${err}`);
    }
    return [];
  }

  async getCicdTools(
    webhooks: Webhook[],
    workflows: Workflow[],
    files: File[],
    repo: Repo,
  ): Promise<{ activeOrgCicdTools: OrgCicdTool[]; disableOrgCicdTools: OrgCicdTool[] }> {
    const extraInfo: ExtraInfo[] = [];
    try {
      const orgFoundCicdTools: OrgCicdTool[] = [];
      const allActive = new Set();
      const deploymentFilesSet = new Set();
      for (const orgCicdTool of this.orgCicdTools) {
        this.addCicdBasedOnWorkflows(orgCicdTool, workflows, orgFoundCicdTools, allActive);
        this.addCicdBasedOnWebhooks(orgCicdTool, webhooks, orgFoundCicdTools, allActive);

        this.addCicdBasedOnFiles(orgCicdTool, files, orgFoundCicdTools, allActive, deploymentFilesSet, repo.ciCandidates);
      }

      repo.orchestrator = repo.orchestrator.filter(orch => repo.ciCandidates.has(orch["fileName"]));

      this.deploymentFiles = Array.from(deploymentFilesSet) as any;
      for (const deploymentFile of this.deploymentFiles) {
        if (!fs.existsSync(deploymentFile)) {
          continue;
        }

        const fileContent = fs.readFileSync(deploymentFile, "utf8");

        for (const tech of Constant.artifactoryPushCmd) {
          const techMatch = tech.pattern.exec(fileContent);
          if (techMatch) {
            repo.isSharedModule = repo.isSharedModule || tech.isSharedModule;
            const startIndex = techMatch.index + techMatch[0].length;
            const endIndex = startIndex + fileContent.slice(startIndex).indexOf("\n");
            const command = fileContent.slice(startIndex, endIndex);
            Constant.artifactoryList.forEach(registry => {
              if (registry.pattern.exec(command) && !this.artifactory.includes(registry.name)) {
                this.artifactory.push(registry.name);
              }
            });
            if (tech.isSharedModule) {
              const replaceInfo = repo.getRepoPathForToolCommand();
              const directoryDownReplaceInfo = replaceInfo.substring(0, replaceInfo.lastIndexOf("/"));
              let fileName = "";
              if (deploymentFile.includes(replaceInfo)) {
                fileName = handleFileNameReplace(deploymentFile, replaceInfo);
              } else if (deploymentFile.includes(directoryDownReplaceInfo)) {
                fileName = handleFileNameReplace(deploymentFile, directoryDownReplaceInfo);
              }
              const contentToSearch = fileContent.substring(techMatch.index, techMatch.index + 9);
              const startLineNumber = this.fileHelper.getLineByContent(deploymentFile, contentToSearch);
              if (startLineNumber === -1) {
                logger.info(`failed to find content: ${contentToSearch}, on file: ${deploymentFile}`);
              } else {
                const lineContent = await this.fileHelper.getContentByLine(deploymentFile, startLineNumber);
                const language = "";
                const link =
                  repo.type === repoType.awsCodeCommit
                    ? repo.fileLink + fileName + repo.linkFilePreffix + startLineNumber + "-" + startLineNumber
                    : repo.fileLink + fileName + repo.linkFilePreffix + startLineNumber;
                extraInfo.push({
                  key: "Snippet",
                  link: link,
                  snippet: {
                    fileName: fileName,
                    text: lineContent,
                    language: language,
                    snippetLineNumber: startLineNumber,
                  },
                });
              }
            }
          }
        }

        for (const [cloudProvider, cloudRegex] of Object.entries(Constant.cloudDeploymentsRegex)) {
          const res = cloudRegex.pattern.exec(fileContent);
          if (res) {
            if (!(cloudProvider in this.cloudDeployments)) {
              this.cloudDeployments[cloudProvider] = [];
            }
            let subtypeExist = false;

            const subType = cloudRegex["subType"];
            const fileName = deploymentFile.replace(`${repo.cloneDir}/`, "");

            for (const reg in subType) {
              const res = subType[reg].exec(fileContent);
              if (res) {
                subtypeExist = true;
                const lineNumber = (fileContent.substring(0, res.index).match(/\n/g) || []).length + 1;

                this.cloudDeployments[cloudProvider].push({
                  type: cloudProvider,
                  subType: reg,
                  link: repo.fileLink + fileName + repo.linkFilePreffix + lineNumber,
                  name: `${fileName}`,
                });
              }
            }

            if (!subtypeExist) {
              const lineNumber = (fileContent.substring(0, res.index).match(/\n/g) || []).length + 1;
              this.cloudDeployments[cloudProvider].push({
                type: cloudProvider,
                subType: "Generic",
                link: repo.fileLink + fileName + repo.linkFilePreffix + lineNumber,
                name: `${fileName}`,
              });
            }
          }
        }
      }

      //Split to active and disable and remove duplication
      let allActiveTools = Array.from(allActive);
      for (const orgCicdTool of orgFoundCicdTools) {
        if (allActiveTools.some(activeTool => activeTool === orgCicdTool.name.toLowerCase())) {
          this.activeOrgCicdTools.push(orgCicdTool);
        } else {
          this.disableOrgCicdTools.push(orgCicdTool);
        }
      }

      this.activeOrgCicdTools = this.activeOrgCicdTools.reduce((unique, o) => {
        if (!unique.some(obj => obj.name === o.name)) {
          unique.push(o);
        }
        return unique;
      }, []);
      this.disableOrgCicdTools = this.disableOrgCicdTools.reduce((unique, o) => {
        if (!unique.some(obj => obj.name === o.name)) {
          unique.push(o);
        }
        return unique;
      }, []);
    } catch (err) {
      logger.error(`failed add cicd tools for ${this.idForLogs}, err: ${err}`);
    }

    try {
      if (repo.isSharedModule) {
        repo.addRepoSeverityChangedReason(severityReasons.publishedPackage, extraInfo);
      }
    } catch (err) {
      logger.error(`failed addRepoSeverityChangedReason for ${this.idForLogs}, err: ${err}`);
    }

    const activeOrgCicdTools = this.activeOrgCicdTools;
    const disableOrgCicdTools = this.disableOrgCicdTools;
    return { activeOrgCicdTools, disableOrgCicdTools };
  }

  addCicdBasedOnFiles(
    orgCicdTool: CicdTool,
    files: File[],
    orgFoundCicdTools: OrgCicdTool[],
    allActive,
    deploymentFilesSet,
    ciCandidates: Set<string>,
  ) {
    try {
      const cicdName = orgCicdTool.name.toLowerCase();
      const unique = new Set();

      for (const file of files) {
        try {
          // if (!ciCandidates.has(file.path)) {
          //   continue;
          // }
          if (
            !file.path.includes("node_modules") &&
            !file.path.includes("wp-content") &&
            !file.path.includes(".git/") &&
            //Same deployment as source control or make sure its not part of the
            //different and not allowed cicd combination
            (this.repoType.toLowerCase() === cicdName || !Constant.sourceControlCICD.includes(cicdName)) &&
            orgCicdTool.regex.exec(file.path) != null
          ) {
            //Keep only unique
            // if (unique.has(orgCicdTool.name)) {
            //   continue;
            // }
            if (!unique.has(orgCicdTool.name)) {
              unique.add(orgCicdTool.name);
              if (orgCicdTool.name) {
                allActive.add(orgCicdTool.name.toLowerCase());
                orgFoundCicdTools.push(
                  new OrgCicdTool(
                    file.objType,
                    orgCicdTool.name,
                    true,
                    file.link,
                    {
                      file: file,
                    },
                    file.name,
                  ),
                );
                logger.info(`found cicd in repo: ${this.idForLogs}, tool: ${orgCicdTool.name.toLowerCase()} based on file ${file.path}`);
              } else {
                logger.info(
                  `found cicd build/deployment file in repo: ${this.idForLogs}, pattern: ${orgCicdTool.regex} based on file ${file.path}`,
                );
              }
            }

            if (
              !(
                file.path.endsWith(".exe") ||
                file.path.endsWith(".bin") ||
                file.path.endsWith(".js") ||
                file.path.endsWith(".ts") ||
                file.path.endsWith(".md") ||
                file.path.endsWith(".txt") ||
                file.path.endsWith(".dll") ||
                file.path.endsWith(".msi") ||
                file.path.endsWith(".svg") ||
                file.path.endsWith(".jpeg")
              )
            ) {
              deploymentFilesSet.add(file.path);
            }
          }
        } catch (err) {
          logger.error(
            `uuid: ${this.uuid}, failed add cicd tool based on file: ${JSON.stringify(file)} for ${this.idForLogs}, err: ${err}`,
          );
        }
      }
    } catch (err) {
      logger.error(`failed add cicd tool based on files for ${this.idForLogs}, err: ${err}`);
    }
  }

  addCicdBasedOnWebhooks(orgCicdTool: CicdTool, webhooks: Webhook[], orgFoundCicdTools: OrgCicdTool[], allActive) {
    try {
      const unique = new Set();

      for (const webhook of webhooks) {
        try {
          if (orgCicdTool.regex.exec(webhook.url) != null || orgCicdTool.regex.exec(webhook.description) != null) {
            //Keep only unique
            if (unique.has(orgCicdTool.name)) {
              continue;
            }
            unique.add(orgCicdTool.name);

            allActive.add(orgCicdTool.name.toLowerCase());

            logger.info(
              `found cicd in repo: ${this.idForLogs}, ${orgCicdTool.name.toLowerCase()} based on webhook ${JSON.stringify(webhook)}`,
            );

            orgFoundCicdTools.push(
              new OrgCicdTool(webhook.objType, orgCicdTool.name, true, webhook.link, { webhook: webhook }, webhook.description),
            );
          }
        } catch (err) {
          logger.error(
            `uuid: ${this.uuid}, failed add cicd tool based on webhook: ${JSON.stringify(webhook)} for ${this.idForLogs}, err: ${err}`,
          );
        }
      }
    } catch (err) {
      logger.error(`failed add cicd tool based on webhook for ${this.idForLogs}, err: ${err}`);
    }
  }

  addCicdBasedOnWorkflows(orgCicdTool: CicdTool, workflows: Workflow[], orgFoundCicdTools: OrgCicdTool[], allActive) {
    try {
      const unique = new Set();

      for (const workflow of workflows) {
        try {
          if (orgCicdTool.regex.exec(workflow.path) != null) {
            //Keep only unique
            if (unique.has(orgCicdTool.name)) {
              continue;
            }
            unique.add(orgCicdTool.name);

            allActive.add(orgCicdTool.name.toLowerCase());

            logger.info(
              `found cicd in repo: ${this.idForLogs}, ${orgCicdTool.name.toLowerCase()} based on workflow ${JSON.stringify(workflow)}`,
            );

            orgFoundCicdTools.push(
              new OrgCicdTool(workflow.objType, orgCicdTool.name, true, workflow.link, { workflow: workflow }, workflow.name),
            );
          }
        } catch (err) {
          logger.error(
            `uuid: ${this.uuid}, failed add cicd tool based on workflow: ${JSON.stringify(workflow)} for ${this.idForLogs}, err: ${err}`,
          );
        }
      }
    } catch (err) {
      logger.error(`failed add cicd tool based on workflow for ${this.idForLogs}, err: ${err}`);
    }
  }
}

export default CicdHelper;
