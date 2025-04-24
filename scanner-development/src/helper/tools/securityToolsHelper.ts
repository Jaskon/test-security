import artifactoryToolsJson from "../../codeOpenSourceTools/config/artifactoryTools.json";
import cloudSecurityToolsJson from "../../codeOpenSourceTools/config/cloudSecurityTools.json";
import codeSecurityToolsJson from "../../codeOpenSourceTools/config/codeSecurityTools.json";
import CollectorBase from "../../dal/base/collectorBase";
import {
  CodeRepoTypes,
  DevLanguages,
  File,
  Repo,
  repoType,
  SecurityAlertType,
  SecurityEvent,
  SpecialFile,
  Webhook,
  Workflow,
} from "../../entitis/codeRepoTypes";
import Constant, { OXtools } from "../../entitis/constant";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";
import { OrgSecurityTool, SecurityTool, SecurityToolType } from "../../entitis/tool/securityVendorsTypes";
import { getStringFromEnumSecInfra } from "../../entitis/tool/toolsTypes";
import loggerImport from "../../logger";
import IacLangs from "../../policy/org/config/iacLanguages.json";
import SastLangs from "../../policy/org/config/sastLanguages.json";
import ScaLangs from "../../policy/org/config/scaLanguages.json";
import securityVendorsToolsJson from "../../policy/org/config/securityVendors.json";
import { AppToolCoverage, AppToolCoverageSource, AppToolCoverageSourceType, CoverageReasons } from "../../policy/reporting/types";
import { staticConnectors } from "../connectorsSpecific/tokensHelper";
import { isDevelopment, isLocalDevelopment } from "../envUtils";
import FileHelper from "../IO/fileHlper";
import StatesHelper from "../statesHelper";
import ToolsConnectorsHelper from "./toolsConnectorsHelper";

const logger = loggerImport.getDebugLogger();
const path = require("path");

class DuplicateInfo {
  event: SecurityEvent;
  oxTool: boolean;
}

class SecurityToolsHelper {
  securityTools: SecurityTool[] = [];
  uuid: string;
  idForLogs: string;
  deploymentFiles: string[] = [];
  collectors: [] = [];
  fileHelper;
  repoFileLink: string;
  cloneDir: string;
  languages: DevLanguages[] = [];
  files: File[] = [];
  repo: Repo;

  //Tool coverage
  toolCoverage: AppToolCoverage[] = [];
  static failedConvertToolEnum = new Set();

  constructor(
    uuid: string,
    idForLogs: string,
    securityTools: SecurityTool[],
    deplymentFiles: string[],
    collectors: any,
    repo: Repo,
    files: File[],
  ) {
    this.uuid = uuid;
    this.idForLogs = idForLogs;
    this.securityTools = securityTools;
    this.deploymentFiles = deplymentFiles;
    this.collectors = collectors;
    this.fileHelper = new FileHelper(uuid);
    this.repoFileLink = repo.fileLink;
    this.cloneDir = repo.cloneDir;
    this.languages = repo.languages;
    this.repo = repo;
    this.files = files;
  }

  static getUniqueForSca(securityEvent: SecurityEvent) {
    let uniqueStr = `${securityEvent.fileName}_${securityEvent.blame.cve}_${securityEvent.pkgName}_${securityEvent.installedVersion}`;
    if (securityEvent.blame?.triggerPackage?.name && securityEvent.blame?.triggerPackage?.version) {
      uniqueStr = `${securityEvent.fileName}_${securityEvent.blame.cve}_${securityEvent.pkgName}_${securityEvent.installedVersion}_${securityEvent.blame?.triggerPackage?.name}_${securityEvent.blame?.triggerPackage?.version}`;
    }
    return uniqueStr;
  }

  static removeDuplication(uuid: string, idForLogs: string, securityEvents: SecurityEvent[]) {
    try {
      const securityEventsFiltered: SecurityEvent[] = [];

      let filteredCount = 0;
      let missingSomeItemForCheckDuplication = 0;
      const uniqueMapping = {};
      const removedByCat = {};
      let foundRuleId = false;
      let foundSmallRuleId = false;

      for (const securityEvent of securityEvents) {
        try {
          const isSca =
            securityEvent.securityAlertType === SecurityAlertType.sca &&
            securityEvent.securitySubTypeAlertType === SecurityAlertType.Unknown;

          const shouldRunThisLogic =
            isSca ||
            securityEvent.securityAlertType === SecurityAlertType.iac ||
            securityEvent.securityAlertType === SecurityAlertType.sast ||
            securityEvent.securityAlertType === SecurityAlertType.container ||
            (securityEvent.securityAlertType === SecurityAlertType.secrets && !securityEvent.fromCommitHistory) ||
            securityEvent.skipEnrichment;

          //Always added container events
          if (!shouldRunThisLogic) {
            securityEventsFiltered.push(securityEvent);
            continue;
          }

          if (securityEvent.securityProvider.toLowerCase() === "klocwork") {
            securityEventsFiltered.push(securityEvent);
            continue;
          }

          let uniqueStr;

          if (isSca) {
            //For SCA use cve for unique alerts
            if (!securityEvent?.blame?.cve) {
              securityEventsFiltered.push(securityEvent);
              continue;
            }
            uniqueStr = `${securityEvent.filePath}_${securityEvent.blame.cve}_${securityEvent.pkgName}_${securityEvent.installedVersion}`;
          } else if (securityEvent.securityAlertType === SecurityAlertType.container) {
            if (
              !securityEvent?.blame?.cve ||
              !securityEvent.pkgName ||
              !securityEvent.installedVersion ||
              !securityEvent?.artifacts?.dockerFileInRunTime
            ) {
              securityEventsFiltered.push(securityEvent);
              continue;
            }

            uniqueStr = `${securityEvent.artifacts.dockerFileInRunTime}_${securityEvent.blame.cve}_${securityEvent.pkgName}_${securityEvent.installedVersion}`;
          } else {
            if (
              !securityEvent.fileName ||
              !securityEvent.startLineNumber ||
              securityEvent.startLineNumber === -1 ||
              !securityEvent.securityAlertTypeStr
            ) {
              securityEventsFiltered.push(securityEvent);
              missingSomeItemForCheckDuplication++;
              continue;
            }

            uniqueStr = `${securityEvent.fileName}_${securityEvent.startLineNumber.toString()}_${securityEvent.securityAlertTypeStr}}`;
          }

          const newObjToAdd: DuplicateInfo = {
            event: securityEvent,
            oxTool: securityEvent.oxTool,
          };

          uniqueStr = uniqueStr.toLowerCase();
          const currentItem = uniqueMapping[uniqueStr];

          if (currentItem == undefined) {
            //First time
            uniqueMapping[uniqueStr] = newObjToAdd;
          } else {
            //Choose ox object as it will holds al the data
            const currSecItem: SecurityEvent = currentItem.event;
            const newSecItem: SecurityEvent = newObjToAdd.event;

            //When retrieve this object from cash it return as {}, this needs to be refactor
            if (currSecItem?.securityProviders?.size > 0) {
              //Do nothing
            } else {
              currSecItem.securityProviders = new Set();
            }
            currSecItem?.securityProvidersArr?.forEach(i => {
              currSecItem.securityProviders.add(i);
            });

            if (newSecItem?.securityProviders?.size > 0) {
              //Do nothing
            } else {
              newSecItem.securityProviders = new Set();
            }
            newSecItem?.securityProvidersArr?.forEach(i => {
              newSecItem.securityProviders.add(i);
            });

            //Check if same tool trigger twise on the same data with diff rule id's
            let sameToolDiffRules = false;
            Array.from(securityEvent.securityProviders).forEach(secTool => {
              if (currentItem.event.securityProviders.has(secTool) && currSecItem.ruleId !== newSecItem.ruleId) {
                sameToolDiffRules = true;
              }
            });
            if (sameToolDiffRules) {
              securityEventsFiltered.push(securityEvent);
              continue;
            }

            //in case it sca and both of them ox tools make sure they diff by trigger pkg for cases
            //where same lib have multi trigger pkg
            if (securityEvent.oxTool && isSca && securityEvent?.blame?.triggerPackage?.name) {
              const cSecEvent: SecurityEvent = currentItem.event;
              if (
                cSecEvent.oxTool &&
                cSecEvent.securityAlertType === SecurityAlertType.sca &&
                cSecEvent.securitySubTypeAlertType === SecurityAlertType.Unknown &&
                cSecEvent?.blame?.triggerPackage?.name
              ) {
                const uStr = `${securityEvent.fileName}_${securityEvent.blame.cve}_${securityEvent.pkgName}_${securityEvent.installedVersion}_${securityEvent?.blame?.triggerPackage?.name}`;
                const uStr2 = `${cSecEvent.fileName}_${cSecEvent.blame.cve}_${cSecEvent.pkgName}_${cSecEvent.installedVersion}_${cSecEvent?.blame?.triggerPackage?.name}`;
                if (uStr !== uStr2) {
                  securityEventsFiltered.push(securityEvent);
                  continue;
                }
              }
            }

            let chooseTheCorrectOne;
            if (currSecItem.oxTool) {
              chooseTheCorrectOne = currentItem;
              Array.from(newObjToAdd.event.securityProviders).forEach(i => {
                chooseTheCorrectOne.event.securityProviders.add(i);
              });
            } else if (newSecItem.oxTool) {
              chooseTheCorrectOne = newObjToAdd;
              Array.from(currentItem.event.securityProviders).forEach(i => {
                chooseTheCorrectOne.event.securityProviders.add(i);
              });
            } else {
              chooseTheCorrectOne = currentItem;
              Array.from(newObjToAdd.event.securityProviders).forEach(i => {
                chooseTheCorrectOne.event.securityProviders.add(i);
              });
            }

            //Overwrite
            uniqueMapping[uniqueStr] = chooseTheCorrectOne;

            filteredCount++;

            if (removedByCat[securityEvent.securityProvider]) {
              removedByCat[securityEvent.securityProvider]++;
            } else {
              removedByCat[securityEvent.securityProvider] = 1;
            }
            continue;
          }
        } catch (err) {
          securityEventsFiltered.push(securityEvent);
          logger.error(`failed check single securityEvent: err: ${err}, type: ${securityEvent.securityProvider}`);
        }
      }

      for (const uniqueItem in uniqueMapping) {
        try {
          const item = uniqueMapping[uniqueItem];
          const ev: SecurityEvent = item.event;
          if (ev.securityProviders.size > 0) {
            ev.securityProvidersArr = Array.from(ev.securityProviders) as string[];
          }

          securityEventsFiltered.push(ev);
        } catch (err) {
          logger.error(`failed add sec event from remove duplication for repo: ${idForLogs}, err: ${err}`);
        }
      }

      if (filteredCount > 0) {
        logger.info(
          `uuid: ${uuid}, removed: ${filteredCount} duplicated security, removedByCat: ${JSON.stringify(
            removedByCat,
          )}, missing some item for check duplication: ${missingSomeItemForCheckDuplication}, total event reminded: ${
            securityEventsFiltered.length
          }, events for repo: ${idForLogs}`,
        );
      }

      return securityEventsFiltered;
    } catch (err) {
      logger.error(`uuid: ${uuid}, failed remove duplication of security events for repo: ${idForLogs}, err: ${err}`);
    }
    return securityEvents;
  }

  handleSastCoverage(orgSastLangs, securityTools) {
    const toolsVendors = this.securityTools;
    let sastCoveredByOx = null;
    let sastCoveredByClient = null;
    let sastNotCovered = null;
    let sastNa = null;
    let highestSastLang;
    let unprotectedSastDevLanguages: DevLanguages[] = [];

    try {
      if (orgSastLangs.length) {
        // get the highest percentage language
        highestSastLang = orgSastLangs.reduce((max, lang) => (max.languagePercentage > lang.languagePercentage ? max : lang));

        // get ox tools and their languages from list
        const toolsByOx = [];
        for (const tool of securityTools.oxSecurityTools.oxSastTools) {
          const found = toolsVendors.find(i => i.name.toLowerCase() === tool.name.toLowerCase() && i.oxDelivered);

          if (found != undefined) {
            toolsByOx.push(found);
          }
        }

        // check if language is supported by one of the tools by ox
        if (toolsByOx.length) {
          sastCoveredByOx = toolsByOx.some(tool =>
            tool.sastLanguages?.some(lang => lang.toLowerCase() == highestSastLang.language.toLowerCase()),
          );
        }
        // check if language is supported by one of the tools by client
        if (securityTools.activeSast.length) {
          sastCoveredByClient = securityTools.activeSast.some(tool =>
            tool.securityTool.sastLanguages.some(lang => lang.toLowerCase() == highestSastLang.language.toLowerCase()),
          );
        }

        if (!sastCoveredByOx && !sastCoveredByClient) {
          sastNotCovered = true;
          if (toolsByOx.length || securityTools.activeSast.length) {
            unprotectedSastDevLanguages.push(highestSastLang);
          }
        }
      } else {
        // if no sast languages - not applicable
        sastNa = true;
      }

      return {
        unprotectedSastDevLanguages,
        sast: {
          byOx: sastCoveredByOx,
          byClient: sastCoveredByClient,
          nc: sastNotCovered,
          na: sastNa,
        },
      };
    } catch (err) {
      logger.error(`failed on handleSastCoverage for ${this.idForLogs} : ${err}`);
    }

    return {
      unprotectedSastDevLanguages,
      sast: {
        byOx: sastCoveredByOx,
        byClient: sastCoveredByClient,
        nc: sastNotCovered,
        na: sastNa,
      },
    };
  }

  getHighestPercentageLanFromDepFiles(langsFromDep, repoLangs) {
    try {
      if (!repoLangs.length) {
        return;
      }

      // get highest lang detected in repo
      let highestScaLang = repoLangs.reduce((max, lang) => (max.languagePercentage > lang.languagePercentage ? max : lang));

      // check if highest lang has dependency file
      // if not, we check if the next highest language has dependncy file
      if (!langsFromDep.includes(highestScaLang.language.toLowerCase())) {
        // remove from repo langs
        repoLangs = repoLangs.filter(lang => lang.language !== highestScaLang.language);
        highestScaLang = this.getHighestPercentageLanFromDepFiles(langsFromDep, repoLangs);
      }
      return highestScaLang;
    } catch (e) {
      logger.error(`failed getHighestPercentageLanFromDepFiles ${this.idForLogs} : ${e}`);
    }
  }

  handleScaCoverage(orgScaLangs, securityTools, files) {
    // get languages based on dependency files (ex: package.json)
    const languages = this.fileHelper.getLanguagesBasedOnDependencyFiles(files);

    // getting languages support from tool config
    const toolsVendors = this.securityTools;
    let scaCoveredByOx = null;
    let scaCoveredByClient = null;
    let scaNotCovered = null;
    let scaNa = null;
    let highestScaLang;
    let unprotectedScaDevLanguages: DevLanguages[] = [];

    try {
      // get higest SCA
      if (orgScaLangs.length) {
        highestScaLang = this.getHighestPercentageLanFromDepFiles(languages, orgScaLangs);

        if (highestScaLang === undefined) {
          scaNa = true;
        } else {
          // get tools by ox with languages
          const toolsByOx = [];
          for (const tool of securityTools.oxSecurityTools.oxScaTools) {
            const found = toolsVendors.find(i => i.name.toLowerCase() === tool.name.toLowerCase() && i.oxDelivered);

            if (found != undefined) {
              toolsByOx.push(found);
            }
          }

          if (toolsByOx.length) {
            scaCoveredByOx = toolsByOx.some(tool =>
              tool.scaLanguages?.some(lang => lang.toLowerCase() == highestScaLang.language.toLowerCase()),
            );
          }

          if (securityTools.activeSca.length) {
            scaCoveredByClient = securityTools.activeSca.some(tool =>
              tool.securityTool.scaLanguages.some(lang => lang.toLowerCase() == highestScaLang.language.toLowerCase()),
            );
          }

          if (!scaCoveredByOx && !scaCoveredByClient) {
            scaNotCovered = true;
            if (toolsByOx.length || securityTools.activeSca.length) {
              unprotectedScaDevLanguages.push(highestScaLang);
            }
          }
        }
      } else {
        scaNa = true;
      }

      return {
        unprotectedScaDevLanguages,
        sca: {
          byOx: scaCoveredByOx,
          byClient: scaCoveredByClient,
          nc: scaNotCovered,
          na: scaNa,
        },
      };
    } catch (err) {
      logger.error(`failed on handleScaCoverage for ${this.idForLogs} : ${err}`);
    }
    return {
      unprotectedScaDevLanguages,
      sca: {
        byOx: scaCoveredByOx,
        byClient: scaCoveredByClient,
        nc: scaNotCovered,
        na: scaNa,
      },
    };
  }

  handleIacCoverage(orgIacLangs, securityTools) {
    let iacCoveredByOx = null;
    let iacCoveredByClient = null;
    let iacNotCovered = null;
    let iacNa = null;

    try {
      if (orgIacLangs.length) {
        if (securityTools.oxSecurityTools.oxIacTools.length) {
          iacCoveredByOx = true;
        }

        if (securityTools.activeIac.length) {
          iacCoveredByClient = true;
        }

        if (!securityTools.activeIac.length && !securityTools.oxSecurityTools.oxIacTools.length) {
          iacNotCovered = true;
        }
      } else {
        iacNa = true;
      }
      return {
        byOx: iacCoveredByOx,
        byClient: iacCoveredByClient,
        nc: iacNotCovered,
        na: iacNa,
      };
    } catch (err) {
      logger.error(`failed on handleIacCoverage for ${this.idForLogs} : ${err}`);
    }
    return {
      byOx: iacCoveredByOx,
      byClient: iacCoveredByClient,
      nc: iacNotCovered,
      na: iacNa,
    };
  }

  getUnprotectedLanguages(
    webhooks: Webhook[],
    workflows: Workflow[],
    files: File[],
    securityEvents: SecurityEvent[],
    devLanguages: DevLanguages[],
  ) {
    // get applied tools from ox and client
    const securityTools = this.getSecurityTools(webhooks, workflows, files, securityEvents);

    const orgSastLangs = [],
      orgIacLangs = [],
      orgScaLangs = [];

    const sastLangs = SastLangs.languages.map(i => i.toLowerCase());
    const scaLangs = ScaLangs.languages.map(i => i.toLowerCase());
    const iacLangs = IacLangs.languages.map(i => i.toLowerCase());

    try {
      // segregate the langs to types
      for (const devLanguage of devLanguages) {
        const language = devLanguage.language;
        if (sastLangs.includes(language.toLowerCase())) {
          orgSastLangs.push(devLanguage);
        }

        if (scaLangs.includes(language.toLowerCase())) {
          orgScaLangs.push(devLanguage);
        }

        if (iacLangs.includes(language.toLowerCase())) {
          orgIacLangs.push(devLanguage);
        }
      }
      // SAST
      const sast = this.handleSastCoverage(orgSastLangs, securityTools);

      // SCA
      const sca = this.handleScaCoverage(orgScaLangs, securityTools, files);

      // IaC
      const iac = this.handleIacCoverage(orgIacLangs, securityTools);

      return {
        unprotectedSastDevLanguages: sast.unprotectedSastDevLanguages,
        unprotectedScaDevLanguages: sca.unprotectedScaDevLanguages,
        secInfra: {
          sast,
          sca,
          iac,
        },
      };
    } catch (err) {
      logger.error(`failed to get unprotected sec Infra ${err}`);
    }
  }

  getContainerFiles(files: File[]) {
    try {
      const res = files.filter(i => Constant.dockerRegex.exec(i.path) != null);
      return res.length;
    } catch (err) {
      logger.error(`failed get container files based on files for ${this.idForLogs}, err: ${err}`);
    }
    return 0;
  }

  static getTypeFromEnum(type: string) {
    const t = getStringFromEnumSecInfra(type);
    if (t) {
      return t;
    }
    SecurityToolsHelper.failedConvertToolEnum.add(type);
  }

  getSecurityTools(webhooks: Webhook[], workflows: Workflow[], files: File[], securityEvents: SecurityEvent[]) {
    let activeSast: OrgSecurityTool[] = [];
    let activeSca: OrgSecurityTool[] = [];
    let activeSecrets: OrgSecurityTool[] = [];
    let activeIac: OrgSecurityTool[] = [];
    let disableSast: OrgSecurityTool[] = [];
    let disableSca: OrgSecurityTool[] = [];
    let activeCspm: OrgSecurityTool[] = [];

    try {
      let orgSecurityTools: OrgSecurityTool[] = [];
      for (const SecurityTool of this.securityTools) {
        this.addSecurityToolBasedOnWorkflows(SecurityTool, workflows, orgSecurityTools);
        this.addSecurityToolBasedOnWebhooks(SecurityTool, webhooks, orgSecurityTools);
        this.addSecurityToolBasedOnSecurityEvents(SecurityTool, securityEvents, orgSecurityTools);
        this.addSecurityToolBasedOnFiles(SecurityTool, files, orgSecurityTools);
        this.addSecurityToolBasedOnCollectors(SecurityTool, orgSecurityTools);
        this.addSecurityToolBasedOnGHSecurity(SecurityTool, orgSecurityTools);
      }
      this.addSecurityToolBasedOnFilesContent(this.securityTools, orgSecurityTools);

      //Split to active and disable and remove duplication
      let activeOrgSecurityTool: OrgSecurityTool[] = [];
      let disableOrgSecurityTooll: OrgSecurityTool[] = [];
      for (const orgCicdTool of orgSecurityTools) {
        if (orgCicdTool.active) {
          activeOrgSecurityTool.push(orgCicdTool);
        } else {
          disableOrgSecurityTooll.push(orgCicdTool);
        }
      }

      activeOrgSecurityTool = activeOrgSecurityTool.reduce((unique, o) => {
        if (!unique.some(obj => obj.name === o.name)) {
          unique.push(o);
        }
        return unique;
      }, []);
      disableOrgSecurityTooll = disableOrgSecurityTooll.reduce((unique, o) => {
        if (!unique.some(obj => obj.name === o.name)) {
          unique.push(o);
        }
        return unique;
      }, []);

      activeCspm = activeOrgSecurityTool.filter(i =>
        i.securityTool.type.some(j => j.toLowerCase() === SecurityToolType[SecurityToolType.Cspm].toString().toLowerCase()),
      );

      activeSast = activeOrgSecurityTool.filter(i =>
        i.securityTool.type.some(j => j.toLowerCase() === SecurityToolType[SecurityToolType.SAST].toString().toLowerCase()),
      );
      activeSca = activeOrgSecurityTool.filter(i =>
        i.securityTool.type.some(j => j.toLowerCase() === SecurityToolType[SecurityToolType.SCA].toString().toLowerCase()),
      );

      activeSecrets = activeOrgSecurityTool.filter(i =>
        i.securityTool.type.some(j => j.toLowerCase() === SecurityToolType[SecurityToolType.Secrets].toString().toLowerCase()),
      );

      activeIac = activeOrgSecurityTool.filter(i =>
        i.securityTool.type.some(j => j.toLowerCase() === SecurityToolType[SecurityToolType.IaC].toString().toLowerCase()),
      );

      disableSast = disableOrgSecurityTooll.filter(i =>
        i.securityTool.type.some(j => j.toLowerCase() === SecurityToolType[SecurityToolType.SAST].toString().toLowerCase()),
      );
      disableSca = disableOrgSecurityTooll.filter(i =>
        i.securityTool.type.some(j => j.toLowerCase() === SecurityToolType[SecurityToolType.SCA].toString().toLowerCase()),
      );
    } catch (err) {
      logger.error(`failed add security tools for ${this.idForLogs}, err: ${err}`);
    }

    const oxSecurityTools = this.getOxSecurityTools();

    return {
      activeSast,
      activeSca,
      activeSecrets,
      activeIac,
      activeCspm,
      disableSast,
      disableSca,
      oxSecurityTools,
    };
  }

  enableByPolicy(SecurityTool) {
    const toolName = SecurityTool.name.toUpperCase();
    const toolNameEnv = `TOOLS_${toolName}`;

    if (SecurityTool.disableByOx) return false;
    if (toolNameEnv in process.env && process.env[toolNameEnv] === "enabled") {
      return true;
    }

    return false;
  }

  getOxSecurityTools() {
    const oxSastTools: ToolConfig[] = [];
    const oxScaTools: ToolConfig[] = [];
    const oxIacTools: ToolConfig[] = [];
    const oxSecretsTools: ToolConfig[] = [];
    const oxContainerTools: ToolConfig[] = [];
    const oxCspmTools: ToolConfig[] = [];
    const oxSbomTools: ToolConfig[] = [];

    try {
      const tools: ToolConfig[] = [...artifactoryToolsJson.tools, ...codeSecurityToolsJson.tools, ...cloudSecurityToolsJson.tools];

      for (const SecurityTool of tools) {
        if (!this.enableByPolicy(SecurityTool)) {
          continue;
        }

        this.addToToolsCoverage(SecurityTool.oxToolName, true, AppToolCoverageSourceType.OX, "", SecurityTool.supportedTypes);

        let res = SecurityTool.supportedTypes.find(i => i.toLowerCase() === "sca");
        if (res != undefined) {
          oxScaTools.push(SecurityTool);
        }
        res = SecurityTool.supportedTypes.find(i => i.toLowerCase() === "sast");
        if (res != undefined) {
          oxSastTools.push(SecurityTool);
        }
        res = SecurityTool.supportedTypes.find(i => i.toLowerCase() === "iac");
        if (res != undefined) {
          oxIacTools.push(SecurityTool);
        }
        res = SecurityTool.supportedTypes.find(i => i.toLowerCase() === "secrets");
        if (res != undefined) {
          oxSecretsTools.push(SecurityTool);
        }
        res = SecurityTool.supportedTypes.find(i => i.toLowerCase() === "container");
        if (res != undefined) {
          oxContainerTools.push(SecurityTool);
        }
        res = SecurityTool.supportedTypes.find(i => i.toLowerCase() === "cspm");
        if (res != undefined) {
          oxCspmTools.push(SecurityTool);
        }
        res = SecurityTool.supportedTypes.find(i => i.toLowerCase() === "sbom");
        if (res != undefined) {
          oxSbomTools.push(SecurityTool);
        }
      }
    } catch (err) {
      logger.error(`failed add ox security tools for ${this.idForLogs}, err: ${err}`);
    }

    return {
      oxSastTools,
      oxScaTools,
      oxIacTools,
      oxSecretsTools,
      oxCspmTools,
      oxContainerTools,
      oxSbomTools,
    };
  }

  addSecurityToolBasedOnCollectors(securityTool: SecurityTool, orgSecurityTools: OrgSecurityTool[]) {
    try {
      // going through collectors (tokens) and taking only those who are actually
      // tools (not code/ci/etc..) by customer
      const tool = (this.collectors as CollectorBase[]).find(
        collector => collector.token.name.toLowerCase() == securityTool.connectorName?.toLowerCase() && !securityTool.oxDelivered,
      );

      if (tool != undefined) {
        orgSecurityTools.push(
          new OrgSecurityTool(null, securityTool.name, true, null, securityTool, {
            tool,
          }),
        );
      }
    } catch (e) {
      logger.error(`error addSecurityToolBasedOnCollectors ${e}`);
    }
  }

  addSecurityToolBasedOnWorkflows(securityTool: SecurityTool, workflows: Workflow[], orgSecurityTools: OrgSecurityTool[]) {
    try {
      const unique = new Set();

      for (const workflow of workflows) {
        try {
          const regexExec = securityTool.regex.exec(workflow.path) != null;
          if (regexExec) {
            if (unique.has(securityTool.name)) {
              continue;
            }

            this.addToToolsCoverage(
              securityTool.name,
              securityTool.oxDelivered,
              AppToolCoverageSourceType.MentionInFile,
              workflow.path,
              securityTool.type,
            );
            unique.add(securityTool.name);

            //Debug
            //logger.info(`repo: ${this.idForLogs}, found security tool: ${securityTool.name.toLowerCase()} workflow`);

            orgSecurityTools.push(
              new OrgSecurityTool(workflow.objType, securityTool.name, workflow.active, workflow.link, securityTool, {
                workflow: workflow,
              }),
            );
          }
        } catch (err) {
          logger.error(
            `uuid: ${this.uuid}, failed add security tool based on workflows: ${JSON.stringify(workflow)} for ${
              this.idForLogs
            }, err: ${err}`,
          );
        }
      }
    } catch (err) {
      logger.error(`failed add security tool based on workflows for ${this.idForLogs}, err: ${err}`);
    }
  }

  addToToolsCoverage(
    toolName: string,
    oxDelivered: boolean,
    appToolCoverageSourceType: AppToolCoverageSourceType,
    match: string,
    types: string[],
  ) {
    for (const type of types) {
      const isCovering = this.getToolCoverage(toolName, type, this.deploymentFiles);
      if (!isCovering) {
        continue;
      }

      const possibleNewItem: AppToolCoverage = new AppToolCoverage();
      possibleNewItem.toolName = toolName;
      possibleNewItem.oxDelivered = oxDelivered;
      possibleNewItem.coverage = isCovering.isCovered;
      possibleNewItem.type = SecurityToolsHelper.getTypeFromEnum(type);

      const appToolCoverageSource: AppToolCoverageSource = new AppToolCoverageSource();

      if (!possibleNewItem.validateInfo()) {
        continue;
      }

      possibleNewItem.reason = isCovering.reason;
      appToolCoverageSource.type = appToolCoverageSourceType;
      appToolCoverageSource.match = match;
      possibleNewItem.sources.push(appToolCoverageSource);

      SecurityToolsHelper.addToToolCoverage(this.toolCoverage, possibleNewItem);
    }
  }

  static getAppToolCoverageFromAlertsForApp(repo: Repo, securityEvent: SecurityEvent) {
    try {
      if (!repo.realRepo) {
        return;
      }

      const appToolCoverage: AppToolCoverage = new AppToolCoverage();
      appToolCoverage.coverage = true;
      appToolCoverage.oxDelivered = false;
      appToolCoverage.toolName = securityEvent.securityProvider;
      appToolCoverage.type = SecurityToolsHelper.getTypeFromEnum(securityEvent.securityAlertTypeStr);

      if (!appToolCoverage.validateInfo()) {
        return;
      }

      const source: AppToolCoverageSource = new AppToolCoverageSource();
      source.match = "";
      source.type = AppToolCoverageSourceType.Alert;
      appToolCoverage.sources.push(source);

      return appToolCoverage;
    } catch (err) {
      logger.error(`failed get app tool coverage from alerts for app, repo name: ${securityEvent.repoFullName} err: ${err}`);
    }
  }

  static addToToolCoverage(toolsCoverage: AppToolCoverage[], possibleNewItem: AppToolCoverage) {
    const toolsCoverageExist: AppToolCoverage = toolsCoverage.find(
      i => i.type === possibleNewItem.type && i.toolName === possibleNewItem.toolName,
    );
    if (!toolsCoverageExist) {
      toolsCoverage.push(possibleNewItem);
      return true;
    }
    //Found already checkmarx
    else {
      for (const source of possibleNewItem.sources) {
        const t = toolsCoverageExist.sources.find(i => i.type.toLowerCase() === source.type.toLowerCase());
        //Add only new source
        if (!t) {
          toolsCoverageExist.sources.push(source);
          return true;
        }
      }
    }
  }

  addSecurityToolBasedOnSecurityEvents(securityTool: SecurityTool, securityEvents: SecurityEvent[], orgSecurityTools: OrgSecurityTool[]) {
    try {
      const unique = new Set();

      for (const securityEvent of securityEvents) {
        try {
          if (securityTool.regex.exec(securityEvent.securityProvider) != null) {
            if (unique.has(securityTool.name)) {
              continue;
            }

            this.addToToolsCoverage(securityTool.name, securityTool.oxDelivered, AppToolCoverageSourceType.Alert, "", securityTool.type);
            unique.add(securityTool.name);

            //Debug
            //logger.info(`repo: ${this.idForLogs}, found security tool: ${securityTool.name.toLowerCase()} based on title`);

            orgSecurityTools.push(
              new OrgSecurityTool(securityEvent.objType, securityTool.name, securityEvent.active, securityEvent.link, securityTool, {
                securityEvent: securityEvent,
              }),
            );
          }
        } catch (err) {
          logger.error(
            `failed add security tool based on security event: ${JSON.stringify(securityEvent)} for ${this.idForLogs}, err: ${err}`,
          );
        }
      }
    } catch (err) {
      logger.error(`failed add security tool based on security event for ${this.idForLogs}, err: ${err}`);
    }
  }

  addSecurityToolBasedOnWebhooks(securityTool: SecurityTool, webhooks: Webhook[], orgSecurityTools: OrgSecurityTool[]) {
    try {
      const unique = new Set();

      for (const webhook of webhooks) {
        try {
          if (securityTool.regex.exec(webhook.url) != null || securityTool.regex.exec(webhook.description) != null) {
            if (unique.has(securityTool.name)) {
              continue;
            }

            this.addToToolsCoverage(
              securityTool.name,
              securityTool.oxDelivered,
              AppToolCoverageSourceType.Webhook,
              webhook.url,
              securityTool.type,
            );
            unique.add(securityTool.name);

            //Debug
            // logger.info(
            //   `repo: ${this.idForLogs}, found security tool: ${securityTool.name.toLowerCase()} based on webhook ${JSON.stringify(
            //     webhook,
            //   )}`,
            // );

            orgSecurityTools.push(
              new OrgSecurityTool(webhook.objType, securityTool.name, webhook.active, webhook.link, securityTool, { webhook: webhook }),
            );
          }
        } catch (err) {
          logger.error(
            `uuid: ${this.uuid}, failed add security tool based on webhooks: ${JSON.stringify(webhooks)}} for ${
              this.idForLogs
            }, err: ${err}`,
          );
        }
      }
    } catch (err) {
      logger.error(`failed add security tool based on webhooks for ${this.idForLogs}, err: ${err}`);
    }
  }

  isEmptyFile(file: File) {
    try {
      const content = this.fileHelper.readFile(file.path);
      if (!content || content === "\n") {
        return true;
      }
      return false;
    } catch (e) {
      logger.error(`isEmptyFile failed, err: ${e}`);
    }
    return false;
  }

  isInDirectory(file: File, dirs: string[] = [".github", ".gitlab", "docs"]) {
    try {
      const path = file.fileNameWithoutDisk.split("/");
      if (path.length === 1) {
        // means its root
        return true;
      }

      return dirs.includes(path[0]);
    } catch (e) {
      logger.error(`isInDirectory failed err: ${e}`);
    }
  }

  setIsEmptyFile(file: File) {
    try {
      const filesToRead = StatesHelper.Instance.filesToRead;
      const flat = [...StatesHelper.Instance.filesToRead.values()].flat().map(f => f.toLowerCase());

      if (!flat.includes(file.name.toLowerCase())) {
        return;
      }
      for (let [f, v] of filesToRead) {
        v = v.map(i => i.toLowerCase());

        const repoSpecialFiles = this.repo.specialFiles;
        repoSpecialFiles[f] = repoSpecialFiles[f] || [];

        if (v.includes(file.name.toLowerCase())) {
          const specialFile = new SpecialFile();
          specialFile.name = file.name;
          specialFile.isEmpty = this.isEmptyFile(file);
          specialFile.isInValidDir = this.isInDirectory(file);
          specialFile.isValid = !specialFile.isEmpty && specialFile.isInValidDir;
          specialFile.file = file;
          this.repo.specialFiles[f].push(specialFile);

          break;
        }
      }
    } catch (e) {
      logger.error(`setIsEmptyFile failed`, e);
    }
  }

  addSecurityToolBasedOnFiles(securityTool: SecurityTool, files: File[], orgSecurityTools: OrgSecurityTool[]) {
    try {
      const unique = new Set();

      for (const file of files) {
        try {
          if (securityTool.regexFilePath && securityTool.regexFilePath.exec(file.path) != null) {
            if (unique.has(securityTool.name)) {
              continue;
            }

            this.addToToolsCoverage(
              securityTool.name,
              securityTool.oxDelivered,
              AppToolCoverageSourceType.MentionInFile,
              `${this.repoFileLink}/${file.fileNameWithoutDisk}`,
              securityTool.type,
            );
            unique.add(securityTool.name);

            //Debug
            // logger.info(
            //   `addSecurityToolBasedOnFiles: repo: ${
            //     this.idForLogs
            //   },  found security tool: ${securityTool.name.toLowerCase()} based on file ${file.path}`,
            // );

            orgSecurityTools.push(new OrgSecurityTool(file.objType, securityTool.name, true, file.link, securityTool, { file: file }));
          }
        } catch (err) {
          logger.error(`failed add security tool based on files, for ${this.idForLogs}, err: ${err}`);
        }
      }
    } catch (err) {
      logger.error(`failed add security tool based on files for ${this.idForLogs}, err: ${err}`);
    }
  }

  setSpecialFiles(files: File[]) {
    try {
      for (const file of files) {
        this.setIsEmptyFile(file);
      }
    } catch (e) {
      logger.error(`setSpecialFiles failed err: ${e}`);
    }
  }

  addSecurityToolBasedOnGHSecurity(securityTool: SecurityTool, orgSecurityTools: OrgSecurityTool[]) {
    try {
      if (this.repo.type.toLowerCase() !== repoType.github.toLowerCase()) {
        return;
      }

      if (securityTool.name.toLowerCase() === "dependabot") {
        if (this.repo.isDependabotEnabled) {
          orgSecurityTools.push(new OrgSecurityTool(CodeRepoTypes.files, securityTool.name, true, "", securityTool, "GHSecurity"));
        }
      }

      if (securityTool.name.toLowerCase() === "dependabot") {
        if (this.repo.isSecretScanningEnabled) {
          orgSecurityTools.push(new OrgSecurityTool(CodeRepoTypes.files, securityTool.name, true, "", securityTool, "GHSecurity"));
        }
      }
    } catch (e) {
      logger.error(``, e);
    }
  }

  addSecurityToolBasedOnFilesContent(securityTools: SecurityTool[], orgSecurityTools: OrgSecurityTool[]) {
    try {
      const unique = new Set();

      for (const deploymentFile of this.deploymentFiles) {
        try {
          const content = this.fileHelper.readFile(deploymentFile);
          if (!content) {
            continue;
          }

          for (const securityTool of securityTools) {
            try {
              if (securityTool.regex.exec(content) != null) {
                if (unique.has(securityTool.name)) {
                  continue;
                }
                this.addToToolsCoverage(
                  securityTool.name,
                  securityTool.oxDelivered,
                  AppToolCoverageSourceType.MentionInFile,
                  `${this.repoFileLink}/${this.getPathWithoutDiskPrefix(deploymentFile, this.cloneDir)}`,
                  securityTool.type,
                );

                unique.add(securityTool.name);

                //Debug
                // logger.info(
                //   `addSecurityToolBasedOnFilesContent: repo: ${
                //     this.idForLogs
                //   },  found security tool: ${securityTool.name.toLowerCase()} based on file ${deploymentFile}`,
                // );

                orgSecurityTools.push(
                  new OrgSecurityTool(CodeRepoTypes.files, securityTool.name, true, "", securityTool, { file: deploymentFile }),
                );
              }
            } catch (err) {
              logger.error(`failed add security tool based single security tool, for ${this.idForLogs}, err: ${err}`);
            }
          }
        } catch (err) {
          logger.error(`failed add all security tool for single deployment file, for ${this.idForLogs}, err: ${err}`);
        }
      }
    } catch (err) {
      logger.error(`failed add security tool based on all files for ${this.idForLogs}, err: ${err}`);
    }
  }

  getPathWithoutDiskPrefix(path: string, repoCloneDir: string) {
    try {
      const fileNameWithoutDisk = path.replace(`${repoCloneDir}/`, "").toLowerCase();

      return fileNameWithoutDisk;
    } catch (err) {
      logger.error(`cannot set file name: ${path}, err: ${err}`);
    }
    return path;
  }

  getToolCoverage = (toolName, toolType, files) => {
    try {
      // here we have tools that were detected,
      // NOTICE: right now, aug 2022, connectors thar are not configured will not be in this list.
      // so if it is not there we cans assume it is not configured
      // local will always be undefined

      const toolConnector = staticConnectors.find(connector => connector.name.toLowerCase() === toolName.toLowerCase());

      if (toolConnector !== undefined) {
        if (!toolConnector.isConfigured) {
          return {
            isCovered: true,
            reason: CoverageReasons.DiscoveredNotConnected,
          };
        }
      }

      if (toolConnector === undefined) {
        return {
          isCovered: true,
          reason: CoverageReasons.DiscoveredNotConnected,
        };
      }

      const tool = securityVendorsToolsJson.securityVendorsTools.find(tool => tool.name.toLowerCase() === toolName.toLowerCase());

      switch (getStringFromEnumSecInfra(toolType)) {
        case "sast":
          const sastLangs = SastLangs.languages.map(i => i.toLowerCase());
          const repoSastLangs = [];
          let highestSastLang;

          if (this.languages.length) {
            for (const devLanguage of this.languages) {
              const language = devLanguage.language;

              if (sastLangs.includes(language.toLowerCase())) {
                repoSastLangs.push(devLanguage);
              }
            }

            if (repoSastLangs.length) {
              // get the highest percentage language
              highestSastLang = repoSastLangs.reduce((max, lang) => (max.languagePercentage > lang.languagePercentage ? max : lang));
            } else {
              return { isCovered: true, reason: CoverageReasons.NoLanguages };
            }

            const toolSastLangs = tool.sastLanguages.map(lang => lang.toLowerCase());
            // get highest must implement that if all are equal then, pick one that is in list
            const isLangCoveredByTool = toolSastLangs.includes(highestSastLang.language.toLowerCase());

            if (!isLangCoveredByTool) {
              return {
                isCovered: false,
                reason: `${CoverageReasons.LanguagesNotSupportedByTool} (${highestSastLang.language})`,
              };
            }

            return {
              isCovered: true,
              reason: CoverageReasons.NoReason,
            };
          } else {
            return { isCovered: true, reason: CoverageReasons.NoLanguages };
          }

        case "sca":
          const languagesFromDeps = this.fileHelper.getLanguagesBasedOnDependencyFiles(this.files);

          if (languagesFromDeps.length) {
            const highesScaLang = this.getHighestPercentageLanFromDepFiles(languagesFromDeps, this.languages);

            if (highesScaLang === undefined) {
              return {
                isCovered: true,
                reason: CoverageReasons.NoLanguages,
              };
            }

            const toolScaLangs = tool.scaLanguages.map(lang => lang.toLowerCase());

            const isLangCoveredByTool = toolScaLangs.includes(highesScaLang.language.toLowerCase());
            if (!isLangCoveredByTool) {
              return {
                isCovered: false,
                reason: `${CoverageReasons.LanguagesNotSupportedByTool} (${highesScaLang.language})`,
              };
            }

            return {
              isCovered: true,
              reason: CoverageReasons.NoReason,
            };
          } else {
            return {
              isCovered: true,
              reason: CoverageReasons.NoLanguages,
            };
          }
        case "secrets":
          return { isCovered: true, reason: CoverageReasons.NoReason };
        case "iac":
          return { isCovered: true, reason: CoverageReasons.NoReason };
        case "cspm":
          return { isCovered: true, reason: CoverageReasons.NoReason };
      }
    } catch (e) {
      logger.error(`get tool coverage failed on: ${this.idForLogs}, for tool: ${toolName} ${e}`);
    }
    return { isCovered: false, reason: CoverageReasons.NoReason };
  };
}

export default SecurityToolsHelper;
