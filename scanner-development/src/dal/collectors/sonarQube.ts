//https://snyk.docs.apiary.io/#reference/reporting-api/latest-issues/get-list-of-latest-issues
import { AlertSeverity, SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import axios, { AxiosResponse, AxiosRequestConfig, AxiosError } from "axios";
import PromisePool from "@supercharge/promise-pool/dist";

import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";

import path from "path";
import StatesHelper from "../../helper/statesHelper";

import {
  RulesDescriptionSections,
  Rules,
  SonarQubeComponent,
  SonarQubeProjectBranch,
  SonarCloudProject,
  SonarCloudProjectBranch,
  SonarQubeIssueStatus,
  SonarQubeHotspotStatus,
  SonarQubeHotspotResolution,
  SonarQubeComponentFilterQualifiers,
  SonarCloudComponentQualifier,
} from "../collectors/types/sonarQubeTypes";

const logger = loggerImport.getDebugLogger();

const linkToExternalProduct = `{host}/project/issues?resolved=false&id={project}&open={key}`;

const PAGE_SIZE = 500;

const CONCURRENT_POOL_CALL = {
  SONARCLOUD: {
    ORGANIZATION: 10,
    PROJECTS: 10,
    RULES: 10,
    ISSUES: 10,
    HOTSPOT: 10,
  },
  SONARQUBE: {
    PROJECTS: 10,
    RULES: 10,
    ISSUES: 10,
    HOTSPOT: 10,
  },
};

class SonarCloudAPI {
  private api: string;
  private token: string;

  public isValidToken: boolean = false;
  public uniqueProjects = new Set();
  public serverVersion: number = 0;

  public logName: string = "SonarCloud";

  private TIME_UNITS = {
    SEC: 1000,
    MIN: 60 * 1000,
  };

  private TIME_OUTS = {
    SHORT: 10 * this.TIME_UNITS.SEC,
    MEDIUM: 50 * this.TIME_UNITS.SEC,
    LONG: 2 * this.TIME_UNITS.MIN,
  };

  constructor(api: any, token: any) {
    this.api = api;
    this.token = token;
    this.isValidToken = false;

    try {
      if (this.api.endsWith("/")) {
        this.api = this.api.substring(0, this.api.length - 1);
      }
    } catch (err) {
      logger.error(`failed for sonarQube in constructor, err: ${err}`);
    }
  }

  getHeaders() {
    return {
      "Content-Type": "application/json",
    };
  }

  async auth() {
    const errMessage = `${this.logName} - Authenticate Failed : for token ${this.token}, host: ${this.api}, err: `;

    try {
      logger.info(`${this.logName} - Authentication Begin`);

      const result: AxiosResponse<any> = await axios.get(this.api + "/api/authentication/validate", {
        withCredentials: true,
        timeout: this.TIME_OUTS.MEDIUM,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
      if (result.data.valid) {
        this.isValidToken = true;
        logger.info(`${this.logName} - Authentication Success`);
      } else {
        this.isValidToken = false;
        logger.error(errMessage, "Not a valid Token!");
        StatesHelper.Instance.failedExternalTools.add("sonar-qube");
      }
      return result.data;
    } catch (error: any) {
      this.isValidToken = false;
      logger.error(errMessage, error);
      StatesHelper.Instance.failedExternalTools.add("sonar-qube");
    }
  }

  async getServerVersion() {
    try {
      logger.info(`${this.logName} - Getting Server Version`);

      const url = this.api + "/api/server/version";
      const result: AxiosResponse<any> = await axios.get(url, {
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });

      if (result.data) {
        logger.info(`${this.logName} - Found Server Version : ${result.data}`);
        this.serverVersion = parseFloat(result.data);
      }
    } catch (e) {
      logger.error(`${this.logName} - Error in Getting Server Version , Error : ${e}`);
    }
  }

  async getOrganization(page: number): Promise<AxiosResponse<any>> {
    try {
      const params = { ps: PAGE_SIZE, p: page, member: true };
      const url = this.api + "/api/organizations/search";

      return await axios.get(url, {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
    } catch (e) {
      logger.error(`${this.logName} - Getting Organizations Error , from ${(page - 1) * PAGE_SIZE} to ${page * PAGE_SIZE} , Error : ${e}`);
      return;
    }
  }

  async getOrganizations(organizationsList: Array<any>) {
    logger.info(`${this.logName} - Getting Organizations - ** Begin **`);

    const result: AxiosResponse<any> = await this.getOrganization(1);

    if (result?.data?.organizations?.length > 0) {
      organizationsList.push(...result.data.organizations);

      const total = result.data.paging.total;
      logger.info(`${this.logName} - Getting Organizations - Found ${total} Organizations`);

      const getTotalPage = Math.ceil(total / PAGE_SIZE);

      await PromisePool.for(Array.from({ length: getTotalPage - 1 }, (x, i) => i + 2))
        .withConcurrency(CONCURRENT_POOL_CALL.SONARCLOUD.ORGANIZATION)
        .process(async (page: number) => {
          const res = await this.getOrganization(page);
          if (res?.data?.organizations?.length > 0) {
            organizationsList.push(...res.data.organizations);
          }
        });
    }

    logger.info(`${this.logName} - Getting Organizations - ** Completed **`);
  }

  async getProject(organization: string, page: number): Promise<AxiosResponse<any>> {
    try {
      const params = { organization: organization, ps: PAGE_SIZE, p: page };
      const url = this.api + "/api/components/search";

      return await axios.get(url, {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
    } catch (e) {
      logger.error(`${this.logName} - Error Getting Projects , from ${(page - 1) * PAGE_SIZE} to ${page * PAGE_SIZE} , Error : ${e}`);
      return;
    }
  }

  async getProjects(organization: string, projectsList: SonarCloudProject[]) {
    logger.info(`${this.logName} - Getting Projects - ** Begin **`);

    const result: AxiosResponse<any> = await this.getProject(organization, 1);

    if (result?.data?.components?.length > 0) {
      for (const project of result.data.components as SonarCloudProject[]) {
        if (project.qualifier === SonarCloudComponentQualifier.TRK) {
          projectsList.push(project);
        }
      }

      const total = result.data.paging.total;
      logger.info(`${this.logName} - Getting Components - Found ${total} Components`);

      const getTotalPage = Math.ceil(total / PAGE_SIZE);

      await PromisePool.for(Array.from({ length: getTotalPage - 1 }, (x, i) => i + 2))
        .withConcurrency(CONCURRENT_POOL_CALL.SONARCLOUD.PROJECTS)
        .process(async (page: number) => {
          const res = await this.getProject(organization, page);
          if (res?.data?.components?.length > 0) {
            projectsList.push(...res.data.components);
          }
        });
    }

    logger.info(`${this.logName} - Getting Projects , Found ${projectsList.length} Projects - ** Completed **`);
  }

  async getProjectBranch(project: SonarCloudProject): Promise<AxiosResponse<any>> {
    try {
      const params = {
        project: project.key,
      };

      const url = this.api + "/api/project_branches/list";

      return await axios.get(url, {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
    } catch (e) {
      logger.error(`${this.logName} - Error Getting ProjectBranches , Error : ${e}`);
      return;
    }
  }

  async getProjectBranches(project: SonarCloudProject) {
    logger.info(`${this.logName} - Getting ProjectBranches for Project : '${project.name}'  - ** Begin **`);

    const result: AxiosResponse<any> = await this.getProjectBranch(project);

    if (result?.data?.branches?.length > 0) {
      project.branches = result.data.branches;

      const total = result.data.branches.length;
      logger.info(`${this.logName} - Getting ProjectBranches - Found ${total} Branches`);
    }

    logger.info(`${this.logName} - Getting ProjectBranches for Project : '${project.name}' - ** Completed **`);
  }

  async getRule(organization: string, page: number): Promise<AxiosResponse<any>> {
    const params = { organization: organization, ps: PAGE_SIZE, p: page };
    try {
      logger.info(`${this.logName} - Getting Rules , from ${(page - 1) * PAGE_SIZE} to ${page * PAGE_SIZE}`);

      return await axios.get(this.api + "/api/rules/search", {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
    } catch (e) {
      logger.error(`${this.logName} - Error Getting Rules , from ${(page - 1) * PAGE_SIZE} to ${page * PAGE_SIZE} , Error : ${e}`);
      return;
    }
  }

  async getRules(organization: string, rules: Rules[]) {
    logger.info(`${this.logName} - Getting Rules - ** Begin **`);

    const result: AxiosResponse<any> = await this.getRule(organization, 1);

    if (result?.data?.rules?.length > 0) {
      rules.push(...result.data.rules);

      const total = result.data.total;
      logger.info(`${this.logName} - Getting Rules - Found ${total} Rules`);

      const getTotalPage = Math.ceil(total / PAGE_SIZE);

      await PromisePool.for(Array.from({ length: getTotalPage - 1 }, (x, i) => i + 2))
        .withConcurrency(CONCURRENT_POOL_CALL.SONARCLOUD.RULES)
        .process(async (page: number) => {
          const res = await this.getRule(organization, page);
          if (res?.data?.rules?.length > 0) {
            rules.push(...res.data.rules);
          }
        });
    }

    logger.info(`${this.logName} - Getting Rules - ** Completed **`);
  }

  async getIssue(branch: SonarCloudProjectBranch, project: SonarCloudProject, page: number): Promise<AxiosResponse<any>> {
    const params = { componentKeys: project.key, components: project.key, branch: branch.name, ps: PAGE_SIZE, p: page, resolved: false };
    try {
      logger.info(`${this.logName} - Getting Issues , from ${(page - 1) * PAGE_SIZE} to ${page * PAGE_SIZE}`);

      return await axios.get(this.api + "/api/issues/search", {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
    } catch (e) {
      logger.error(
        `${this.logName} - Error Getting Issues for Project ${project.name} with Branch : ${branch.name}, from ${
          (page - 1) * PAGE_SIZE
        } to ${page * PAGE_SIZE} , Error : ${e}`,
      );
      return;
    }
  }

  async getIssues(branch: SonarCloudProjectBranch, project: SonarCloudProject) {
    logger.info(`${this.logName} - Getting Issues - ** Begin ** for Project : ${project.name}, branch : ${branch.name}`);

    const result: AxiosResponse<any> = await this.getIssue(branch, project, 1);

    if (result?.data?.issues?.length > 0) {
      branch.issues.push(...result.data.issues);

      const total = result.data.paging.total;
      logger.info(`${this.logName} - Getting Issues - Found ${total} Issues`);

      const getTotalPage = Math.ceil(total / PAGE_SIZE);

      //
      await PromisePool.for(Array.from({ length: getTotalPage - 1 }, (x, i) => i + 2))
        .withConcurrency(CONCURRENT_POOL_CALL.SONARCLOUD.ISSUES)
        .process(async (page: number) => {
          const res = await this.getIssue(branch, project, page);
          if (res?.data?.issues?.length > 0) {
            branch.issues.push(...res.data.issues);
          }
        });
    }

    logger.info(`${this.logName} - Getting Issues - ** Completed ** for Project : ${project.name}, branch : ${branch.name}`);
  }

  setIssue(project: SonarCloudProject, branch: SonarCloudProjectBranch, issue, rules, securityEventList) {
    try {
      const fullPath = issue.component.replace(`${issue.project}:`, "");
      const fileName = path.basename(fullPath);
      const securityEvent = new SecurityEvent(
        "SonarQube",
        true,
        "",
        issue.creationDate,
        "",
        "",
        "",
        `${issue.type} - ${issue.message}`,
        `${issue.type} - ${issue.message}`,
        fileName,
        issue.severity,
        "",
        issue.line,
        AlertSeverity[AlertSeverity.High],
        SecurityAlertType.sast,
        "",
        "",
        "",
        issue?.textRange?.endLine ? issue?.textRange?.endLine : -1,
        false,
        false,
        issue.author,
        "",
        issue.author,
        issue.creationDate,
        issue.rule,
        "",
        "",
        issue.project,
        "",
        fullPath,
        "sonar-qube",
      );

      securityEvent.version = branch.name;

      if (issue.key) {
        securityEvent.linkToExternalProduct = linkToExternalProduct
          .replace(`{host}`, this.api)
          .replace(`{key}`, issue.key)
          .replace(`{project}`, issue.project);
      }

      const realMatch = issue.hash ? issue.hash : fullPath;
      securityEvent.realMatch = realMatch;
      securityEvent.repoFullName = project.name;

      if (!securityEvent.realMatch) {
        logger.error(`sonarQube - failed real match, hash to single sec event, project: ${issue.project}, branch: ${branch.name}`);
        return;
      }

      rules
        .filter(rule => rule.key == issue.rule)
        .forEach((cRule: Rules) => {
          cRule.descriptionSections.forEach((rulesDesc: RulesDescriptionSections) => {
            if (rulesDesc.key == "root_cause") {
              securityEvent.title = rulesDesc.content;
            }

            if (rulesDesc.key == "how_to_fix") {
              securityEvent.recommendation = rulesDesc.content;
            }
          });
        });

      securityEventList.push(securityEvent);
    } catch (err) {
      logger.error(`${this.logName} - failed create single issue for project: ${project.name}, branch : ${branch.name}, Error: ${err}`);
    }
  }

  setIssueForFlow(project: SonarCloudProject, branch: SonarCloudProjectBranch, issue, flow, location, rules, securityEventList) {
    try {
      const fullPath = location.component.replace(`${issue.project}:`, "");
      const fileName = path.basename(fullPath);

      const securityEvent = new SecurityEvent(
        "SonarQube",
        true,
        "",
        issue.creationDate,
        "",
        "",
        "",
        `${issue.type} - ${location.msg}`,
        `${issue.type} - ${location.msg}`,
        fileName,
        issue.severity,
        "",
        location?.textRange?.startLine ? location?.textRange?.startLine : -1,
        AlertSeverity[AlertSeverity.High],
        SecurityAlertType.sast,
        issue.message,
        "",
        "",
        location?.textRange?.endLine ? location?.textRange?.endLine : -1,
        false,
        false,
        issue.author,
        "",
        issue.author,
        issue.creationDate,
        issue.rule,
        "",
        "",
        issue.project,
        "",
        fullPath,
        "sonar-qube",
      );

      securityEvent.version = branch.name;

      const realMatch = issue.hash ? issue.hash : fullPath;
      securityEvent.realMatch = realMatch;
      securityEvent.repoFullName = project.name;

      if (issue.key) {
        securityEvent.linkToExternalProduct = linkToExternalProduct
          .replace(`{host}`, this.api)
          .replace(`{key}`, issue.key)
          .replace(`{project}`, issue.project);
      }

      if (!securityEvent.realMatch) {
        logger.error(`sonarQube - failed real match hash2 to single sec event, project: ${issue.project}, branch : ${branch.name}`);
        return;
      }

      rules
        .filter(rule => rule.key == issue.rule)
        .forEach((cRule: Rules) => {
          cRule.descriptionSections.forEach((rulesDesc: RulesDescriptionSections) => {
            if (rulesDesc.key == "root_cause") {
              securityEvent.title = rulesDesc.content;
            }

            if (rulesDesc.key == "how_to_fix") {
              securityEvent.recommendation = rulesDesc.content;
            }
          });
        });

      securityEventList.push(securityEvent);
    } catch (err) {
      logger.error(`sonarQube - failed generate single location in project: ${issue.project}, branch : ${branch.name}, Error: ${err}`);
    }
  }

  async setIssues(project: SonarCloudProject, rules: Rules[], securityEventList: SecurityEvent[]) {
    for (const branch of project.branches) {
      await this.getIssues(branch, project);

      for (const issue of branch.issues) {
        if (issue.status === SonarQubeIssueStatus.Closed || issue.status === SonarQubeIssueStatus.Resolved) {
          continue;
        }

        if (issue.flows?.length > 0) {
          for (const flow of issue.flows) {
            for (const location of flow.locations) {
              this.setIssueForFlow(project, branch, issue, flow, location, rules, securityEventList);
            }
          }
        } else {
          this.setIssue(project, branch, issue, rules, securityEventList);
        }
      }
    }
  }

  async getHotspot(project: SonarCloudProject, branch: SonarCloudProjectBranch, page: number): Promise<any> {
    const params = { projectKey: project.key, ps: PAGE_SIZE, p: page };
    try {
      logger.info(`${this.logName} - Getting Hotspots , from ${(page - 1) * PAGE_SIZE} to ${page * PAGE_SIZE}`);

      return await axios.get(this.api + "/api/hotspots/search", {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
    } catch (e) {
      logger.error(
        `${this.logName} - Error Getting Hotspots for Project ${project.name} with Branch : ${branch.name}, from ${
          (page - 1) * PAGE_SIZE
        } to ${page * PAGE_SIZE} , Error : ${e}`,
      );
      return;
    }
  }

  async getHotspots(project: SonarCloudProject, branch: SonarCloudProjectBranch) {
    logger.info(`${this.logName} - Getting Hotspots - ** Begin ** for Project : ${project.name}, branch : ${branch.name}`);

    const result: AxiosResponse<any> = await this.getHotspot(project, branch, 1);

    if (result?.data?.hotspots?.length > 0) {
      branch.hostspots.push(...result.data.hotspots);

      const total = result.data.paging.total;
      logger.info(`${this.logName} - Getting Hotspots - Found ${total} Hotspots`);

      const getTotalPage = Math.ceil(total / PAGE_SIZE);

      await PromisePool.for(Array.from({ length: getTotalPage - 1 }, (x, i) => i + 2))
        .withConcurrency(CONCURRENT_POOL_CALL.SONARCLOUD.HOTSPOT)
        .process(async (page: number) => {
          const res = await this.getHotspot(project, branch, page);
          if (res?.data?.hotspots?.length > 0) {
            branch.hostspots.push(...res.data.hotspots);
          }
        });
    }

    logger.info(`${this.logName} - Getting Hotspots - ** Completed ** for Project : ${project}, branch : ${branch.name}`);
  }

  setHotspot(project: SonarCloudProject, branch: SonarCloudProjectBranch, hotspot, rules: Rules[], securityEventList: SecurityEvent[]) {
    try {
      const cat = hotspot.securityCategory;
      const fullPath = hotspot.component.replace(`${hotspot.project}:`, "");
      const fileName = path.basename(fullPath);
      const securityEvent = new SecurityEvent(
        "SonarQube",
        true,
        "",
        hotspot.creationDate,
        "",
        "",
        "",
        cat ? `hotspot(${cat}) - ${hotspot.message}` : `hotspot - ${hotspot.message}`,
        cat ? `hotspot(${cat}) - ${hotspot.message}` : `hotspot - ${hotspot.message}`,
        fileName,
        hotspot.vulnerabilityProbability,
        "",
        hotspot.line,
        AlertSeverity[AlertSeverity.High],
        SecurityAlertType.sast,
        hotspot.message,
        "",
        "",
        -1,
        false,
        false,
        hotspot.author,
        "",
        hotspot.author,
        hotspot.creationDate,
        hotspot.ruleKey,
        "",
        "",
        hotspot.project,
        "",
        fullPath,
        "sonar-qube",
      );

      if (hotspot.key) {
        securityEvent.linkToExternalProduct = linkToExternalProduct
          .replace(`{host}`, this.api)
          .replace(`{key}`, hotspot.key)
          .replace(`{project}`, hotspot.project);
      }

      const realMatch = fullPath ? fullPath : hotspot.key;
      securityEvent.realMatch = realMatch;
      securityEvent.repoFullName = project.name;

      if (!securityEvent.realMatch) {
        logger.error(`sonarQube - failed real match to fullPath single sec event, project: ${hotspot.project}, branch: ${branch.name}`);
        return;
      }

      rules
        .filter(rule => rule.key == hotspot.rule)
        .forEach((cRule: Rules) => {
          cRule.descriptionSections.forEach((rulesDesc: RulesDescriptionSections) => {
            if (rulesDesc.key == "root_cause") {
              securityEvent.title = rulesDesc.content;
            }

            if (rulesDesc.key == "how_to_fix") {
              securityEvent.recommendation = rulesDesc.content;
            }
          });
        });

      securityEventList.push(securityEvent);
    } catch (err) {
      logger.error(`sonarQube - failed generate single location in project: ${hotspot.project}, branch: ${branch.name}, Error : ${err}`);
    }
  }

  async setHotspots(project: SonarCloudProject, rules: Rules[], securityEventList: SecurityEvent[]) {
    for (const branch of project.branches) {
      // hotspots currently does not support the branch filter , so we are using the main branch
      if (branch.isMain === true) {
        await this.getHotspots(project, branch);

        for (const hotspot of branch.hostspots) {
          if (hotspot.status !== "TO_REVIEW" && hotspot.status == "REVIEWED" && hotspot.resolution !== "ACKNOWLEDGED") {
            continue;
          }

          this.setHotspot(project, branch, hotspot, rules, securityEventList);
        }
      }
    }
  }

  async securityEvents() {
    let securityEventList: SecurityEvent[] = [];
    if (this.isValidToken) {
      try {
        await this.getServerVersion();

        logger.info(`${this.logName} - Try Collect Security Events`);

        const organizationsList: Array<any> = [];
        await this.getOrganizations(organizationsList);

        if (organizationsList.length > 0) {
          const projectsList: SonarCloudProject[] = [];
          for (const org of organizationsList) {
            await this.getProjects(org.key, projectsList);
          }

          const rules = [];
          if (projectsList.length > 0) {
            for (const org of organizationsList) {
              await this.getRules(org.key, rules);
            }
          }

          for (const project of projectsList) {
            try {
              await this.getProjectBranches(project);
              await this.setIssues(project, rules, securityEventList);
              await this.setHotspots(project, rules, securityEventList);
            } catch (e) {
              logger.error(`${this.logName} - failed collect single issue, Error : ${e}`);
            }
          }
        }
      } catch (err) {
        logger.error(`${this.logName} - failed to set all ${this.logName} security events, Error : ${err}`);
        StatesHelper.Instance.globalApisFails.add("sonar-qube");
      }

      logger.info(`${this.logName} - Finish Collecting Security Events with Count: ${securityEventList.length}`);
    }

    return securityEventList;
  }
}

class SonarQubeAPI {
  private api: string;
  private token: string;

  public isValidToken: boolean = false;
  public uniqueProjects = new Set();
  public serverVersion: number = 0;

  public logName: string = "SonarQube";

  private TIME_UNITS = {
    SEC: 1000,
    MIN: 60 * 1000,
  };

  private TIME_OUTS = {
    SHORT: 10 * this.TIME_UNITS.SEC,
    MEDIUM: 50 * this.TIME_UNITS.SEC,
    LONG: 2 * this.TIME_UNITS.MIN,
  };

  constructor(api: any, token: any) {
    this.api = api;
    this.token = token;
    this.isValidToken = false;
  }

  async auth() {
    const errMessage = `${this.logName} - Authenticate Failed : for token ${this.token}, host: ${this.api}, err: `;

    try {
      logger.info(`${this.logName} - Authentication Begin`);

      const result: AxiosResponse<any> = await axios.get(this.api + "/api/authentication/validate", {
        withCredentials: true,
        timeout: this.TIME_OUTS.MEDIUM,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
      if (result.data.valid) {
        this.isValidToken = true;
        logger.info(`${this.logName} - Authentication Success`);
      } else {
        this.isValidToken = false;
        logger.error(errMessage, "Not a valid Token!");
        StatesHelper.Instance.failedExternalTools.add("sonar-qube");
      }
      return result.data;
    } catch (error: any) {
      this.isValidToken = false;
      logger.error(errMessage, error);
      StatesHelper.Instance.failedExternalTools.add("sonar-qube");
    }
  }

  getHeaders() {
    return {
      "Content-Type": "application/json",
    };
  }

  async getServerVersion() {
    try {
      logger.info(`${this.logName} - Getting Server Version`);

      const url = this.api + "/api/server/version";
      const result: AxiosResponse<any> = await axios.get(url, {
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });

      if (result.data) {
        logger.info(`${this.logName} - Found Server Version : ${result.data}`);
        this.serverVersion = parseFloat(result.data);
      }
    } catch (e) {
      logger.error(`${this.logName} - Error in Getting Server Version , Error : ${e}`);
    }
  }

  async getProject(page: number): Promise<AxiosResponse<any>> {
    try {
      const params = {
        ps: PAGE_SIZE,
        p: page,
        qualifiers: SonarQubeComponentFilterQualifiers.TRK,
      };

      const url = this.api + "/api/components/search";

      return await axios.get(url, {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
    } catch (e) {
      logger.error(`${this.logName} - Error Getting Projects , from ${(page - 1) * PAGE_SIZE} to ${page * PAGE_SIZE} , Error : ${e}`);
      return;
    }
  }

  async getProjects(projectsList: SonarQubeComponent[]) {
    logger.info(`${this.logName} - Getting Projects - ** Begin **`);

    const result: AxiosResponse<any> = await this.getProject(1);

    if (result?.data?.components?.length > 0) {
      projectsList.push(...result.data.components);

      const total = result.data.paging.total;
      logger.info(`${this.logName} - Getting Projects - Found ${total} Projects`);

      const getTotalPage = Math.ceil(total / PAGE_SIZE);

      await PromisePool.for(Array.from({ length: getTotalPage - 1 }, (x, i) => i + 2))
        .withConcurrency(CONCURRENT_POOL_CALL.SONARQUBE.PROJECTS)
        .process(async (page: number) => {
          const res = await this.getProject(page);
          if (res?.data?.components?.length > 0) {
            projectsList.push(...res.data.components);
          }
        });
    }

    logger.info(`${this.logName} - Getting Projects - ** Completed **`);
  }

  async getProjectBranch(project: SonarQubeComponent): Promise<AxiosResponse<any>> {
    try {
      const params = {
        project: project.key,
      };

      const url = this.api + "/api/project_branches/list";

      return await axios.get(url, {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
    } catch (e) {
      logger.error(`${this.logName} - Error Getting ProjectBranches , Error : ${e}`);
      return;
    }
  }

  async getProjectBranches(project: SonarQubeComponent) {
    logger.info(`${this.logName} - Getting ProjectBranches for Project : '${project.name}'  - ** Begin **`);

    const result: AxiosResponse<any> = await this.getProjectBranch(project);

    if (result?.data?.branches?.length > 0) {
      project.branches = result.data.branches;

      const total = result.data.branches.length;
      logger.info(`${this.logName} - Getting ProjectBranches - Found ${total} Branches`);
    }

    logger.info(`${this.logName} - Getting ProjectBranches for Project : '${project.name}' - ** Completed **`);
  }

  async getRule(page: number): Promise<AxiosResponse<any>> {
    const params = { ps: PAGE_SIZE, p: page };
    try {
      logger.info(`${this.logName} - Getting Rules , from ${(page - 1) * PAGE_SIZE} to ${page * PAGE_SIZE}`);

      return await axios.get(this.api + "/api/rules/search", {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
    } catch (e) {
      logger.error(`${this.logName} - Error Getting Rules , from ${(page - 1) * PAGE_SIZE} to ${page * PAGE_SIZE} , Error : ${e}`);
      return;
    }
  }

  async getRules(rules: Rules[]) {
    logger.info(`${this.logName} - Getting Rules - ** Begin **`);

    const result: AxiosResponse<any> = await this.getRule(1);

    if (result?.data?.rules?.length > 0) {
      rules.push(...result.data.rules);

      const total = result.data.paging.total;
      logger.info(`${this.logName} - Getting Rules - Found ${total} Rules`);

      const getTotalPage = Math.ceil(total / PAGE_SIZE);

      await PromisePool.for(Array.from({ length: getTotalPage - 1 }, (x, i) => i + 2))
        .withConcurrency(CONCURRENT_POOL_CALL.SONARQUBE.RULES)
        .process(async (page: number) => {
          const res = await this.getRule(page);
          if (res?.data?.rules?.length > 0) {
            rules.push(...res.data.rules);
          }
        });
    }

    logger.info(`${this.logName} - Getting Rules - ** Completed **`);
  }

  async getIssue(branch: SonarQubeProjectBranch, project: SonarQubeComponent, page: number): Promise<AxiosResponse<any>> {
    // 10.2 - Parameter 'componentKeys' renamed to 'components'
    const params = {
      branch: branch.name,
      componentKeys: project.key,
      components: project.key,
      resolved: false,
      ps: PAGE_SIZE,
      p: page,
    };

    try {
      logger.info(`${this.logName} - Getting Issues , from ${(page - 1) * PAGE_SIZE} to ${page * PAGE_SIZE}`);

      return await axios.get(this.api + "/api/issues/search", {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
    } catch (e) {
      logger.error(
        `${this.logName} - Error Getting Issues for Project ${project} with Poject Name : ${project.name} with Branch : ${
          branch.name
        }, from ${(page - 1) * PAGE_SIZE} to ${page * PAGE_SIZE}, Error : ${e}`,
      );
      return;
    }
  }

  async getIssues(branch: SonarQubeProjectBranch, project: SonarQubeComponent) {
    logger.info(`${this.logName} - Getting Issues - ** Begin ** for Project : ${project.name} for Branch : ${branch.name}`);

    branch.issues = [];
    const result: AxiosResponse<any> = await this.getIssue(branch, project, 1);

    if (result?.data?.issues?.length > 0) {
      branch.issues.push(...result.data.issues);

      const total = result.data.paging.total;
      logger.info(`${this.logName} - Getting Issues - Found ${total} Issues`);

      const getTotalPage = Math.ceil(total / PAGE_SIZE);

      await PromisePool.for(Array.from({ length: getTotalPage - 1 }, (x, i) => i + 2))
        .withConcurrency(CONCURRENT_POOL_CALL.SONARQUBE.ISSUES)
        .process(async (page: number) => {
          const res = await this.getIssue(branch, project, page);
          if (res?.data?.issues?.length > 0) {
            branch.issues.push(...res.data.issues);
          }
        });
    }

    logger.info(`${this.logName} - Getting Issues - ** Completed ** for Project : ${project.name} for Branch : ${branch.name}`);
  }

  decodeEntities(encodedString) {
    const translate_re = /&(nbsp|amp|quot|lt|gt);/g;
    const translate = {
      nbsp: " ",
      amp: "&",
      quot: '"',
      lt: "<",
      gt: ">",
    };
    return encodedString
      .replace(translate_re, function (match, entity) {
        return translate[entity];
      })
      .replace(/&#(\d+);/gi, function (match, numStr) {
        const num = parseInt(numStr, 10);
        return String.fromCharCode(num);
      });
  }

  async getLineContent(file, textRange: any) {
    const content = { lineContent: "", snippetContent: "" };
    try {
      const contentLines = [];

      if (!textRange || (textRange && !textRange.startLine)) {
        return content;
      }

      const params = {
        key: file,
        from: textRange.startLine < 3 ? 1 : textRange.startLine - 2,
        to: textRange.endLine + 2,
      };

      try {
        const res: any = await axios.get(this.api + "/api/sources/lines", {
          params: params,
          withCredentials: true,
          timeout: this.TIME_OUTS.LONG,
          headers: this.getHeaders(),
          auth: {
            username: this.token,
            password: "",
          },
        });

        if (res && res.data && res.data.sources) {
          for (const row of res.data.sources) {
            contentLines.push({ line: row.line, content: this.decodeEntities(row.code.replace(/<[^>]*>?/gm, "")) });
          }
        }
      } catch (e) {
        logger.error(`Error in getting line content for file : ${file} , error ${e}`);
      }

      for (const contentLine of contentLines) {
        if (content.snippetContent != "") {
          content.snippetContent += "\r\n";
        }

        content.snippetContent += contentLine.content;

        if (contentLine.line == textRange.startLine) {
          content.lineContent = contentLine.content;
        }
      }
    } catch (e) {
      logger.error(`Error in getting line content for file : ${file} , error ${e}`);
    }

    return content;
  }

  setIssue(project: SonarQubeComponent, branch: SonarQubeProjectBranch, issue, content: any, rules, securityEventList) {
    try {
      const fullPath = issue.component.replace(`${issue.project}:`, "");
      const fileName = path.basename(fullPath);

      const securityEvent = new SecurityEvent(
        "SonarQube",
        true,
        "",
        issue.creationDate,
        "",
        "",
        "",
        `${issue.type} - ${issue.message}`,
        `${issue.type} - ${issue.message}`,
        fileName,
        issue.severity,
        "",
        issue.line,
        AlertSeverity[AlertSeverity.High],
        SecurityAlertType.sast,
        "",
        content.lineContent,
        "",
        issue?.textRange?.endLine ? issue?.textRange?.endLine : -1,
        false,
        false,
        issue.author,
        "",
        issue.author,
        issue.creationDate,
        issue.rule,
        "",
        "",
        issue.project,
        "",
        fullPath,
        "sonar-qube",
      );

      securityEvent.snippetContent = content.snippetContent;

      if (issue.key) {
        securityEvent.linkToExternalProduct = linkToExternalProduct
          .replace(`{host}`, this.api)
          .replace(`{key}`, issue.key)
          .replace(`{project}`, issue.project);
      }

      const realMatch = issue.hash ? issue.hash : fullPath;
      securityEvent.realMatch = realMatch;
      securityEvent.repoFullName = project.name;
      if (branch.name) {
        securityEvent.version = branch.name;
      }

      if (!securityEvent.realMatch) {
        logger.error(`sonarQube - failed real match to hash3 single sec event, project: ${issue.project}`);
        return;
      }

      rules
        .filter(rule => rule.key == issue.rule)
        .forEach((cRule: Rules) => {
          cRule.descriptionSections.forEach((rulesDesc: RulesDescriptionSections) => {
            if (rulesDesc.key == "root_cause") {
              securityEvent.title = rulesDesc.content;
            }

            if (rulesDesc.key == "how_to_fix") {
              securityEvent.recommendation = rulesDesc.content;
            }
          });
        });

      securityEventList.push(securityEvent);
    } catch (err) {
      logger.error(`${this.logName} - failed create single issue for project: ${project.name}, Error : ${err}`);
    }
  }

  setIssueForFlow(
    project: SonarQubeComponent,
    branch: SonarQubeProjectBranch,
    issue,
    flow,
    location,
    content: any,
    rules,
    securityEventList,
  ) {
    try {
      const fullPath = location.component.replace(`${issue.project}:`, "");
      const fileName = path.basename(fullPath);
      const securityEvent = new SecurityEvent(
        "SonarQube",
        true,
        "",
        issue.creationDate,
        "",
        "",
        "",
        `${issue.type} - ${location.msg}`,
        `${issue.type} - ${location.msg}`,
        fileName,
        issue.severity,
        "",
        location?.textRange?.startLine ? location?.textRange?.startLine : -1,
        AlertSeverity[AlertSeverity.High],
        SecurityAlertType.sast,
        issue.message,
        content.lineContent,
        "",
        location?.textRange?.endLine ? location?.textRange?.endLine : -1,
        false,
        false,
        issue.author,
        "",
        issue.author,
        issue.creationDate,
        issue.rule,
        "",
        "",
        issue.project,
        "",
        fullPath,
        "sonar-qube",
      );
      securityEvent.snippetContent = content.snippetContent;

      const realMatch = issue.hash ? issue.hash : fullPath;
      securityEvent.realMatch = realMatch;
      securityEvent.repoFullName = project.name;
      if (branch.name) {
        securityEvent.version = branch.name;
      }

      if (issue.key) {
        securityEvent.linkToExternalProduct = linkToExternalProduct
          .replace(`{host}`, this.api)
          .replace(`{key}`, issue.key)
          .replace(`{project}`, issue.project);
      }

      if (!securityEvent.realMatch) {
        logger.error(`sonarQube - failed real match to hash4 single sec event, project: ${issue.project}`);
        return;
      }

      rules
        .filter(rule => rule.key == issue.rule)
        .forEach((cRule: Rules) => {
          cRule.descriptionSections.forEach((rulesDesc: RulesDescriptionSections) => {
            if (rulesDesc.key == "root_cause") {
              securityEvent.title = rulesDesc.content;
            }

            if (rulesDesc.key == "how_to_fix") {
              securityEvent.recommendation = rulesDesc.content;
            }
          });
        });

      securityEventList.push(securityEvent);
    } catch (err) {
      logger.error(`sonarQube - failed generate single location in project: ${issue.project}, Error : ${err}`);
    }
  }

  async setIssues(project: SonarQubeComponent, rules: Rules[], securityEventList: SecurityEvent[]) {
    for (const branch of project.branches) {
      await this.getIssues(branch, project);

      for (const issue of branch.issues) {
        if (issue.status == SonarQubeIssueStatus.Resolved || issue.status == SonarQubeIssueStatus.Closed) {
          continue;
        }

        //Ignore none VULNERABILITYs for mobily only
        if (StatesHelper.Instance.isMobiliy) {
          if (issue?.type !== "VULNERABILITY") {
            continue;
          }
        } else {
          if (issue.type !== "VULNERABILITY" && issue.type !== "CODE_SMELL" && issue.type !== "BUG") {
            continue;
          }
        }

        // only get the file content , if the token has the username and password
        let content = await this.getLineContent(issue.component, issue.textRange);

        if (issue.flows?.length > 0) {
          for (const flow of issue.flows) {
            for (const location of flow.locations) {
              this.setIssueForFlow(project, branch, issue, flow, location, content, rules, securityEventList);
            }
          }
        } else {
          this.setIssue(project, branch, issue, content, rules, securityEventList);
        }
      }
    }
  }

  async getHotspot(project: SonarQubeComponent, branch: SonarQubeProjectBranch, page: number): Promise<any> {
    // 10.2 - Parameter 'projectKey' renamed to 'project'
    const params = {
      projectKey: project.key,
      project: project.key,
      branch: branch.name,
      ps: PAGE_SIZE,
      p: page,
    };

    try {
      logger.info(`${this.logName} - Getting Hotspots , from ${(page - 1) * PAGE_SIZE} to ${page * PAGE_SIZE}`);

      return await axios.get(this.api + "/api/hotspots/search", {
        params: params,
        withCredentials: true,
        timeout: this.TIME_OUTS.LONG,
        headers: this.getHeaders(),
        auth: {
          username: this.token,
          password: "",
        },
      });
    } catch (e) {
      logger.error(
        `${this.logName} - Error Getting Hotspots for Project ${project.name} with Branch : ${branch.name}, from ${
          (page - 1) * PAGE_SIZE
        } to ${page * PAGE_SIZE}, Error : ${e}`,
      );
    }
  }

  async getHotspots(project: SonarQubeComponent, branch: SonarQubeProjectBranch) {
    branch.hostspots = [];
    logger.info(`${this.logName} - Getting Hotspots - ** Begin ** for Project : ${project.name}, Branch : ${branch.name}`);

    const result: AxiosResponse<any> = await this.getHotspot(project, branch, 1);

    if (result?.data?.hotspots?.length > 0) {
      branch.hostspots.push(...result.data.hotspots);

      const total = result.data.paging.total;
      logger.info(`${this.logName} - Getting Hotspots - Found ${total} Hotspots`);

      const getTotalPage = Math.ceil(total / PAGE_SIZE);

      await PromisePool.for(Array.from({ length: getTotalPage - 1 }, (x, i) => i + 2))
        .withConcurrency(CONCURRENT_POOL_CALL.SONARQUBE.HOTSPOT)
        .process(async (page: number) => {
          const res = await this.getHotspot(project, branch, page);
          if (res?.data?.hotspots?.length > 0) {
            branch.hostspots.push(...res.data.hotspots);
          }
        });
    } else {
      logger.info(`${this.logName} - Getting Hotspots - Found 0 Hotspots`);
    }

    logger.info(`${this.logName} - Getting Hotspots - ** Completed ** for Project : ${project.name}, Branch : ${branch.name}`);
  }

  setHotspot(project: SonarQubeComponent, branch: SonarQubeProjectBranch, hotspot, rules: Rules[], securityEventList: SecurityEvent[]) {
    try {
      const cat = hotspot.securityCategory;
      const fullPath = hotspot.component.replace(`${hotspot.project}:`, "");
      const fileName = path.basename(fullPath);
      const securityEvent = new SecurityEvent(
        "SonarQube",
        true,
        "",
        hotspot.creationDate,
        "",
        "",
        "",
        cat ? `hotspot(${cat}) - ${hotspot.message}` : `hotspot - ${hotspot.message}`,
        cat ? `hotspot(${cat}) - ${hotspot.message}` : `hotspot - ${hotspot.message}`,
        fileName,
        hotspot.vulnerabilityProbability,
        "",
        hotspot.line,
        AlertSeverity[AlertSeverity.High],
        SecurityAlertType.sast,
        hotspot.message,
        "",
        "",
        -1,
        false,
        false,
        hotspot.author,
        "",
        hotspot.author,
        hotspot.creationDate,
        hotspot.ruleKey,
        "",
        "",
        hotspot.project,
        "",
        fullPath,
        "sonar-qube",
      );

      if (hotspot.key) {
        securityEvent.linkToExternalProduct = linkToExternalProduct
          .replace(`{host}`, this.api)
          .replace(`{key}`, hotspot.key)
          .replace(`{project}`, hotspot.project);
      }

      const realMatch = fullPath ? fullPath : hotspot.key;
      securityEvent.realMatch = realMatch;
      securityEvent.repoFullName = project.name;
      if (branch.name) {
        securityEvent.version = branch.name;
      }

      if (!securityEvent.realMatch) {
        logger.error(`sonarQube - failed real match to fullPath2 single sec event, project: ${hotspot.project}, Branch: ${branch.name}`);
        return;
      }

      rules
        .filter(rule => rule.key == hotspot.rule)
        .forEach((cRule: Rules) => {
          cRule.descriptionSections.forEach((rulesDesc: RulesDescriptionSections) => {
            if (rulesDesc.key == "root_cause") {
              securityEvent.title = rulesDesc.content;
            }

            if (rulesDesc.key == "how_to_fix") {
              securityEvent.recommendation = rulesDesc.content;
            }
          });
        });

      securityEventList.push(securityEvent);
    } catch (err) {
      logger.error(`sonarQube - failed generate single location in project: ${hotspot.project}, Branch : ${branch.name}, Error : ${err}`);
    }
  }

  async setHotspots(project: SonarQubeComponent, rules: Rules[], securityEventList: SecurityEvent[]) {
    for (const branch of project.branches) {
      await this.getHotspots(project, branch);

      for (const hotspot of branch.hostspots) {
        if (hotspot.status === SonarQubeHotspotStatus.Reviewed && hotspot.resolution !== SonarQubeHotspotResolution.Acknowledged) {
          continue;
        }

        this.setHotspot(project, branch, hotspot, rules, securityEventList);
      }
    }
  }

  async securityEvents() {
    let securityEventList: SecurityEvent[] = [];
    if (this.isValidToken) {
      await this.getServerVersion();

      try {
        logger.info(`${this.logName} - Try Collect Security Events`);

        let projectsList: SonarQubeComponent[] = [];

        try {
          await this.getProjects(projectsList);
        } catch (err) {
          logger.error(`${this.logName} - failed collect single org project, Error : ${err}`);
        }

        logger.info(`${this.logName} - found ${projectsList.length} projects`);

        const rules: Rules[] = [];
        if (projectsList.length > 0) {
          await this.getRules(rules);

          for (const project of projectsList) {
            try {
              await this.getProjectBranches(project);
              await this.setIssues(project, rules, securityEventList);
              await this.setHotspots(project, rules, securityEventList);
            } catch (e) {
              logger.error(`${this.logName} - failed collect single issue, Error : ${e}`);
            }
          }
        }
      } catch (err) {
        logger.error(`${this.logName} - failed to set all ${this.logName} security events, Error : ${err}`);
        StatesHelper.Instance.globalApisFails.add("sonar-qube");
      }

      logger.info(
        `${this.logName} - Finish Collecting Security Events with Count: ${securityEventList.length}, projects: ${Array.from(
          this?.uniqueProjects,
        )}`,
      );
    }

    return securityEventList;
  }
}

class SonarQube extends ExternalSecurityProviderBase {
  host: string;
  private_token: string;
  uniqueRepos = {};
  private clientApi: SonarQubeAPI | SonarCloudAPI;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.token = token;
    this.host = token.host;
    this.private_token = token.password;
  }

  getClientAPI() {
    logger.info(`set ${this.token.name}, host: ${this.host}`);

    if (this.host.endsWith("/")) {
      const i = this.host.lastIndexOf("/");
      this.host = this.host.substring(0, i);
      logger.info(`${this.token.name} - removing slash from apiUrl: ${this.host}`);
    }

    if (this.host == "https://sonarcloud.io") {
      logger.info(`${this.token.name} - setting the API for the SonarCloud`);
      this.clientApi = new SonarCloudAPI(this.host, this.private_token);
    } else {
      logger.info(`${this.token.name} - setting the API for the SonarQube`);
      this.clientApi = new SonarQubeAPI(this.host, this.private_token);
    }
  }

  async initLib() {
    try {
      // Setting the Client API for the cloud or the self hosted
      this.getClientAPI();

      await this.clientApi.auth();
    } catch (err) {
      logger.error(`failed to initialize ${this.token.name}, , host: ${this.host}, Error : ${err}`);
      StatesHelper.Instance.globalApisFails.add("sonar-qube");
    }
  }

  async securityEvents() {
    try {
      return await this.clientApi.securityEvents();
    } catch (e) {
      logger.error(`${this.clientApi.logName} - Error in securityEvents , ${e}`);
      return [];
    }
  }
}

export default SonarQube;
