import http from "https";
import StatesHelper from "../../../helper/statesHelper";
import loggerImport from "../../../logger";
const Jenkins = require("jenkins");
const logger = loggerImport.getDebugLogger();

export interface JenkinsApiResultWithStatus {
  status: number; // 200 for success, 404 for not found, etc.
  data: any; // the data returned from the API call
}

export default class JenkinsApi {
  token: string;
  user: string;
  url: string;
  jenkins: any;

  constructor(user: string, token: string, url: string) {
    this.token = token;
    this.user = user;
    this.url = url;
  }

  async connect() {
    const isHttps = this.url.startsWith("https");
    let url = this.url.replace(/(^\w+:|^)\/\//, "");

    const jenkinsConfig = {
      baseUrl: `${isHttps ? "https" : "http"}://${this.user}:${encodeURIComponent(this.token)}@${url}`,
      promisify: true,
      timeout: 30000,
    };

    //    if (await isJenkinsCertBypassEnabledForOrg.isJenkinsCertBypassEnabled(StatesHelper.Instance.orgName)) {
    jenkinsConfig["rejectUnauthorized"] = false;
    jenkinsConfig["agent"] = new http.Agent();
    //  }

    this.jenkins = new Jenkins(jenkinsConfig);
  }

  async getJobs() {
    try {
      const jobs = await this.jenkins.job.list();
      return jobs;
    } catch (e) {
      logger.error(`Failed to get Jenkins jobs, see err: ${e}`);
      StatesHelper.Instance.globalApisFails.add("jenkins");
    }

    return [];
  }

  async getJobInfo(jobName: string): Promise<JenkinsApiResultWithStatus> {
    try {
      const job = await this.jenkins.job.config(jobName);

      return {
        status: 200,
        data: job,
      };
    } catch (error) {
      logger.error(`Failed to get job info with error: `, error);
      return {
        status: error.statusCode ?? 400,
        data: null,
      };
    }
  }

  async getJob(jobName: string) {
    try {
      const job = await this.jenkins.job.get(jobName);
      return job;
    } catch (error) {
      logger.error(error);
      return null;
    }
  }
}
