import loggerImport from "../../../logger";
const logger = loggerImport.getDebugLogger();
//const { CircleCI } = require("circleci-api");
import { BuildSummary, CircleCI, Me, Project } from "circleci-api";

let counter = 1;
let deadQueue = [];

class CircleCIApi {
  ciOps: Project[];
  me: Me;
  token: string;
  api: CircleCI;

  constructor(token, optionalOwner = null, optionalRepo = null) {
    this.token = token;
    this.me = null;
    this.ciOps = null;

    try {
      if (optionalOwner === null && optionalRepo === null) {
        this.api = new CircleCI({
          token: this.token,
        });
      } else {
        this.api = new CircleCI({
          token: this.token,
          vcs: { owner: optionalOwner, repo: optionalRepo },
        });
      }
    } catch (error) {
      logger.error(error);
    }
  }

  async fetchImpl(functor: Function, retryBackoff: number) {
    return new Promise(async resolve => {
      setTimeout(async () => {
        try {
          const response = await functor();
          logger.debug(`Waited ${retryBackoff} seconds before fetching the data`);
          resolve(response);
        } catch (e) {
          if (e.response?.status === 429) {
            if (retryBackoff >= 30) {
              logger.error(`Waited for more than 30 seconds`);
              resolve({});
            } else {
              logger.debug(`Going to wait ${retryBackoff + 5} seconds now`);
              resolve(await this.fetchImpl(functor, retryBackoff + 5));
            }
          } else {
            resolve({});
          }
        }
      }, retryBackoff * 1000);
    });
  }

  async fetchCIProjects() {
    if (this.me === null) {
      this.me = await this.api.me();
    }

    return (await this.me).projects;
  }

  async fetchName() {
    if (this.me === null) {
      this.me = await this.api.me();
    }

    return (await this.me).login;
  }

  async fetchRecentBuilds() {
    const recentBuilds = await this.api.recentBuilds({ limit: 1 });
    return recentBuilds;
  }

  async fetchBuilds() {
    try {
      const builds = await this.fetchImpl(async () => {
        return this.api.builds();
      }, 1);
      return builds as BuildSummary[];
    } catch (error) {
      logger.error(`Failed to get build from CircleCI:`, error);
    }

    return [];
  }

  async fetchCIData() {
    if (this.ciOps === null) {
      this.ciOps = await this.api.projects();
    }

    const ciOpsList = await this.ciOps;

    let ciData = [];
    for (const ciOp of ciOpsList) {
      const { reponame, username, vcs_type, vcs_url, default_branch } = ciOp;

      ciData.push({
        reponame,
        username,
        vcs_type,
        vcs_url,
        default_branch,
      });
    }

    return ciData;
  }
}

export default CircleCIApi;
