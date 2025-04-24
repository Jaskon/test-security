import CodeRepoGithub from "../../dal/collectors/github";
import GitHubCITool from "../../dal/collectors/githubci";
import GlobalCodeRepoData from "../../dal/GolobalCollectorData/globalCodeRepoData";
import { Organization } from "../../entitis/codeRepoTypes";
import loggerImport from "../../logger";
import RateLimitHelper from "../rateLimitHelper";
import StatesHelper from "../statesHelper";
import TimeHelper from "../timeHelper";
const logger = loggerImport.getDebugLogger();

export class GithubHelper {
  per_page_max_res: number;
  connector: CodeRepoGithub | GitHubCITool;
  orgs: Organization[] = [];
  orgObjs: any[] = [];
  timeHelper: TimeHelper = new TimeHelper("");

  constructor(per_page_max_res: number, connector: CodeRepoGithub | GitHubCITool) {
    this.connector = connector;
    this.per_page_max_res = per_page_max_res;
  }

  async getTimeToWait(rateLimitHelper: RateLimitHelper, timeout_to_wait_after_rate_limit_happen: number) {
    let timeToWait;
    if (rateLimitHelper.isRateLimitDueToMaxAllowedRequest()) {
      const res = await this.getGithubRateLimitInfo();
      if (res) {
        //Set the allowed rate limit, when this will not be in rate limit it will have the
        //number of request we can start to do
        rateLimitHelper.totalRequestAllowed = res.remaining;
        logger.info(`set remaining request: ${rateLimitHelper.totalRequestAllowed}`);
        //In case rate limit now over return 0 as time to wait
        if (rateLimitHelper.totalRequestAllowed != 0) {
          return 0;
        }

        //Calc how match time need to wait
        timeToWait = this.timeHelper.getDiffFromNowInMilliSeconds(res.reset);
        return timeToWait;
      }
    }
    return timeout_to_wait_after_rate_limit_happen;
  }

  async getGithubRateLimitInfo() {
    try {
      const res = await this.connector.octokit.request("GET /rate_limit", {});
      logger.info(`github rate limit info: ${JSON.stringify(res.data)}`);
      return res.data.rate;
    } catch (err) {
      logger.error(`failed to get github rate limit info, err: ${err}`);
    }
  }

  async getSingleRepositoryById(repoId: string) {
    try {
      const query = {
        url: "GET /repositories/{id}",
        parms: {
          id: repoId,
          page: 1,
          per_page: 1,
        },
      };

      const res = await this.connector.invokeRequest(query);
      return res[0] ? res[0] : null;
    } catch (err) {
      logger.error(`failed to getSingleRepositoryById, e: ${err}`);
      return null;
    }
  }

  // additionally pushes org objects to class instance, see getOrgsRepos
  async getAllReposOfOrg() {
    //For perion, kaltura
    if ("org_lUeR3PnnVN9oFM3B" === StatesHelper.Instance.orgName || "org_8TD2RD60KX032Cyz" === StatesHelper.Instance.orgName) {
      const allRepos = await this.getAuthenticatedRepos();
      logger.info(`github helper, getAllReposOfOrg: ${allRepos.length}`);
      return allRepos;
    }

    const allRepos = await Promise.all([this.getUserRepos(), this.getOrgsRepos()]);

    logger.info(`github helper, getAllReposOfOrg: ${allRepos.length}`);

    const apiRepos = allRepos.flat();

    const unique = new Map();

    for (const repo of apiRepos) {
      if (repo.security_and_analysis) {
        unique.set(repo.id, repo);
      }
    }

    for (const repo of apiRepos) {
      if (!unique.has(repo.id)) {
        unique.set(repo.id, repo);
      }
    }

    return [...unique.values()];
  }

  // for GitHub App
  // returns org info if installation is associated to an organization (and not a user)
  private async getInstallationOrg(repo: any) {
    if (!repo) return null;

    const { owner } = repo;
    if (owner.type !== "Organization") return null;

    return this.augmentOrgInfo(owner);
  }

  // for GitHub App
  private async getInstallationRepos() {
    try {
      const query = {
        url: "GET /installation/repositories",
        parms: {
          page: 1,
          per_page: this.per_page_max_res,
        },
      };

      const res = await this.connector.invokeRequest(query, 45);
      return res.flatMap(res => res.repositories);
    } catch (err) {
      logger.error(`failed to getInstallationRepos, err: ${err}`);
    }
    return [];
  }

  // for GitHub App
  // also fetches and sets organization data mimicing getAllReposOfOrg behaviour
  public async getAllInstallationRepos() {
    const repos = await this.getInstallationRepos();

    const organization = await this.getInstallationOrg(repos[0]);

    if (organization) {
      GlobalCodeRepoData.Instance.orgs.set(organization.login, organization);

      this.orgs.push(new Organization(organization.login, organization.id, organization.twoFactorEnabled, organization.isVerified));
      // keeping bc
      this.orgObjs.push(organization);
    }

    return repos;
  }

  async getUser() {
    const query = {
      url: "GET /user",
      parms: {
        page: 1,
        per_page: this.per_page_max_res,
      },
      singleRequest: true,
    };

    const res = await this.connector.invokeRequest(query);
    return res[0];
  }

  async getUserRepos() {
    try {
      let userRepos = [];
      try {
        const user = await this.getUser();
        if (user) {
          if (user.login) {
            userRepos = await this.getAllUserRepos(user.login);
            logger.info(`github helper, getAllUserRepos: ${userRepos.length}`);
          }
        }
      } catch (e) {
        logger.error(`failed to getUser, e: ${e}`);
      }
      const autoRepos = await this.getAuthenticatedRepos();
      logger.info(`github helper, getAuthenticatedRepos: ${autoRepos.length}`);

      return [userRepos, autoRepos].flat();
    } catch (err) {
      logger.error(`failed to getUserRepos, e: ${err}`);
    }
    return [];
  }

  async getOrgsRepos() {
    try {
      const orgs = await this.getAllUserOrgs();
      logger.info(`github helper, getAllUserOrgs: ${orgs.length}`);

      const orgReposPromises = orgs.map(org => this.getAllOrgRepos(org.login));

      orgs.forEach(i => this.orgs.push(new Organization(i.login, i.id, i.twoFactorEnabled, i.isVerified)));
      // keeping bc
      orgs.forEach(i => this.orgObjs.push(i));

      const orgRepos = await Promise.all(orgReposPromises);
      logger.info(`github helper, orgRepos: ${orgRepos.length}`);

      return orgRepos.flat();
    } catch (err) {
      logger.error(`failed to getOrgsRepos, e: ${err}`);
    }
    return [];
  }

  // mutates input org object
  async augmentOrgInfo(org) {
    const orgName = org.login;
    try {
      const query = {
        url: "GET /orgs/{org}",
        parms: {
          page: 1,
          org: orgName,
          per_page: this.per_page_max_res,
        },
      };

      const res = await this.connector.invokeRequest(query);

      if (res[0].two_factor_requirement_enabled === null || !res[0].hasOwnProperty("two_factor_requirement_enabled")) {
        logger.info(`getOrgInfo failed to get 2fa setting because token doesnt have owner permissions`);
      } else {
        org.twoFactorEnabled = res[0].two_factor_requirement_enabled;
      }

      org.isVerified = res[0].is_verified;
    } catch (err) {
      logger.error(`failed to getOrgInfo, e :${err}`);
    }
    return org;
  }

  async getAllUserOrgs() {
    try {
      const query = {
        url: "GET /user/orgs",
        parms: {
          page: 1,
          per_page: this.per_page_max_res,
        },
      };

      const res = await this.connector.invokeRequest(query);

      for (const organization of res) {
        await this.augmentOrgInfo(organization);
        GlobalCodeRepoData.Instance.orgs.set(organization.login, organization);
      }

      return res;
    } catch (err) {
      logger.error(`failed to getAllOrgs, e: ${err}`);
    }
    return [];
  }

  async getAllUserRepos(username: string) {
    try {
      const query = {
        url: "GET /users/{username}/repos",
        parms: {
          username: username,
          type: "all",
          page: 1,
          per_page: this.per_page_max_res,
        },
      };

      const res = await this.connector.invokeRequest(query, 45);
      return res;
    } catch (err) {
      logger.error(`username: ${username}, err: ${err}`);
    }
    return [];
  }

  async getAuthenticatedRepos() {
    try {
      const query = {
        url: "GET /user/repos",
        parms: {
          page: 1,
          per_page: this.per_page_max_res,
        },
      };

      const res = await this.connector.invokeRequest(query, 45);
      return res;
    } catch (err) {
      logger.error(`failed to getAuthenticatedRepos, e: ${err}`);
    }
    return [];
  }

  async getAllOrgRepos(org: string) {
    try {
      const query = {
        url: "GET /orgs/{org}/repos",
        parms: {
          org: org,
          page: 1,
          per_page: this.per_page_max_res,
        },
      };

      const res = await this.connector.invokeRequest(query, 45);
      return res;
    } catch (err) {
      logger.error(`failed get all orgs, err: ${err}`);
    }
    return [];
  }
}
