import PromisePool from "@supercharge/promise-pool/dist";
import { CodeCommit } from "aws-sdk";
import { getBearerToken } from "../../codeOpenSourceTools/cloudTools/specifcTools/AWSCodeCommitAuth";
import getAwsKeys, { AWSAccountCredentials } from "../../codeOpenSourceTools/cloudTools/specifcTools/AWSCredentialsProvider";
import {
  Branch,
  CodeRepoTypes,
  Commit,
  File,
  MergeUser,
  PullRequest,
  Repo,
  repoResourceType,
  repoType,
  Reviewer,
  setFileInfo,
} from "../../entitis/codeRepoTypes";
import { AWSCredReturnType, Token } from "../../entitis/collectorEntitisTypes";
import RepoImportanceCalcHelper from "../../helper/appPriority/repoImportanceCalcHelper";
import GitHelper from "../../helper/gitHelper";
import FileHelper from "../../helper/IO/fileHlper";
import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import CodeRepoBase from "../base/codeRepoBase";

const logger = loggerImport.getDebugLogger();
const concurrent_pool_call = 5;
const max_brach_to_fetch = 100;
const max_pull_to_fetch = 1000;

const regions = [
  "us-east-1",
  "us-east-2",
  "us-west-1",
  "us-west-2",
  "af-south-1",
  "ap-east-1",
  "ap-south-1",
  "ap-northeast-3",
  "ap-northeast-2",
  "ap-southeast-1",
  "ap-southeast-2",
  "ap-northeast-1",
  "ca-central-1",
  "eu-central-1",
  "eu-west-1",
  "eu-west-2",
  "eu-south-1",
  "eu-west-3",
  "eu-north-1",
  "me-south-1",
  "sa-east-1",
  "us-gov-east-1",
  "us-gov-west-1",
  "cn-north-1",
  "cn-northwest-1",
];

interface AllCodeCommitInstance {
  [key: string]: {
    region: string;
    instance: CodeCommit;
    credentials: AWSAccountCredentials;
  };
}

class AWSCodeCommit extends CodeRepoBase {
  private base64GitCred: string;
  private allCodeCommitInstances: AllCodeCommitInstance = {};
  accountTokensEx: AWSCredReturnType[] = [];
  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);
    this.fileHelper = new FileHelper(this.uuid);
  }

  async initLib() {
    try {
      if (this.token.accountName && this.token.secret) {
        logger.info(`Found Aws secrets in token, hence initializing code commit for single account`);
        const awsCredential = {
          name: "default",
          accessKeyId: this.token.accountName,
          secretAccessKey: this.token.secret,
        };

        for (const region of regions) {
          this.allCodeCommitInstances[`default=${region}`] = {
            region,
            credentials: awsCredential,
            instance: new CodeCommit({
              accessKeyId: this.token.accountName,
              secretAccessKey: this.token.secret,
              region,
            }),
          };
        }
        return;
      }

      //IAM
      logger.info(`${this.token.name}, initiated Aws with IAM policy, hence initializing code commit for single account`);
      this.accountTokensEx = await this.token.getAWSCredAccountsEx(this.uuid, this.orgName);
      getAwsKeys().registerKeys(this.accountTokensEx);
      const allAccountCred: AWSAccountCredentials[] = await getAwsKeys().fetchCredentials();

      logger.info(`${this.token.name} found after waiting for aws cred total account cred: ${JSON.stringify(allAccountCred)}`);

      for (const cred of allAccountCred) {
        const accountCred: AWSAccountCredentials = await getAwsKeys().fetchKeyByName(cred.name);
        if (accountCred) {
          for (const region of regions) {
            this.allCodeCommitInstances[`${cred.name}=${region}`] = {
              region,
              credentials: accountCred,
              instance: new CodeCommit({
                accessKeyId: accountCred.accessKeyId,
                secretAccessKey: accountCred.secretAccessKey,
                sessionToken: accountCred.sessionToken,
                region,
              }),
            };
          }
        } else {
          logger.warn(`${cred.name} cannot be found or reissued for aws code commit`);
        }
      }
      logger.info(`${this.token.name}, finish init, ${Object.keys(this.allCodeCommitInstances).join(", ")}`);
    } catch (err) {
      logger.error(`${this.token.name}, err: ${err}`);
    }
  }

  async getAllRepos() {
    const allRepos = [];
    try {
      const instances = Object.keys(this.allCodeCommitInstances);
      await PromisePool.for(instances)
        .withConcurrency(concurrent_pool_call)
        .process(async instance => {
          await this.getReposFromRegion(instance, allRepos);
        });

      const monitored = allRepos.filter(apiRepo => this.repoSelectedByUser(apiRepo.repositoryId.toString(), apiRepo.repositoryName, ""));
      logger.info(
        `Found all repos before filter: ${allRepos.length}, after filter: ${monitored.length}, for: ${this.token.name} ${this.token.type}`,
      );
      return monitored;
    } catch (err) {
      logger.error(`failed to get repos list obj for: ${this.token.name} ${this.token.type}, err: ${err}`);
    }
    return [];
  }

  async getReposFromRegion(instance: string, allRepos) {
    try {
      const [accountName, region] = instance.split("=");
      logger.info(`Fetching aws codecommit repositories from account: ${accountName} and region: ${region}`);
      const codeCommitInstance = this.allCodeCommitInstances[instance].instance;
      const params: any = {};
      const repos = [];
      // Here we are getting all repos with name and id
      while (true) {
        const reposResponse: any = await codeCommitInstance.listRepositories(params).promise();
        if (reposResponse?.repositories?.length) {
          for (const repo of reposResponse.repositories) {
            repos.push(repo.repositoryName);
          }
        }
        if (!reposResponse.nextToken) {
          break;
        }
        params.nextToken = reposResponse.nextToken;
      }
      logger.info(`Fetched total aws codecommit repositories count: ${repos.length}, from account: ${accountName} and region: ${region}`);
      // Here we are using "batchGetRepositories" method to get all info about repos
      while (repos.length) {
        try {
          const repositoryNames = repos.splice(0, 25);
          const reposDetailsResponse: any = await codeCommitInstance.batchGetRepositories({ repositoryNames }).promise();
          if (reposDetailsResponse?.repositories?.length) {
            for (const repo of reposDetailsResponse.repositories) {
              repo.region = region;
              repo.accountName = accountName;
              allRepos.push(repo);
            }
          }
        } catch (err) {
          logger.error(
            `failed to get repos details info from instance: ${instance}, for ${this.token.name} ${this.token.type}, err: ${err}`,
          );
        }
      }
    } catch (err) {
      logger.info(`failed to get repos from instance: ${instance}, for ${this.token.name} ${this.token.type}, err: ${err}`);
    }
  }

  async setRepo(apiRepo, repoObj) {
    try {
      const fullName = apiRepo.repositoryName;
      const pipelineScanInfo = this.getPipelineScanInfo(apiRepo.repositoryId, fullName);

      //create file prefix
      const link = `https://${apiRepo.region}.console.aws.amazon.com/codesuite/codecommit/repositories/${fullName}`;
      const defaultBranchName = apiRepo.defaultBranch ? (apiRepo.defaultBranch == null ? "main" : apiRepo.defaultBranch) : "main";
      const res = [link, "browse", "refs", "heads", defaultBranchName, "--", ""].join("/");

      const instanceName = this.allCodeCommitInstances[`${apiRepo.accountName}=${apiRepo.region}`];
      // @ts-ignore
      const gitToken = getBearerToken(fullName, apiRepo.region, instanceName.credentials);
      const cloneHeaders = [`-c`, `http.extraHeader=Authorization: Basic ${gitToken}`];

      let repo = new Repo(
        this.uuid,
        this.orgName,
        repoType.awsCodeCommit,
        fullName,
        apiRepo.repositoryId,
        fullName,
        apiRepo.creationDate,
        apiRepo.defaultBranch ? (apiRepo.defaultBranch == null ? "main" : apiRepo.defaultBranch) : "main",
        apiRepo.repositoryDescription ? apiRepo.repositoryDescription : "",
        false,
        this.getCloneUrl(apiRepo),
        -1,
        false,
        false,
        false,
        "",
        true, // default all repos are private
        [],
        0,
        0,
        "",
        link,
        0,
        apiRepo.lastModifiedDate,
        "",
        res,
        `?region=${apiRepo.region}&lines=`,
        0,
        link + `/browse`,
        link + `/commits`,
        "",
        "",
        "",
        apiRepo.repositoryId,
        true,
        fullName,
        pipelineScanInfo,
        undefined,
        undefined,
        cloneHeaders,
        undefined,
        apiRepo.region,
        apiRepo.accountName,
      );

      this.setClientConfiguredProps(repo);

      const cal = new RepoImportanceCalcHelper(this.uuid, this.orgName);
      if (cal.isRepoImportanceAreZero(repo, 100).length > 0) {
        StatesHelper.Instance.skippedClone.add(repo.fullName);
      }

      if (apiRepo.delta) {
        repo.isDelta = true;
      }

      //Must clone here
      if (repo.noneRelevantRepo) {
        this.fileHelper.createDir(repo.cloneDir);
      } else {
        const gitHelper: GitHelper = new GitHelper(this.uuid, this.orgName);
        const cloneRes = await gitHelper.cloneRepo(repo, this);
        if (!cloneRes) {
          repo.failedClone = true;
        } else {
          repo.successfulClone = true;
          repo.headSha = await this.getHeadSha(repo, gitHelper);
        }
      }

      const filesList: File[] = await this.files(repo);
      repoObj[CodeRepoTypes[CodeRepoTypes.files]] = filesList;
      repo.filesCount = filesList.length;

      await this.getAndSetRepoDevLanguagesKubernetesAndOrchestrator(repo, filesList);

      repo.deploymentFilesYmls = this.getDeploymentFilesYmls(filesList);

      return repo;
    } catch (err) {
      logger.error(`failed to create repo obj for: ${JSON.stringify(apiRepo)}, err: ${err}`);
    }
    return null;
  }

  async branches(repo: Repo): Promise<any> {
    let branchList: Branch[] = [];
    const codeCommitInstance = this.allCodeCommitInstances[`${repo.accountName}=${repo.region}`].instance;
    try {
      const allBranches = [];
      const params: any = {
        repositoryName: repo.name,
      };
      while (true) {
        const branchResponse: any = await codeCommitInstance.listBranches(params).promise();
        if (branchResponse?.branches?.length) {
          allBranches.push(...branchResponse.branches);
        }
        if (allBranches.length >= max_brach_to_fetch || !branchResponse.nextToken) {
          break;
        }
        params.nextToken = branchResponse.nextToken;
      }

      for (const branchName of allBranches) {
        try {
          let branch = new Branch(branchName);
          branchList.push(branch);
        } catch (err) {
          logger.error(`failed to create branch obj for: ${repo.name}, branch: ${branchName}, err: ${err}`);
        }
      }
      logger.info(
        `Found all branches before filter: ${allBranches.length}, after filter: ${branchList.length}, for: ${this.token.name} ${this.token.type}`,
      );
    } catch (err) {
      logger.error(`get branches failed repo: ${repo.name}, err: ${err}`);
    }
    return branchList;
  }

  getCloneUrl(repo) {
    return repo.cloneUrlHttp;
  }

  async pulls(repoObj: any): Promise<any> {
    return [];
  }

  formatUserDetails(arn: string) {
    const userDetails = {
      id: null,
      username: "",
    };
    try {
      if (!arn) {
        return userDetails;
      }
      const splittedValues = arn.split("/");
      const userIdDetails = splittedValues[0].split("::").pop();
      const userId = Number(userIdDetails.split(":")[0]);

      if (!isNaN(userId)) {
        userDetails.id = userId;
      }
      userDetails.username = splittedValues.pop();
    } catch (err) {
      logger.error(`format user details failed for: ${arn}, err: ${err}`);
    }
    return userDetails;
  }

  async getPullDetails(pullRequestId: string, repo: any, pulls: any, codeCommitInstance) {
    try {
      const pullDetails = await codeCommitInstance.getPullRequest({ pullRequestId }).promise();
      if (pullDetails?.pullRequest) {
        pulls.push(pullDetails.pullRequest);
      }
    } catch (err) {
      logger.error(`get pulls details failed repo: ${repo.name}, err: ${err}`);
    }
  }

  async getCommitRelatedToPullReq(repo: Repo, pullInfo: any, pullRequest: PullRequest, commitsFromDisk: Commit[]) {
    try {
      const res = [];
      if (pullInfo?.push_data?.commit_from) {
        res.push({ id: pullInfo?.push_data?.commit_from });
      }
      if (pullInfo?.push_data?.commit_to) {
        res.push({ id: pullInfo?.push_data?.commit_to });
      }
      if (pullInfo?.meta_rev_id) {
        res.push({ id: pullInfo?.meta_rev_id });
      }
      if (pullInfo.merge_commit_sha) {
        res.push({ id: pullInfo?.merge_commit_sha });
      }

      for (const resCommit of res) {
        try {
          const commitInfoFromDisk = commitsFromDisk.filter(i => i.hash === resCommit.id);
          if (commitInfoFromDisk.length > 0) {
            pullRequest.pullsCommitInfo = [...pullRequest.pullsCommitInfo, ...commitInfoFromDisk];
          }
        } catch (err) {
          logger.error(`repo: ${repo.name}, get related single commit to pull request err: ${err}`);
        }
      }
      setFileInfo(pullRequest);
    } catch (err) {
      logger.error(`failed to get commit related to pull request for repo: ${repo.name}, err: ${err}`);
    }
  }

  getFileLinkPrefix(repo) {
    try {
      const str = repo?.links?.html?.href + "/src/" + repo?.mainbranch?.name + "/";
      return str;
    } catch (err) {
      logger.error(`failed get file link repo name: ${repo.name}`);
    }
    return "";
  }

  async getCodeBaseLastCodeChange(application) {
    return new Date(application.pushed_at);
  }

  getCodeRepoId(application) {
    return application.id;
  }

  getAPICredentials() {
    return null;
  }

  getAPIRepoInfo(repo: Repo) {
    return null;
  }

  async findPullRequestIntroducingMergeCommit(repoObj: any, branch: string, sha: string) {
    return null;
  }

  async findFilesModifiedInPullRequest() {
    return null;
  }
}

export default AWSCodeCommit;
