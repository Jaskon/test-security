import { IOxTag, OxTagCategory } from "@oxappsec/ox-consolidated-tags";
import { GitCommit } from "@oxappsec/ox-git-parse";
import { Fix } from "sarif";
import GlobalCodeRepoData from "../dal/GolobalCollectorData/globalCodeRepoData";
import { ApiSecurityItem } from "../entitis/apiTypes";
import { AppFlowCICD, AppFlowRepo, FoundLocation } from "../entitis/applicationsFlowTypes";
import Constant, { OXtools } from "../entitis/constant";
import { isK8Mode } from "../helper/envUtils";
import FileHelper from "../helper/IO/fileHlper";
import localToolRunner from "../helper/localToolRunner";
import CallGraphHelper from "../helper/service/callGraphHelper";
import StatesHelper from "../helper/statesHelper";
import TimeHelper from "../helper/timeHelper";
import loggerImport from "../logger";
import { AppToolCoverage, Owner, Pipeline } from "../policy/reporting/types";
import { Tool } from "../policy/rules/code/policyRulesBase";
import { ContainerSecurityType } from "./artifactoryTypes";
import { ArtifactorySecEvent } from "./ArtifactTypes";
import { OrgCicdTool } from "./cicdTypes";
import { CICDConnectorsTypes, getCICDProvider, getCICDType } from "./cicidRepoTypes";
import { CloudSecurityEvent } from "./cloudTypes";
import { Nullable } from "./commonTypes";
import { ExtraInfo } from "./issuesTypes";
import { KubernetesFile } from "./kubernetesTypes";
import { OrchestratorFile } from "./orchestratorTypes";
import { AlertRecommendationResponse } from "./service/alertrRcommendationTypes";
import { AutoFixResponse } from "./service/autoFixTypes";
import { BlameResponse, ChangeReason, severityReasons } from "./service/blameTypes";
import { IacValidatorTypesResponse } from "./service/iacValidatorTypes";
import { ScaValidatorTypesResponse } from "./service/scaValidatorTypes";

const pathApi = require("path");
const uuidGenerator = require("uuid");
const logger = loggerImport.getDebugLogger();

const onPrem = process.env.redisOnPrem != undefined;
const isk8 = isK8Mode();

const sharedDir = process.env.OX_SHARED_DATA == undefined ? "/var/shared-data" : process.env.OX_SHARED_DATA;
const globalDir = process.env.OX_GLOBAL_DATA == undefined ? "/var/shared-data" : process.env.OX_GLOBAL_DATA;

export enum repoType {
  gitlab = "gitlab",
  github = "github",
  azure = "Azure",
  azureTFS = "AzureTFS",
  bitbucket = "bitbucket",
  bitbucketStash = "bitbucketstash",
  azureGit = "azure repos (git)",
  gerrit = "Gerrit",
  awsCodeCommit = "Aws CodeCommit",
}

export enum RepoTypeName {
  gitlab = "GitLab",
  github = "GitHub",
  azure = "Azure",
  azureTFS = "Azure TFS",
  bitbucket = "Bitbucket",
  bitbucketStash = "Bitbucket stash",
  gerrit = "Gerrit",
  awsCodeCommit = "Aws CodeCommit",
}

export enum RegistryName {
  gcr = "Google container registry",
}

export enum CodeRepoTypes {
  Unknown,
  webhooks,
  workflows,
  files,
  uniqueFiles,
  pulls,
  pushedCommits,
  commits,
  branches,
  environments,
  repos,
  keys,
  securityEvents,
  users,
  allUsers,
  auditLog,
  reviewer,
  allPulls,
  allCommits,
  mergeUser,
  parentMonoRepo,
  branchSettings,
  allOrgsRepos,
  allPublicRepos,
  teams,
  scopesRepoMap,
  allSecEvents,
  groups,
}

export enum AlertSeverity {
  Unknown = 100,
  Info = 0,
  Low = 1,
  Medium = 2,
  High = 3,
  Critical = 4,
  Appoxalypse = 5,
}

export enum AlertConfidence {
  Low = 1,
  Medium = 2,
  High = 3,
}

export enum SecurityAlertType {
  Unknown = 0,
  secrets,
  sast,
  iac,
  sca,
  cloudRunTime,
  cspm,
  container,
  ox,
  license,
  typosquatting,
  depConfusionScopes,
  depConfusionPkgs,
  dockerFileVul,
  securityApi,
  dast,
  PII,
  runTimeConfiguration,
}

export enum VCSType {
  git = "git",
  tfvc = "tfvc",
}

export class License {
  id: string;
  name: string;
  url: string;
}

export class Dependency {
  name: string;
  importName?: string[];
  version?: string;
  package_manager?: string;
  dependencyAmount?: number;
  path?: string;
  licenses?: string[];
  dependencyGraph?: string;
  dependencyType?: string;
  match?: string;
  snippet?: string;
  startLineNumber?: number;
  snippetLineNumber?: number;
  found?: boolean;
  commit_info?: any;
}

export class LicenseFinderRes {
  version: string;
  licenses: License[];
  dependencies: Dependency[];
}

export class Repository {
  repoAppFlow: AppFlowRepo[] = [];
  sbomHandled: boolean = false;
}

export class Webhook {
  createdAt: string;
  lastResponseCode: string;
  lastResponseMsg: string;
  secret: boolean;
  ssl: boolean;
  active: boolean;
  description: string;
  link: string;
  objType: CodeRepoTypes = CodeRepoTypes.webhooks;
  reputationData = [];
  reputationSkip: any;
  resolvedDns: any;
  matchingLocalIps: any;
  events = [];

  //This is needed for exclusions dont delete this or change!!!
  url: string;
  domain: string;
  domainAppearAcrossOrgPercentage = 0;
  numberOfReposDomainAppear = 0;
  tool: Tool;

  id?;
  constructor(
    url: string,
    createdAt: string,
    lastResponseCode: string,
    lastResponseMsg: string,
    secret: boolean,
    ssl: boolean,
    active: boolean,
    description: string,
    link: string,
    events: any,
    tool: Tool,
    id?: any,
  ) {
    this.url = url == null ? "" : url;
    this.createdAt = createdAt == null ? "" : createdAt;
    this.lastResponseCode = lastResponseCode == null ? "" : lastResponseCode;
    this.lastResponseMsg = lastResponseMsg == null ? "" : lastResponseMsg;
    this.description = description == null ? "" : description;
    this.link = link == null ? "" : link;
    this.secret = secret == null ? false : secret;
    this.ssl = ssl == null ? false : ssl;
    this.active = active == null ? false : active;
    this.events = events;
    this.tool = tool;
    if (this.url === "") {
      throw new Error(`err: constructor, webhook url is empty`);
    }
    this.id = id;
  }

  toString() {
    return ` url (${this.url}, ssl: (${this.ssl}, description: (${this.description}, lastResponseCode (${this.lastResponseCode}, secret (${this.secret}, active (${this.active}, htmlUrl (${this.link}, createdAt (${this.createdAt}, id (${this.id})`;
  }
}

export class Workflow {
  createdAt: string;
  link: string;
  active: boolean;
  path: string;
  name: string;
  id: string;
  objType: CodeRepoTypes = CodeRepoTypes.workflows;

  constructor(createdAt: string, link: string, active: boolean, path: string, name: string, id: string) {
    this.createdAt = createdAt == null ? "" : createdAt;
    this.link = link == null ? "" : link;
    this.name = name == null ? "" : name;
    this.path = path == null ? "" : path;
    this.id = id == null ? "" : id;
    this.active = active == null ? false : active;

    if (this.path === "") {
      throw new Error(`err: constructor, workflow path is empty, link: ${link}, name: ${name}`);
    }
  }
}

export class File {
  path: string;
  link: string;
  name: string;
  fileNameWithoutDisk: string;
  objType: CodeRepoTypes = CodeRepoTypes.files;

  constructor(path: string, link: string, repoCloneDir: string) {
    this.path = path;
    this.link = link;
    this.name = pathApi.basename(path);

    this.fileNameWithoutDisk = "";
    try {
      this.fileNameWithoutDisk = this.path.replace(`${repoCloneDir}/`, "").toLowerCase();
    } catch (err) {
      logger.error(`cannot set file name: ${this.path}, err: ${err}`);
    }
  }
}

export class FileCommit {
  path: string;
  sha: string;
  additions: number;
  deletions: number;
  link: string;
  objType: CodeRepoTypes = CodeRepoTypes.files;

  constructor(path: string, sha: string, additions: number, deletions: number, link: string) {
    this.path = path == null ? "" : path;
    this.sha = sha == null ? "" : sha;
    this.link = link == null ? "" : link;
    this.additions = additions == null ? -1 : additions;
    this.deletions = deletions == null ? -1 : deletions;
    this.additions = additions == null ? -1 : additions;
  }
}

export class Reviewer {
  author: string;
  userName: string;
  id: number | string;
  objType: CodeRepoTypes;

  constructor(author: string, userName: string, id?: number | string) {
    this.author = author;
    this.userName = userName;
    this.id = id;
    this.objType = CodeRepoTypes.reviewer;

    if (this.author === "") {
      throw new Error("err: review author pull request is empty");
    }
  }
}

export class MergeUser {
  author: string;
  userName: string;
  id: number;
  objType: CodeRepoTypes;

  constructor(author: string, userName: string, id?: number) {
    this.author = author;
    this.userName = userName;
    this.id = id;
    this.objType = CodeRepoTypes.mergeUser;
  }
}

export class PullRequest {
  type: string;
  createdAt: string;
  createdAtData: Date;
  link: string;
  description: string;
  mergedAt: string;
  title: string;
  reviewerCount: number;
  objType: CodeRepoTypes;
  author: string;
  authorUserName: string;
  pullsCommitInfo: Commit[] = [];
  id: string;
  diffFromNowToCreatedAtInDays: number;
  uniqueFilesChanged = [];
  avatarUrl: string;
  reviewers: Reviewer[];
  email: string;
  emailDomain: string;
  mergeUser: MergeUser;
  isMerged: boolean;

  //This is needed for exclusions dont delete this or change!!!
  sha: string;

  constructor(
    createdAt: string,
    link: string,
    description: string,
    sha: string,
    mergedAt: string,
    title: string,
    reviewerCount: number,
    author: string,
    id: string,
    codeRepoTypes: CodeRepoTypes,
    reviewers: Reviewer[],
    mergeUser: MergeUser,
    isMerged: boolean,
  ) {
    this.createdAt = createdAt == null ? "" : createdAt;
    this.createdAtData = new Date(this.createdAt);
    this.link = link == null ? "" : link;
    this.description = description == null ? "" : description;
    this.sha = sha == null ? "" : sha;
    this.mergedAt = mergedAt == null ? "" : mergedAt;
    this.title = title == null ? "" : title;
    this.reviewerCount = reviewerCount == null ? -1 : reviewerCount;
    this.author = author;
    this.id = id;
    this.diffFromNowToCreatedAtInDays = -1;
    this.objType = codeRepoTypes;
    this.reviewers = reviewers;
    this.email = "";
    this.emailDomain = "";
    this.mergeUser = mergeUser;
    this.isMerged = isMerged;

    const timeHelper: TimeHelper = new TimeHelper("Commit");
    if (this.mergedAt != null) {
      this.diffFromNowToCreatedAtInDays = timeHelper.getTimeIntervalFronNowInDays(this.mergedAt);
    } else if (this.createdAt != null) {
      this.diffFromNowToCreatedAtInDays = timeHelper.getTimeIntervalFronNowInDays(this.createdAt);
    }

    if (this.sha === "" && this.objType !== CodeRepoTypes.pushedCommits) {
      throw new Error("err: sha pull request is empty");
    }
    if (this.author === "") {
      throw new Error("err: author pull request is empty");
    }
  }
}

export function setFileInfo(pullRequest: PullRequest) {
  const tempUniqueFilesChanged = new Set();
  pullRequest.pullsCommitInfo.forEach(i => i.uniqueFiles.forEach(j => tempUniqueFilesChanged.add(j)));
  pullRequest.uniqueFilesChanged = Array.from(tempUniqueFilesChanged);
}

export enum AffiliationType {
  all = "all",
  outside = "outside",
  direct = "direct",
}

export enum resourceType {
  allPulls = "all-pulls",
  allUsers = "all-users",
  allCommits = "all-commits",
  allOrgsRepos = "all-orgsReposect",
  allPublicRepos = "all-publicRepos",
  auditLog = "audit-log",
  allRepos = "all-repos",
  scopesRepoMap = "scopes-repoMap",
  allSecEvents = "all-sec-events",
  depConfusionAlert = "dep-confusion-alert",
}

export enum repoResourceType {
  pulls = "pulls",
  users = "users",
  commits = "commits",
  secEvents = "sec-events",
  pushedCommits = "pushed-commits",
  webhooks = "webhooks",
  branches = "branches",
  branchSettings = "branch-settings",
  securityEvents = "security-events",
  depConfusionPkgAlert = "dep-confusion-alert",
  depJacking = "dep-jacking",
  specialFiles = "special-files",
}
export class Organization {
  name: string;
  id: string;
  workflowPermissions: any = null;
  twoFactorEnabled: boolean;
  isVerified: boolean;
  alowForking: boolean = false;

  constructor(name, id, twoFactorEnabled, isVerified) {
    this.name = name ? name : "";
    this.id = id ? id : "";
    this.workflowPermissions = null;
    this.twoFactorEnabled = twoFactorEnabled;
    this.isVerified = isVerified;
  }
}

export class UserAuditLog {
  name: string;
  action: string = "AuditLog";
  actionFriendly: string;
  timestamp: Date;
  org: string;
  actorLocation: string = "";
  repo: string;
  isRepo: boolean = false;
  isOrg: boolean = false;
  actionInfo: string;
  ip_address: string;
}

export class UserRepos {
  name: string;
}

export enum ForkReasons {
  public = "public",
  fork = "fork",
  forkNoneExitUser = "fork none exit user",
  sameName = "same Name",
}

export class ForkedRepos {
  source: Repo;
  destination: Repo;
  reasons: string[] = [];

  //Check if user still working in org
  user: User;
  checkedUser: boolean = true;

  //In case destination is org
  destinationOrgName: string;
  destinationUserName: string;
}

export class User {
  id: number;
  name: string;
  email: string;
  domain: string;
  avatarUrl: string;

  expiresAt: string;
  createdAt: string;
  createdAtDate: Date;
  createdAtDays: Number;
  diffFromNowToCreatedAtInDays: Number;
  userRepos: UserRepos[] = [];

  hasAnyActivity: any;
  objType: CodeRepoTypes = CodeRepoTypes.users;
  twoFactorEnabled: boolean = true;
  partOfOrgMembers: boolean = true;
  affiliation = new Set();
  role: UserRole = UserRole.NONE;
  allRoles: UserRole[] = [];
  orgRole = new Set();

  //Only in github
  htmlLink: string = "";
  org: string;
  isOwnerInherited: boolean = true;

  //This is needed for exclusions dont delete this or change!!!
  username: string;
  repoThatTheUserIsAdmin: number = 0;

  //Org
  //Dev
  devOperation: number = 0;
  devOperationDate: Date;
  foundDevData: boolean = false;
  //Review
  reviewOperation: number = 0;
  reviewOperationDate: Date;
  foundReviewData: boolean = false;
  //Admin
  foundAdminData: boolean = false;
  lastActivityData: Date;
  adminOperation: number = 0;
  adminOperationDate: Date;
  adminLocation: string = "";
  lastAdminOperation: string = "";

  //Repo
  //Dev
  devOperationRepo: number = 0;
  devOperationDateRepo: Date;
  foundDevDataRepo: boolean = false;
  //Review
  reviewOperationRepo: number = 0;
  reviewOperationDateRepo: Date;
  foundReviewDataRepo: boolean = false;
  //Admin
  foundAdminDataRepo: boolean = false;
  lastActivityDataRepo: Date;
  adminOperationRepo: number = 0;
  adminOperationDateRepo: Date;
  adminLocationRepo: string = "";
  lastAdminOperationRepo: string = "";

  repoRoleName: string = "";

  repoPermissions: string = "";

  repoRolesRaw: string[] = [];

  canBypassPullSettings: boolean = false;

  canBypassPushSettings: boolean = false;

  forkedReposFromOrg: ForkedRepos[] = [];

  repoAdminActivity: string[] = [];

  descriptor: string;

  constructor(
    name: string,
    username: string,
    id: number,
    avatarUrl: string,
    expiresAt: string,
    createdAt: string,
    orgRole?: OrgRoles,
    org?: string,
  ) {
    this.name = name == null ? "" : name;
    this.username = username == null ? "" : username;
    this.id = id;
    this.avatarUrl = avatarUrl == null ? "" : avatarUrl;
    this.expiresAt = expiresAt == null ? "" : expiresAt;
    this.createdAt = createdAt == null ? "" : createdAt;
    if (this.createdAt) {
      this.createdAtDate = new Date(this.createdAt);
    }

    this.diffFromNowToCreatedAtInDays = -1;
    this.role = UserRole.NONE;
    if (orgRole) {
      this.orgRole.add(orgRole);
    }
    this.org = org;

    if (this.name === "") {
      throw new Error("err: constructor, user name is empty");
    }
    if (this.email === "") {
      throw new Error("err: constructor, user email is empty");
    }
    if (this.domain === "") {
      throw new Error("err: constructor, user domain url is empty");
    }
  }
}

export class Commit {
  link: string;
  date: string;
  diffFromNowToCreatedAtInDays: number;
  authorEmail: string;
  authorName: string;
  description: string;
  objType: CodeRepoTypes = CodeRepoTypes.commits;
  merged: boolean;
  filesAdded: any;
  filesDeleted: any;
  filesModified: any;
  filesRenamed: any;
  uniqueFiles = [];
  noFilesFound: boolean;
  //This is needed for exclusions dont delete this or change!!!
  hash: string;
  sha: string;

  constructor(
    link: string,
    date: string,
    authorEmail: string,
    authorName: string,
    message: string,
    hash: string,
    filesAdded: any,
    filesDeleted: any,
    filesModified: any,
    filesRenamed: any,
    noFilesFound: boolean = false,
  ) {
    this.date = date == null ? "" : date;
    this.link = link == null ? "" : link;
    this.authorEmail = authorEmail == null ? "" : authorEmail.toLowerCase();
    this.description = message == null ? "" : message;
    this.authorName = authorName == null ? "" : authorName;
    this.hash = hash == null ? "" : hash;
    this.filesAdded = filesAdded;
    this.filesDeleted = filesDeleted;
    this.filesModified = filesModified;
    this.filesRenamed = filesRenamed;
    this.noFilesFound = noFilesFound;

    const tempUniqueFiles = new Set();
    this.filesDeleted.forEach(i => tempUniqueFiles.add(i.path));
    this.filesAdded.forEach(i => tempUniqueFiles.add(i.path));
    this.filesRenamed.forEach(i => tempUniqueFiles.add(i.newPath));
    this.filesModified.forEach(i => tempUniqueFiles.add(i.path));
    this.uniqueFiles = Array.from(tempUniqueFiles);

    const timeHelper: TimeHelper = new TimeHelper("Commit");
    this.diffFromNowToCreatedAtInDays = timeHelper.getTimeIntervalFronNowInDays(this.date);

    if (this.hash === "") {
      throw new Error("err: constructor, commit is empty");
    }

    if (this.diffFromNowToCreatedAtInDays == -1) {
      throw new Error("err: constructor, commit diffFromNowToCreatedAtInDays is empty");
    }

    if (this.authorName === "") {
      throw new Error("err: constructor, user is empty");
    }
  }
}

export class Branch {
  name: string;
  objType: CodeRepoTypes = CodeRepoTypes.branches;

  constructor(name: string) {
    this.name = name == null ? "" : name;

    if (this.name === "") {
      throw new Error("err: constructor, banch is empty");
    }
  }
}

export class BranchSettingAPI {
  type: string;
  settings = {};

  constructor(type: string, settings: any) {
    this.type = type;
    this.settings = settings;
  }
}

export class BranchSettings {
  pushEventEnabled: boolean = false;
  MRWithoutReviewEnabled: boolean = false;
  forceDeleteAllowed: boolean = false;
  requiredSignedCommits: boolean = true;
  restrictions = {};
  enforceAdmins = false;
  dissmisalRestrictions = {};
  bypassPullReqAllowances = {};
  branchProtection: boolean = false;
  rule = {};
  pushRole: PushRole = PushRole.DEVELOPER;
  codeOwnerApproval?: boolean = false;

  constructor(
    pushEventEnabled: boolean = false,
    MRWithoutReviewEnabled: boolean = false,
    forceDeleteAllowed: boolean = false,
    requiredSignedCommits: boolean = true,
    restrictions: any = {},
    enforceAdmins: boolean = false,
    dissmisalRestrictions: any = {},
    bypassPullReqAllowances: any = {},
    branchProtection: boolean = false,
    rule: any = {},
    codeOwnerApproval?,
  ) {
    this.pushEventEnabled = pushEventEnabled;
    this.MRWithoutReviewEnabled = MRWithoutReviewEnabled;
    this.forceDeleteAllowed = forceDeleteAllowed;
    this.requiredSignedCommits = requiredSignedCommits;
    (this.restrictions = restrictions),
      (this.enforceAdmins = enforceAdmins),
      (this.dissmisalRestrictions = dissmisalRestrictions),
      (this.bypassPullReqAllowances = bypassPullReqAllowances),
      (this.branchProtection = branchProtection);
    this.rule = rule;
    this.codeOwnerApproval = codeOwnerApproval;
  }
}

export class RepositoryKey {
  id: number;
  title: string;
  key: string;
  createdAt: string;
  expired: boolean;
  revoked: boolean;
  expiredAt: string;
  expiredAtDays: number;
  expiredInDays: number;
  lastUsed: string;
  lastUsedDays: number;
  scop: string[] = [];
  deployed: boolean;
  objType: CodeRepoTypes = CodeRepoTypes.keys;

  constructor(
    id: number,
    title: string,
    key: string,
    createdAt: string,
    expired: boolean,
    revoked: boolean,
    expiredAt: string,
    lastUsed: string,
    scop: string[],
    deployed: boolean,
  ) {
    const timeHelper: TimeHelper = new TimeHelper("");

    this.title = title == null ? "" : title;
    this.key = key == null ? "" : key;
    this.createdAt = createdAt == null ? "" : createdAt;
    this.expired = expired == null ? false : expired;
    this.revoked = revoked == null ? false : revoked;
    this.expiredAt = expiredAt == null ? "" : expiredAt;
    this.lastUsed = lastUsed == null ? "" : lastUsed;
    this.scop = scop == null ? [] : scop;
    this.deployed = deployed;

    this.lastUsedDays = timeHelper.getTimeIntervalFronNowInDays(this.lastUsed);
    this.expiredAtDays = timeHelper.getTimeIntervalFronNowInDays(this.expiredAt);

    this.expiredInDays = -1;
    if (this.expired == false && expiredAt != null) {
      this.expiredInDays = timeHelper.getTimeIntervalFronNowInDays(expiredAt, true);
    }

    if (this.lastUsedDays != -1 && !this.revoked && this.expired) {
      if (this.lastUsedDays > 60) this.revoked = true;
    }
  }
}

export class Enviroment {
  name: string;
  link: string;
  createdAt: string;
  deploymentBranchPolicy: string;
  additionalInfo: string;
  objType: CodeRepoTypes = CodeRepoTypes.environments;

  constructor(name: string, link: string, createdAt: string, deploymentBranchPolicy: string, additionalInfo: string) {
    this.name = name == null ? "" : name;
    this.createdAt = createdAt == null ? "" : createdAt;
    this.link = link == null ? "" : link;
    this.deploymentBranchPolicy = deploymentBranchPolicy == null ? "" : deploymentBranchPolicy;
    this.additionalInfo = additionalInfo == null ? "" : additionalInfo;
  }
}

export class DevLanguages {
  language: string;
  languagePercentage: number;

  constructor(language: string, languagePercentage: number) {
    this.language = language == null ? "" : language;
    this.languagePercentage = languagePercentage == null ? -1 : languagePercentage;

    if (this.language === "") {
      throw new Error("err: constructor, dev languages is empty");
    }
  }
}

export class Topic {
  tagId: string;
  tagType: string;
  isOxTag: boolean;
  name: string;
  displayName: string;
  createdBy: string;
  appliedBy: string;
  isGithubTopicTag: boolean = true;
  tagCategory: OxTagCategory;

  constructor(
    tagId: string,
    tagType: string,
    isOxTag: boolean,
    name: string,
    displayName: string,
    createdBy: string,
    appliedBy: string,
    tagCategory: OxTagCategory,
    isGithubTopicTag: boolean = true,
  ) {
    this.tagId = tagId;
    this.tagType = tagType;
    this.isOxTag = isOxTag;
    this.name = name;
    this.displayName = displayName;
    this.createdBy = createdBy;
    this.appliedBy = appliedBy;
    this.isGithubTopicTag = isGithubTopicTag;
    this.tagCategory = tagCategory;
  }
}

export class Repo {
  fullName: string;
  fullPath: string;
  createdAt: string;
  defaultBranch: string;
  description: string;
  disable: boolean;
  cloneURL: string;
  downloadCount: Number;
  hasPages: boolean;
  hasPorject: boolean;
  hasWiki: boolean;
  hasIssues: boolean;
  homepage: string;
  privateVisability: boolean;
  sizeInBytes: number;
  watchersCount: number;
  ownerName: string;
  ownerNameApi: string;
  ownerEmail: string;
  link: string;
  securityResDir: string;
  blameResDir: string;
  secretValidationDir: string;
  autoFixValidationDir: string;
  resolveIssuesValidationDir: string;
  openSourceInfoDir: string;
  iacValidatorDir: string;
  scaValidatorDir: string;
  alertRecommendation: string;
  alertDepJackingDir: string;
  forksCount: number;
  lastPushTime: string;
  type: string;
  parentType: string = "Git";
  appCategory: string = "Repo";
  name: string;
  project: string;
  projectName: string;
  id: string;
  fileLink: string;
  languages: DevLanguages[] = [];
  linkFilePreffix: string;
  objType: CodeRepoTypes = CodeRepoTypes.repos;
  tags: number;
  filesCount: number;
  settingLink: string;
  commitLink: string;
  pushesLink: string;
  pullsLink: string;
  cloudDeployments: Object[] = [];
  organization: string;
  vcsType: VCSType;
  overrideRelevance: Relevance;
  overridePriority: number = -1;
  appOwners: Owner[];
  repoUsers: User[] = [];
  mostVeretanUsers: string[] = [];
  /**
   * dont use this id anywhere in code. for PRs. use 'id'
   */
  repoId: string = "";
  isOrgRepo: boolean = false;
  useDotGit: boolean = true;
  repoRealName: string;
  dependencyGraphInfoPath: string;
  apiDiscoveryInfoPath: string | null | undefined;
  apiSecurityItems: ApiSecurityItem[] = [];
  dockerfileScannerInfoPath: string | null | undefined;
  headSha: string | null = null;
  pkgManagers: string[] = [];
  sbomPathDir: string;

  ignoredTools: string[] = [];

  failedSecurityTools = new Set<string>();

  //Open wiki
  openWiki: boolean = false;
  openWikiRequestId: string;
  isOverridingPriority: boolean = false;
  /** Identified by OX as non relevant (won't be scanned) */
  noneRelevantRepo: boolean = false;
  /** Marked by user as relevant no matter what (will be scanned) */
  markedAsRelevant: boolean = false;
  pipeline: Pipeline;

  //TFS
  tfsUrl: string;
  tfsRepoClonePath: string;
  tfsToken: string;

  //DeploymentFiles
  deploymentFilesYmls: File[] = [];

  //Checkmarx
  importSecurityTemplateYml = {};

  //App flow found from the repo itself
  artifacts: any = [];
  kubernetes: KubernetesFile[] = [];
  orchestrator: OrchestratorFile[] = [];
  artifactory: Object[] = [];

  users: number = -1;
  ciCandidates = new Set<string>();

  //Mono repo
  monoRepoChild: boolean = false;
  monoRepoParent: boolean = false;
  parentRepoOfMonoRepo: Repo = null;
  insideFolder: string = "";
  isSharedModule: boolean = false;

  sourceBranch: string;

  get isMonoRepoParentOrChild() {
    return this.monoRepoParent || this.monoRepoChild;
  }

  // monorepo parent if its children do not include all of the files in the repository
  monoRepoParentOrphanedFilesCount = 0;
  // this property contains an array of folders contents of which we consider separate monorepo children
  monoRepoChildrenSubfolders: string[] | null = null;

  // determine if scannable with tools
  get isMonoRepoParentWithOrphanedFiles() {
    if (!this.monoRepoParent) return false;
    return this.monoRepoParentOrphanedFilesCount > 0;
  }
  // passed to toolrunner to unzip orphaned files only for parents containing them
  get ignoredMonoRepoChildrenSubfolders() {
    if (!this.isMonoRepoParentWithOrphanedFiles) return null;
    return this.monoRepoChildrenSubfolders;
  }

  cloneDir: string;
  codeZipDir: string;
  toolCopyDestination: string;
  persistentCloneDir: string;

  realRepo: boolean = true;

  dockerfiles: Array<{ path: string }>;

  //Clone
  failedClone: boolean = false;
  successfulClone: boolean = false;

  //Specific for bitbucket
  workspace: string;

  //Only Github - open source
  issueCount = -1;

  // Pipeline scans
  pipelineScanInfo: PipelineScanInfo;
  // only for pipeline scans scanning pull (merge) requests. if found via API requests per SCM provider, sent over to cloner
  filesModifiedInPullRequest: string[] = null;

  // roles for git vendor
  gitRoles: any = {};

  // License, Codeowners, security
  specialFiles: any = {};

  //Github actions
  workflowPermissions: any = {};
  defaultWorkflowPermissions: any = {};

  totalRepos: number = 0;
  isDelta: boolean = false;

  severityChangedReason: ChangeReason[] = [];
  cloneArgs = [];

  // failed operation
  failedCollectSecTools: boolean = false;
  failedCollectSecToolsReason: string;
  mainFolder: string;

  monorepoChildrenCount: number = 0;
  monorepoChildrenAppIds: Set<string> = new Set();

  isOrg2faEnabled: boolean = null;
  isOrgVerified: boolean = null;

  frameworks = new Set();

  forkedRepos: ForkedRepos[] = [];

  unlistedActions = new Map();

  allowForking: boolean = false;

  appTags: (IOxTag & { appliedBy: string })[] = [];
  excludedTagsIds: string[] = [];

  // Repository history size
  repositoryHistorySize: number = 0;
  teams: any[];
  pipPoetryDir: string;
  largeGitHistory: boolean = false;

  // For aws code commit specific
  region: string;
  accountName: string;

  // Call Graph
  callGraphHelper: CallGraphHelper;

  // For ACM (Artifact-to-cloud-matcher)
  acmDir;

  hasSecurityEventsInDiskDB: boolean = false;

  // topics - only github
  topics: Topic[] = [];

  // github only
  securityAndAnalysis: any = {};
  isAdvancedSecurityEnabled: boolean = false; // gh advaced security
  isSecretScanningEnabled: boolean = false; // gh Secret scanning
  isDependabotEnabled: boolean = false; // gh sca Dependabot

  constructor(
    uuid: string,
    orgId: string,
    type: string,
    name: string,
    id: string,
    fullName: string,
    createdAt: string,
    defaultBranch: string,
    description: string,
    disable: boolean,
    cloneURL: string,
    downloadCount: Number,
    hasPages: boolean,
    hasWiki: boolean,
    hasIssues: boolean,
    homepage: string,
    privateVisability: boolean,
    languages: DevLanguages[],
    sizeMB: number,
    watchersCount: number,
    ownerName: string,
    link: string,
    forksCount: number,
    lastPushTime: string,
    project: string,
    fileLink: string,
    linkFilePreffix: string,
    tags: number,
    settingLink: string,
    commitLink: string,
    pushesLink: string,
    pullsLink: string,
    organization: string,
    repoId: string,
    isOrgRepo: boolean,
    repoName: string,
    pipelineScanInfo: PipelineScanInfo = {
      sourceBranch: null,
      targetBranch: null,
      sha: null,
      baseSha: null,
    },
    vcsType: VCSType = VCSType.git,
    cloudDeployments: Object[] = [],
    cloneArgs = [],
    teams = [],
    region: string = "",
    accountName: string = "",
  ) {
    this.id = id == null ? "" : id;
    this.type = type;

    let typeForPath = "";
    if (this.type.toLowerCase() === repoType.gitlab.toLowerCase()) {
      this.type = "GitLab";
      typeForPath = this.type;
    } else if (this.type.toLowerCase() === repoType.github.toLowerCase()) {
      this.type = "GitHub";
      typeForPath = this.type;
    } else if (
      this.type.toLowerCase() === repoType.azure.toLowerCase() ||
      this.type.toLowerCase() === "Azure Repos (TFVC)".toLowerCase() ||
      this.type.toLowerCase() === "Azure Repos (Git)".toLowerCase()
    ) {
      if (vcsType == VCSType.tfvc) {
        this.type = "Azure Repos (TFVC)";
        typeForPath = "AzureReposTFVC";
      } else {
        this.type = "Azure Repos (Git)";
        typeForPath = "AzureReposGit";
      }
    } else if (this.type.toLowerCase() === repoType.bitbucket.toLowerCase()) {
      this.type = "Bitbucket";
      typeForPath = this.type;
    } else if (this.type.toLowerCase() === repoType.bitbucketStash.toLowerCase()) {
      this.type = "Bitbucket-Stash";
      typeForPath = this.type;
    } else if (this.type.toLowerCase() === repoType.azureTFS.toLowerCase()) {
      this.type = "Azure TFS";
      typeForPath = "AzureTFS";
    } else if (this.type.toLowerCase() === repoType.gerrit.toLowerCase()) {
      this.type = repoType.gerrit;
      typeForPath = repoType.gerrit;
    }

    this.createdAt = createdAt == null ? "" : createdAt;
    this.link = link == null ? "" : link;
    this.fullName = fullName == null ? "" : fullName;
    this.description = description == null ? "" : description;
    this.name = name == null ? "" : name;
    this.defaultBranch = defaultBranch ? defaultBranch : "main";
    this.ownerName = ownerName == null ? "" : ownerName;
    this.ownerNameApi = this.ownerName;
    this.lastPushTime = lastPushTime == null ? "" : lastPushTime;
    this.watchersCount = watchersCount == null ? 0 : watchersCount;
    this.sizeInBytes = sizeMB == null ? -1 : sizeMB;
    this.languages = languages == null ? [] : languages;
    this.homepage = homepage == null ? "" : homepage;
    this.privateVisability = privateVisability == null ? false : privateVisability;
    this.hasWiki = hasWiki == null ? false : hasWiki;
    this.cloneURL = cloneURL == null ? "" : cloneURL;
    this.project = project == null ? "" : project;
    this.forksCount = forksCount == null ? 0 : forksCount;
    this.hasPages = hasPages == null ? false : hasPages;
    this.downloadCount = downloadCount == null ? 0 : downloadCount;
    this.disable = disable == null ? false : disable;
    this.hasIssues = hasIssues == null ? false : hasIssues;
    this.tags = tags;
    this.settingLink = settingLink == null ? "" : settingLink;
    this.filesCount = 0;
    this.commitLink = commitLink;
    this.pushesLink = pushesLink;
    this.pullsLink = pullsLink;
    this.cloudDeployments = cloudDeployments;
    this.organization = organization;
    this.vcsType = vcsType;
    this.pipelineScanInfo = pipelineScanInfo;
    this.repoId = repoId;
    this.isOrgRepo = isOrgRepo;
    this.repoRealName = repoName;
    this.openWikiRequestId = uuidGenerator.v4();
    this.cloneArgs = cloneArgs;
    this.teams = teams;
    this.region = region;
    this.accountName = accountName;

    this.mainFolder = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}`;

    const orgGitCloneDir = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/clone`;
    const orgGitCloneDirLocal = `${
      process.env.DOCKER_DEBUG ? `${process.env.OX_SHARED_DATA}/scratch` : "/mnt/scratch"
    }/${orgId}/scan_${replaceAll(uuid, "-", "_")}/clone`;
    this.sbomPathDir = `${"c:"}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/sbom`;
    const orgGitResDir = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/securityResults`;

    const blameResDir = getBlameDir(orgId, uuid);

    const secretValidation = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/secretValidation`;

    const autoFixValidation = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/autoFix`;

    const resolveIssuesValidation = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/resolveIssue`;

    const pipPoetryDir = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/pip2poetry`;

    const openSourceInfo = `${globalDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/openSourceInfo`;

    const alertRecommendation = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/alertRecommendation`;

    const iacVerification = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/iacVerification`;

    const scaVerification = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/scaVerification`;

    const alertDepJacking = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/alertDepJacking`;

    const acmDir = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/acm`;

    let repoNameTrimmed = this.name.trimEnd();
    repoNameTrimmed = `${repoNameTrimmed}_${uuidGenerator.v4()}`;
    repoNameTrimmed = replaceAll(repoNameTrimmed, " ", "_");

    const pathToRepo = typeForPath + "/" + repoNameTrimmed;

    this.codeZipDir = orgGitCloneDir + "/" + pathToRepo;

    this.persistentCloneDir = `${process.env.OX_GLOBAL_DATA}/keep/${orgId}/persistentCloneDir/${typeForPath}/${replaceAll(
      this.id.trimEnd(),
      " ",
      "_",
    )}`;

    if ((process.env.DEBUG != undefined || onPrem) && !isk8 && !process.env.DOCKER_DEBUG) {
      // locally or on prem, the clone is not a zip, it's actually the content of the repo
      this.cloneDir = this.codeZipDir;
    } else {
      // should unzip the content of the repo from efs to /mnt/scratch when clone is done
      this.cloneDir = orgGitCloneDirLocal + "/" + pathToRepo;
    }

    this.toolCopyDestination = orgGitCloneDirLocal + "/" + pathToRepo + "/" + uuidGenerator.v4().replace(/-/g, "_");

    //Dir for services
    this.securityResDir = orgGitResDir + "/" + pathToRepo;
    this.blameResDir = blameResDir + "/" + pathToRepo;
    this.secretValidationDir = secretValidation + "/" + pathToRepo;
    this.autoFixValidationDir = autoFixValidation + "/" + pathToRepo;
    this.resolveIssuesValidationDir = resolveIssuesValidation + "/" + pathToRepo;
    this.pipPoetryDir = pipPoetryDir + "/" + pathToRepo;
    this.openSourceInfoDir = openSourceInfo + "/" + pathToRepo;
    this.iacValidatorDir = iacVerification + "/" + pathToRepo;
    this.alertRecommendation = alertRecommendation + "/" + pathToRepo;
    this.alertDepJackingDir = alertDepJacking + "/" + pathToRepo;
    this.scaValidatorDir = scaVerification + "/" + pathToRepo;
    this.acmDir = acmDir;
    const fileHelper: FileHelper = new FileHelper(this.fullName);
    fileHelper.createDir(this.securityResDir);

    this.fileLink = fileLink == null ? "" : fileLink;
    this.linkFilePreffix = linkFilePreffix == null ? "" : linkFilePreffix;

    if (this.id === "" || this.name === "") {
      throw new Error("err: constructor, repo is empty");
    }

    if (this.isOrgRepo) GlobalCodeRepoData.Instance.addRepo(this);
  }

  isPip2PoetryOrDependencyGTool(tool: string) {
    return tool.toLowerCase() === OXtools.pip2poetry.toLowerCase() || tool.toLowerCase() === OXtools.dependencyG.toLowerCase();
  }

  fixSecurityToolsName(tool: string) {
    try {
      let t = tool;

      if (this.isPip2PoetryOrDependencyGTool(t)) {
        t = OXtools.trivyCode;
      }

      return t.toLowerCase();
    } catch (error) {
      logger.error(`Error while convertSecurityToolNames, error: ${error}`);
      return tool.toLowerCase();
    }
  }

  addFailedSecurityTools(tool: string) {
    if (!StatesHelper.Instance.enableFallback) {
      return;
    }

    //Mostly done for adjust pip2poetry failed or dep.G to add the sca tool
    const toolName = this.fixSecurityToolsName(tool);
    if (this.failedSecurityTools.has(toolName)) {
      return;
    }

    this.failedSecurityTools.add(toolName);
    logger.error(`adding failed tool to repo: ${this.fullName}, tool: ${tool}, tool name added: ${toolName}`);

    //If pip2poetry failed or dep.G add depJacking & depConfusionAlert tools for dep jaking
    if (this.isPip2PoetryOrDependencyGTool(tool)) {
      if (!this.failedSecurityTools.has(OXtools.depJacking.toLowerCase())) {
        this.failedSecurityTools.add(OXtools.depJacking.toLowerCase());
        logger.error(`adding failed tool to repo: ${this.fullName}, tool: ${tool}, tool name added: ${OXtools.depJacking}`);
      }

      if (!this.failedSecurityTools.has(OXtools.depConfusionAlert.toLowerCase())) {
        this.failedSecurityTools.add(OXtools.depConfusionAlert.toLowerCase());
        logger.error(`adding failed tool to repo: ${this.fullName}, tool: ${tool}, tool name added: ${OXtools.depConfusionAlert}`);
      }
    }
  }

  getRepoForToolsBasedOnEnv() {
    if (process.env.DEBUG && !process.env.DOCKER_DEBUG) {
      return this.cloneDir;
    }

    if (localToolRunner().isConfiguredToRunToolsLocally()) {
      return localToolRunner().updatePath(this.toolCopyDestination);
    }

    //If onPrem take the clone dir and use shared file system
    //If SAST use unique zip destination folder

    //On orem
    if (onPrem && !isk8) {
      return this.cloneDir;
    }

    const toolCopyDestination = this.toolCopyDestination;

    // avoid double slash situation
    return toolCopyDestination.replace(/\/\//g, "/");
  }

  getRepoPathForToolCommand() {
    const repoForTools = this.getRepoForToolsBasedOnEnv();
    //for onprem or k8 it will be:
    //repo example ..../deliberately-vulnerable-apps_e4eb3c241dbc38c11d9edd9f6f9/DSVW
    //for sast/k8:§
    //repo example ..../deliberately-vulnerable-apps_e4eb3c241dbc38c11d9edd9f6f9
    // if (process.env.DEBUG) return repoForTools.substring(0, repoForTools.lastIndexOf("/")).replace("/mnt/scratch", process.env.OX_SHARED_DATA);
    const isMonoRepo = this.monoRepoChild;
    if (!isMonoRepo) return repoForTools;

    //Onorem
    //On onprem dont add any suffix to mono repo
    if (onPrem && !isk8) {
      return repoForTools;
    }

    //SAST/k8
    //MONO Repo
    //avoid double slash situation
    //inside foder is empty in all cases except mono repo where we will add the suffix DSVW
    //in case it sast/k8
    return (repoForTools + "/" + this.insideFolder).replace(/\/\//g, "/");
  }

  sast: string[] = [];
  dast: string[] = [];
  sca: string[] = [];
  secrets: string[] = [];
  iac: string[] = [];
  cspm: string[] = [];
  disableSast: string[] = [];
  disableSca: string[] = [];
  oxSecurityTools: any = [];
  unprotectedSastDevLanguages: DevLanguages[];
  unprotectedScatDevLanguages: DevLanguages[];
  cicd: string[] = [];
  cicdInfo: AppFlowCICD[] = [];
  webhook: boolean = false;
  containerFiles: number = 0;
  repoImportance: RepoImportance;
  deploymentFiles;
  secInfra: any;
  toolsCoverage: AppToolCoverage[] = [];

  addFramework(frameworkInfo: ChangeReason, frameworkName: string) {
    const changeReason = this.severityChangedReason.find(s => s.shortName == frameworkInfo.shortName);
    if (changeReason && changeReason?.extraInfo && changeReason.extraInfo.length >= changeReason.requiredHits) {
      this.frameworks.add(frameworkName);
    }
  }

  addRepoSeverityChangedReason(newSeverityChangedReason: ChangeReason, extraInfo?: ExtraInfo[]) {
    // customer override tags
    const isTagExcluded = this.isChangeReasonExcluded(newSeverityChangedReason);
    if (isTagExcluded) {
      logger.info(
        `${newSeverityChangedReason.shortName} tagId: ${newSeverityChangedReason.tagId} is excluded by client config. appId: ${this.id}`,
      );
      return;
    }
    // tag already exist for this repo
    const existAlready = this.severityChangedReason.find(s => s.shortName == newSeverityChangedReason.shortName);
    if (existAlready && existAlready?.extraInfo && existAlready.extraInfo.length < 10) {
      if (extraInfo) {
        extraInfo.forEach((ei: ExtraInfo) => {
          if (!existAlready.extraInfo.some((obj: ExtraInfo) => obj.link === ei.link)) {
            existAlready.extraInfo.push(ei);
          }
        });
      }
      return;
    }
    // new tag seen
    const copySeverityChangedReason = ChangeReason.copy(newSeverityChangedReason);
    if (extraInfo) {
      copySeverityChangedReason.extraInfo = extraInfo;
    }
    this.severityChangedReason.push(copySeverityChangedReason);
  }

  isChangeReasonExcluded(changeReason: ChangeReason) {
    try {
      if (changeReason.tagId) {
        return this.excludedTagsIds.includes(changeReason.tagId);
      }
      return false;
    } catch (e) {
      logger.error(`failed isChangeReasonExcluded. appId: ${this.id} cr: ${changeReason.tagId || changeReason.shortName}`);
    }
    return false;
  }

  setAdditionalInfo(
    sast: string[],
    sca: string[],
    secrets: string[],
    iac: string[],
    cspm: string[],
    disableSast: string[],
    disableSca: string[],
    oxSecurityTools: any,
    unprotectedSastDevLanguages: DevLanguages[],
    unprotectedScatDevLanguages: DevLanguages[],
    foundCICD: OrgCicdTool[],
    webhook: boolean,
    containerFiles: number,
    repoImportance: any,
    filesCount: number,
    deploymentFiles: string[],
    cloudDeployments: Object[],
    secInfra: any,
    users: User[],
    mostVeretanUsers: string[],
    toolsCoverage: AppToolCoverage[],
  ) {
    this.sast = sast;
    this.sca = sca;
    this.secrets = secrets;
    this.iac = iac;
    this.cspm = cspm;
    this.disableSast = disableSast;
    this.disableSca = disableSca;
    this.oxSecurityTools = oxSecurityTools;
    this.unprotectedSastDevLanguages = unprotectedSastDevLanguages;
    this.unprotectedScatDevLanguages = unprotectedScatDevLanguages;
    this.cicd = foundCICD.map(i => i.name);

    this.webhook = webhook;
    this.containerFiles = containerFiles;
    this.repoImportance = repoImportance;
    this.deploymentFiles = deploymentFiles;
    this.cloudDeployments = cloudDeployments;
    this.secInfra = secInfra;
    this.repoUsers = users;
    this.mostVeretanUsers = mostVeretanUsers;
    this.toolsCoverage = toolsCoverage;
    this.setCICDInfo(foundCICD);
  }

  setCICDInfo(foundCICD: OrgCicdTool[]) {
    try {
      const unique = new Set();
      foundCICD.forEach(singleCICD => {
        try {
          const system = getCICDProvider(singleCICD.name);
          if (!system) {
            return;
          }
          const key = singleCICD.resouceName + "_" + system;
          if (unique.has(key)) {
            return;
          }
          unique.add(key);

          let cicd: AppFlowCICD = this.cicdInfo.find(i => i.system === system);
          if (!cicd) {
            const isConnected = StatesHelper.Instance.cicdConnectorsNames.has(system.toLowerCase());

            cicd = new AppFlowCICD();
            cicd.system = system;

            if (system === CICDConnectorsTypes.Generic) {
              cicd.lastMonthJobCount = "0";
              cicd.latestDate = "Not Executed";
            } else if (!isConnected) {
              const str = `N/A (${system} Not connected)`;
              cicd.latestDate = str;
              cicd.lastMonthJobCount = "0";
            }

            this.cicdInfo.push(cicd);
          }

          const c: FoundLocation = new FoundLocation();
          c.foundBy = getCICDType(CodeRepoTypes[singleCICD.objType]);
          if (!c.foundBy) {
            return;
          }

          c.foundIn = `${Constant.DeploymentFile} - ${singleCICD.resouceName}`;
          c.link = singleCICD.htmlUrl;
          cicd.location.push(c);
        } catch (err) {
          logger.error(`failed set single CICD info for repo: ${this.fullName}, cicd: ${JSON.stringify(singleCICD)}`);
        }
      });
    } catch (err) {
      logger.error(`failed set all CICD info for repo: ${this.fullName}`);
    }
  }

  setRepositoryHistorySize(size: number) {
    this.repositoryHistorySize = size;
  }
}

export function getBlameDir(orgId: string, uuid: string) {
  const blameResDir = `${sharedDir}/${orgId}/scan_${replaceAll(uuid, "-", "_")}/blameDir`;
  return blameResDir;
}

export const replaceAll = (str, find, replace) => {
  return str.replace(new RegExp(find, "g"), replace);
};

export function setSecEventFromDelta(repo: Repo, secEvent: SecurityEvent) {
  try {
    secEvent.securityProviders = new Set();
    secEvent.securityProvidersArr?.forEach(i => {
      secEvent.securityProviders.add(i);
    });
    secEvent.securityProviders.add(secEvent.securityProvider);
    secEvent.fromCash = true;
    secEvent.askedOnceForSecretValidation = false;
    secEvent.askedOnceForAutoFix = false;
    secEvent.askedOnceForIacValidator = false;
    secEvent.askedOnceForScaValidator = false;
    secEvent.askedOnceForAlertRecommendation = false;
    secEvent.blame.askedOnce = false;

    const copySeverityReasons = JSON.parse(JSON.stringify(secEvent.severityChangedReason)) as ChangeReason[];

    //Rest severity data before inject again the severity chnages reasons
    secEvent.severityChangedReason = [];

    //The reason for that is that the tag can be excluded
    copySeverityReasons.forEach(i => {
      addSeverityChangedReason(i, secEvent, repo, secEvent.extraInfo);
    });
  } catch (err) {
    logger.error(`failed set sec event from delta for repo: ${repo?.fullName}, err: ${err}`);
  }
}

export class SecurityEvent {
  privateVisability: boolean = true;
  isSilent: boolean = false;
  isGeneric: boolean = false;
  securityProvider: string;
  securityProviders = new Set<string>();
  securityProvidersArr: string[] = [];
  active: boolean;
  link: string;
  createdAt: string;
  createdAtInDays: number;
  closedAt: string;
  closeDismisser: string;
  closeReason: string;
  violationInfo: string;
  title: string;
  severity: AlertSeverity;
  originalSeverity: AlertSeverity;
  confidence: AlertSeverity;
  severityStr: string;
  originalSeverityStr: string;
  confidenceStr: string;
  additionalInfo: string;
  securityAlertTypeStr: string;
  recommendation: string;
  cweList: string[] = [];
  eduVideoLink: string = "";
  description: string = "";
  openTimeInDays: number;
  securityAlertType: SecurityAlertType;
  cloudSubType: SecurityAlertType = SecurityAlertType.Unknown;
  securitySubTypeAlertType: SecurityAlertType = SecurityAlertType.Unknown;
  objType: CodeRepoTypes = CodeRepoTypes.securityEvents;
  oxTool: boolean; // flag if this source tool is deployed by OX (OX deployed)
  fromCommitHistory: boolean = false;
  moreInfoLink: string;
  uid: string;
  language: string;
  organization: string;
  cloudEnv: string;
  extraInfo: ExtraInfo[] = [];
  secretGroup: string = "";
  // For recommendation service JavaPom
  groupId: string = "";

  severityChangedReason: ChangeReason[] = [];

  //Corelated Issue - can be container to SCA and vice verse
  corelateIssue: string;
  correlatedRegistry: string;
  branch: string;

  //Region info
  startLineNumber: number;
  endLineNumber: number;
  lineContent: string;
  snippetContent: string;
  componentName: string;

  //Secret validation
  validSecret: boolean = false;
  secretChecked: boolean = false;
  askedOnceForSecretValidation = false;
  askedOnceForAutoFix = false;
  askedOnceForIacValidator = false;
  askedOnceForScaValidator = false;
  askedOnceForAlertRecommendation = false;

  //Validator
  iacValidation: boolean = false;
  sastValidation: boolean = false;
  dastValidation: boolean = false;

  skipEnrichment: boolean = false;

  //Auto fix
  autoFixResponse: AutoFixResponse = new AutoFixResponse();

  //Sca validation
  scaValidatorTypesResponse: ScaValidatorTypesResponse = new ScaValidatorTypesResponse();

  //Recommendation
  alertRecommendationResponse: AlertRecommendationResponse = new AlertRecommendationResponse();

  //Iac verification
  iacValidatorTypesResponse: IacValidatorTypesResponse = new IacValidatorTypesResponse();

  //Fix
  fixes: Fix[] = [];

  //Commit info
  relatedPR: PullRequest;

  version: string = "main";

  correlatedSCAEvent: boolean = false;
  correlatedCloudEvent: boolean = false;

  //SCA
  fixedVersion: string = "";
  installedVersion: string = "";
  pkgName: string = "";
  pkgManager: string = "";
  lockfile: string = "";

  legitimatePkgName: string = "";
  registry: string = "";
  /**
   * Pkg manger coming from Blame service
   */
  betterPkgManager?: string;
  similarityScore: number;
  legitimatePkgLink: string = "";

  //Artifacts
  artifacts: ArtifactorySecEvent;
  matchFromArtifact: string;
  artifactFilePath: string;
  artifactFileLine: number = -1;
  imageId: string;
  dockerInstructions: string;
  dockerInstructionsCreation: string;

  //Blame service
  repoFullName: string;
  cloneForBlameService: string;
  filePathForBlameService: string;
  issueOwner: string;
  blame: BlameResponse;

  //DONT USE THIS FILED IS FOR STATS ONLY
  cves: string[] = [];

  //This is needed for exclusions dont delete this or change!!!
  realMatch: string;
  secretWithoutObfuscation: string;
  fileName: string;
  ruleId: string;
  collectedAsPartOfRepos: boolean = false;

  filePath: string;

  graphNodesCount: number = 0;

  fromCash: boolean = false;
  metaVars: any;

  //Layer id
  LayerId: string = "";
  LayerOrder: number = -1;
  isOsLib: boolean = false;
  containerScanType: string = "";

  //Dependency scope confusion
  orgScopeId: string = "";
  privateRegistryName: string = "";
  privateRegistryUrl: string = "";
  isOrgScopeAvailable: boolean = false;
  publicRegistry: string = "";
  scopeRegisteredBy: string[] = [];

  //Dependency package confusion
  isPkgAvailable: boolean = false;
  pkgRegisteredBy: string[] = [];
  type: string;
  linkPrefix: string;
  tools: Tool[] = [];
  tool: Tool;

  linkToExternalProduct: string;

  // Dor
  container_image_digest?: string;
  isPII: boolean = false;

  // For pipline scans (reduce blame)
  originalFilName: string;
  isOldEvent: boolean = false;

  constructor(
    securityProvider: string,
    active: boolean,
    link: string,
    createdAt: string,
    closedAt: string,
    closeDismisser: string,
    closeReason: string,
    violationInfo: string,
    title: string,
    fileName: string,
    severity: string,
    additionalInfo: string,
    startLineNumber: number,
    confidence: string,
    securityAlertType: SecurityAlertType,
    recommendation: string,
    lineContent: string,
    snippetContent: string,
    endLineNumber: number,
    ourTool: boolean,
    fromCommitHistory: boolean,
    commiterName: string,
    commitSha: string,
    commiterEmail: string,
    commitDate: string,
    ruleId: string,
    moreInfoLink: string,
    cloneDir: string,
    repoFullName: string,
    insideFolderForMonoRepo: string,
    filePath: string,
    tool: Tool,
    metaVars?: any,
    artifacts?: ArtifactorySecEvent,
    version?: string,
  ) {
    this.blame = new BlameResponse();
    this.active = active == null ? false : active;
    this.link = link == null ? "" : link;
    this.securityProvider = securityProvider == null ? "" : securityProvider;
    this.securityProviders.add(this.securityProvider);
    this.securityProvidersArr.push(this.securityProvider);
    this.createdAt = createdAt == null ? "" : createdAt;
    this.closedAt = closedAt == null ? "" : closedAt;
    this.closeDismisser = closeDismisser == null ? "" : closeDismisser;
    this.closeReason = closeReason == null ? "" : closeReason;
    this.violationInfo = violationInfo == null ? "" : violationInfo;
    this.additionalInfo = additionalInfo == null ? "" : additionalInfo;
    this.title = title == null ? "" : title;
    this.fileName = fileName == null ? "" : fileName;
    this.blame.commitDate = commitDate == null ? "" : commitDate;
    this.securityAlertType = securityAlertType;
    this.securityAlertTypeStr = SecurityAlertType[securityAlertType];
    this.startLineNumber = startLineNumber < 0 ? -1 : startLineNumber;
    this.endLineNumber = endLineNumber < 0 || startLineNumber == endLineNumber ? -1 : endLineNumber;
    this.recommendation = recommendation;
    this.lineContent = lineContent;
    this.snippetContent = snippetContent == undefined ? "" : snippetContent;
    this.oxTool = ourTool;
    this.fromCommitHistory = fromCommitHistory;
    this.blame.commiterName = commiterName == null || commiterName == undefined ? "" : commiterName;
    this.blame.commitSha = commitSha == null || commiterName == undefined ? "" : commitSha;
    this.blame.commiterEmail = commiterEmail == null || commiterName == undefined ? "" : commiterEmail;
    this.ruleId = ruleId == null ? "" : ruleId;
    this.moreInfoLink = moreInfoLink == null ? "" : moreInfoLink;
    this.filePath = filePath;
    this.uid = uuidGenerator.v4();
    this.artifacts = artifacts === null ? null : artifacts;
    this.tool = tool;
    this.tools.push(tool);
    addParentTool(this, tool);
    const local = process.env.OX_SCRATCH_DATA == undefined ? "/mnt/scratch" : process.env.OX_SCRATCH_DATA;

    this.repoFullName = repoFullName;
    this.version = version;

    if (!process.env.DEBUG) {
      this.cloneForBlameService = cloneDir.replace(`${local}/`, "");
    } else {
      this.cloneForBlameService = cloneDir;
    }
    this.filePathForBlameService = this.fileName;

    //Set file for mono repo
    if (insideFolderForMonoRepo != "") {
      this.filePathForBlameService = `${insideFolderForMonoRepo}/${this.filePathForBlameService}`;
      if (this.filePathForBlameService.startsWith("/")) {
        this.filePathForBlameService = this.filePathForBlameService.substring(1, this.filePathForBlameService.length);
      }
    }

    if (this.ruleId === "") {
      throw new Error(`ruleId empty, link ${this.link}`);
    }

    if (this.securityProvider === "") {
      throw new Error(`securityProvider are empty, link ${this.link}`);
    }

    if (securityAlertType === SecurityAlertType.Unknown) {
      throw new Error(`securityAlertType are unknown, link ${this.link}, ruleId: ${this.ruleId}`);
    }

    if (this.violationInfo === "") {
      throw new Error(`violationInfo are empty, link: ${this.link}, ruleId: ${this.ruleId}`);
    }

    if (SecurityAlertType.container !== this.securityAlertType && this.fileName === "") {
      throw new Error(`file name are empty: link ${this.link} title: ${this.title}, ruleId: ${this.ruleId}`);
    }

    if (
      this.securityAlertType != SecurityAlertType.sca &&
      this.securityAlertType != SecurityAlertType.container &&
      this.securityAlertType != SecurityAlertType.iac &&
      this.securityAlertType != SecurityAlertType.license
    ) {
      if (this.startLineNumber == -1) {
        throw new Error(`line number are empty: link ${this.link} title: ${this.title}`);
      }
    }

    const timeHelper: TimeHelper = new TimeHelper("security event");
    this.createdAtInDays = timeHelper.getTimeIntervalFronNowInDays(this.createdAt);

    setOepnTimeInfo(this);
    setSeverity(severity, this);
    setConfidence(confidence, this);

    this.originalSeverityStr = this.severityStr;
    this.originalSeverity = this.severity;

    if (!this.securityProvider) {
      throw new Error(`securityProvider is empty, link: ${this.link}`);
    }

    if (this.severity == AlertSeverity.Unknown) {
      throw new Error(`failed to detect severity for: ${severity}`);
    }

    this.metaVars = metaVars ? metaVars : {};
  }

  public async setEduLink(eduVideoLink: string) {
    this.blame.eduVideoLink = eduVideoLink;
  }
  public setLayeridIssue(_LayerId: string, allLayers: string[]) {
    try {
      if (!_LayerId) {
        return;
      }

      this.LayerId = _LayerId?.replace("sha256:", "");

      let count = 1;
      for (const l of allLayers) {
        if (l === _LayerId) {
          this.LayerOrder = count;
          break;
        }
        count++;
      }
    } catch (err) {
      logger.error(`setLayeridIssue, err: ${err}`);
    }
  }
  public setIsOsTypeLib(typeOfLib: string) {
    this.isOsLib =
      typeOfLib.toLowerCase() === "os-pkgs" ||
      typeOfLib.toLowerCase() === "deb" ||
      typeOfLib.toLowerCase() === "debian" ||
      typeOfLib.toLowerCase() === "alpine" ||
      typeOfLib.toLowerCase() === "linux";
  }
}

export class SecurityEventWithIndex {
  event: SecurityEvent;
  index: number;
}

export function getUniqueInfoForCloudAggregation(alert: CloudSecurityEvent) {
  if (StatesHelper.Instance.aggCloudAlertsBaseOnOrg) {
    let unique = `${alert.ruleId}_${alert.cloudService}_${alert.accountName}`;
    return unique;
  }

  let unique = `${alert.ruleId}_${alert.cloudService}`;
  return unique;
}

export function getToolsNames(securityProviders: Set<string>, tools: Tool[]) {
  try {
    const res = new Set<Tool>();

    if (securityProviders) {
      Array.from(securityProviders).forEach(i => {
        try {
          const tool = i.toLowerCase().replaceAll(" ", "-") as Tool;
          res.add(tool);
        } catch (e) {
          logger.error(`failed to create tool from providers. error: ${e}`);
        }
      });
    }

    if (tools) {
      tools.forEach(i => {
        res.add(i.toLowerCase() as Tool);
      });
    }

    return Array.from(res);
  } catch (e) {
    logger.error(`failed to getToolsNames. error: ${e}`);
  }
  return [];
}

export const addParentTool = (secEvent: SecurityEvent | CloudSecurityEvent, tool: string) => {
  try {
    if (tool.includes("-cspm")) {
      const parentTool = tool.replace("-cspm", "");
      secEvent.tools.push(parentTool as Tool);
    }
  } catch (e) {
    logger.error(`failed to getParentTool. error: ${e}`, e);
  }
};

export function getUniqueInfoForAggregation(securityEvent: SecurityEvent) {
  let item = getUniqueInfoForAggregationInternal(securityEvent);
  if (securityEvent.version && StatesHelper.Instance.orgName === "org_lr5xmDFD829DrFAK") {
    item = `${item}_${securityEvent.version}`;
  }
  return item;
}

function getUniqueInfoForAggregationInternal(securityEvent: SecurityEvent) {
  if (securityEvent.securityAlertType === SecurityAlertType.ox) {
    return securityEvent.lineContent;
  }
  if (
    securityEvent.securityAlertType === SecurityAlertType.typosquatting ||
    securityEvent.securityAlertType === SecurityAlertType.depConfusionPkgs
  ) {
    return `${securityEvent.pkgName}_${securityEvent.installedVersion}`;
  }

  const iacContainerAggItem =
    securityEvent.securityAlertType === SecurityAlertType.container && securityEvent.securitySubTypeAlertType === SecurityAlertType.iac;
  if (iacContainerAggItem) {
    return `${securityEvent.ruleId}_${securityEvent.artifacts.dockerFileInRunTime}`;
  }

  const secretContainerAggItem =
    securityEvent.securityAlertType === SecurityAlertType.container && securityEvent.securitySubTypeAlertType === SecurityAlertType.secrets;
  if (secretContainerAggItem) {
    //contianer PII
    if (securityEvent.isPII) {
      return `${securityEvent.ruleId}-${securityEvent.artifacts.dockerFileInRunTime}`;
    }

    if (securityEvent.ruleId) {
      if (securityEvent.ruleId.toLowerCase().includes("generic")) {
        return `${securityEvent.ruleId}-${false}-${false}-${securityEvent.artifacts.dockerFileInRunTime}`;
      }
    }
    return `${securityEvent.realMatch}-${securityEvent.artifacts.dockerFileInRunTime}`;
  }

  const shouldAggBySCA =
    securityEvent.securityAlertType === SecurityAlertType.sca ||
    (securityEvent.securityAlertType === SecurityAlertType.container && securityEvent.securitySubTypeAlertType === SecurityAlertType.sca);
  if (shouldAggBySCA) {
    //SCA
    if (securityEvent.securityAlertType === SecurityAlertType.sca && securityEvent.securitySubTypeAlertType === SecurityAlertType.Unknown) {
      if (securityEvent?.blame?.triggerPackage?.name && securityEvent?.blame?.triggerPackage?.version) {
        return `${securityEvent.blame.triggerPackage.name}_${securityEvent.blame.triggerPackage.version}`;
      } else {
        return `${securityEvent.pkgName}_${securityEvent.installedVersion}`;
      }
    }

    //Docker file
    if (
      securityEvent.securityAlertType === SecurityAlertType.sca &&
      securityEvent.securitySubTypeAlertType === SecurityAlertType.dockerFileVul
    ) {
      if (securityEvent?.blame?.triggerPackage?.name && securityEvent?.blame?.triggerPackage?.version) {
        return `${securityEvent.blame.triggerPackage.name}_${securityEvent.blame.triggerPackage.version}_${securityEvent.fileName}`;
      } else {
        return `${securityEvent.pkgName}_${securityEvent.installedVersion}_${securityEvent.fileName}`;
      }
    }

    //Container sca
    if (
      securityEvent.securityAlertType === SecurityAlertType.container &&
      securityEvent.securitySubTypeAlertType === SecurityAlertType.sca
    ) {
      //baseOnly
      if (securityEvent.containerScanType === ContainerSecurityType.baseOnly) {
        return `${securityEvent.artifacts.baseImage}_${securityEvent.artifacts.baseImageOsVersion}_${securityEvent.artifacts.dockerFileInRunTime}`;
      }
      //possibleOsOnly
      else if (securityEvent.containerScanType === ContainerSecurityType.possibleOsOnly) {
        return `${securityEvent.artifacts.os}_${securityEvent.artifacts.osVersion}_${securityEvent.artifacts.dockerFileInRunTime}`;
      }
      //app only or user instractions
      else {
        //application
        let pkgNameVer = `${securityEvent.pkgName}_${securityEvent.installedVersion}`;
        if (securityEvent?.blame?.triggerPackage?.name && securityEvent?.blame?.triggerPackage?.version) {
          pkgNameVer = `${securityEvent.blame.triggerPackage.name}_${securityEvent.blame.triggerPackage.version}`;
        }
        return `${pkgNameVer}_${securityEvent.artifacts.dockerFileInRunTime}`;
      }
    }

    return `${securityEvent.pkgName}_${securityEvent.installedVersion}`;
  }

  const runTimeAggItem =
    securityEvent.securityAlertType === SecurityAlertType.container &&
    securityEvent.securitySubTypeAlertType === SecurityAlertType.cloudRunTime;
  if (runTimeAggItem) {
    let item;
    if (securityEvent.cloudSubType === SecurityAlertType.secrets) {
      item = `${securityEvent.ruleId}_${securityEvent.lineContent}_${securityEvent?.artifacts?.dockerFileInRunTime}`;
    } else if (securityEvent.containerScanType === ContainerSecurityType.possibleOsOnly) {
      item = `${securityEvent.pkgName}_${securityEvent.installedVersion}`;
    } else {
      item = `${securityEvent.pkgName}_${securityEvent.installedVersion}`;
    }

    if (StatesHelper.Instance.aggCloudAlertsBaseOnOrg) {
      item = `${item}_${securityEvent?.artifacts?.accountId}`;
    }

    return item;
  }

  if (securityEvent.securityAlertType === SecurityAlertType.sast) {
    return `${securityEvent.ruleId}-${securityEvent.sastValidation}`;
  }
  if (securityEvent.securityAlertType === SecurityAlertType.dast) {
    return `${securityEvent.ruleId}-${securityEvent.dastValidation}`;
  }
  if (securityEvent.securityAlertType === SecurityAlertType.iac) {
    return `${securityEvent.ruleId}-${securityEvent.iacValidation}`;
  }

  //Code
  if (securityEvent.securityAlertType === SecurityAlertType.secrets) {
    // pii code
    if (securityEvent.isPII) {
      return `${securityEvent.ruleId}-${securityEvent.repoFullName}`;
    }

    if (securityEvent.ruleId) {
      if (securityEvent.ruleId.toLowerCase().includes("generic")) {
        //keep same format for BC - return `${securityEvent.ruleId}-${securityEvent.validSecret}-${securityEvent.secretChecked}`;
        return `${securityEvent.ruleId}-${false}-${false}`;
      }
    }
    return securityEvent.realMatch;
  }

  return securityEvent.ruleId;
}

export function addSeverityChangedReason(
  newSeverityChangedReason: ChangeReason,
  securityEvent: SecurityEvent,
  repo: Repo,
  extraInfo?: ExtraInfo[],
  compareKey: boolean = false,
) {
  if (repo?.realRepo) {
    const isTagExcluded = repo.isChangeReasonExcluded(newSeverityChangedReason);
    if (isTagExcluded) {
      logger.info(`${newSeverityChangedReason.shortName} is excluded by client config`);
      return;
    }
  }
  const existAlready = securityEvent.severityChangedReason.find(s => s.shortName == newSeverityChangedReason.shortName);
  if (existAlready) {
    if (extraInfo) {
      if (compareKey) {
        extraInfo.forEach((ei: ExtraInfo) => {
          if (!existAlready.extraInfo.some((obj: ExtraInfo) => obj.key === ei.key)) {
            existAlready.extraInfo.push(ei);
          }
        });
      } else {
        extraInfo.forEach((ei: ExtraInfo) => {
          if (!existAlready.extraInfo.some((obj: ExtraInfo) => obj.link === ei.link)) {
            existAlready.extraInfo.push(ei);
          }
        });
      }
    }
    return;
  }
  const copySeverityChangedReason = ChangeReason.copy(newSeverityChangedReason);
  if (extraInfo) {
    copySeverityChangedReason.extraInfo = extraInfo;
  }
  securityEvent.severityChangedReason.push(copySeverityChangedReason);
}

export function addSeverityCloudChangedReason(
  newSeverityChangedReason: ChangeReason,
  securityEvent: CloudSecurityEvent,
  extraInfo?: ExtraInfo[],
) {
  try {
    const existAlready = securityEvent.severityChangedReason.find(s => s.shortName == newSeverityChangedReason.shortName);
    if (existAlready) {
      if (extraInfo && newSeverityChangedReason !== severityReasons.runningInCloud) {
        extraInfo.forEach((ei: ExtraInfo) => {
          if (!existAlready.extraInfo.some((obj: ExtraInfo) => obj.link === ei.link)) {
            existAlready.extraInfo.push(ei);
          }
        });
      } else if (extraInfo && newSeverityChangedReason === severityReasons.runningInCloud) {
        extraInfo.forEach((ei: ExtraInfo) => existAlready.extraInfo.push(ei));
      }
      return;
    }
    const copySeverityChangedReason = ChangeReason.copy(newSeverityChangedReason);
    if (extraInfo) {
      copySeverityChangedReason.extraInfo = extraInfo;
    }
    securityEvent.severityChangedReason.push(copySeverityChangedReason);
  } catch (err) {
    logger.error(`failed addSeverityCloudChangedReason, err: ${err}`);
  }
}

export function setSeverity(severity: string, securityEvent: SecurityEvent) {
  securityEvent.severity = AlertSeverity.Unknown;
  securityEvent.severityStr = AlertSeverity[AlertSeverity.Unknown];

  if (severity == null || !severity) {
    return;
  }
  if (Constant.infoRegex.exec(severity) != null) {
    securityEvent.severity = AlertSeverity.Info;
  }
  if (Constant.lowRegex.exec(severity) != null) {
    securityEvent.severity = AlertSeverity.Low;
  }
  if (Constant.mediumRegex.exec(severity) != null) {
    securityEvent.severity = AlertSeverity.Medium;
  }
  if (Constant.highRegex.exec(severity) != null) {
    securityEvent.severity = AlertSeverity.High;
  }
  if (Constant.criticalRegex.exec(severity) != null) {
    securityEvent.severity = AlertSeverity.Critical;
  }
  if (Constant.applRegex.exec(severity) != null) {
    securityEvent.severity = AlertSeverity.Appoxalypse;
  }
  securityEvent.severityStr = AlertSeverity[securityEvent.severity];
}

export function setConfidence(confidence: string, securityEvent: SecurityEvent) {
  securityEvent.confidence = AlertSeverity.Unknown;
  securityEvent.confidenceStr = AlertSeverity[AlertSeverity.Unknown];

  if (confidence == null || !confidence) {
    return;
  }
  if (Constant.lowRegex.exec(confidence) != null) {
    securityEvent.confidence = AlertSeverity.Low;
  }
  if (Constant.mediumRegex.exec(confidence) != null) {
    securityEvent.confidence = AlertSeverity.Medium;
  }
  if (Constant.highRegex.exec(confidence) != null) {
    securityEvent.confidence = AlertSeverity.High;
  }
  if (Constant.criticalRegex.exec(confidence) != null) {
    securityEvent.confidence = AlertSeverity.Critical;
  }
  if (Constant.applRegex.exec(confidence) != null) {
    securityEvent.confidence = AlertSeverity.Appoxalypse;
  }

  securityEvent.confidenceStr = AlertSeverity[securityEvent.confidence];
}

export function setOepnTimeInfo(securityEvent: SecurityEvent) {
  securityEvent.openTimeInDays = -1;
  if (securityEvent.active && securityEvent.createdAt != null) {
    let openTime = new Date(securityEvent.createdAt);
    const openTimeInfo = openTime.getTime();
    const seconds = (new Date().getTime() - openTimeInfo) / 1000;
    const openTimeInHours = seconds / 3600;

    securityEvent.openTimeInDays = Math.trunc(openTimeInHours / 24);
  }
}

export function getTFSRepo(tfsItemName: string) {
  return tfsItemName.replace("$/", "");
}

export function getTFSRepoNameFromBranch(tfsSubFolder: string) {
  tfsSubFolder = getTFSRepo(tfsSubFolder);
  const index = tfsSubFolder.indexOf("/");
  if (index != -1) {
    return tfsSubFolder.substring(0, index);
  } else {
    return tfsSubFolder;
  }
}

export enum Relevance {
  RELEVANT = "relevant",
  IRRELEVANT = "irrelevant",
  DEFAULT = "default",
}

export enum UserRole {
  NONE = "",
  OWNER = "Owner",
  MAINTAINER = "Maintainer",
  DEVELOPER = "Developer",
  REPORTER = "Reporter",
  GUEST = "Guest",
  NO_ACCESS = "No Access",
}

export enum PushRole {
  NONE = "No one",
  DEVELOPER = "Developers + Maintainers",
  MAINTAINER = "Maintainers",
}

export enum OrgRoles {
  NONE = "",
  OWNER = "Owner",
  ADMIN = "Owner",
  GUEST = "Guest",
  REPORTER = "Reporter",
  DEVELOPER = "Developer",
  MEMBER = "Member",
  MODERATOR = "Moderator",
  MAINTAINER = "Maintainer",
  BILLING_MANAGER = "Billing manager",
  SECURITY_MANAGER = "Security manager",
  COLLABORATORS = "Outside Collaborator",
}

export type OrgRolesNames = keyof typeof OrgRoles;
export interface IssueOwner {
  name: string;
  email: string;
  username?: string;
}

export interface AccessLevel {
  repo: Repo;
  lastActivity: string;
  lastActivityDays: number;
  accessLevel: string[];
  role: UserRole;
}

export class CweObject {
  shortName: string = "N/A";
  name: string = "";
  description: string = "";
  url: string = "";
}

export class GitHubRequest {
  query: any;
  maxPage: number;
  shouldBeCached: boolean = true;
}

export class GitlabRequest {
  query: any;
  page: number = 1;
  maxPage: number;
  shouldBeCached: boolean = true;
  perPage?: number;
}

export interface PipelineScanInfo {
  // branch of the repository to scan
  sourceBranch: Nullable<string>;
  // in case of pull requests, branch of the repository to merge into (compare against)
  targetBranch: Nullable<string>;
  // commit sha on the branch in case of branch scan
  sha: Nullable<string>;
  // commit sha to compare against in case of branch scan
  baseSha: Nullable<string>;
}

export declare namespace NormalizedData {
  export interface MergeRequest {
    state: string; //"merged"
    created_at: string;
    merged_by: string;
    author: string;
    reviewers: string[];
    sha: string;
    merge_commit_sha: string;
    web_url: string;
    source_branch: string;
    target_branch: string;
  }
}

export class SpecialFile {
  name: string;
  file: File;
  isEmpty: boolean;
  isValid: boolean;
  isInValidDir: boolean;
}

export interface GitInfoJSON {
  headSha: string | null;
  commitCount: number;
  commits: GitCommit[];
}

interface DevLanguage {
  language: string;
  languagePercentage: number;
}

export interface RepositoryInfo {
  size: number; // in bytes
  gitSize: number; // in bytes
  codeSize: number; // in bytes
  repoHistorySize: number;
  devLanguages: DevLanguage[];
  filesWithLanguages: FileWithLanguage[];
  kubernetesFiles: KubernetesFile[]; // no link
  orchestratorFiles: OrchestratorFile[]; // no link
}

export interface FileWithLanguage {
  filePath: string;
  language: string | null;
}

export interface RepositoryInfoJSON {
  repoInfo: RepositoryInfo; // file info for root repo
  isMonoRepo: boolean;
  repoInfoPerMonorepoChild: {
    repoInfo: RepositoryInfo;
    monoRepoChild: string;
  }[]; // empty array if isMonoRepo: false
  repoInfoForOrphanedFiles: RepositoryInfo | null;
}

export interface RepoImportanceRes {
  repo_name: string;
  repo_creation_date: string;
  repo_creator: string;
  number_of_files: number;
  repo_size_bytes: number;
  main_branch_name: string;
  numberOfcommits: number;
  codeChanges: number;
  commit_count: number;
  pushCount: number;
  pullCount: number;
  num_of_unique_user_with_commits: number;
  lastCodeChange: string;
  tag_count: number;
  yaml_count: number;
  branch_count: number;
  public_repo: boolean;
  extendedInfo: {
    version: string;
    forks_count: number;
    has_downloads: boolean;
    watchers_count: number;
  };
  irrelevantReasons: any[];
}

export interface RepoImportanceInfo {
  numberOfcommits: number;
  codeChanges: number;
  uniqueCommits: number;
  lastCodeChange: string;
  numberOfPushes: number;
  numberOfPullRequests: number;
  numberOfUniqueCodeChangesByDate: number;
  numberOfMerges: number;
  numberOfLanguageFiles: number;
  branches: number;
  numberOfTags: number;
  numberOfYMLs: number;
  numberOfFiles: number;
  mainBranch: string;
  size: number;
  creator: string;
  createdAt: string;
  gitIgnore: {
    exist: boolean;
    lines: number;
  };
  readMe: boolean;
  securityMD: boolean;
  license: boolean;
  isPrivate: boolean;
  extendedInfo: RepoImportanceRes["extendedInfo"];
}

export interface RepoImportance {
  res: RepoImportanceRes;
  total: number;
  info: RepoImportanceInfo;
  originalBp?: number;
}
