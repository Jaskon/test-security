import { SecurityAlertType } from "../codeRepoTypes";

export interface Synk {
  results: Result[];
  total: number;
}

export interface Result {
  issue: Issue;
  isFixed: boolean;
  introducedDate: string;
  project: Project;
}

export interface Issue {
  url: string;
  id: string;
  title: string;
  type: IssueType;
  package: string;
  version: string;
  severity: Severity;
  originalSeverity: null;
  uniqueSeveritiesList: Severity[];
  language: string;
  packageManager: string;
  semver: Semver;
  isIgnored: boolean;
  publicationTime?: string;
  disclosureTime?: string;
  isUpgradable?: boolean;
  isPatchable?: boolean;
  isPinnable?: boolean;
  identifiers?: { [key: string]: string[] };
  credit?: string[];
  CVSSv3?: string;
  cvssScore?: string;
  patches?: any[];
  isPatched?: boolean;
  exploitMaturity?: string;
  reachability?: string;
  priorityScore?: number;
  jiraIssueUrl: null;
  cloudConfigPath?: string;
}

export enum Severity {
  Info = "info",
  High = "high",
  Low = "low",
  Medium = "medium",
  Critcal = "critcal",
}
export interface Semver {
  vulnerable: string[];
}
Severity;

export enum IssueType {
  Vuln = "vuln",
  License = "license",
  Configuration = "configuration",
}

export interface Project {
  url: string;
  id: string;
  name: string;
  source: string;
  packageManager: string;
  targetFile?: string;
}

export interface Org {
  id: string;
  name: string;
  slug: string;
  url: string;
  group: Group;
  created: string;
}

export interface Group {
  name: string;
  id: string;
}

export interface GetUserOrgsResponse {
  orgs: Org[];
}

export interface ProjectInfo {
  jsonapi: Jsonapi;
  data: Daum[];
  links: any;
}

export interface Jsonapi {
  version: string;
}

export interface Daum {
  type: string;
  id: string;
  attributes: Attributes;
  relationships: any;
}

export interface Attributes {
  name: string;
  created: string;
  origin: string;
  type: string;
  status: string;
  targetReference: string;
  businessCriticality: any[];
  lifecycle: any[];
  environment: any[];
  tags: any[];
}

export interface orgIds {
  data: Daum[];
  jsonapi: Jsonapi;
  links: Links;
}

export interface Daum {
  attributes: Attributes;
  id: string;
  type: string;
}

export interface Attributes {
  group_id: string;
  is_personal: boolean;
  name: string;
  slug: string;
}

export interface Jsonapi {
  version: string;
}

export interface Links {
  prev: string;
}

export interface SastIssue {
  jsonapi: Jsonapi;
  data: Issues[];
  links: any;
}

export interface Jsonapi {
  version: string;
}

export interface Issues {
  type: string;
  id: string;
  attributes: Attributes;
  links: Links;
}

export interface Attributes {
  issueType: string;
  title: string;
  severity: string;
  ignored: boolean;
  cwe: string[];
}

export interface IssueDetails {
  jsonapi: any;
  data: Data;
}
export interface Data {
  type: string;
  id: string;
  attributes: Attributes;
}

export interface Attributes {
  issueType: string;
  title: string;
  severity: string;
  cwe: string[];
  ignored: boolean;
  fingerprint: string;
  fingerprintVersion: string;
  primaryRegion: PrimaryRegion;
  priorityScore: number;
  priorityScoreFactors: string[];
  primaryFilePath: string;
}

export interface PrimaryRegion {
  endLine: number;
  endColumn: number;
  startLine: number;
  startColumn: number;
}

export interface orgsAndProjects {
  OrgId: string;
  ProjectIds: string[];
}

export interface ProjectDetails {
  data: Data;
  jsonapi: Jsonapi;
  links: Links5;
}

export interface Data {
  attributes: Attributes;
  id: string;
  relationships: Relationships;
  type: string;
}

export interface Attributes {
  business_criticality: string[];
  created: string;
  environment: any[];
  lifecycle: any[];
  name: string;
  origin: string;
  read_only: boolean;
  status: string;
  tags: any[];
  target_reference: string;
  type: string;
}

export interface Tag {
  key: string;
  value: string;
}

export interface Relationships {
  importing_user: ImportingUser;
  org: Org;
  owner: Owner;
  target: Target;
}

export interface ImportingUser {
  data: Data2;
  links: Links;
}

export interface Data2 {
  id: string;
  type: string;
}

export interface Links {
  related: Related;
}

export interface Related {
  href: string;
}

export interface Org {
  data: Data3;
  links: Links2;
}

export interface Data3 {
  id: string;
  type: string;
}

export interface Links2 {
  related: Related2;
}

export interface Related2 {
  href: string;
}

export interface Owner {
  data: Data4;
  links: Links3;
}

export interface Data4 {
  id: string;
  type: string;
}

export interface Links3 {
  related: Related3;
}

export interface Related3 {
  href: string;
}

export interface Target {
  data: Data5;
  links: Links4;
}

export interface Data5 {
  id: string;
  type: string;
}

export interface Links4 {
  related: Related4;
}

export interface Related4 {
  href: string;
}

export interface Jsonapi {
  version: string;
}

export interface Links5 {
  first: string;
  last: string;
  next: string;
  prev: string;
  related: string;
  self: string;
}
