import { CodeRepoTypes } from "./codeRepoTypes";

export class CicdTool {
  name: string;
  regex: RegExp;

  constructor(name: string, regex: string) {
    if (name === "" || regex === "") {
      throw `err: constructor, CicdTool name: ${name}, regex: ${regex} are empty`;
    }

    this.name = name;
    this.regex = new RegExp(regex, "i");
  }
}

export class OrgCicdTool {
  objType: CodeRepoTypes;
  name: string;
  active: boolean;
  htmlUrl: string;
  resouceName: string;
  additionalInfo: any;

  constructor(objType: CodeRepoTypes, name: string, active: boolean, htmlUrl: string, additionalInfo: any, resouceName: string) {
    this.objType = objType == null ? CodeRepoTypes.Unknown : objType;
    this.name = name == null ? "" : name;
    this.htmlUrl = htmlUrl == null ? "" : htmlUrl;
    this.additionalInfo = additionalInfo == null ? {} : additionalInfo;
    this.active = active == null ? false : active;
    this.resouceName = resouceName;
  }
}

export enum CicdRepoTypes {
  Unknown,
  repositories,
  jobs,
}

export enum RepoType {
  GIT = "git",
  TFS = "tfs",
}

export class AzureCI {
  branch: string;
  isMaster: boolean;
  repoName: string;
  repoId: string;
  type: RepoType;
  tfsSubFolder: string;
  linkToBuild: string;
  reason: string;
  startTime: string;
  requestedBy: string;
  requestedByMail: string;
  project: string;
  buildNumber: string;
}
