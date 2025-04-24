import { AppToolCoverageSource } from "../../policy/reporting/types";
import { CodeRepoTypes } from "../codeRepoTypes";

export enum SecurityToolType {
  unknown,
  SAST,
  SCA,
  Container,
  Secrets,
  IaC,
  Cspm,
}

export class SecurityTool {
  name: string;
  connectorName: string;
  regex: RegExp;
  regexFilePath: RegExp;
  product: string;
  sastLanguages: string[];
  scaLanguages: string[];
  containerFiles: string[];
  type: string[];
  oxDelivered: boolean;

  constructor(
    name: string,
    connectorName: string,
    regex: string,
    regexFilePath: string,
    product: string,
    sastLanguages: string[],
    scaLanguages: string[],
    containerFiles: string[],
    type: string[],
    oxDelivered: boolean,
  ) {
    this.name = name;
    this.connectorName = connectorName;
    this.regex = new RegExp(regex, "i");
    this.regexFilePath = regexFilePath ? new RegExp(regexFilePath, "i") : null;
    this.product = product;
    this.sastLanguages = sastLanguages;
    this.scaLanguages = scaLanguages;
    this.containerFiles = containerFiles;
    this.type = type.map(i => i.toLowerCase());
    this.oxDelivered = oxDelivered;

    if (name === "" || regex === "") {
      throw `err: constructor, SecurityVendorsTool name: ${name}, regex: ${regex} are empty`;
    }
    if (
      sastLanguages.length === 0 &&
      scaLanguages.length === 0 &&
      containerFiles.length === 0 &&
      !this.type.includes("artifactory") &&
      !this.type.includes("iac") &&
      !this.type.includes("sbom") &&
      !this.type.includes("cspm") &&
      !this.type.includes("secrets")
    ) {
      throw `err: constructor, SecurityVendorsTool name: ${name}, regex: ${regex} all data are empty empty`;
    }
    if (type.length == 0) {
      throw `err: constructor, SecurityVendorsTool name: ${name}, regex: ${regex} type is empty empty`;
    }
  }
}

export class OrgSecurityTool {
  objType: CodeRepoTypes;
  name: string;
  active: boolean;
  htmlUrl: string;
  securityTool: SecurityTool;
  additionalInfo: any;

  constructor(objType: CodeRepoTypes, name: string, active: boolean, htmlUrl: string, securityTool: SecurityTool, additionalInfo: any) {
    this.objType = objType == null ? CodeRepoTypes.Unknown : objType;
    this.securityTool = securityTool;
    this.name = name == null ? "" : name;
    this.htmlUrl = htmlUrl == null ? "" : htmlUrl;
    this.additionalInfo = additionalInfo == null ? {} : additionalInfo;
    this.active = active == null ? false : active;
  }
}
