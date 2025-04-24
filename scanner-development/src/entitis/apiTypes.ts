import { SeveritiesObject } from "../policy/reporting/types";

export class Parameter {
  description: string;
  in: string;
  name: string;
  required: boolean;
}

export class ApiSecurityItemResponse {
  description: string;
  code: string;
}

export enum ApiSecurityItemSource {
  code = "code",
  codeOpenApi = "code_open_api",
}

export enum Frameworks {
  expressJS = "ExpressJS",
  flask = "Flask",
  django = "Django",
  fastapi = "FastAPI",
  springBoot = "SpringBoot",
  gin = "Gin",
  nestJS = "NestJS",
  koa = "Koa",
}

export enum httpMethods {
  get = "get",
  post = "post",
  put = "put",
  patch = "patch",
  delete = "delete",
  head = "head",
  options = "options",
  trace = "trace",
  connect = "connect",
}

export class ApiSecurityItemDef {
  fileName: string;
  line: string;
  source: ApiSecurityItemSource;
  snippet: String;
  link: string;
  llmTitle: string;
  llmDescription: string;
  functions: ApiSecurityItemFunction[] = [];
}

export class ApiSecurityItemFunction {
  function: string;
  line: number;
  snippet: string;
  filepath: string;
  link: string;
}

export class ApiSecurityItem {
  scanId: string;
  title: string;
  description: string;
  version: string;
  openapi: string;
  servers: string[] = [];
  epName: string;
  methodName: string | undefined;
  methodDescription: string;
  methodOperationId: string;
  methodResponses: ApiSecurityItemResponse[] = [];
  methodSummary: string;
  methodTags: string[] = [];
  methodParameters: Parameter[] = [];
  appId: string;
  appType: string;
  appName: string;
  appLink: string;
  fileName: string[] = [];
  framework: string;
  firstSeen: Date;
  definitions: ApiSecurityItemDef[] = [];
  uuid: string;
  issuesBySeverity: SeveritiesObject;
}
