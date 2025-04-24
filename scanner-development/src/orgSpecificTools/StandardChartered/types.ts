import { Repo } from "../../entitis/codeRepoTypes";

export type ToolType = "kong" | "solace" | "generic";

export interface ToolDefinition {
  metadata: {
    type: ToolType;
    version: string;
    lastUploadDate?: string;
    target: string[];
    runs: ToolCommand[];
  };
  policy_file: string;
  ignore_file: string;
}

export interface ToolCommand {
  command: string;
  arguments: string;
  sarif: string;
}

export type InterceptResource = KongResource | SolaceResource | GenericResource;

export interface KongResource {
  type: "kong";
  name: string;
  url: string;
  token: string;
}

export interface SolaceResource {
  type: "solace";
  name: string;
  username: string;
  password: string;
}

export interface GenericResource {
  type: "generic";
  name: string;
  repo: Repo;
}
