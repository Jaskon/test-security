export interface Globals {
  cicd: string[];
  securityTools: string[];
}

export class Resource {
  name: string;
  type: string;
  global: boolean;
}

export class Connector {
  type: string;
  scanSCA: boolean;
  scanSAST: boolean;
  scanSecrets: boolean;
  inclusions: any[];
}

export class OrgPolicy {
  orgName: string;
  globals: Globals;
  connectors: Connector[];
}
