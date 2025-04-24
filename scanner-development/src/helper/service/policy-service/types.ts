export interface GetSelectedPoliciesForActiveProfile {
  getSelectedPoliciesForActiveProfile: {
    policies: Policy[];
  };
}

export interface Policy {
  usage: string;
  policyId: string;
  ruleId: string;
  exclusionCategory: string;
  name: string;
  categoryId: string;
  catId: number;
  system: string;
  description: string;
  detailedDescription: string;
  severity: number;
  selected: boolean;
  functionName: string;
  args: Arg[];
  resources: Resource[];
  isPipeline?: boolean;
  newIssuesPipelineOptionId?: PipelineOptionId;
  oldIssuesPipelineOptionId?: PipelineOptionId;
  countRule: CountRule;
  res: any;
  execType: string;
  displayIssueSeverity: number;
  ignoreMonoRepoChild?: boolean;
  oscarId: string[];
  cwe: string[];
  compliance?: ComplianceControl[];
  defaultSeverity?: number;
  dataRangeInDays?: number;
  ignoreResolve?: boolean;
}

export class ComplianceControl {
  control: string;
  description?: string;
  category?: string;
  standard?: string;
  controlLink?: string;
}

export enum PipelineOptionId {
  Block = "1",
  Monitor = "2",
  Disable = "3",
}

export interface Arg {
  id: string;
  name: string;
  label: string;
  tooltip: string;
  type: string;
  value: any;
  range?: any;
  multiSelect?: boolean;
  visible: boolean;
}
export class Input {
  type: string;
  name: string;
  minSelect: number = -1;
  maxSelect: number = -1;
  options: InputOption[] = [];
  multiSelect: boolean = false;
  displayName: string;
}

export class InputOption {
  name: string;
  displayName: string;
  info: string;
  selected: boolean = false;
  metadata: string = "";
  isDisabled?: boolean = false;
}

export class PolicyFix {
  settingType: string;
  tooltip: string;
  description: string;
  warning: string;
  confirmation: string;
  inputs: Input[] = [];
}

export enum CountRule {
  aggItems = "aggItems",
  scaVulnerabilities = "scaVulnerabilities",
  default = "default",
}

export interface Resource {
  id: string;
  name: string;
  type: string;
  global?: boolean;
}
