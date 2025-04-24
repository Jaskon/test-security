export class SetPipelineDataInput {
  pipelineJobId: string;
  pipelineJobTriggeredAt: string;
  pipelineJobUrl?: string;
  pipelineIssuesCount: number;
  pipelineScanResult: PipelineScanResult;
  pipelineJobTriggeredBy?: string;
}

export enum PipelineScanResult {
  none = "none",
  monitor = "monitor",
  block = "block",
}

export interface SetPipelineDataRes {
  setPipelineData: {
    appId: string;
    acknowledged: boolean;
  };
}
