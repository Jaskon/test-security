export declare namespace AWS {
  export namespace Attributes {
    export interface CommonCloudAttributes {
      registeredAt: Date;
      registeredBy?: string;
      account?: string;
      zone?: string;
    }

    export interface ECS extends CommonCloudAttributes {
      os: string;
      cpu: string;
      memory: string;
      containers: string;
    }

    export interface Lambda extends CommonCloudAttributes {
      runtime: string;
      handler: string;
      size: string;
    }
  }
}
