export interface CloneToSecondaryInput {
  orgId: string;
  scanId: string;
}

export interface CloneToSecondaryRes {
  cloneToSecondary: {
    scanId?: string;
    db?: string;
  };
}
