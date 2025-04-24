export class OpenWikiTypesRequest {
  uid: string;
  analysisUid: string;
  orgId: string;
  repoUrl: string;
  repoName: string;
  sourceControl: string;
  repoId: string;
}

export class OpenWikiTypesResponse {
  uid: string;
  repoName: string;
  isOpen: boolean;
  isSuccess: boolean;
}
