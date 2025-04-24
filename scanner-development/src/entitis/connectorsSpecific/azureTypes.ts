export interface AzureRepo {
  name: string;
  repoId: string;
  organization: string;
}

export interface AzureProject {
  id: string;
  name: string;
  url: string;
  state: string;
  revision: number;
  visibility: string;
  lastUpdateTime: string;
}
