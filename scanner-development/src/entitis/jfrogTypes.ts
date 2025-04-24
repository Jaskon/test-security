export interface JFrogRepo {
  repo: string;
  path: string;
  created: string;
  lastModified: string;
  lastUpdated: string;
  children: Child[];
  uri: string;
}

export interface Child {
  uri: string;
  folder: boolean;
}
