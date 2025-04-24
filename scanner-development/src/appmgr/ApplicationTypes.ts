export interface repositoryComponent {
  id: string; // represents the repo name
  values: {
    id: string;
    repo_name: string;
    repo_id: string;
    vcs_type: string;
    url: string;
    default_branch: string;
  }[];
}

export interface ciToolComponent {
  id: string; // represents the url
  values: {
    id: string; // represents the url
    reponame: string;
    username: string;
    vcs_type: string;
    default_branch: string;
    vcs_url: string;
    tool?: string;
  }[];
}

export interface ciJobComponent {
  id: string; // represents the repo name
  values: {
    id: string; // represents the repo name
    repo_name: string;
    result: string;
    subject: string;
    username: string;
    commit: string;
    defaultBranch: string;
    buildUrl: string;
    aritifactes: string[];
  }[];
}

export interface artifactComponent {
  id: string; // represents the build url
  values: {
    id: string; // represents the build url
    type: string;
    subType: string;
    name: string;
    size: string;
    hashType: string;
    hash: string;
    resolved: boolean;
    inputHash: string;
  }[];
}

export interface productArtifactComponent {
  id: string; // represents the image name
  values: {
    id: string; // represents the image name
    type: string;
    subType: string;
    name: string;
    size: string;
    hashType: string;
    hash: string;
    resolved: boolean;
    inputHash: string;
  }[];
}
