export interface DockerHubInfo {
  id: string; //Image name
  active: boolean;
  pull_count: number;
  star_count: number;
  namespace: string;
  badge: string;
  source: string;
  dockerHubManifestSha: string;
  dockerHubManifestImagePushDate: string;
  last_updated: string;
  last_updater: number;
  last_updater_username: string;
}

export interface DockerhubRequest {
  imageName: string;
  imageTag: string;
  imageArchitecture: string;
}
