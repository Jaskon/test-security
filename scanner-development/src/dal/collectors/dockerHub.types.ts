/**
 * https://docs.docker.com/docker-hub/api/latest/#tag/repositories/paths/~1v2~1namespaces~1%7Bnamespace%7D~1repositories~1%7Brepository%7D~1tags/get
 */

export interface ListTagsResponse {
  /**
   * total number of results available across all pages
   */
  count: number;
  /**
   * link to next page of results if any
   */
  next?: string;
  /**
   * link to previous page of results if any
   */
  previous?: string;
  results: ListTagsResult[];
}

export interface ListTagsResult {
  /**
   * tag ID
   */
  id: number;

  images: Image[];
  /**
   * ID of the user that pushed the tag
   */
  creator: number;
  /**
   * datetime of last update
   */
  last_updated?: string;
  /**
   * ID of the last user that updated the tag
   */
  last_updater: number;
  /**
   * Hub username of the user that updated the tag
   */
  last_updater_username: string;
  /**
   * name of the tag
   */
  name: string;
  /**
   * repository ID
   */
  repository: number;
  /**
   * compressed size (sum of all layers) of the tagged image
   */
  full_size: number;

  media_type: string;
  /**
   * repository API version
   */
  v2: string;
  /**
   * whether a tag has been pushed to or pulled in the past month
   */
  status: "active" | "inactive";
  /**
   * datetime of last pull
   */
  tag_last_pulled?: string;
  /**
   * datetime of last push
   */
  tag_last_pushed?: string;
}

export interface Layer {
  /**
   * image layer digest
   */
  digest?: string;
  /**
   * size of the layer
   */
  size: number;
  /**
   * Dockerfile instruction
   */
  instruction: string;
}

export interface Image {
  /**
   * CPU architecture
   */
  architecture: string;
  /**
   * CPU features
   */
  features: string;
  /**
   * CPU variant
   */
  variant: string;
  /**
   * image digest
   */
  digest?: string;

  layers: Layer[];
  /**
   * operating system
   */
  os: string;
  /**
   * OS features
   */
  os_features: string;
  /**
   * OS version
   */
  os_version: string;
  /**
   * size of the image
   */
  size: number;
  /**
   * Status of the image
   */
  status: "active" | "inactive";
  /**
   * datetime of last pull
   */
  last_pulled?: string;
  /**
   * datetime of last push
   */
  last_pushed?: string;
}
