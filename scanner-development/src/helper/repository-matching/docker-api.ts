import { gql, GraphQLClient } from "graphql-request";
import { setTimeout } from "node:timers/promises";
import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();

export class DockerApi {
  private static _instance: DockerApi;
  private readonly dockerApi = new GraphQLClient("https://api.dso.docker.com/v1/graphql");

  static get instance(): DockerApi {
    if (!this._instance) {
      this._instance = new DockerApi();
    }
    return this._instance;
  }

  async getBaseImage(diffIds: string[]): Promise<BaseImage | undefined> {
    const response = await this.queryApi(diffIds);
    const imageMatch = response.imagesByDiffIds.pop();
    if (!imageMatch) {
      logger.info(`[${DockerApi.name}] No base image found`);
      return undefined;
    }
    const firstImage = imageMatch.images.pop();
    const tag = firstImage.tags?.filter(tag => tag.current).map(tag => tag.name)?.[0] || firstImage.tags?.map(tag => tag.name)?.[0];
    const tags = firstImage.tags?.map(({ name, current }) => ({ name, current }));
    logger.info(
      `[${DockerApi.name}] Found base image: ${firstImage?.repository.repoName}, with possible tags: ${tags
        ?.map(tag => tag.name)
        .join(", ")}`,
    );
    return { repo: firstImage.repository.repoName, digest: firstImage.digest, layers: new Set(imageMatch.matches), tag, tags };
  }

  private async queryApi(diffIds: string[], retries = 3): Promise<ImagesByDiffIdsResponse> {
    try {
      const response = await this.dockerApi.request<ImagesByDiffIdsResponse>(ImagesByDiffIdsQuery, {
        diffIds,
      });
      return response;
    } catch (err) {
      logger.info(`Docker API failed to fetch base image (${retries} left)`);
      if (retries > 0) {
        await setTimeout(30000); // Sleep some time
        return await this.queryApi(diffIds, retries - 1);
      } else {
        logger.error(`Docker API failed to fetch base image (${retries} left)`, err);
      }
    }
  }
}

const ImagesByDiffIdsQuery = gql`
  query ImagesByDiffIds($diffIds: [ID!]!) {
    imagesByDiffIds(context: {}, diffIds: $diffIds) {
      matches
      images {
        tags {
          current
          name
        }
        repository {
          repoName
        }
        digest
      }
    }
  }
`;

interface ImagesByDiffIdsResponse {
  imagesByDiffIds: ImageMatch[];
}

interface ImageMatch {
  matches: string[];
  images: Image[];
}

interface Image {
  repository: {
    repoName: string;
  };
  digest: string;
  tags?: {
    current: boolean;
    name: string;
  }[];
}

export interface BaseImage {
  repo?: string;
  digest?: string;
  layers: Set<string>;
  tag: string;
  tags: Array<{ name: string; current: boolean }>;
}
