import { ImageDetail } from "../entitis/cloudTypes";
import loggerImport from "../logger";
import { ArtifactRepository, ArtifactRepositorySchema } from "./ArtifactRepository.schema";
import MongoConnect from "./mongoConnect";
import MongoModel from "./mongoModel";

const logger = loggerImport.getDebugLogger();

export class ArtifactRepositoryService {
  private readonly artifactRepositoryMongoModel: MongoModel<ArtifactRepository>;

  constructor(orgId: string, scanId: string, private readonly mongoConnect: MongoConnect) {
    this.artifactRepositoryMongoModel = new MongoModel(
      "artifact-repositories",
      [{ schemaName: "artifact-repositories", schema: ArtifactRepositorySchema }],
      orgId,
      scanId,
    );
  }

  async getArtifactRepositoryByName({ name, repositoryName: registry, cloudEnv }: ImageDetail): Promise<ArtifactRepository | null> {
    try {
      await this.artifactRepositoryMongoModel.verifyConnection(this.mongoConnect);
      const artifactRepository = await this.artifactRepositoryMongoModel.model.findOne({ name, registry, cloudEnv }, null, { lean: true });
      return artifactRepository;
    } catch (err) {
      logger.error(`failed to fetch artifact repository ${name}: ${err}`, err);
      return null;
    }
  }

  async setArtifactRepository(artifactRepository: ArtifactRepository): Promise<void> {
    try {
      await this.artifactRepositoryMongoModel.verifyConnection(this.mongoConnect);
      await this.artifactRepositoryMongoModel.model.updateOne(
        { name: artifactRepository.name, registry: artifactRepository.registry, cloudEnv: artifactRepository.cloudEnv },
        artifactRepository,
        { upsert: true },
      );
      logger.info(`Saved artifact repository: ${artifactRepository.name}`);
    } catch (err) {
      logger.error(`failed to set artifact repository: ${err}`, err);
    }
  }
}
