import loggerImport from "../../logger";
import MongoConnect from "../mongoConnect";
import MongoModel from "../mongoModel";
import { ArtifactScreenSchema } from "./ArtifactScreen.schema";
import { Artifact } from "./types/artifact-screen";

const logger = loggerImport.getDebugLogger();

export class ArtifactScreenService {
  private readonly artifactScreenMongoModel: MongoModel<Artifact>;

  constructor(orgId: string, scanId: string, private readonly mongoConnect: MongoConnect) {
    this.artifactScreenMongoModel = new MongoModel(
      "artifact-screen",
      [{ schemaName: "artifact-screen", schema: ArtifactScreenSchema }],
      orgId,
      scanId,
      null,
      true,
    );
  }

  async setArtifactScreen(artifacts: Artifact[]): Promise<void> {
    if (!artifacts.length) {
      return;
    }
    try {
      await this.artifactScreenMongoModel.verifyConnection(this.mongoConnect);
      const bulkInsert = this.artifactScreenMongoModel.model.collection.initializeUnorderedBulkOp();
      for (const artifact of artifacts) {
        bulkInsert
          .find({ id: artifact.id })
          .upsert()
          .updateOne({ $set: { ...artifact } });
      }
      await bulkInsert.execute();
      logger.info(`Saved artifacts to artifact-screen`);
    } catch (error) {
      logger.error(`failed to set artifacts to artifact-screen:`, error);
    }
  }
}
