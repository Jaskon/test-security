import StatesHelper from "../helper/statesHelper";
import loggerImport from "../logger";
import { DependencyGraph, DependencyGraphSchema } from "./DependencyGraph.schema";
import MongoConnect from "./mongoConnect";
import MongoModel from "./mongoModel";

const logger = loggerImport.getDebugLogger();

export class DependencyGraphService {
  private readonly MAX_NODE_SAVED = 500;
  private readonly depGraphMongoModel: MongoModel<DependencyGraph>;

  constructor(private readonly orgId: string, private readonly scanId: string, private readonly mongoConnect: MongoConnect) {
    this.depGraphMongoModel = new MongoModel(
      "dependency-graphs",
      [{ schemaName: "dependency-graphs", schema: DependencyGraphSchema }],
      orgId,
      scanId,
    );
  }

  async addGraphs(graphs: DependencyGraph[]): Promise<DependencyGraph[]> {
    if (!graphs.length) {
      return;
    }
    const chunks = this.chunkGraphs(graphs);
    for (const chunk of chunks) {
      try {
        await this.depGraphMongoModel.verifyConnection(this.mongoConnect);
        await this.depGraphMongoModel.insertMany(chunk, { rawResult: true, lean: true });
      } catch (err) {
        StatesHelper.Instance.scanInfoStats.mongoErrors++;
        logger.error(`failed to add dep graphs, error: ${err}, orgId: ${this.orgId}`, err);
      }
    }
  }

  async findGraphsExist(triggerPackages: string[]): Promise<Map<string, boolean>> {
    const graphsExistsMap = new Map<string, boolean>();
    try {
      await this.depGraphMongoModel.verifyConnection(this.mongoConnect);
      const results = await this.depGraphMongoModel.model.find({ libForSearch: { $in: triggerPackages } }, { libForSearch: 1 });
      results.reduce((acc, result) => {
        acc.set(result.libForSearch, true);
        return acc;
      }, graphsExistsMap);
    } catch (err) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to find dep graphs, error: ${err}, orgId: ${this.orgId}`);
    }
    return graphsExistsMap;
  }

  async removeOldGraphs(appId: string) {
    try {
      logger.info(`deleting old dep graphs, orgId: ${this.orgId}. scanId: ${this.scanId}`);
      await this.depGraphMongoModel.verifyConnection(this.mongoConnect);
      const res = await this.depGraphMongoModel.deleteMany({ scanId: { $ne: this.scanId }, appId });
      return res;
    } catch (e) {
      StatesHelper.Instance.scanInfoStats.mongoErrors++;
      logger.error(`failed to remove old dep graphs, error: ${e}, orgId: ${this.orgId}`);
    }
    return null;
  }

  private chunkGraphs(graphs: DependencyGraph[]): DependencyGraph[][] {
    const chunks: DependencyGraph[][] = [];
    let currentChunk = [];
    let currentChunkNodes = 0;
    for (const graph of graphs) {
      currentChunk.push(graph);
      currentChunkNodes += graph.nodes.length;
      if (currentChunkNodes >= this.MAX_NODE_SAVED) {
        chunks.push(currentChunk);
        currentChunk = [];
        currentChunkNodes = 0;
      }
    }
    if (currentChunk.length) {
      chunks.push(currentChunk);
    }
    return chunks;
  }
}
