import MongoConnect from "../../mongoConnect";
import { SbomModel } from "../model/sbom.model";
import { SbomMongoDocument } from "../types";

export class SbomService {
  private readonly sbomModel: SbomModel;
  constructor(orgId: string, scanId: string, mongoConnect: MongoConnect) {
    this.sbomModel = new SbomModel(orgId, scanId, mongoConnect);
  }

  async addSboms(sboms: SbomMongoDocument[]) {
    return await this.sbomModel.addSboms(sboms);
  }

  async getSbomsByAppId(appId: string, appName: string) {
    return await this.sbomModel.getSbomsByAppId(appId, appName);
  }

  async removeOldSboms() {
    return await this.sbomModel.removeOldSboms();
  }
}
