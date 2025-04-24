import mongoose from "mongoose";

export enum MatchMethod {
  Manual = "manual",
  Cicd = "cicd",
  Name = "name",
  PackageJson = "packageJson",
  FileNames = "fileNames",
  Dockerfile = "dockerfile",
}

export interface ArtifactRepository {
  registry: string;
  name: string;
  cloudEnv: string;
  link: string;
  location: string;
  region: string;
  matchedApp?: {
    id: string;
    name: string;
    dockerfilePath?: string;
    method: MatchMethod;
  };
}

export const ArtifactRepositorySchema = new mongoose.Schema<ArtifactRepository>(
  {
    registry: { type: String },
    name: { type: String },
    cloudEnv: { type: String },
    link: { type: String },
    location: { type: String },
    region: { type: String },
    matchedApp: {
      id: { type: String, required: true },
      name: { type: String, required: true },
      dockerfilePath: { type: String, required: false },
      method: { type: String, enum: Object.values(MatchMethod), required: true },
    },
  },
  { timestamps: true },
);

ArtifactRepositorySchema.index({ registry: 1, name: 1 });
