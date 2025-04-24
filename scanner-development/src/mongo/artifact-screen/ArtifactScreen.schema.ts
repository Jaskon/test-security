import mongoose from "mongoose";
import {
  ApplicationDescription,
  Artifact,
  ArtifactInfo,
  ArtifactRegistryDescription,
  CICDArtifactDescription,
  CloudArtifactData,
  CloudDescription,
  CodeArtifactDescription,
  FileChanged,
  FilterScreenData,
  IssueSummary,
  PipelineExecution,
  ToolInfo,
} from "./types/artifact-screen";

const IssueSeveritiesSchema = new mongoose.Schema<IssueSummary["severities"]>({
  info: Number,
  low: Number,
  medium: Number,
  high: Number,
  critical: Number,
  appox: Number,
});

const ArtifactInfoSchema = new mongoose.Schema<ArtifactInfo>({
  type: String,
  name: String,
  version: String,
  hash: String,
  size: String,
});

const ToolInfoSchema = new mongoose.Schema<ToolInfo>({
  toolName: String,
  name: [String],
  total: Number,
  category: String,
  criticality: Number,
});

const FileChangedSchema = new mongoose.Schema<FileChanged>({
  fileName: String,
  change: String,
});

const CodeArtifactDescriptionSchema = new mongoose.Schema<CodeArtifactDescription>({
  scm: String,
  commit: String,
  commitLink: String,
  mergeLink: String,
  prDate: Date,
  prOwner: String,
  prApprovals: [String],
  prReviewers: [String],
  fileChanged: [FileChangedSchema],
  isPublic: Boolean,
  sourceBranch: String,
  destinationBranch: String,
});

const PipelineExecutionSchema = new mongoose.Schema<PipelineExecution>({
  link: String,
  pipelineName: String,
  pipelineId: String,
  pushType: String,
  executedBy: String,
  createTime: Date,
  updateTime: Date,
  status: String,
  intermediateRegistryLink: [String],
});

const ArtifactRegistryDescriptionSchema = new mongoose.Schema<ArtifactRegistryDescription>({
  type: String,
  name: String,
  project: String,
  link: String,
  hash: String,
  tags: [String],
  username: String,
  userType: String,
  uploadTime: Date,
  lastUpdate: Date,
  buildTime: Date,
  isPublic: Boolean,
});

const CloudDescriptionSchema = new mongoose.Schema<CloudDescription>({
  type: String,
  subType: String,
  cloudEntityAttributes: mongoose.Schema.Types.Mixed,
});

const CloudArtifactDataSchema = new mongoose.Schema<CloudArtifactData>({
  cloudIdentifier: String,
  environment: String,
  link: String,
  lastExecutionTime: Date,
  lastModifiedTime: Date,
  account: String,
  zone: String,
  cloudDescription: CloudDescriptionSchema,
});

const IssueSummarySchema = new mongoose.Schema<IssueSummary>({
  catId: Number,
  severities: IssueSeveritiesSchema,
});

const FilterScreenDataSchema = new mongoose.Schema<FilterScreenData>({
  lastExecutionTime: Date,
  inProduction: Boolean,
  deployed: Boolean,
  highSeverityIssues: Number,
  lastVersion: Boolean,
});

const ApplicationDescriptionSchema = new mongoose.Schema<ApplicationDescription>({
  appType: String,
  appName: String,
  appId: String,
  businessPriority: Number,
  appFlow: Object,
  toolsInfo: [ToolInfoSchema],
});

const CICDArtifactDescriptionSchema = new mongoose.Schema<CICDArtifactDescription>({
  id: String,
  type: String,
  pipeline: Object,
  pipelineExecution: PipelineExecutionSchema,
});

export const ArtifactScreenSchema = new mongoose.Schema<Artifact>(
  {
    id: String,
    collectedAt: Date,
    scanId: String,
    artifactInfo: ArtifactInfoSchema,
    appDescription: ApplicationDescriptionSchema,
    categories: [IssueSummarySchema],
    codeDescription: CodeArtifactDescriptionSchema,
    cicdDescription: CICDArtifactDescriptionSchema,
    pipelineInfo: Object,
    registryDescription: [ArtifactRegistryDescriptionSchema],
    cloudData: [CloudArtifactDataSchema],
    filterScreenData: FilterScreenDataSchema,
    secretIssues: [String],
    confIssues: [String],
    vulnDepIssues: [String],
    vulnDepBaseIssues: [String],
    vulnDepInstructionIssues: [String],
  },
  { timestamps: true },
);

ArtifactScreenSchema.index({ id: 1 }, { unique: true });
ArtifactScreenSchema.index({ "appDescription.appId": 1 });
ArtifactScreenSchema.index({ "artifactInfo.name": 1 });
ArtifactScreenSchema.index({ "cicdDescription.pipelineExecution.createTime": 1 });
ArtifactScreenSchema.index({ "cloudData.lastExecutionTime": 1 });
ArtifactScreenSchema.index({ "cloudData.lastModifiedTime": 1 });
