import mongoose from "mongoose";

export interface CveTool {
  appName: string;
  cve: string;
  pkgName: string;
  pkgVersion: string;
  alertType: string;
  tools: string[];
  toolsCategories: string[];
  isOs: boolean;
  filePaths: string[];
  pkgManagers: string[];
  dependencyTypes: string[];
  severities: string[];
}

export const CveToolSchema = new mongoose.Schema<CveTool>({
  appName: { type: String },
  cve: { type: String },
  tools: [{ type: String }],
  pkgName: { type: String },
  pkgVersion: { type: String },
  alertType: { type: String },
  toolsCategories: [{ type: String }],
  isOs: { type: Boolean },
  filePaths: [{ type: String }],
  pkgManagers: [{ type: String }],
  dependencyTypes: [{ type: String }],
  severities: [{ type: String }],
});

export interface CveTools {
  scanId: string;
  appName: string;
  cveTools: CveTool[];
  totalCveTools: number;
}

export const CveToolsSchema = new mongoose.Schema<CveTools>(
  { scanId: { type: String }, appName: { type: String }, cveTools: [CveToolSchema], totalCveTools: { type: Number } },
  { timestamps: true },
);
CveToolsSchema.index({ scanId: 1 });
