import mongoose from "mongoose";
import { Edge, Node } from "../helper/graphHelper";
import { DependencyGraphEdgeSchema, DependencyGraphNodeSchema } from "./schemas";

export interface DependencyGraph {
  appId: string;
  scanId: string;
  libName: string;
  libVersion: string;
  libForSearch: string;

  nodes: Node[];
  edges: Edge[];
}

export const DependencyGraphSchema = new mongoose.Schema<DependencyGraph>(
  {
    appId: { type: String },
    scanId: { type: String },
    libName: { type: String },
    libVersion: { type: String },
    libForSearch: { type: String },

    nodes: [DependencyGraphNodeSchema],
    edges: [DependencyGraphEdgeSchema],
  },
  { timestamps: true },
);

DependencyGraphSchema.index({ scanId: 1 });
DependencyGraphSchema.index({ scanId: 1, appId: 1, libForSearch: 1 });
DependencyGraphSchema.index({ appId: 1, libForSearch: 1 });
