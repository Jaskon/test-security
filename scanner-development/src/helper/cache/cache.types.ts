import mongoose from "mongoose";
import { ApiSecurityItemSchema, IssueAttackPathSchema } from "../../mongo/schemas";
import {
  CachedArtifactSchema,
  CachedComplianceSchema,
  ExtendedSbomSchema,
  InfectedRepoSchema,
  SbomSchema,
  SecurityEventSchema,
} from "./cache.model";

export enum Cache {
  Artifacts = "cached-artifacts",
  SecurityEvents = "cached-security-events",
  Sbom = "cached-sboms",
  ExtendedSbom = "cached-extended-sboms",
  InfectedRepo = "cached-infected-repos",
  Compliance = "cached-compliance",
  apiSecurityEvents = "cached-api-sec-events",
  issueAttackPath = "cached-issue-attack-path",
}

export const schemas: Record<Cache, mongoose.Schema> = {
  [Cache.Artifacts]: CachedArtifactSchema,
  [Cache.SecurityEvents]: SecurityEventSchema,
  [Cache.Sbom]: SbomSchema,
  [Cache.ExtendedSbom]: ExtendedSbomSchema,
  [Cache.InfectedRepo]: InfectedRepoSchema,
  [Cache.Compliance]: CachedComplianceSchema,
  [Cache.apiSecurityEvents]: ApiSecurityItemSchema,
  [Cache.issueAttackPath]: IssueAttackPathSchema,
};

export interface InfectedRepo {
  repoId: string;
  securityEvents?: boolean;
  sboms?: boolean;
  pulls?: boolean;
}

export type InfectedRepoFilter = Omit<InfectedRepo, "repoId">;
