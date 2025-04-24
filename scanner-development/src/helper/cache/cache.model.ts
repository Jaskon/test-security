import mongoose from "mongoose";
import { PullRequest, SecurityEvent } from "../../entitis/codeRepoTypes";
import { AlertRecommendationResponse } from "../../entitis/service/alertrRcommendationTypes";
import { AutoFixResponse } from "../../entitis/service/autoFixTypes";
import { BlameResponse, ChangeReason } from "../../entitis/service/blameTypes";
import { IacValidatorTypesResponse } from "../../entitis/service/iacValidatorTypes";
import { ScaValidatorTypesResponse } from "../../entitis/service/scaValidatorTypes";

const BlameResponseSchema = new mongoose.Schema({}, { strict: false });
const ChangeReasonSchema = new mongoose.Schema({}, { strict: false });
const AutoFixResponseSchema = new mongoose.Schema({}, { strict: false });
const ScaValidatorTypesResponseSchema = new mongoose.Schema({}, { strict: false });
const AlertRecommendationResponseSchema = new mongoose.Schema({}, { strict: false });
const IacValidatorTypesResponseSchema = new mongoose.Schema({}, { strict: false });
const PullRequestSchema = new mongoose.Schema({}, { strict: false });

BlameResponseSchema.loadClass(BlameResponse);
ChangeReasonSchema.loadClass(ChangeReason);
AutoFixResponseSchema.loadClass(AutoFixResponse);
ScaValidatorTypesResponseSchema.loadClass(ScaValidatorTypesResponse);
AlertRecommendationResponseSchema.loadClass(AlertRecommendationResponse);
IacValidatorTypesResponseSchema.loadClass(IacValidatorTypesResponse);
PullRequestSchema.loadClass(PullRequest);

// helper function to clean non-wanted fields before saving in mongo
const toClean = (v: string): string => "";

export const SecurityEventSchema = new mongoose.Schema(
  {
    repoId: { type: String, index: true, required: false },
    imageCacheId: { type: String, index: true, required: false },
    blame: BlameResponseSchema,
    autoFixResponse: AutoFixResponseSchema,
    severityChangedReason: [ChangeReasonSchema],
    scaValidatorTypesResponse: ScaValidatorTypesResponseSchema,
    alertRecommendationResponse: AlertRecommendationResponseSchema,
    iacValidatorTypesResponse: IacValidatorTypesResponseSchema,
    relatedPR: PullRequestSchema,
    secretWithoutObfuscation: { type: String, set: toClean },
  },
  { strict: false },
);
SecurityEventSchema.loadClass(SecurityEvent);

export const CachedComplianceSchema = new mongoose.Schema(
  { imageCacheId: { type: String, index: true, required: false } },
  { strict: false },
);
export const CachedArtifactSchema = new mongoose.Schema(
  { imageCacheId: { type: String, index: true, required: false }, scanId: { type: String, index: true, required: false } },
  { strict: false },
);
export const SbomSchema = new mongoose.Schema(
  { repoId: { type: String, index: true, required: false }, imageCacheId: { type: String, index: true, required: false } },
  { strict: false },
);
export const ExtendedSbomSchema = new mongoose.Schema(
  { repoId: { type: String, index: true, required: false }, imageCacheId: { type: String, index: true, required: false } },
  { strict: false },
);
export const InfectedRepoSchema = new mongoose.Schema({}, { strict: false });
