import { Match, OxExclusionLevel, OxExclusionMode, OxExclusionScope, OxExclusionType } from "@oxappsec/ox-consolidated-exclusions";
import PolicyRulesBase from "../../policy/rules/code/policyRulesBase";
import { Repo } from "../codeRepoTypes";

export class Exclusion {
  repoName: string;
  repoId: string;
  policyId: string;
  policyName: string;
  exclusionCategory: string;
  exclusionId: string;
  exclusionType: OxExclusionType;
  excludeRepoOnly: boolean;
  exclusionMatch: Match[];
  exclusionScope: OxExclusionScope;
  exclusionMode: OxExclusionMode;
  isActive: boolean;
  expiredAt?: Date;
  issueId: string;

  validateField(val: string) {
    if (isInValidStr(val)) {
      throw `${val} is not in correct format, cannot set exclusion`;
    }
  }

  public validateExclusion() {
    this.validateField(this.policyId);
    this.validateField(this.repoId);
    this.validateField(this.repoName);
    this.validateMatch(this.exclusionMatch);
    this.validateField(this.exclusionMode);
    this.validateField(this.exclusionId);
    this.validateEnum<OxExclusionType>(this.exclusionType, OxExclusionType);
    this.validateEnum<OxExclusionMode>(this.exclusionMode, OxExclusionMode);
    this.validateEnum<OxExclusionScope>(this.exclusionScope, OxExclusionScope);
    if (this.exclusionMode === OxExclusionMode.pipelineScan && this.exclusionScope === OxExclusionScope.issue) {
      for (const m of this.exclusionMatch) {
        if (m.key === "issueId" && m.level === OxExclusionLevel.issue) {
          m.value = this.issueId;
          break;
        }
      }
    }
  }
  private validateEnum<T>(str: T, object: Object) {
    const isValidEnum = Object.values(object).includes(str);
    if (!isValidEnum) {
      throw `${str} is not valid enum: ${object} type, cannot set exclusion`;
    }
  }

  private validateMatch(match: Match[]) {
    if (match === null || match === undefined || match.length === 0) {
      throw `match is not defined`;
    }
    for (const m of match) {
      this.validateField(m.key);
      this.validateField(m.value);
      this.validateField(m.level);
    }
  }

  validate() {
    this.validateBase();
  }

  excludedBaseByRepoAndPolicy(repo: Repo, policy: PolicyRulesBase) {
    if (this.excludeRepoOnly) {
      if (this.repoId.toLowerCase() !== repo.id.toLowerCase()) {
        return false;
      }
      if (
        this.policyId.toLowerCase() !== policy.policyRuleMetadata.policyId.toLowerCase() &&
        this.policyName.toLowerCase() !== policy.policyRuleMetadata.name.toLowerCase()
      ) {
        return false;
      }
    } else {
      //No need to check
      return true;
    }

    return true;
  }

  validateBase() {
    this.validateField(this.exclusionCategory);
    this.validateField(this.policyId);
    this.validateField(this.policyName);
    this.validateField(this.exclusionCategory);
    this.validateField(this.exclusionType);
    this.validateField(this.repoName);
    this.validateField(this.repoId);
  }
}

export class ExclusionCodeSecEvents extends Exclusion {
  fileName: string;
  match: string;
  ruleId: string;

  validate() {
    this.validateBase();

    //All this fields required
    if (isInValidStr(this.fileName) && isInValidStr(this.match) && isInValidStr(this.ruleId)) {
      throw `all values are empty`;
    }
  }

  /**
   * In this policy there are several options to exclude alert
   * due to this case we first check if the exclude are not empty otherwise
   * exclusion without one filed will never match
   * example: exclude only by ruleID, the exclusion have only ruleID but the alert have all the fields
   */
  excludedCodeSecAlert(codeSecurityEvent: AggregatedCodeData, repo: Repo, policy: PolicyRulesBase) {
    let atLeasOneItemIsExist = false;

    if (codeSecurityEvent.match && this.match) {
      atLeasOneItemIsExist = true;
      if (codeSecurityEvent.match.toLowerCase() !== this.match.toLowerCase()) {
        return false;
      }
    }
    if (codeSecurityEvent.ruleID && this.ruleId) {
      atLeasOneItemIsExist = true;
      if (codeSecurityEvent.ruleID.toLowerCase() !== this.ruleId.toLowerCase()) {
        return false;
      }
    }
    if (codeSecurityEvent.fileName && this.fileName) {
      atLeasOneItemIsExist = true;

      if (codeSecurityEvent.fileName.toLowerCase() !== this.fileName.toLowerCase()) {
        return false;
      }
    }

    if (!this.excludedBaseByRepoAndPolicy(repo, policy)) {
      return false;
    }

    if (!atLeasOneItemIsExist) {
      return false;
    }

    return true;
  }
}

export class ExclusionCloudSecEvents extends Exclusion {
  service: string;
  resource: string;

  //Not mandatory
  match: string;
  ruleId: string;
  accountId: string;

  validate() {
    this.validateBase();

    //All this fields required
    this.validateField(this.resource);
    this.validateField(this.service);
  }

  excludedCloudSecAlert(cloudSecurityEvent: AggregatedCloudData, repo: Repo, policy: PolicyRulesBase) {
    if (cloudSecurityEvent.service.toLowerCase() !== this.service.toLowerCase()) {
      return false;
    }
    if (cloudSecurityEvent.resource.toLowerCase() !== this.resource.toLowerCase()) {
      return false;
    }
    if (cloudSecurityEvent.accountId && this.accountId) {
      if (cloudSecurityEvent.accountId.toLowerCase() !== this.accountId.toLowerCase()) {
        return false;
      }
    }
    if (cloudSecurityEvent.secret && this.match) {
      if (cloudSecurityEvent.secret.toLowerCase() !== this.match.toLowerCase()) {
        return false;
      }
    }
    if (cloudSecurityEvent.ruleId && this.ruleId) {
      if (cloudSecurityEvent.ruleId.toLowerCase() !== this.ruleId.toLowerCase()) {
        return false;
      }
    }

    if (!this.excludedBaseByRepoAndPolicy(repo, policy)) {
      return false;
    }
    return true;
  }
}

export class ExclusionCommits extends Exclusion {
  commitSha: string;

  validate() {
    this.validateBase();

    //All this fields required
    this.validateField(this.commitSha);
  }

  excludedCommit(aggregatedCommit: AggregatedCommit, repo: Repo, policy: PolicyRulesBase) {
    if (aggregatedCommit.sha !== this.commitSha) {
      return false;
    }
    if (!this.excludedBaseByRepoAndPolicy(repo, policy)) {
      return false;
    }
    return true;
  }
}

export class ExclusionUsers extends Exclusion {
  user: string;

  validate() {
    this.validateBase();

    //All this fields need to be
    this.validateField(this.user);
  }

  excludedUser(aggregatedUser: AggregatedUser, repo: Repo, policy: PolicyRulesBase) {
    if (aggregatedUser.user !== this.user) {
      return false;
    }
    if (!this.excludedBaseByRepoAndPolicy(repo, policy)) {
      return false;
    }
    return true;
  }
}

export class ExclusionWebhook extends Exclusion {
  url: string;

  validate() {
    this.validateBase();

    //All this fields need to be
    this.validateField(this.url);
  }

  excludedWebhook(AggregatedWebhook: AggregatedWebhook, repo: Repo, policy: PolicyRulesBase) {
    if (AggregatedWebhook.url !== this.url) {
      return false;
    }
    if (!this.excludedBaseByRepoAndPolicy(repo, policy)) {
      return false;
    }
    return true;
  }
}

export class ExclusionContainer extends Exclusion {
  image: string;

  //Not mandatory
  sha: string;
  secret: string;

  validate() {
    this.validateBase();

    //All this fields required
    this.validateField(this.image);
  }

  excludedContainer(aggregatedContainerData: AggregatedContainerData, repo: Repo, policy: PolicyRulesBase) {
    let atLeasOneItemIsExist = false;

    //Mandatory
    if (aggregatedContainerData.image) {
      atLeasOneItemIsExist = true;
      if (aggregatedContainerData.image !== this.image) {
        return false;
      }
    }

    //Not mandatory
    if (aggregatedContainerData.sha && this.sha) {
      atLeasOneItemIsExist = true;
      if (aggregatedContainerData.sha !== this.sha) {
        return false;
      }
    }
    if (!this.excludedBaseByRepoAndPolicy(repo, policy)) {
      return false;
    }

    if (!atLeasOneItemIsExist) {
      return false;
    }

    return true;
  }
}

export class ExclusionSBOM extends Exclusion {
  realMatch: string;

  validate() {
    this.validateBase();

    //All this fields required
    this.validateField(this.realMatch);
  }

  excludedSbom(AggregatedSbomData: AggregatedSbomData, repo: Repo, policy: PolicyRulesBase) {
    if (AggregatedSbomData.realMatch !== this.realMatch) {
      return false;
    }
    if (!this.excludedBaseByRepoAndPolicy(repo, policy)) {
      return false;
    }
    return true;
  }
}

export abstract class AggregatedInfoForExclusion {
  aggId: string;
  exclusionId?: string;
  hashAggId: string;
  isSilent: boolean;
  abstract getExclusionObj();
  abstract setAggId();
}

export class AggregatedWebhook {
  url: string;
}

export class AggregatedUser {
  user: string;
}

export class AggregatedExposedRepo {
  sourceRepoName: string;
  destinationRepoName: string;
}

export class AggregatedNotUsedLibs {
  nameAndVer: string;
}

export class AggregatedRepo {
  repo: string;
}

export class AggregatedCommit {
  sha: string;
}

export class AggregatedCodeData {
  fileName: string;
  match: string;
  ruleID: string;
}

export class AggregatedSbomData {
  realMatch: string;
}

export class AggregatedCloudData {
  service: string;
  accountId: string;
  resource: string;
  secret: string;
  ruleId: string;
}

export class AggregatedContainerData {
  sha: string;
  image: string;
}

// export interface ExclusionRecommend {
//   id: string;
//   label: string;
//   recommended: boolean;
//   excludeBy: string[];
//   tooltip: string;
//   uidOnly: boolean;
//   isDefault: boolean;
// }

function isInValidStr(val: string) {
  return val == null || val === undefined || val === "";
}
