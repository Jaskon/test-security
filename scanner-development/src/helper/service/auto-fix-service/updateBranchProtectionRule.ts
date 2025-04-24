export class BranchProtectionRule {
  requiredPullRequestReviews: object | null;
  enforceAdmins: object | boolean;
  requiredStatusChecks: object | null;
  restrictions: object | null;
  allowDeletions: boolean;
  allowForcePushes: boolean | null;
  signedCommits?: boolean;
  constructor(
    requiredPullRequestReviews,
    enforceAdmins,
    requiredStatusChecks,
    restrictions,
    allowDeletions,
    allowForcePushes,
    signedCommits?,
  ) {
    this.requiredPullRequestReviews = requiredPullRequestReviews;
    this.enforceAdmins = enforceAdmins;
    this.requiredStatusChecks = requiredStatusChecks;
    this.restrictions = restrictions;
    this.allowDeletions = allowDeletions;
    this.allowForcePushes = allowForcePushes;
    this.signedCommits = signedCommits;
  }
}

export enum updateOption {
  RemovingBoth = "Remove both of the bypassing options",
  RemovingBypassed = "Remove the option of bypassed required pull requests",
  RemovingDismissal = "Remove the option of dismissed pull requests reviews",
}

export enum changedValues {
  AllowDeletions = "allow_deletions",
  SignedCommits = "required_signatures",
  BypassPullRequestAllowances = "bypass_pull_request_allowances",
  DismissalRestrictions = "dismissal_restrictions",
  RequiredApprovingReviewCount = "required_approving_review_count",
  Restrictions = "restrictions",
}
