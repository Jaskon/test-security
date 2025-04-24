import { Repo } from "../../../entitis/codeRepoTypes";
import { BranchProtectionRule } from "./updateBranchProtectionRule";

class AutoFix {
  uuid: string;
  constructor(uuid: string) {
    this.uuid = uuid;
  }

  async setRepoToPrivate(octokit: any, repoFullName: string, owner: string) {
    try {
      console.info(`try set repo: ${repoFullName}, owner: ${owner} to private`);

      const res = await octokit.request("PATCH /repos/{owner}/{repo}", {
        owner: owner,
        repo: repoFullName,
        visibility: "private",
      });

      console.info(`finish set repo: ${repoFullName}, owner: ${owner} to private, res: ${JSON.stringify(res)}`);
    } catch (err) {
      console.error(`failed set repo: ${repoFullName}, owner: ${owner} to private: ${err}`);
    }
  }

  async archiveRepo(octokit: any, repoFullName: string, owner: string) {
    try {
      console.info(`try archive repo: ${repoFullName}`);

      const res = await octokit.request("PATCH /repos/{owner}/{repo}", {
        owner: owner,
        repo: repoFullName,
        archived: true,
      });

      console.info(`finish set repo: ${repoFullName}, owner: ${owner} to private, res: ${JSON.stringify(res)}`);
    } catch (err) {
      console.error(`failed archive repo: ${repoFullName}, err: ${err}`);
    }
  }

  async setRepoBranchProtectionUnReviewedCode(
    octokit: any,
    repoFullName: string,
    owner: string,
    branch: string,
    fixedRule: BranchProtectionRule,
    policyName: string,
  ) {
    try {
      console.info(
        `try set branch protection for unreviewed, policy:${policyName}, repo: ${repoFullName}, owner: ${owner}, branch: ${branch}`,
      );

      const res = await octokit.request("PUT /repos/{owner}/{repo}/branches/{branch}/protection", {
        owner: owner,
        repo: repoFullName,
        branch: branch,
        required_pull_request_reviews: fixedRule.requiredPullRequestReviews,
        enforce_admins: fixedRule.enforceAdmins,
        required_status_checks: fixedRule.requiredStatusChecks,
        restrictions: fixedRule.restrictions,
        allow_deletions: fixedRule.allowDeletions,
        allow_force_pushes: fixedRule.allowForcePushes,
      });
      console.info(
        `finish set branch protection for unreviewed, policy:${policyName}, repo: ${repoFullName}, owner: ${owner}, branch: ${branch}, res: ${JSON.stringify(
          res,
        )}`,
      );
    } catch (err) {
      console.error(
        `failed set branch protection for unreviewed, policy:${policyName}, repo: ${repoFullName}, owner: ${owner}, branch: ${branch}, err: ${err}`,
      );
    }
  }

  async setRepoBranchProtectionForDeletionOnBranch(
    octokit: any,
    repoFullName: string,
    owner: string,
    branch: string,
    fixedRule: BranchProtectionRule,
  ) {
    try {
      console.info(`try set branch protection for deletion of branch, repo: ${repoFullName}, owner: ${owner}, branch: ${branch}`);

      const res = await octokit.request("PUT /repos/{owner}/{repo}/branches/{branch}/protection", {
        owner: owner,
        repo: repoFullName,
        branch: branch,
        required_pull_request_reviews: fixedRule.requiredPullRequestReviews,
        enforce_admins: fixedRule.enforceAdmins,
        required_status_checks: fixedRule.requiredStatusChecks,
        restrictions: fixedRule.restrictions,
        allow_deletions: fixedRule.allowDeletions,
        allow_force_pushes: fixedRule.allowForcePushes,
      });

      console.info(
        `finish set branch protection for for deletion of branch, repo: ${repoFullName}, owner: ${owner}, branch: ${branch}, res: ${JSON.stringify(
          res,
        )}`,
      );
    } catch (err) {
      console.error(
        `failed set branch protection for deletion of branch, repo: ${repoFullName}, owner: ${owner}, branch: ${branch}, err: ${err}`,
      );
    }
  }

  async setRepoBranchProtectionForAddingSignedCommits(
    octokit: any,
    repoFullName: string,
    owner: string,
    branch: string,
    fixedRule: BranchProtectionRule,
  ) {
    try {
      console.info(`try set branch protection for adding signed commits, repo: ${repoFullName}, owner: ${owner}, branch: ${branch}`);

      const res = await octokit.request("PUT /repos/{owner}/{repo}/branches/{branch}/protection", {
        owner: owner,
        repo: repoFullName,
        branch: branch,
        required_pull_request_reviews: fixedRule.requiredPullRequestReviews,
        enforce_admins: fixedRule.enforceAdmins,
        required_status_checks: fixedRule.requiredStatusChecks,
        restrictions: fixedRule.restrictions,
        allow_deletions: fixedRule.allowDeletions,
        allow_force_pushes: fixedRule.allowForcePushes,
        required_signatures: fixedRule.signedCommits,
      });

      console.log(res);
      console.info(
        `finish set branch protection for adding signed commits, repo: ${repoFullName}, owner: ${owner}, branch: ${branch}, res: ${JSON.stringify(
          res,
        )}`,
      );
    } catch (err) {
      console.error(
        `failed set branch protection for adding signed commits, repo: ${repoFullName}, owner: ${owner}, branch: ${branch}, err: ${err}`,
      );
    }
  }

  async removeRepoCollaborator(octokit: any, repoFullName: string, owner: string, userToRemove: string) {
    try {
      console.info(`try remove repo collaborator, repo: ${repoFullName}, owner: ${owner}, user: ${userToRemove}`);

      const res = await octokit.request("DELETE /repos/{owner}/{repo}/collaborators/{username}", {
        owner: owner,
        repo: repoFullName,
        username: userToRemove,
      });

      console.info(
        `finish remove repo collaborator, repo: ${repoFullName}, owner: ${owner}, user: ${userToRemove}, res: ${JSON.stringify(res)}`,
      );
    } catch (err) {
      console.error(`failed remove repo collaborator, repo: ${repoFullName}, owner: ${owner}, user: ${userToRemove}, err: ${err}`);
    }
  }

  async changeRepoCollaboratorPermissions(octokit: any, repoFullName: string, owner: string, user: string, permission: string) {
    try {
      console.info(
        `try change repo collaborator permissions, repo: ${repoFullName}, owner: ${owner}, user: ${user}, permission: ${permission}`,
      );

      const allowed = ["pull", "triage", "push", "maintain", "admin"];
      if (allowed.find(i => i === permission) == undefined) {
        throw "bad permission";
      }

      const res = await octokit.request("PUT /repos/{owner}/{repo}/collaborators/{username}", {
        owner: owner,
        repo: repoFullName,
        username: user,
        permission: permission,
      });

      console.info(
        `finish change repo collaborator permissions, repo: ${repoFullName}, owner: ${owner}, user: ${user}, permission: ${permission}, res: ${JSON.stringify(
          res,
        )}`,
      );
    } catch (err) {
      console.error(
        `failed change repo collaborator permissions, repo: ${repoFullName}, owner: ${owner}, user: ${user}, permission: ${permission}, err: ${err}`,
      );
    }
  }

  async removeUser(octokit: any, userToRemove: string, org: string) {
    try {
      console.info(`try remove, user: ${userToRemove}, org: ${org}`);

      const res = await octokit.request("DELETE /orgs/{org}/members/{username}", {
        username: userToRemove,
        org: org,
      });

      console.info(`finish remove, user: ${userToRemove}, org: ${org}, res: ${JSON.stringify(res)}`);
    } catch (err) {
      console.error(`failed remove, user: ${userToRemove}, org: ${org}, err: ${err}`);
    }
  }
  async upgradeOrgUserRole(octokit: any, user: string, org: string) {
    try {
      console.info(`try change user: ${user}, org: ${org}`);

      const res = await octokit.request("PUT /orgs/{org}/memberships/{username}", {
        org: org,
        username: user,
        role: "admin",
      });

      console.info(`finish change user to owner: ${user}, org: ${org}, res: ${JSON.stringify(res)}`);
    } catch (err) {
      console.error(`failed change user: ${user}, org: ${org}, err: ${err}`);
    }
  }

  async changeUserPermissions(octokit: any, user: string, permission: string, org: string) {
    try {
      console.info(`try change user: ${user}, permission: ${permission}, org: ${org}`);

      if (!user.includes("sivansalzmann")) {
        return;
      }

      const res = await octokit.request("PUT /orgs/{org}/memberships/{username}", {
        org: org,
        username: user,
        role: permission,
      });

      console.info(`finish change user: ${user}, permission: ${permission}, org: ${org}, res: ${JSON.stringify(res)}`);
    } catch (err) {
      console.error(`failed change, user: ${user}, permission: ${permission}, org: ${org}, err: ${err}`);
    }
  }

  async changeForkSettingsRepo(octokit: any, repo: string, owner: string, policyName: string) {
    try {
      console.info(`try disable forking private repo, policy:${policyName}, repo: ${repo}, owner: ${owner}`);

      const res = await octokit.request("PATCH /repos/{owner}/{repo}", {
        owner: owner,
        repo: repo,
        allow_forking: false,
      });

      console.info(`res: ${JSON.stringify(res)}`);

      console.info(
        `finish set disable forking private repo, policy:${policyName}, repo: ${repo}, owner: ${owner}, res: ${JSON.stringify(res)}`,
      );
    } catch (err) {
      console.error(`failed disable forking private repo, policy:${policyName}, repo: ${repo}, owner: ${owner}, err: ${err}`);
    }
  }

  async changeForkSettingsOrg(octokit: any, org: string, policyName: string) {
    try {
      console.info(`try disable forking private repo for org , policy:${policyName}, org: ${org}`);

      const res = await octokit.request("PATCH /orgs/{org}", {
        org: org,
        members_can_fork_private_repositories: false,
      });

      console.info(`res: ${JSON.stringify(res)}`);

      console.info(`finish set disable forking private repo for org , policy:${policyName}, org: ${org}, res: ${JSON.stringify(res)}`);
    } catch (err) {
      console.error(`failed disable forking private repofor org , policy:${policyName}, org: ${org}, err: ${err}`);
    }
  }
  async changeWorkflowsPermOrg(octokit: any, org: string, policyName: string) {
    try {
      console.info(`try set workflows permissions, policy:${policyName}, org: ${org}`);

      const res = await octokit.request("PUT /orgs/{org}/actions/permissions/workflow", {
        org: org,
        default_workflow_permissions: "read",
        can_approve_pull_request_reviews: false,
      });

      console.info(`res: ${JSON.stringify(res)}`);

      console.info(`finish set workflows permissions , policy:${policyName}, org: ${org}, res: ${JSON.stringify(res)}`);
    } catch (err) {
      console.error(`failed set workflows permissions , policy:${policyName}, org: ${org}, err: ${err}`);
    }
  }

  async changeWorkflowsPermRepo(octokit: any, repo: Repo, policyName: string) {
    try {
      console.info(`try set workflows permissions, policy:${policyName}, org: ${repo.organization}`);

      const res = await octokit.request("PUT /repos/{owner}/{repo}/actions/permissions/workflow", {
        owner: repo.ownerNameApi,
        repo: repo.name,
        default_workflow_permissions: "read",
        can_approve_pull_request_reviews: false,
      });

      console.info(`res: ${JSON.stringify(res)}`);

      console.info(`finish set workflows permissions , policy:${policyName}, org: ${repo.organization}, res: ${JSON.stringify(res)}`);
    } catch (err) {
      console.error(`failed set workflows permissions , policy:${policyName}, org: ${repo.organization}, err: ${err}`);
    }
  }

  async changeWebhookSSL(octokit: any, repo: Repo, policyName: string, hookId, config) {
    try {
      console.info(`try set ssl webhook, policy:${policyName}, org: ${repo.organization}`);

      const res = await octokit.request("PATCH /repos/{owner}/{repo}/hooks/{hook_id}", {
        owner: repo.ownerNameApi,
        repo: repo.name,
        hook_id: hookId,
        config: config,
      });

      console.info(`res: ${JSON.stringify(res)}`);

      console.info(`finish set ssl webhook, policy:${policyName}, org: ${repo.organization}, res: ${JSON.stringify(res)}`);
    } catch (err) {
      console.error(`failed set ssl webhook, policy:${policyName}, org: ${repo.organization}, err: ${err}`);
    }
  }
  async deleteWebhook(octokit: any, repo: Repo, policyName: string, hookId) {
    try {
      console.info(`try delete webhook, policy:${policyName}, org: ${repo.organization}`);

      const res = await octokit.request("DELETE /repos/{owner}/{repo}/hooks/{hook_id}", {
        owner: repo.ownerNameApi,
        repo: repo.name,
        hook_id: hookId,
      });

      console.info(`res: ${JSON.stringify(res)}`);

      console.info(`finish delete webhook, policy:${policyName}, org: ${repo.organization}, res: ${JSON.stringify(res)}`);
    } catch (err) {
      console.error(`failed delete webhook, policy:${policyName}, org: ${repo.organization}, err: ${err}`);
    }
  }
}

export default AutoFix;
