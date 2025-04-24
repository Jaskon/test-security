import FeatureFlags from "@oxappsec/ox-feature-flag";

export class isGitInfoJsonFeatureEnabledForOrg {
  private static isEnabledPromise: Promise<boolean>;
  private static runOnce = false;

  static async isEnabled(org: string): Promise<boolean> {
    if (!this.runOnce) {
      this.runOnce = true;

      this.isEnabledPromise = FeatureFlags.isFeatureEnabled.execute(org, "ox-git-info-json", true);
    }

    const isFeatureEnabled = await this.isEnabledPromise;
    return isFeatureEnabled;
  }
}
