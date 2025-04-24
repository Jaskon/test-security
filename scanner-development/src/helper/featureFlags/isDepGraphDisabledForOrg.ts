import FeatureFlags from "@oxappsec/ox-feature-flag";

export class isDepGraphDisabledForOrg {
  private static isDisabledPromise: Promise<boolean>;
  private static runOnce = false;

  static async isDisabled(org: string): Promise<boolean> {
    if (!this.runOnce) {
      this.runOnce = true;

      this.isDisabledPromise = FeatureFlags.isFeatureEnabled.execute(org, "ox-disabled-dep-graph", true);
    }

    const isFeatureDisabled = await this.isDisabledPromise;
    return isFeatureDisabled;
  }
}
