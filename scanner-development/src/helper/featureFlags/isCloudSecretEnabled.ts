import FeatureFlags from "@oxappsec/ox-feature-flag";

export default class isCloudSecretEnabledForOrg {
  private static isEnabled: Promise<boolean>;
  private static runOnce = false;

  static async isOn(org: string): Promise<boolean> {
    if (!this.runOnce) {
      this.runOnce = true;

      this.isEnabled = new Promise(resolve => {
        FeatureFlags.isFeatureEnabled.execute(org, "oxEnableCloudSecretsScan").then(result => resolve(result));
      });
    }

    const isFeatureEnabled = await this.isEnabled;
    return isFeatureEnabled;
  }
}
