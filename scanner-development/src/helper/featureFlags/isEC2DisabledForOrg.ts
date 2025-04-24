import FeatureFlags from "@oxappsec/ox-feature-flag";

export default class isEC2DisabledForOrg {
  private static isEnabled: Promise<boolean>;
  private static runOnce = false;

  static async isEC2DisabledForOrgImpl(org: string): Promise<boolean> {
    if (!this.runOnce) {
      this.runOnce = true;

      this.isEnabled = new Promise(resolve => {
        FeatureFlags.isFeatureEnabled.execute(org, "ox-disable-ec2", true).then(result => resolve(!result));
      });
    }

    const isFeatureEnabled = await this.isEnabled;
    return !isFeatureEnabled;
  }
}
