import FeatureFlags from "@oxappsec/ox-feature-flag";

export default class isJenkinsCertBypassEnabledForOrg {
  private static isEnabled: Promise<boolean>;
  private static runOnce = false;

  static async isJenkinsCertBypassEnabled(org: string): Promise<boolean> {
    if (!this.runOnce) {
      this.runOnce = true;

      this.isEnabled = new Promise(resolve => {
        FeatureFlags.isFeatureEnabled.execute(org, "ox-disable-jenkins-cert-validation", true).then(result => resolve(result));
      });
    }

    const isFeatureEnabled = await this.isEnabled;
    return isFeatureEnabled;
  }
}
