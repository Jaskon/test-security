import FeatureFlags from "@oxappsec/ox-feature-flag";

export default class isDockerHubResponseRequired {
  private static isEnabled: Promise<boolean>;
  private static runOnce = false;

  static async isDockerHubResponseRequiredImpl(org: string): Promise<boolean> {
    if (!this.runOnce) {
      this.runOnce = true;

      this.isEnabled = new Promise(resolve => {
        FeatureFlags.isFeatureEnabled.execute(org, "ox-docker-hub-response-required", true).then(result => resolve(!result));
      });
    }

    const isFeatureEnabled = await this.isEnabled;
    return !isFeatureEnabled;
  }
}
