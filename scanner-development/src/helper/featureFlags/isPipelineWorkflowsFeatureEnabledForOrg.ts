import FeatureFlags from "@oxappsec/ox-feature-flag";

export class isPipelineWorkflowsFeatureEnabledForOrg {
  private static isEnabledPromise: Promise<boolean>;
  private static runOnce = false;

  static async isEnabled(org: string): Promise<boolean> {
    if (!this.runOnce) {
      this.runOnce = true;

      this.isEnabledPromise = FeatureFlags.isFeatureEnabled.execute(org, "oxPipelineWorkflowsEnabled");
    }

    const isFeatureEnabled = await this.isEnabledPromise;
    return isFeatureEnabled;
  }
}
