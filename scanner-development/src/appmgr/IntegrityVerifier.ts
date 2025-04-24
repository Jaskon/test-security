import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();
import { Session } from "../entitis/ArtifactTypes";

export default class IntegrityVerifier {
  static unverifiedHashes = new Map<string, Set<string>>();

  static async isVerified(session: Session, hash: string): Promise<boolean> {
    try {
      const cachedSessionArtifactIntegrityInstance = this.unverifiedHashes.get(session.orgId);

      if (cachedSessionArtifactIntegrityInstance) {
        return !cachedSessionArtifactIntegrityInstance.has(hash);
      }

      logger.error(`Failed to get artifact integrity instance for ${session.orgId}, ${session.uuid}`);
      return false;
    } catch (err) {
      logger.error(`Failed to get artifact integrity instance for ${session.orgId}, ${session.uuid} with error: ${err}`);
    }
  }
}
