import { InfectedRepo } from "./cache.types";

export class CacheHelper {
  public async verifyUniqeness(infectedRepos: InfectedRepo[]) {
    const reposIds = new Set<string>();
    infectedRepos.forEach(i => {
      const before = reposIds.size;
      const after = reposIds.add(i.repoId).size;
      if (before === after) throw Error(`duplicted repos ids. not setting infected repos`);
    });
  }
}
