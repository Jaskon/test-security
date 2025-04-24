import CodeRepoBase from "../../src/dal/base/codeRepoBase";
import { Token } from "../../src/entitis/collectorEntitisTypes";
import loggerImport from "../../src/logger";
import JsonApplicationDiscoveryOverview from "../../src/policy/reporting/jsonApplicationDiscoveryOverview";
import RulesManager from "../../src/policy/rules/ruleManager";
const logger = loggerImport.getDebugLogger();
class TestCodeRepo extends CodeRepoBase {
  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);
  }
  getAllRepos(callObj: RulesManager) {
    return [];
    // return mock api repos(u can take example from debug om gitlab and return it)
  }
  setRepo(apiRepo: any, repoObj) {
    // return mock repo
  }
  initLib() {
    return;
  }
}
export default TestCodeRepo;
