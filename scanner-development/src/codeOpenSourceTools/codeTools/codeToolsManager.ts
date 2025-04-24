import { Repo } from "../../entitis/codeRepoTypes";
import Iqueue from "../../helper/queue/Iqueue";
import loggerImport from "../../logger";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import ToolProgressBase from "../base/toolProgressBase";
import ToolsManagerBase from "../base/toolsManagerBase";
import codeToolsCreator from "./codeToolsCreator";

const logger = loggerImport.getDebugLogger();

class CodeToolsManager extends ToolsManagerBase {
  constructor(
    uuid: string,
    orgPolicyParser: OrgPolicyParser,
    orgName: string,
    repoObj: any,
    securityToolsQueue: Iqueue,
    codeToolsCreator: codeToolsCreator,
    toolProgressBase: ToolProgressBase,
  ) {
    const repo: Repo = repoObj as Repo;
    const resultsDir = repo.securityResDir;
    const filterMessage = repo.fullName;
    const id = repo.id;

    super(
      uuid,
      orgPolicyParser,
      orgName,
      resultsDir,
      filterMessage,
      repo,
      securityToolsQueue,
      codeToolsCreator,
      "code_all_done",
      "repo",
      toolProgressBase,
      id,
    );
  }
}

export default CodeToolsManager;
