import { CloudResourcesToRun } from "../../entitis/cloudTypes";
import Iqueue from "../../helper/queue/Iqueue";
import loggerImport from "../../logger";
import OrgPolicyParser from "../../policy/org/ruleConfigParser";
import ToolProgressBase from "../base/toolProgressBase";
import ToolsManagerBase from "../base/toolsManagerBase";
import CloudToolsCreator from "./cloudToolsCreator";

const logger = loggerImport.getDebugLogger();

class cloudToolsManager extends ToolsManagerBase {
  constructor(
    uuid: string,
    orgPolicyParser: OrgPolicyParser,
    orgName: string,
    cloudObj: any,
    securityToolsQueue: Iqueue,
    cloudToolsCreator: CloudToolsCreator,
    toolProgressBase: ToolProgressBase,
  ) {
    const cloudResourcesToExecute: CloudResourcesToRun = cloudObj as CloudResourcesToRun;

    const resultsDir = cloudResourcesToExecute.fileForResults;
    const filterMessage = cloudResourcesToExecute.idForTools;
    const id = cloudResourcesToExecute.idForTools;

    super(
      uuid,
      orgPolicyParser,
      orgName,
      resultsDir,
      filterMessage,
      cloudResourcesToExecute,
      securityToolsQueue,
      cloudToolsCreator,
      "cloud_all_done",
      "cloud",
      toolProgressBase,
      id,
    );
  }
}

export default cloudToolsManager;
