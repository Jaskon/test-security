import { DockerHubInfo, DockerhubRequest } from "../../entitis/DockerhubTypes";
import loggerImport from "../../logger";
import EnvQueueFactory from "../queue/envQueueFactory";
import Iqueue from "../queue/Iqueue";
import DockerhubHelper, { getDockerHubCache } from "../service/dockerhubHelper";
import StatesHelper from "../statesHelper";
const logger = loggerImport.getDebugLogger();

const dockerHelperCaller = () => {
  const dockerHubQueue: Iqueue = EnvQueueFactory.getQueue(StatesHelper.Instance.uuid, this, StatesHelper.Instance.orgName);
  const dockerHubHelper: DockerhubHelper = new DockerhubHelper(dockerHubQueue, StatesHelper.Instance.uuid, StatesHelper.Instance.orgName);

  return {
    sendRequest: async (request: DockerhubRequest): Promise<DockerHubInfo | null> => {
      const foundInDockerHub: DockerHubInfo | null = await dockerHubHelper.sendAndWaitForRes(
        request as DockerhubRequest,
        "artifact-screen",
      );

      return foundInDockerHub;
    },
  };
};

async function checkArtifactOnDockerHub(dockerHubCaller: ReturnType<typeof dockerHelperCaller>, req: DockerhubRequest) {
  const cache = getDockerHubCache();

  const cachedArtifactInfo = await cache.get(`${req.imageName}:${req.imageTag}`);

  if (cachedArtifactInfo) {
    await cache.set(`${req.imageName}:${req.imageTag}`, cachedArtifactInfo);
    return cachedArtifactInfo;
  }

  return await dockerHubCaller.sendRequest(req);
}
