import { SbomEvent, ImageInfo, AppSbomImage } from "../../../entitis/artifactoryTypes";
import appSbomsJSON from "./app-sboms.json";

import fireboltCliJson from "./firebolt/firebolt-cli.json";
import airbyteSourceFireboltJSON from "./firebolt/airbyte-source-firebolt.json";
import airbyteDestinationFireboltJSON from "./firebolt/airbyte-destination-firebolt.json";

const firebolt = [
  {
    appId: "Artifactory-Storage",
    scanId: "9a37e8d5-b5df-4e58-8ba0-8eb11193a404",
    scanDate: "2022-05-27T08:46:46.239Z",
    imageDetail: {
      registryId: "***",
      repositoryName: "firebolt-cli",
      name: "ghcr.io/firebolt-db/firebolt-cli",
      region: "***",
      cloudEnv: "ghcr",
    },
    sbom: fireboltCliJson,
  },
  {
    appId: "Artifactory-Storage",
    scanId: "9a37e8d5-b5df-4e58-8ba0-8eb11193a404",
    scanDate: "2022-05-27T08:46:46.239Z",
    imageDetail: {
      registryId: "***",
      repositoryName: "airbyte-source-firebolt",
      name: "ghcr.io/firebolt-db/airbyte-source-firebolt",
      region: "***",
      cloudEnv: "ghcr",
    },
    sbom: airbyteSourceFireboltJSON,
  },
  {
    appId: "Artifactory-Storage",
    scanId: "9a37e8d5-b5df-4e58-8ba0-8eb11193a404",
    scanDate: "2022-05-27T08:46:46.239Z",
    imageDetail: {
      registryId: "***",
      repositoryName: "airbyte-destination-firebolt",
      name: "ghcr.io/firebolt-db/airbyte-destination-firebolt",
      region: "***",
      cloudEnv: "ghcr",
    },
    sbom: airbyteDestinationFireboltJSON,
  },
];

// rm firebolt data when done
const appSboms = firebolt.map((appSbomJSON, i) => ({
  ...appSbomJSON,
  scanDate: new Date(appSbomJSON.scanDate),
})) as AppSbomImage[];

export const getMockSbomEventsForImages = (): ImageInfo[] => {
  return appSboms.map(appSbom => {
    const imageInfo = new ImageInfo();
    imageInfo.image = appSbom.imageDetail;
    imageInfo.sbomEvents = [new SbomEvent(appSbom.sbom, undefined)];
    return imageInfo;
  });
};
