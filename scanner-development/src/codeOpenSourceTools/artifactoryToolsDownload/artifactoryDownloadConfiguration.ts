import { ArtifactoryDownloadToRun } from "../../entitis/artifactoryTypes";
import { ArtifactConnectorsTypes } from "../../entitis/ArtifactTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { ToolConfig } from "../../entitis/tool/secuirtyToolsConfig";
import { isLocalDevelopment } from "../../helper/envUtils";
import StatesHelper from "../../helper/statesHelper";
import loggerImport from "../../logger";
import ToolConfigurationBase from "../base/toolConfigurationBase";
const logger = loggerImport.getDebugLogger();

const localDebug = process.env.DEBUG != undefined;

class ArtifactoryDownloadConfiguration extends ToolConfigurationBase {
  constructor(uuid: string, toolConfig: ToolConfig, token: Token) {
    super(uuid, toolConfig, token);
  }

  getCommand(resource: ArtifactoryDownloadToRun) {
    let location = resource.imageDetail.name + ":" + resource.imageDetail.imageTags[0];

    const mapofCommands: Map<string, string> = new Map<string, string>([
      [
        "jfrogArtifacts",
        "'skopeo login -u {USERNAME} -p {APIKEY} {HOSTURL} && skopeo  --override-os linux --override-arch amd64 copy docker://{IMAGENAME} docker-archive:{OUTPUTPATH}/artifactdownload.tar:ubu'",
      ],
      [
        "Google Artifact Registry",
        `'skopeo login -u oauth2accesstoken -p {APIKEY} {HOSTURL} && skopeo copy --retry-times=3 docker://{IMAGENAME} docker-archive:{OUTPUTPATH}/artifactdownload.tar:ubu'`,
      ],
      [
        "Google Container Registry",
        `'skopeo login -u oauth2accesstoken -p {APIKEY} {HOSTURL} && skopeo copy --retry-times=3 docker://{IMAGENAME} docker-archive:{OUTPUTPATH}/artifactdownload.tar:ubu'`,
      ],
      [
        "GitLab Container Registry",
        "'skopeo login -u {USERNAME} -p {APIKEY} registry.gitlab.com && skopeo copy --retry-times=3 --src-creds={USER_CRED} docker://{IMAGENAME} docker-archive:{OUTPUTPATH}/artifactdownload.tar:ubu'",
      ],
      [
        "cloudAWS",
        "'skopeo login --username AWS -p {APIKEY} {HOSTURL} && skopeo copy --retry-times=3 docker://{IMAGENAME} docker-archive:{OUTPUTPATH}/artifactdownload.tar:ubu'",
      ],
      [
        "Azure Container Registry",
        "'skopeo login -u 00000000-0000-0000-0000-000000000000 -p {APIKEY} {HOSTURL} && skopeo --override-os linux copy docker://{IMAGENAME} docker-archive:{OUTPUTPATH}/artifactdownload.tar:ubu'",
      ],
      [
        "Docker Hub",
        `"skopeo login -u {USERNAME} -p '{APIKEY}' {HOSTURL} && skopeo copy --retry-times=3 docker://{IMAGENAME} docker-archive:{OUTPUTPATH}/artifactdownload.tar:ubu"`,
      ],
      [
        "GoHarbor Container Registry",
        `"${StatesHelper.Instance.dnsNameOverride ? `${StatesHelper.Instance.dnsNameOverride} && ` : ""}skopeo login ${
          StatesHelper.Instance.allowSkopeoToAcceptSelfSignedCertificate ? "--tls-verify=false " : " "
        }-u {USERNAME} -p {APIKEY} {HOSTURL} && skopeo copy --retry-times=3 ${
          StatesHelper.Instance.allowSkopeoToAcceptSelfSignedCertificate ? "--debug --dest-tls-verify=false --src-tls-verify=false " : " "
        }docker://{IMAGENAME} docker-archive:{OUTPUTPATH}/artifactdownload.tar:ubu"`,
      ],
    ]);
    let command = mapofCommands.get(this.token.friendlyName);
    if (isLocalDevelopment()) {
      command = command.substring(1, command.length - 1);
    }
    let hostUrlNoArtifactory = "";
    if (this.token.friendlyName === "jfrogArtifacts") {
      hostUrlNoArtifactory = this.token.host.substring("https://".length, this.token.host.indexOf("/artifactory"));
    }
    if (this.token.friendlyName === ArtifactConnectorsTypes.GOHARBOR_CONTAINER_REGISTRY) {
      hostUrlNoArtifactory = resource.imageDetail.location.substring(0, resource.imageDetail.location.indexOf("/"));
    }

    if (!resource.imageDetail?.imageTags?.length && this.token.friendlyName === ArtifactConnectorsTypes.cloudAWS) {
      location = `${resource.imageDetail.name}@${resource.imageDetail.imageDigest}`;
    }

    if (
      this.token.friendlyName === ArtifactConnectorsTypes.GCP_ARTIFACTS ||
      this.token.friendlyName === ArtifactConnectorsTypes.GCP_CONTAINER ||
      this.token.friendlyName === ArtifactConnectorsTypes.AZURE_CONTAINER_REGISTRY ||
      this.token.friendlyName === ArtifactConnectorsTypes.DOCKER_HUB ||
      this.token.friendlyName === ArtifactConnectorsTypes.GOHARBOR_CONTAINER_REGISTRY ||
      this.token.friendlyName === ArtifactConnectorsTypes.JFROG_ARTIFACTS ||
      this.token.friendlyName === ArtifactConnectorsTypes.GitLabContainerRegistry
    ) {
      if (resource.imageDetail?.imageTags?.length) {
        location = `${resource.imageDetail.location}:${resource.imageDetail.imageTags[0]}`;
      } else {
        location = `${resource.imageDetail.location}@${resource.imageDetail.imageDigest}`;
      }
    }

    let regexToValueMap = {
      "{USERNAME}": this.token.userName,
      "{IMAGENAME}": location,
      "{OUTPUTPATH}": resource.artifactoryResultsDir,
      "{USER_CRED}": `${this.token.userName}:${this.token.password}`,
    };

    if (
      this.token.friendlyName === ArtifactConnectorsTypes.AZURE_CONTAINER_REGISTRY ||
      this.token.friendlyName === ArtifactConnectorsTypes.GCP_ARTIFACTS ||
      this.token.friendlyName === ArtifactConnectorsTypes.GCP_CONTAINER
    ) {
      command = command.replace("{APIKEY}", resource.imageDetail.accessToken);
      command = command.replace("{HOSTURL}", location.split("/")[0] || "");
    } else {
      command = command.replace("{APIKEY}", this.token.password);
      if (!this.token.host && hostUrlNoArtifactory.length === 0) {
        const host = location.substring(0, location.indexOf("/"));
        logger.info(`Replacing URL with ${host} to command ${command} in pos ${command.indexOf("{HOSTURL}")}`);
        command = command.replace("{HOSTURL}", host);
      } else {
        command = command.replace("{HOSTURL}", hostUrlNoArtifactory.length === 0 ? this.token.host : hostUrlNoArtifactory);
      }
    }

    const commandFromConfig = Object.entries(regexToValueMap).reduce(
      (result, [regex, value]) => this.stringHelper.replaceAllRegex(result, regex, value),
      command,
    );
    logger.info(`Command return for ${this.token.friendlyName} is ${commandFromConfig}`);
    return commandFromConfig;
  }
}

export default ArtifactoryDownloadConfiguration;
