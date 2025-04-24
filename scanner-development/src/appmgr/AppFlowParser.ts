import { ApplicationManager } from "./AppManager";
import { unzip } from "unzipit";
import loggerImport from "../logger";
import { ArtifactResult, parseArtifacts, parseK8Description } from "./ParseArtifacts";
import { artifactType, artifactSchema, K8Description } from "../entitis/ArtifactTypes";
import { OrchestratorSystem } from "../entitis/orchestratorTypes";

const logger = loggerImport.getDebugLogger();

const AppFlowParser = uuid => {
  const appMgr = new ApplicationManager(uuid);

  async function parseData(jobTrace: string, url: string, id: string = "") {
    const artifacts = await parseArtifacts(
      "any", // family
      jobTrace, // data
      id, // id
      uuid, // uiid
    );

    if (artifacts.success) {
      logger.debug(`AppFlowParser: Parsed artifacts successfully for ${url}`);

      for (const singleArtifact of artifacts.output) {
        const safelyParsedArtifact = artifactSchema.safeParse(singleArtifact);
        if (safelyParsedArtifact.success) {
          logger.debug(`parseData: Found artifacts for ${url}`);

          singleArtifact["buildUrl"] = url;
          const promise = await appMgr.CreateNode("Artifact", singleArtifact);
        } else {
          logger.error(`Failed to parse artifacts (${JSON.stringify(safelyParsedArtifact)})`);
        }
      }
    } else {
      logger.info(`AppFlowParser: Did not find artifacts for ${url}`);
    }

    return artifacts;
  }

  async function parseHelmData(path: string, url: string, id: string): Promise<K8Description> {
    const k8Description = await parseK8Description(
      "helm", // family
      path, // data
      id, // id
      uuid, // uiid
    );

    return k8Description;
  }

  async function parseDotNetData(path: string, url: string, id: string) {
    const artifacts = await parseArtifacts(
      "dotnet-pipeline", // family
      path, // data
      id, // id
      uuid, // uiid
    );

    return artifacts;
  }

  async function parseTFStateData(jobTrace: string, url: string, id: string) {
    // Ask the oxparser to parse the artifact
    const artifacts = await parseArtifacts(
      "tfstate", // family
      jobTrace, // data
      id, // id
      uuid, // uiid
    );

    if (artifacts.success) {
      for (const singleArtifact of artifacts.output) {
        const safelyParsedArtifact = artifactSchema.safeParse(singleArtifact);
        if (safelyParsedArtifact.success) {
          logger.info(`parseArtifacts: Found artifacts for ${url}`);

          singleArtifact["buildUrl"] = url;

          await appMgr.CreateProductArtifact(singleArtifact);
        } else {
          logger.error(`Failed to parse artifacts (${JSON.stringify(safelyParsedArtifact)})`);
        }
      }
    }

    return artifacts;
  }

  return {
    //
    // Parse Job as a zip file
    //
    parseAsciiJob: async (jobTrace: string, pipelineName: string, id: string) => {
      const artifacts = [];
      artifacts.push(await parseData(jobTrace, pipelineName, id));
      return artifacts;
    },

    parseJob: async (jobsTrace: ArrayBuffer, pipelineName: string, id: string) => {
      const artifacts: ArtifactResult[] = [];
      if (jobsTrace && jobsTrace.byteLength > 2) {
        const buffer = new Uint8Array(jobsTrace);
        if (buffer[0] === 0x50 && buffer[1] === 0x4b) {
          // Zip file
          const { entries } = await unzip(jobsTrace);
          const parsingPromises: Promise<ArtifactResult>[] = [];

          let counter = 0;
          for (const [name, entry] of Object.entries(entries)) {
            const arrayBuffer = await entries[name].text();

            parsingPromises.push(parseData(arrayBuffer, pipelineName, `${id}-${counter++}`));
          }

          const results = await Promise.all(parsingPromises);
          for (const result of results) {
            if (result.success) {
              artifacts.push(result);
            }
          }
        } else {
          // Ascii Console file
          artifacts.push(await parseData(jobsTrace.toString(), pipelineName, id));
        }
      } else {
        // Empty file
      }

      return artifacts;
    },

    parseTFState: async (jobsTrace: ArrayBuffer, pipelineName: string, id: string) => {
      try {
        let buffer = new Uint8Array(jobsTrace);
        if (buffer[0] === 80 && buffer[1] === 75) {
          const { entries } = await unzip(jobsTrace);
          for (const [name, entry] of Object.entries(entries)) {
            const arrayBuffer = await entries[name].arrayBuffer();

            try {
              buffer = new Uint8Array(arrayBuffer);
              if (buffer[0] === 80 && buffer[1] === 75) {
                let entries_1 = await unzip(arrayBuffer);
                for (const [name_1, entry_1] of Object.entries(entries_1.entries)) {
                  if (name_1.endsWith("tfstate")) {
                    const arrayBuffer_1 = await entries_1.entries[name_1].text();

                    await parseTFStateData(arrayBuffer_1, pipelineName, id);
                  }
                }
              }
            } catch (error) {
              // Not sure we care about this
              logger.debug(`Inner zip failed with error: ${error}`);
            }
          }
        } else {
          logger.info("Not a zip file");
        }
      } catch (error) {
        logger.error(`Failed to parse terraform plan for ${pipelineName} with error: ${error}`);
      }
    },

    parseHelm: async (cloneDir: string, pipelineName: string, id: string): Promise<K8Description> => {
      try {
        logger.debug(`Parsing helm charts for ${cloneDir}:${pipelineName}`);
        return await parseHelmData(cloneDir, pipelineName, id);
      } catch (error) {
        logger.error(`Failed to parse helm for ${pipelineName} with error: ${error}`);
      }

      return {
        capabilities: {},
        cloudEnv: "AWS",
        images: [],
      };
    },

    parseDotnetPipeline: async (cloneDir: string, pipelineName: string, id: string): Promise<ArtifactResult> => {
      try {
        logger.info(`Parsing dotnet pipeline for ${cloneDir}:${pipelineName}`);
        return await parseDotNetData(cloneDir, pipelineName, id);
      } catch (error) {
        logger.error(`Failed to parse dotnet pipeline for ${pipelineName} with error: ${error}`);
      }

      return {
        success: false,
        output: [],
      };
    },
  };
};

export default AppFlowParser;
