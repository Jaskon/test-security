import memoryDB from "@oxappsec/ox-memory-db";
import { gql, GraphQLClient } from "graphql-request";
import {
  artifactType,
  DockerSearchCriteria,
  EnrichedDockerSearchResult,
  K8Description,
  Pagination,
  SCM,
  Session,
} from "../entitis/ArtifactTypes";
import { compress } from "../helper/compression/zStream";
import { isLocalDevelopment } from "../helper/envUtils";
import { hash } from "../helper/hash";
import { TimeOp } from "../helper/performance";
import loggerImport from "../logger";
import OXParserToolHandler, { scanPath, sendEnrichMessagesToToolRunner, sendParseMessagesToToolRunner } from "./OXParserToolHandler";
import { ParsingRequest } from "./OXParserToolHandlerTypes";
const logger = loggerImport.getDebugLogger();

const disableParsing = process.env.DISABLE_ARTIFACTE != undefined;

export interface ArtifactResult {
  success: boolean;
  output: artifactType[];
}

export async function parseArtifacts(family, file, id, uuid): Promise<ArtifactResult> {
  const failedResult: ArtifactResult = {
    success: false,
    output: [],
  };

  //kosta
  return failedResult;

  if (disableParsing) {
    return failedResult;
  }

  if (process.env.OX_PARSER_ASA_TOOL) {
    try {
      const failedSet = new Set<string>();

      const hashedId = hash(id);
      const hashedLogId = hash(hashedId);
      await memoryDB.queueSet.execute(hashedLogId, 300, await compress(file));

      const currentMessage: ParsingRequest = {
        id: hashedId,
        uuid: uuid,
        logs: [hashedLogId],
      };

      const promisesBatch = await OXParserToolHandler.sendAndWaitRequest(
        [currentMessage],
        failedSet,
        sendParseMessagesToToolRunner,
        scanPath.getOutputFolderForOXResults(isLocalDevelopment()),
      );

      await Promise.all(promisesBatch);

      const data = await memoryDB.queueGet.execute(hashedLogId);
      OXParserToolHandler.cleanUp(hashedLogId);
      await memoryDB.queueDel.execute(hashedId);
      memoryDB.del.execute(hashedLogId);

      if (failedSet.size > 0) {
        logger.error(`Failed to parse ${hashedId} using OX Parser Tool, check K8s logs`);
      }

      try {
        const outputResult = JSON.parse(data);
        return { success: true, output: outputResult };
      } catch (err) {
        logger.info(`parseArtifacts(hashLogId: ${hashedLogId}, id: ${hashedId}, uuid: ${uuid}) - ${err}`);
      }

      return failedResult;
    } catch (e) {
      logger.error(`Failed to parse logs using OX Parser tool with error: ${e}`);
    }

    return failedResult;
  }

  const retryCountMax = process.env.RETRY_COUNT ? parseInt(process.env.RETRY_COUNT) : 4;

  for (let retryCount = 0; retryCount < retryCountMax; retryCount++) {
    // Generate application data
    try {
      const endpoint = `http://${process.env.OXPARSER_HOST}:${process.env.OXPARSER_PORT}/oxparser`;

      const graphQLClient = new GraphQLClient(endpoint, {
        timeout: 300000,
        headers: {
          authorization: `Bearer empty`,
        },
      });

      const compressedFile = await compress(file);

      const query = gql`
        query {
          enhancedParser(uuid:"${uuid}", family:"${family}", file:"${compressedFile}", id:"${id}")
          }`;

      const data = await graphQLClient.request(query);

      switch (family) {
        case "helm":
        case "tfstate":
        case "dotnet-pipeline":
        case "any":
          {
            const parsingResult: artifactType[] = JSON.parse(data.enhancedParser);
            return { success: true, output: parsingResult };
          }
          break;
        case "docker": // BC
          {
            // Deprecated
            // const parsingResult: artifactType = JSON.parse(data.enhancedParser);
            // if (parsingResult.resolved)
            //   return { success: true, output: parsingResult };
          }
          break;
      }

      return failedResult;
    } catch (err) {
      logger.error(`parseArtifacts failed: ${err}, retryCount: ${retryCount}`);

      if ("code" in err && err.code === "ECONNREFUSED") {
        const delay = ms => new Promise(res => setTimeout(res, ms));
        await delay(1000 * 15);
      }
    }
  }

  return failedResult;
}

export async function parseK8Description(family, file, id, uuid): Promise<K8Description> {
  const failedResult: K8Description = {
    capabilities: {},
    cloudEnv: "AWS",
    images: [],
  };

  if (process.env.OX_PARSER_ASA_TOOL) {
    return failedResult;
  }

  const retryCountMax = process.env.RETRY_COUNT ? parseInt(process.env.RETRY_COUNT) : 4;

  for (let retryCount = 0; retryCount < retryCountMax; retryCount++) {
    // Generate application data
    try {
      if (disableParsing) {
        return failedResult;
      }

      const endpoint = `http://${process.env.OXPARSER_HOST}:${process.env.OXPARSER_PORT}/oxparser`;

      const graphQLClient = new GraphQLClient(endpoint, {
        timeout: 300000,
        headers: {
          authorization: `Bearer empty`,
        },
      });

      const compressedFile = await compress(file);

      const query = gql`
        query {
          enhancedParser(uuid:"${uuid}", family:"${family}", file:"${compressedFile}", id:"${id}")
          }`;

      const data = await graphQLClient.request(query);

      switch (family) {
        case "helm":
          {
            const parsingResult: K8Description = JSON.parse(data.enhancedParser);
            return parsingResult;
          }
          break;
      }

      return failedResult;
    } catch (err) {
      logger.error(`parseK8Description failed: ${err}, retryCount: ${retryCount}`);

      if ("code" in err && err.code === "ECONNREFUSED") {
        const delay = ms => new Promise(res => setTimeout(res, ms));
        await delay(1000 * 15);
      }
    }
  }

  return failedResult;
}

export async function enrichArtifacts(
  session: Session,
  scm: SCM,
  searchFor: DockerSearchCriteria,
  pagination: Pagination,
): Promise<EnrichedDockerSearchResult> {
  const failedResult: EnrichedDockerSearchResult = {
    results: {
      items: searchFor,
      jobId: "",
    },
    pagination: {
      page: "0",
      size: "0",
      maxSize: "0",
    },
  };

  if (disableParsing) {
    return failedResult;
  }

  // Generate application data
  try {
    const query = gql`
    query {
      enrichedParser(session: {uuid: "${session.uuid}", orgId: "${session.orgId}"}, scm: {type: "${scm.type}", id: "${scm.id}", site: "${
      scm.site
    }", token: "${scm.token}", scanAll: "${scm.scanAll ? scm.scanAll : "false"}"}, searchCriteria: {imageUri: "${
      searchFor.imageUri
    }", tag: "${searchFor.tag}", digest: "${searchFor.digest}", date: "${searchFor.date ? searchFor.date : ""}"}, pagination: {page: "${
      pagination.page
    }", size: "${pagination.size}", maxSize:"${pagination.maxSize}"})
          {
            results: results {
              jobId
            }
            pagination: pagination {
              page
              size
              maxSize
            }
          }}`;

    const enrichOpDuration = TimeOp();

    enrichOpDuration.start();

    let data = undefined;

    if (process.env.OX_PARSER_ASA_TOOL) {
      try {
        const failedSet = new Set<string>();

        const hashedId = hash(query);
        const hashedLogId = hash(hashedId);

        logger.info(`EnrichArtifacts: ${JSON.stringify(query)}, id: (${hashedId}), logId: (${hashedLogId})`);

        await memoryDB.queueSet.execute(hashedLogId, 900, query);

        const currentMessage: ParsingRequest = {
          id: hashedId,
          uuid: session.uuid,
          logs: [hashedLogId],
        };

        const promisesBatch = await OXParserToolHandler.sendAndWaitRequest(
          [currentMessage],
          failedSet,
          sendEnrichMessagesToToolRunner,
          scanPath.getOutputFolderForOXResults(isLocalDevelopment()),
          1, // Send one every second
          1, // Retry 3 times
        );

        await Promise.all(promisesBatch);

        const data = await memoryDB.queueGet.execute(hashedLogId);
        OXParserToolHandler.cleanUp(hashedLogId);
        await memoryDB.queueDel.execute(hashedId);
        await memoryDB.queueDel.execute(hashedLogId);

        if (failedSet.size > 0) {
          logger.error(`Failed to enrich ${hashedId} using OX Parser Tool, check K8s logs`);
        }

        logger.info(`Received ${JSON.stringify(data)} after enriching, and took: ${enrichOpDuration.end()}`);

        return JSON.parse(data);
      } catch (e) {
        logger.error(`Failed to enrich logs using OX Parser tool with error: ${e}`);
      }

      return failedResult;
    } else {
      const endpoint = `http://${process.env.OXPARSER_HOST}:${process.env.OXPARSER_PORT}/oxparser`;

      const graphQLClient = new GraphQLClient(endpoint, {
        timeout: 300000,
        headers: {
          authorization: `Bearer empty`,
        },
      });

      logger.info(`EnrichArtifacts: ${JSON.stringify(query)}`);
      data = await graphQLClient.request(query);

      if (data && data.enrichedParser) {
        logger.info(`Received ${JSON.stringify(data)} after enriching, and took: ${enrichOpDuration.end()}`);
        return data.enrichedParser;
      } else {
        logger.error(`Received empty data after enriching, and took: ${enrichOpDuration.end()}`);
      }

      return failedResult;
    }
  } catch (err) {
    logger.error(`enrichArtifacts(${JSON.stringify(searchFor)}) failed: ${err}`);
  }
  return failedResult;
}

export async function getOXParserVersion(): Promise<string> {
  const initialVersion = "0.0.0.1";

  if (process.env.OX_PARSER_ASA_TOOL) {
    return initialVersion;
  }

  const retryCountMax = process.env.RETRY_COUNT ? parseInt(process.env.RETRY_COUNT) : 10;

  for (let retryCount = 0; retryCount < retryCountMax; retryCount++) {
    try {
      const endpoint = `http://${process.env.OXPARSER_HOST}:${process.env.OXPARSER_PORT}/oxparser`;

      const graphQLClient = new GraphQLClient(endpoint, {
        timeout: 300000,
        headers: {
          authorization: `Bearer empty`,
        },
      });

      const query = gql`
        query {
          getProductVersion
        }
      `;

      logger.info(`GetVersion: ${JSON.stringify(query)}`);
      const data: any = await graphQLClient.request(query);

      if (data && data.getProductVersion) {
        logger.info(`Received ${JSON.stringify(data)} after asking for Parser version`);

        return data.getProductVersion;
      } else {
        logger.error(`Received empty data asking for a Parser version`);
      }

      return initialVersion;
    } catch (err) {
      logger.warn(`getOXParserVersion failed with error: ${err}, retry count: ${retryCount}`);

      //No need to wait in case its local and the service is not running
      if (isLocalDevelopment()) {
        return initialVersion;
      }

      if ("code" in err && err.code === "ECONNREFUSED") {
        const delay = ms => new Promise(res => setTimeout(res, ms));
        await delay(1000 * 30);
      }
    }
  }

  return initialVersion;
}
