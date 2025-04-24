const dotenv = require("dotenv");
dotenv.config();
import mongoose from "mongoose";
import loggerImport from "../../logger";
import { SbomSchema } from "../../mongo/sbom/model/sbom-schema";
import { IssueSchema } from "../../mongo/schemas";
import { CurrentIssuesIndexes, SbomIndexes, SearchIndexCollections } from "./searchIndexDefinition";
import { AtlasIndexFormat, SearchIndexPayload } from "./searchIndexTypes";
const urllib = require("urllib");
const logger = loggerImport.getDebugLogger();

const projectID = process.env.MONGO_PROJECTID || null;
const clusterName = process.env.ATLAS_CLUSTER_NAME || null;
const publicKey = process.env.ATLAS_API_PUBLIC_KEY || null;
const privateKey = process.env.ATLAS_API_PRIVATE_KEY || null;

const baseUrl = `https://cloud.mongodb.com/api/atlas/v1.0/groups/${projectID}/clusters/${clusterName}/fts/indexes`;
const digestAuth = `${publicKey}:${privateKey}`;

//collection name and indexes mapper
const indexCollectionMap = {
  "current-issues": CurrentIssuesIndexes,
  sboms: SbomIndexes,
};

export const initiateSearchIndexCreation = async (orgId: string, collectionName: string) => {
  logger.info(`initiateSearchIndexCreation called for org:${orgId}, collection: ${collectionName}`);
  const indexes = indexCollectionMap[collectionName];
  const createIndexProms = indexes.map(index => {
    return createIndex(index, orgId);
  });
  const createIndexResponse = await Promise.all(createIndexProms);
  const result = createIndexResponse.every(i => i === true);
  logger.info(`searchIndex response for org:${orgId}, collection: ${collectionName}, IS: ${result}`);
  return result;
};

export const createIndex = async (input: AtlasIndexFormat, orgId: string) => {
  try {
    let payload: SearchIndexPayload = {
      analyzer: input.index.analyzer,
      analyzers: input.index.analyzers,
      collectionName: input.collectionName,
      database: orgId,
      mappings: input.index.mappings,
      name: input.indexName,
      searchAnalyzer: input.index.analyzer,
    };
    logger.info(`called for createIndex: ${JSON.stringify(orgId)}`);
    const API_URL = `${baseUrl}?envelope=true&pretty=true`;
    logger.info(`API_URL for createIndex: ${JSON.stringify(API_URL)}`);

    const createIndexResponse = await urllib.request(API_URL, {
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      digestAuth,
      method: "POST",
      data: payload,
    });
    logger.info(`createIndexResponse: ${createIndexResponse.status}`);
    if (createIndexResponse && createIndexResponse.data) {
      const { content } = JSON.parse(createIndexResponse.data.toString());
      if (content) {
        logger.info(`search index content: ${JSON.stringify(content)}`);
      }
      return true;
    } else return false;
  } catch (err) {
    logger.error(`failed for ${orgId}; Error: ${err}`);
    return false;
  }
};

export const updateIndex = async (input, orgId) => {
  const databaseName = orgId;
  const collectionName = input.collectionName;
  const indexName = input.indexName;
  const indexes = await getAllIndexesForCollectionName(databaseName, collectionName);
  let payload: SearchIndexPayload = {
    analyzer: input.index.analyzer,
    analyzers: input.index.analyzers,
    collectionName: input.collectionName,
    database: orgId,
    mappings: input.index.mappings,
    name: input.indexName,
    searchAnalyzer: input.index.analyzer,
  };
  if (indexes && indexes.length > 0) {
    const indexObj = indexes.find(i => i.name === indexName);
    if (indexObj && indexObj.indexID) {
      const indexID = indexObj.indexID;
      const updateIndexUrl = `${baseUrl}/${indexID}`;
      const updateIndex = await urllib.request(updateIndexUrl, {
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
        },
        digestAuth,
        method: "PATCH",
        data: payload,
      });
      console.log("updateIndex response", updateIndex);
      return;
    } else {
      logger.info(`indexObj not found ${JSON.stringify(indexObj)}`);
      return null;
    }
  } else {
    logger.info(`indexes not found ${JSON.stringify(indexes)}`);
    return null;
  }
};

export const dropIndex = () => {};

export const getAllIndexesForCollectionName = async (databaseName: string, collectionName: string) => {
  const url = `${baseUrl}/${databaseName}/${collectionName}?envelope=true&pretty=true`;
  try {
    const response = await urllib.request(url, {
      headers: {
        Accept: "application/json",
        "Content-Type": "application/json",
      },
      digestAuth,
      method: "GET",
    });
    if (response && response.data) {
      const { content } = JSON.parse(response.data.toString());
      return content;
    } else return null;
  } catch (error) {
    logger.error(`failed getAllIndexesForCollectionName for ${databaseName}; Error: ${error}`);
    return null;
  }
};

export const checkIfSearchIndexNeedsToBeCreated = (collectionName: string) => {
  const searchIndexCollections = SearchIndexCollections();
  const exists = searchIndexCollections.includes(collectionName);
  if (exists) return true;
  return false;
};

export const checkIfSearchIndexExists = async (orgId: string, collectionName: string, indexName: string) => {
  const response = await getAllIndexesForCollectionName(orgId, collectionName);
  if (response && (response.length !== 0 || response[0]?.name === indexName)) {
    return true;
  }
  return false;
};

const getSearchIndexNameForCollection = (collectionName: string) => {
  const indexes = indexCollectionMap[collectionName];
  if (indexes?.length > 0) {
    return indexes[0].indexName;
  }
  return null;
};

export const CollectionSchemaMap = () => {
  return [
    {
      collectionName: "current-issues",
      schemaName: "current-issues",
      schema: IssueSchema,
    },
    {
      collectionName: "sboms",
      schemaName: "sboms",
      schema: SbomSchema,
    },
  ];
};

export const mongoSyncSearchIndex = async (connection: mongoose.Connection, orgId: string, uuid: string) => {
  try {
    if (!projectID || !clusterName || !publicKey || !privateKey) {
      logger.info(`ATLAS SEARCH env vars not found; search index failed for ${orgId}  `);
      return false;
    }
    const searchIndexCollections = CollectionSchemaMap();
    const collectionNames = searchIndexCollections.map(col => col.collectionName);
    logger.info(`mongoSyncSearchIndex called for org:${orgId} and uuid:${uuid}, collectionNames: ${collectionNames}`);
    const searchIndexProms = collectionNames.map(collectionName => createSearchIndexIfNecessary(connection, orgId, collectionName));
    await Promise.all(searchIndexProms);
    return true;
  } catch (error) {
    logger.error(`failed mongoSyncSearchIndex for ${orgId}; Error: ${error}`);
    return false;
  }
};

async function createSearchIndexIfNecessary(connection: mongoose.Connection, orgId: string, collectionName: string) {
  const createSearchIndex = checkIfSearchIndexNeedsToBeCreated(collectionName);
  logger.info(`createSearchIndex for org:${orgId}, collection: ${collectionName}, createSearchIndex: ${createSearchIndex}`);
  if (!createSearchIndex) {
    return;
  }
  const indexNameForCollection = getSearchIndexNameForCollection(collectionName);
  const collectionExists = await connection.db.listCollections({ name: collectionName }).hasNext();
  logger.info(`collectionExists:${collectionExists},collectionName:${collectionName} `);
  if (!collectionExists) {
    await connection.db.createCollection(collectionName);
    logger.info(`search index called for ${orgId} & coll: ${collectionName} `);
    await initiateSearchIndexCreation(orgId, collectionName);
  } else {
    const ifSearchIndexExists = await checkIfSearchIndexExists(orgId, collectionName, indexNameForCollection);
    logger.info(
      `ifSearchIndexExists: ${ifSearchIndexExists} for ${orgId} & coll: ${collectionName}, indexNameForCollection:${indexNameForCollection} `,
    );
    if (!ifSearchIndexExists) {
      await initiateSearchIndexCreation(orgId, collectionName);
    }
  }
  return true;
}
