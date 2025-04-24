import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();
import { ApplicationManager } from "./AppManager";
import { GraphQLClient, gql } from "graphql-request";
import { applicationFlow, applicationFlowSchema } from "../entitis/applicationsFlowTypes";
import { performance } from "perf_hooks";

export async function fetchApplications(uid, org, token = "NO_TOKEN") {
  const applications = new Set();

  // Generate application data
  try {
    const conn = new ApplicationManager(uid);
    const connection = await conn.generateConnections();

    const endpoint = `http://${process.env.APPMGR_HOST}:${process.env.APPMGR_PORT}/appmgr`;

    const graphQLClient = new GraphQLClient(endpoint, {
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    const query = gql`
        mutation {
          createApplications(org:"${org}", applications:"${connection}")
        }`;

    const data = await graphQLClient.request(query);

    const detectedApplications = JSON.parse(data.createApplications);

    for (const app of detectedApplications) {
      applications.add(app.applicationName);
    }
  } catch (err) {
    logger.error(`failed generate application data, err: ${err}`);
  }

  return applications;
}

export async function fetchApplicationFlowJson(org, token = "NO_TOKEN") {
  const applicationFlowJson = { flow: [] };

  // Generate application data
  try {
    const endpoint = `http://${process.env.APPMGR_HOST}:${process.env.APPMGR_PORT}/appmgr`;

    const graphQLClient = new GraphQLClient(endpoint, {
      headers: {
        authorization: `Bearer ${token}`,
      },
    });

    const query = gql`
        mutation {
          createApplicationFlows(org:"${org}")
        }`;

    const data = await graphQLClient.request(query);

    const applicationFlows: applicationFlow = JSON.parse(data.createApplicationFlows);

    const applicationFlowParsingResult = applicationFlowSchema.safeParse(applicationFlows);
    if (applicationFlowParsingResult.success) {
      logger.info(`successfully parsed application flow json`);
      return applicationFlows;
    } else {
      logger.error(`failed to parse application flow json see error (${JSON.stringify(applicationFlowParsingResult)})`);
      return applicationFlowJson;
    }
  } catch (err) {
    logger.error(`failed generate application data, err: ${err}`);
  }

  return applicationFlowJson;
}

export async function fetchApplicationsFromMemory(uid, org, token = "NO_TOKEN") {
  const applications = new Set();

  // Generate application data
  try {
    // const conn = new ApplicationManager(uid);
    // const connection = await conn.generateConnections();
    // Todo (kyz)
  } catch (err) {
    logger.error(`failed generate application data from memory, err: ${err}`);
  }

  return applications;
}

export async function fetchApplicationFlowJsonFromMemory(uid, org, token = "NO_TOKEN") {
  const applicationFlowJson = { flow: [] };
  // Generate application data
  try {
    logger.info(`Application Manager performance test`);
    const start = performance.now();

    const conn = new ApplicationManager(uid);
    const connection = await conn.generateConnections();
    const applicationFlows: applicationFlow = await conn.generateApplicationFlowsFromMemory();

    const end = performance.now();
    logger.info(`Application Manager performance test took ${end - start} milliseconds.`);

    const applicationFlowParsingResult = applicationFlowSchema.safeParse(applicationFlows);
    if (applicationFlowParsingResult.success) {
      logger.info(`successfully parsed application flow json`);
      return [applicationFlows, connection];
    } else {
      logger.error(`failed to parse application flow json see error (${JSON.stringify(applicationFlowParsingResult)})`);
      return [applicationFlowJson, ""];
    }
  } catch (err) {
    logger.error(`failed generate application data, err: ${err}`);
  }

  return [applicationFlowJson, ""];
}
