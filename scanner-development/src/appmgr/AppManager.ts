import loggerImport from "../logger";
import redisCacheDB from "../cache/CacheInterface";
import { compress } from "../helper/compression/zStream";
import { multiMapDB } from "./MemoryDB";
import { repositoryComponent, ciToolComponent, ciJobComponent, artifactComponent } from "./ApplicationTypes";
import crypto from "crypto";
import { applicationFlow } from "../entitis/applicationsFlowTypes";
import * as fs from "fs";
import { OrchestratorSystem } from "../entitis/orchestratorTypes";
const logger = loggerImport.getDebugLogger();

export class PropertyCompactor {
  properties: any;

  constructor(properties) {
    this.properties = properties;
  }

  getCypherProperties() {
    let propertyString = "{";

    Object.entries(this.properties).forEach(([key, value]) => {
      if (value) {
        const valueString = value.toString();
        const valueProperty = valueString.replace(/['"\n\r\t]+/g, "");
        propertyString += `${key}:"${valueProperty}", `;
      }
    });

    propertyString += `ox_id:"${crypto.createHash("md5").update(`${propertyString}`).digest("hex")}"`;
    propertyString += "}";

    return propertyString;
  }
}

export class ApplicationManager {
  session: string;
  repoInMemoryDB = new multiMapDB<repositoryComponent>();
  citoolInMemoryDB = new multiMapDB<ciToolComponent>();
  ciJobInMemoryDB = new multiMapDB<ciJobComponent>();
  artifactInMemoryDB = new multiMapDB<artifactComponent>();
  productArtifactInMemoryDB = new multiMapDB<artifactComponent>();
  kubernetesArtifactInMemoryDB = new multiMapDB<artifactComponent>();

  constructor(session) {
    this.session = session; //Unique identifier
  }

  async CreateRepoNode(properties) {
    properties["type"] = "repository";
    properties["id"] = properties["repo_name"];
    redisCacheDB.instance.multiSet(this.session, properties);
  }

  async CreateAppNode(properties) {}

  async CreateCITool(properties, tool) {
    properties["type"] = "citool";
    properties["tool"] = tool;
    properties["id"] = properties["vcs_url"];
    redisCacheDB.instance.multiSet(this.session, properties);
  }

  async CreateCIJob(properties) {
    properties["type"] = "cijob";
    properties["id"] = properties["repo_name"];
    redisCacheDB.instance.multiSet(this.session, properties);
  }

  async CreateConfigArtifact(properties) {
    logger.error("CreateConfigArtifact not implemented");
  }

  async CreateProductArtifact(properties) {
    properties["type"] = "Product Artifact";
    properties["id"] = properties["image"];
    redisCacheDB.instance.multiSet(this.session, properties);
  }

  async RetainProductArtifact(properties) {
    //
    // in case we have cached artifacts
    //
    redisCacheDB.instance.multiSet(this.session, properties);
  }

  async CreateKubernetesArtifact(properties) {
    properties["type"] = "Kubernetes";
    properties["id"] = properties["buildUrl"];
    redisCacheDB.instance.multiSet(this.session, properties);
  }

  // General function to create any node with properties
  async CreateNode(node, properties) {
    switch (node) {
      case "Artifact":
        //properties["type"] = "artifact";
        properties["id"] = properties["buildUrl"];
        redisCacheDB.instance.multiSet(this.session, properties);
        break;
      default:
        logger.debug(`${node} not implemented`);
    }
  }

  async generateConnections(removeFromCache = true) {
    let connections = [];
    logger.info(`ApplicationManager generateConnections: ${this.session}`);

    // Generate text report and zip it
    if (this.session) {
      if (removeFromCache) {
        for (;;) {
          const connection = await redisCacheDB.instance.multiGet(this.session);

          if (connection === null) {
            break; // We are done!
          }

          connections.push(connection);
        }
      } else {
        const numberOfElements = (await redisCacheDB.instance.getLen(this.session)) as any;
        for (let i = 0; i < numberOfElements; i++) {
          const connection = await redisCacheDB.instance.getIndex(this.session, i);
          connections.push(connection);
        }
      }

      logger.info(`ApplicationManager number of connection: ${connections.length}`);

      for (const connection of connections) {
        switch (connection.type) {
          case "repository":
            this.repoInMemoryDB.set(connection);
            break;
          case "citool":
            this.citoolInMemoryDB.set(connection);
            break;
          case "cijob":
            this.ciJobInMemoryDB.set(connection);
            break;
          case "Product Artifact":
            this.productArtifactInMemoryDB.set(connection);
            break;
          case "kubernetesArtifact":
            this.kubernetesArtifactInMemoryDB.set(connection);
            break;
          case "Kubernetes":
            this.kubernetesArtifactInMemoryDB.set(connection);
            break;

          // Anything without explicit type is an artifact
          default:
            this.artifactInMemoryDB.set(connection);
            break;
        }
      }

      logger.info(`Application Manager stats:`);
      logger.info(`Application Manager stats (repoInMemoryDB): ${this.repoInMemoryDB.thisMap().size}`);
      logger.info(`Application Manager stats (citoolInMemoryDB): ${this.citoolInMemoryDB.thisMap().size}`);
      logger.info(`Application Manager stats (ciJobInMemoryDB): ${this.ciJobInMemoryDB.thisMap().size}`);
      logger.info(`Application Manager stats (artifactInMemoryDB): ${this.artifactInMemoryDB.thisMap().size}`);
      logger.info(`Application Manager stats (productArtifactInMemoryDB): ${this.productArtifactInMemoryDB.thisMap().size}`);
      logger.info(`Application Manager stats (kubernetesArtifactInMemoryDB): ${this.kubernetesArtifactInMemoryDB.thisMap().size}`);

      const smallConnections = await compress(JSON.stringify(connections));

      logger.debug(`ApplicationManager smallConnections: ${smallConnections}`);

      if (process.env.RETAIN_CONNECTIONS === "true") {
        fs.writeFileSync("connections.zlib", smallConnections);
      }

      return smallConnections;
    }

    return JSON.stringify(connections);
  }

  async generateApplicationFlowsFromMemory(): Promise<applicationFlow> {
    logger.info(`ApplicationManager generateApplicationFlowsFromMemory called`);

    return new Promise(async (resolve, reject) => {
      const emptyApplicationFlows = { flow: [] };
      let applicationFlows = { flow: [] };
      const uniqueArtifacts = new Set<string>();
      const uniqueCloudDeployments = new Set<string>();

      try {
        const repos = await this.repoInMemoryDB.thisMap().values();

        for (const repo of repos) {
          let citools = await this.citoolInMemoryDB.get(repo.values[0].url);

          if (citools) {
            for (const citool of citools.values) {
              let applicationFlow = {
                repo: repo.id,
                cicd: citool.tool,
                artifacts: [],
                orchestrator: [],
                kubernetes: [],
                cloudDeployment: [],
              };

              if (citool) {
                let ciJobs = await this.ciJobInMemoryDB.get(citool.reponame);
                if (ciJobs) {
                  for (const ciJob of ciJobs.values) {
                    if (ciJob) {
                      let artifacts = await this.artifactInMemoryDB.get(ciJob.buildUrl);

                      if (artifacts) {
                        for (const artifact of artifacts.values) {
                          const artifactId = `${artifact.name}:${artifact.hash}`;
                          if (uniqueArtifacts.has(artifactId)) continue;
                          uniqueArtifacts.add(artifactId);

                          logger.debug(
                            `ApplicationManager::generateApplicationFlowsFromMemory found ${artifacts.values.length} artifacts for ${repo.id}`,
                          );

                          if (artifact) {
                            if (
                              artifact.type.toLowerCase() === OrchestratorSystem.Helm.toLowerCase() ||
                              artifact.type.toLowerCase() === OrchestratorSystem.Terraform.toLowerCase() ||
                              artifact.type.toLowerCase() === OrchestratorSystem.TerraformPlan.toLowerCase()
                            ) {
                              applicationFlow.orchestrator.push({
                                type: artifact.type,
                                subType: artifact.subType,
                                name: artifact.name,
                                size: artifact.size,
                                hashType: artifact.hashType,
                                hash: artifact.hash,
                              });
                            } else {
                              //
                              // Lets check here if we have a product artifact (artifact that actually deployed to the cloud)
                              //
                              let productArtifact = await this.productArtifactInMemoryDB.get(artifact.name);

                              if (productArtifact) {
                                const cloudProductArtifact = `${productArtifact.values[0].image}:${productArtifact.values[0].version}`;
                                if (uniqueCloudDeployments.has(cloudProductArtifact)) continue;
                                uniqueCloudDeployments.add(cloudProductArtifact);

                                applicationFlow.cloudDeployment.push({
                                  type: "AWS",
                                  subType: "ecs",
                                  name: `${productArtifact.values[0].image}:${productArtifact.values[0].version}`,
                                });
                              } else {
                                applicationFlow.artifacts.push({
                                  type: artifact.type,
                                  subType: artifact.subType,
                                  name: artifact.name,
                                  size: artifact.size,
                                  hashType: artifact.hashType,
                                  hash: artifact.hash,
                                });
                              }
                            }
                          }
                        }
                      }

                      let kubernetesArtifacts = await this.kubernetesArtifactInMemoryDB.get(ciJob.buildUrl);

                      if (kubernetesArtifacts) {
                        for (const kubernetesArtifact of kubernetesArtifacts.values) {
                          const kubernetesArtifactId = `${kubernetesArtifact.name}:${kubernetesArtifact.hash}`;
                          if (uniqueArtifacts.has(kubernetesArtifactId)) continue;
                          uniqueArtifacts.add(kubernetesArtifactId);

                          logger.debug(
                            `ApplicationManager::generateApplicationFlowsFromMemory found ${kubernetesArtifacts.values.length} kubernetes artifacts for ${repo.id}`,
                          );

                          if (kubernetesArtifact) {
                            applicationFlow.kubernetes.push({
                              type: kubernetesArtifact.type,
                              subType: kubernetesArtifact.subType,
                              name: `${kubernetesArtifact.image}:${kubernetesArtifact.version}`,
                              size: kubernetesArtifact.size,
                              hashType: kubernetesArtifact.hashType,
                              hash: kubernetesArtifact.hash,
                            });
                          }
                        }
                      }
                    }
                  }
                }
              }

              applicationFlows.flow.push(applicationFlow);
            }
          } else {
            applicationFlows.flow.push({
              repo: repo.id,
              cicd: null,
              artifacts: [],
              orchestrator: [],
              cloudDeployment: [],
            });
          }
        }

        resolve(applicationFlows);
      } catch (error) {
        logger.error(`Error generating application flows from memory: ${error}`);
        resolve(emptyApplicationFlows);
      }
    });
  }
}

export class Neo4JApplicationManager {
  session: string;

  constructor(session) {
    this.session = session; //Unique identifier
  }

  async CreateRepoNode(properties) {
    const repoProperties = new PropertyCompactor(properties);
    const cypherCommand = `CREATE (n:Repository ${repoProperties.getCypherProperties()})`;

    redisCacheDB.instance.multiSet(this.session, cypherCommand);
  }

  async CreateAppNode(properties) {
    redisCacheDB.instance.multiSet(this.session, properties);
  }

  async CreateCITool(properties, tool) {
    properties["tool"] = tool;
    const repoProperties = new PropertyCompactor(properties);
    const cypherCommand = `CREATE (n:CITool ${repoProperties.getCypherProperties()})`;

    redisCacheDB.instance.multiSet(this.session, cypherCommand);
  }

  async CreateCIJob(properties) {
    const repoProperties = new PropertyCompactor(properties);
    const cypherCommand = `CREATE (n:CIJob ${repoProperties.getCypherProperties()})`;

    redisCacheDB.instance.multiSet(this.session, cypherCommand);
  }

  async CreateConfigArtifact(properties) {
    const repoProperties = new PropertyCompactor(properties);
    const cypherCommand = `CREATE (n:ConfigArtifact ${repoProperties.getCypherProperties()})`;

    redisCacheDB.instance.multiSet(this.session, cypherCommand);
  }

  async CreateProductArtifact(properties) {
    const repoProperties = new PropertyCompactor(properties);
    const cypherCommand = `CREATE (n:ProductArtifact ${repoProperties.getCypherProperties()})`;

    redisCacheDB.instance.multiSet(this.session, cypherCommand);
  }

  // General function to create any node with properties
  async CreateNode(node, properties) {
    const repoProperties = new PropertyCompactor(properties);
    const cypherCommand = `CREATE (n:${node} ${repoProperties.getCypherProperties()})`;

    redisCacheDB.instance.multiSet(this.session, cypherCommand);
  }

  async generateConnections() {
    let connections = [];

    // Generate text report and zip it
    if (this.session) {
      for (;;) {
        const connection = await redisCacheDB.instance.multiGet(this.session);

        if (connection === null) {
          break; // We are done!
        }

        connections.push(connection);
      }

      const smallConnections = await compress(JSON.stringify(connections));

      if (process.env.DEBUG_CIRCLECI === "yes") {
        if (connections.length > 0) {
          for (const connection of connections) {
            logger.info(`Found connection: ${connection}`);
          }
          logger.info(`Connections: ${smallConnections}`);
        }
      }

      return smallConnections;
    }

    return JSON.stringify(connections);
  }
}

export class AppConnector {
  token: string;
  key: string;

  constructor(token) {
    this.token = token;
    this.key = this.token + "key://UUID";
  }

  async setUUID(uid) {
    redisCacheDB.instance.set(this.key, uid);
  }

  async getUUID() {
    const cachedResult = await redisCacheDB.instance.get(this.key);
    return cachedResult;
  }
}
