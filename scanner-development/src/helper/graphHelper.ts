const fs = require("fs");

import loggerImport from "../logger";
import { DotGraph } from "./dotGraph";
import { ExtendedSbomComponent } from "./sbom/sbomHelper";
import StatesHelper from "./statesHelper";
var zlib = require("zlib");

const logger = loggerImport.getDebugLogger();

export class Edge {
  v: string;
  w: string;
}

export class IssueCount {
  appox: number = 0;
  critical: number = 0;
  high: number = 0;
  medium: number = 0;
  low: number = 0;
  info: number = 0;
}

export class Position {
  x: number;
  y: number;
}

export class Node {
  position: Position = new Position();
  id: string;
  name: string;
  fullName: string; // Temp until Eyal's fix
  width: number = 200;
  height: number = 50;
  vulnerable: boolean = false;
  issues: IssueCount = new IssueCount();
}

class GraphHelper {
  async setGraphBasedOnSboms(libs: ExtendedSbomComponent[], dependencyGraphResponses: any[], fullName: string): Promise<void> {
    try {
      const libMap = libs.reduce((acc, lib) => {
        acc.set(lib.blame.uid, lib);
        return acc;
      }, new Map<string, ExtendedSbomComponent>());

      const uniqueTriggerLibs = new Set();
      let duplicate = 0;

      for (const dependeRes of dependencyGraphResponses) {
        const depGraph = dependeRes?.triggerPackage?.dependencyGraph;
        delete dependeRes?.triggerPackage?.dependencyGraph;
        try {
          if (!dependeRes?.uid || !depGraph) {
            continue;
          }
          const lib = libMap.get(dependeRes.uid);
          if (!lib) {
            continue;
          }
          lib.triggerPackage = `${dependeRes.triggerPackage.name}@${dependeRes.triggerPackage.version}`;
          if (lib.triggerPackage !== `${lib.name}@${lib.version}`) {
            // Don't save dep graph for indirect dependency (direct dep should be named same as trigger package)
            continue;
          }

          if (uniqueTriggerLibs.has(lib.triggerPackage)) {
            duplicate++;
            continue;
          }
          uniqueTriggerLibs.add(lib.triggerPackage);

          const graphData = await handleGraph(depGraph, fullName, lib.triggerPackage);
          if (!graphData) {
            continue;
          }

          lib.dependencyGraphNodes = graphData.nodes;
          lib.dependencyGraphEdges = graphData.edges;
        } catch (err) {
          logger.error(`Cannot set dep graph for repo ${fullName}. Error: ${err}`);
        }
      }

      if (duplicate > 0) {
        logger.error(`something went wrong, have ${duplicate} duplicate trigger pkg in set graph for sbom`);
      }
    } catch (err) {
      logger.error(`Cannot for all set dep graph for repo: ${fullName}. Error: ${err}`);
    }
  }
}

export default GraphHelper;

export async function handleGraph(
  graphString: string,
  fullName: string,
  triggerPackage: string,
): Promise<{ nodes: Node[]; edges: Edge[] } | undefined> {
  const dotGraph = await DotGraph.decodeAndParseGraph<{ pos: string; fullName: string; version: string }>(graphString);
  if (!dotGraph) {
    return;
  }
  //Dont increase this!
  if (dotGraph.nodes.length > 750) {
    logger.warn(
      `too big edgeC count: ${dotGraph.edges.length}, nodesC count: ${dotGraph.nodes.length}, for ${fullName}, triggerPackage: ${triggerPackage}`,
    );
    StatesHelper.Instance.scanInfoStats.hugeNodeCount++;
    return;
  }
  const newNodes = dotGraph.nodes.map(node => {
    const positions = node.pos?.match(/\d+\.\d+|\d+/g).map(n => parseInt(n)) || [];
    return {
      id: node.id,
      position: positions.length ? { x: positions[0], y: positions[1] } : {},
      name: node.id,
      fullName: node.fullName && node.version ? `${node.fullName}@${node.version}` : node.id,
      width: 200,
      height: 50,
      vulnerable: false,
      issues: new IssueCount(),
    } as Node;
  });
  const newEdges = dotGraph.edges;
  return { nodes: newNodes, edges: newEdges };
}
// DEP GRAPH (fileContent)
export const decodeAndUnzipFile = (fileContent: string, fullName: string) => {
  try {
    if (!fileContent) {
      logger.warn(`no graph data, repo: ${fullName}`);
      return;
    }
    const binaryBuffer = decodeBase64Buffer(fileContent);
    const unzippedFile = unzipBinaryBuffer(binaryBuffer);
    return unzippedFile;
  } catch (error) {
    logger.error(
      `failed the decode and unzip file, err:${error}, fileContent: ${
        fileContent.length > 20 ? fileContent.slice(0, 20) : fileContent
      }, , repo: ${fullName}`,
    );
  }
};

export const decodeBase64Buffer = (base64str: string) => {
  const base64Buffer = Buffer.from(base64str, "base64");
  return base64Buffer;
};

export const unzipBinaryBuffer = (binaryBuffer: Buffer) => {
  const unzipped = zlib.unzipSync(binaryBuffer);
  return unzipped.toString();
};

const parsedInfo = `graph g {
  "jetty-alpn-conscrypt-server@9.4.30.v20200611";
  "poi-ooxml-schemas@4.1.2";
  "log4j-api@2.14.0";
  "antlr@2.7.7";
  "kotlin-compiler-runner@1.3.50";
  "wiremock-jre8@2.27.2";
  "jetty-http@9.4.30.v20200611";
  "jetty-continuation@9.4.30.v20200611";
  "kotlin-gradle-plugin-api@1.3.50";
  "handlebars-helpers@4.2.0";
  "json-path@2.4.0";
  "jsr305@3.0.2";
  "jetty-alpn-server@9.4.30.v20200611";
  "hibernate-jpa-2.0-api@1.0.1.Final";
  "commons-io@2.2";
  "opentest4j@1.1.1";
  "jetty-servlet@9.4.30.v20200611";
  "xmlunit-placeholders@2.7.0";
  "jackson-core@2.11.0";
  "gradle-download-task@3.4.3";
  "jetty-alpn-client@9.4.30.v20200611";
  "kotlin-util-io@1.3.50";
  "commons-compress@1.19";
  "error_prone_annotations@2.3.4";
  "kotlin-scripting-common@1.3.50";
  "jetty-servlets@9.4.30.v20200611";
  "jetty-alpn-conscrypt-client@9.4.30.v20200611";
  "jetty-security@9.4.30.v20200611";
  "kotlin-build-common@1.3.50";
  "kotlin-scripting-jvm@1.3.50";
  "servlet-api@2.3";
  "kotlinx-coroutines-core@1.1.1";
  "annotations@13.0";
  "log4j-core@2.14.0";
  "xmlbeans@3.1.0";
  "http2-server@9.4.30.v20200611";
  "jetty-server@9.4.30.v20200611";
  "kotlin-native-utils@1.3.50";
  "asm@7.0";
  "httpclient@4.5.12";
  "jboss-logging@3.1.0.CR2";
  "commons-math3@3.6.1";
  "dom4j@1.6.1";
  "poi-ooxml@4.1.2";
  "kotlin-daemon-client@1.3.50";
  "kotlin-reflect@1.3.50";
  "kotlin-gradle-plugin-model@1.3.50";
  "jetty-xml@9.4.30.v20200611";
  "json-unit-core@2.12.0";
  "junit@4.12";
  "kotlin-scripting-compiler-embeddable@1.3.50";
  "javassist@3.15.0-GA";
  "commons-logging@1.2";
  "gson@2.8.5";
  "xml-apis@1.0.b2";
  "jaxb-api@2.3.0";
  "kotlin-daemon-embeddable@1.3.50";
  "poi@4.1.2";
  "kotlin-android-extensions@1.3.50";
  "jetty-util@9.4.30.v20200611";
  "http2-common@9.4.30.v20200611";
  "jetty-io@9.4.30.v20200611";
  "zjsonpatch@0.4.4";
  "hibernate-commons-annotations@4.0.1.Final";
  "jstl@1.2";
  "javax.servlet-api@3.1.0";
  "jackson-annotations@2.11.0";
  "jetty-proxy@9.4.30.v20200611";
  "commons-lang3@3.7";
  "trove4j@1.0.20181211";
  "xmlunit-legacy@2.7.0";
  "commons-codec@1.13";
  "kotlin-scripting-compiler-impl-embeddable@1.3.50";
  "SparseBitSet@1.2";
  "accessors-smart@1.2";
  "commons-collections4@4.4";
  "handlebars@4.2.0";
  "conscrypt-openjdk-uber@2.2.1";
  "jopt-simple@5.0.3";
  "httpcore@4.4.13";
  "kotlin-stdlib@1.3.50";
  "kotlin-script-runtime@1.3.50";
  "jackson-databind@2.11.0";
  "curvesapi@1.06";
  "commons-collections@3.2.1";
  "guava@29.0-jre";
  "failureaccess@1.0.1";
  "hibernate-core@4.0.1.Final";
  "jboss-transaction-api_1.1_spec@1.0.0.Final";
  "listenablefuture@9999.0-empty-to-avoid-conflict-with-guava";
  "mysql-connector-java@5.1.26";
  "kotlin-annotation-processing-gradle@1.3.50";
  "slf4j-api@1.7.12";
  "hamcrest-core@1.3";
  "jetty-webapp@9.4.30.v20200611";
  "json@20090211";
  "xmlunit-core@2.7.0";
  "json-smart@2.3";
  "kotlin-gradle-plugin@1.3.50";
  "kotlin-stdlib-common@1.3.50";
  "jetty-client@9.4.30.v20200611";
  "http2-hpack@9.4.30.v20200611";
  "j2objc-annotations@1.3";
  "commons-fileupload@1.4";
  "checker-qual@2.11.1";
  "kotlin-compiler-embeddable@1.3.50";
  "jetty-alpn-conscrypt-server@9.4.30.v20200611" -> "wiremock-jre8@2.27.2"  [key=0];
  "poi-ooxml-schemas@4.1.2" -> "poi-ooxml@4.1.2"  [key=0];
  "log4j-api@2.14.0" -> "log4j-core@2.14.0"  [key=0];
  "antlr@2.7.7" -> "hibernate-core@4.0.1.Final"  [key=0];
  "kotlin-compiler-runner@1.3.50" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  "jetty-http@9.4.30.v20200611" -> "jetty-server@9.4.30.v20200611"  [key=0];
  "jetty-continuation@9.4.30.v20200611" -> "jetty-servlets@9.4.30.v20200611"  [key=0];
  "kotlin-gradle-plugin-api@1.3.50" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  "handlebars-helpers@4.2.0" -> "wiremock-jre8@2.27.2"  [key=0];
  "json-path@2.4.0" -> "wiremock-jre8@2.27.2"  [key=0];
  "jsr305@3.0.2" -> "guava@29.0-jre"  [key=0];
  "jetty-alpn-server@9.4.30.v20200611" -> "wiremock-jre8@2.27.2"  [key=0];
  "hibernate-jpa-2.0-api@1.0.1.Final" -> "hibernate-core@4.0.1.Final"  [key=0];
  "commons-io@2.2" -> "commons-fileupload@1.4"  [key=0];
  "opentest4j@1.1.1" -> "json-unit-core@2.12.0"  [key=0];
  "jetty-servlet@9.4.30.v20200611" -> "wiremock-jre8@2.27.2"  [key=0];
  "xmlunit-placeholders@2.7.0" -> "wiremock-jre8@2.27.2"  [key=0];
  "jackson-core@2.11.0" -> "wiremock-jre8@2.27.2"  [key=0];
  "gradle-download-task@3.4.3" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  "jetty-alpn-client@9.4.30.v20200611" -> "jetty-alpn-conscrypt-client@9.4.30.v20200611"  [key=0];
  "kotlin-util-io@1.3.50" -> "kotlin-native-utils@1.3.50"  [key=0];
  "commons-compress@1.19" -> "poi-ooxml@4.1.2"  [key=0];
  "error_prone_annotations@2.3.4" -> "guava@29.0-jre"  [key=0];
  "kotlin-scripting-common@1.3.50" -> "kotlin-scripting-compiler-impl-embeddable@1.3.50"  [key=0];
  "jetty-servlets@9.4.30.v20200611" -> "wiremock-jre8@2.27.2"  [key=0];
  "jetty-alpn-conscrypt-client@9.4.30.v20200611" -> "wiremock-jre8@2.27.2"  [key=0];
  "jetty-security@9.4.30.v20200611" -> "jetty-servlet@9.4.30.v20200611"  [key=0];
  "kotlin-build-common@1.3.50" -> "kotlin-compiler-runner@1.3.50"  [key=0];
  "kotlin-scripting-jvm@1.3.50" -> "kotlin-scripting-compiler-impl-embeddable@1.3.50"  [key=0];
  "kotlinx-coroutines-core@1.1.1" -> "kotlin-compiler-runner@1.3.50"  [key=0];
  "annotations@13.0" -> "kotlin-stdlib@1.3.50"  [key=0];
  "xmlbeans@3.1.0" -> "poi-ooxml-schemas@4.1.2"  [key=0];
  "http2-server@9.4.30.v20200611" -> "wiremock-jre8@2.27.2"  [key=0];
  "jetty-server@9.4.30.v20200611" -> "wiremock-jre8@2.27.2"  [key=0];
  "kotlin-native-utils@1.3.50" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  "asm@7.0" -> "wiremock-jre8@2.27.2"  [key=0];
  "httpclient@4.5.12" -> "wiremock-jre8@2.27.2"  [key=0];
  "jboss-logging@3.1.0.CR2" -> "hibernate-core@4.0.1.Final"  [key=0];
  "commons-math3@3.6.1" -> "poi@4.1.2"  [key=0];
  "dom4j@1.6.1" -> "hibernate-core@4.0.1.Final"  [key=0];
  "kotlin-daemon-client@1.3.50" -> "kotlin-compiler-runner@1.3.50"  [key=0];
  "kotlin-reflect@1.3.50" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  "kotlin-gradle-plugin-model@1.3.50" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  "jetty-xml@9.4.30.v20200611" -> "jetty-webapp@9.4.30.v20200611"  [key=0];
  "json-unit-core@2.12.0" -> "wiremock-jre8@2.27.2"  [key=0];
  "kotlin-scripting-compiler-embeddable@1.3.50" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  "javassist@3.15.0-GA" -> "hibernate-core@4.0.1.Final"  [key=0];
  "commons-logging@1.2" -> "httpclient@4.5.12"  [key=0];
  "gson@2.8.5" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  "xml-apis@1.0.b2" -> "dom4j@1.6.1"  [key=0];
  "jaxb-api@2.3.0" -> "xmlunit-core@2.7.0"  [key=0];
  "kotlin-daemon-embeddable@1.3.50" -> "kotlin-compiler-embeddable@1.3.50"  [key=0];
  "poi@4.1.2" -> "poi-ooxml@4.1.2"  [key=0];
  "kotlin-android-extensions@1.3.50" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  "jetty-util@9.4.30.v20200611" -> "jetty-servlets@9.4.30.v20200611"  [key=0];
  "http2-common@9.4.30.v20200611" -> "http2-server@9.4.30.v20200611"  [key=0];
  "jetty-io@9.4.30.v20200611" -> "jetty-server@9.4.30.v20200611"  [key=0];
  "zjsonpatch@0.4.4" -> "wiremock-jre8@2.27.2"  [key=0];
  "hibernate-commons-annotations@4.0.1.Final" -> "hibernate-core@4.0.1.Final"  [key=0];
  "javax.servlet-api@3.1.0" -> "jetty-server@9.4.30.v20200611"  [key=0];
  "jackson-annotations@2.11.0" -> "wiremock-jre8@2.27.2"  [key=0];
  "jetty-proxy@9.4.30.v20200611" -> "wiremock-jre8@2.27.2"  [key=0];
  "commons-lang3@3.7" -> "wiremock-jre8@2.27.2"  [key=0];
  "trove4j@1.0.20181211" -> "kotlin-compiler-embeddable@1.3.50"  [key=0];
  "xmlunit-legacy@2.7.0" -> "wiremock-jre8@2.27.2"  [key=0];
  "commons-codec@1.13" -> "poi@4.1.2"  [key=0];
  "kotlin-scripting-compiler-impl-embeddable@1.3.50" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  "SparseBitSet@1.2" -> "poi@4.1.2"  [key=0];
  "accessors-smart@1.2" -> "json-smart@2.3"  [key=0];
  "commons-collections4@4.4" -> "poi@4.1.2"  [key=0];
  "handlebars@4.2.0" -> "wiremock-jre8@2.27.2"  [key=0];
  "conscrypt-openjdk-uber@2.2.1" -> "wiremock-jre8@2.27.2"  [key=0];
  "jopt-simple@5.0.3" -> "wiremock-jre8@2.27.2"  [key=0];
  "httpcore@4.4.13" -> "httpclient@4.5.12"  [key=0];
  "kotlin-stdlib@1.3.50" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  "kotlin-script-runtime@1.3.50" -> "kotlin-compiler-embeddable@1.3.50"  [key=0];
  "jackson-databind@2.11.0" -> "wiremock-jre8@2.27.2"  [key=0];
  "curvesapi@1.06" -> "poi-ooxml@4.1.2"  [key=0];
  "commons-collections@3.2.1" -> "hibernate-core@4.0.1.Final"  [key=0];
  "guava@29.0-jre" -> "wiremock-jre8@2.27.2"  [key=0];
  "failureaccess@1.0.1" -> "guava@29.0-jre"  [key=0];
  "jboss-transaction-api_1.1_spec@1.0.0.Final" -> "hibernate-core@4.0.1.Final"  [key=0];
  "listenablefuture@9999.0-empty-to-avoid-conflict-with-guava" -> "guava@29.0-jre"  [key=0];
  "kotlin-annotation-processing-gradle@1.3.50" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  "slf4j-api@1.7.12" -> "wiremock-jre8@2.27.2"  [key=0];
  "hamcrest-core@1.3" -> "junit@4.12"  [key=0];
  "jetty-webapp@9.4.30.v20200611" -> "wiremock-jre8@2.27.2"  [key=0];
  "xmlunit-core@2.7.0" -> "wiremock-jre8@2.27.2"  [key=0];
  "json-smart@2.3" -> "json-path@2.4.0"  [key=0];
  "kotlin-stdlib-common@1.3.50" -> "kotlin-stdlib@1.3.50"  [key=0];
  "jetty-client@9.4.30.v20200611" -> "jetty-proxy@9.4.30.v20200611"  [key=0];
  "http2-hpack@9.4.30.v20200611" -> "http2-common@9.4.30.v20200611"  [key=0];
  "j2objc-annotations@1.3" -> "guava@29.0-jre"  [key=0];
  "commons-fileupload@1.4" -> "wiremock-jre8@2.27.2"  [key=0];
  "checker-qual@2.11.1" -> "guava@29.0-jre"  [key=0];
  "kotlin-compiler-embeddable@1.3.50" -> "kotlin-gradle-plugin@1.3.50"  [key=0];
  }
  `;
