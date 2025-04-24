import parse, { Graph } from "dotparser";
import { promisify } from "node:util";
import { unzip } from "node:zlib";
import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

export class DotGraph<T extends Record<string, string>> {
  nodes: DotNode<T>[];
  edges: DotEdge[];
  reverseAdjacencyList: Record<string, string[]> = {};
  adjacencyList: Record<string, string[]> = {};

  static parseGraph<T extends Record<string, string>>(graph: string): DotGraph<T> | undefined {
    if (!graph) {
      logger.warn(`[${DotGraph.name}] Graph is empty`);
      return;
    }
    return new DotGraph<T>(parse(graph)[0]);
  }

  static async decodeAndParseGraph<T extends Record<string, string>>(compressedGraph: string): Promise<DotGraph<T> | undefined> {
    if (!compressedGraph) {
      logger.warn(`[${DotGraph.name}] Graph is empty`);
      return;
    }
    try {
      const decompressedGraph = await this.decodeZippedGraph(compressedGraph);
      return this.parseGraph(decompressedGraph);
    } catch (err) {
      logger.error(`[${DotGraph.name}] Failed the decode and unzip file: ${err}`, err);
    }
  }

  private constructor(graph: Graph) {
    const [nodes, edges] = this.parseChildren(graph);
    this.nodes = nodes;
    this.edges = edges;

    for (const edge of this.edges) {
      if (!this.reverseAdjacencyList[edge.w]) {
        this.reverseAdjacencyList[edge.w] = [];
      }
      this.reverseAdjacencyList[edge.w].push(edge.v);

      if (!this.adjacencyList[edge.v]) {
        this.adjacencyList[edge.v] = [];
      }
      this.adjacencyList[edge.v].push(edge.w);
    }
  }

  private parseChildren(graph: Graph): [DotNode<T>[], DotEdge[]] {
    const nodes: DotNode<T>[] = [];
    const edges: DotEdge[] = [];
    for (const child of graph.children) {
      if (child.type === "node_stmt") {
        const node = { id: child.node_id.id as string };
        for (const attr of child.attr_list) {
          node[attr.id] = attr.eq;
        }
        nodes.push(node as DotNode<T>);
      } else if (child.type === "edge_stmt" && child.edge_list?.length) {
        edges.push({ v: child.edge_list[0].id as string, w: child.edge_list[1].id as string });
      }
    }
    return [nodes, edges];
  }

  findAllBranchesRecursively(nodeName: string, maxNodesForBranch: number = 5, reverse: boolean = false): string[][] {
    const branches: string[][] = [];
    const adjacencyList = reverse ? this.reverseAdjacencyList : this.adjacencyList;
    function findRecursive(node: string, currentBranch: string[]): void {
      if (currentBranch.length >= maxNodesForBranch) {
        // prevent cycles
        branches.push([...currentBranch]);
        return;
      }

      if (!adjacencyList[node]) {
        // Leaf node, add the current branch to the list of branches
        branches.push([...currentBranch]);
        return;
      }

      for (const child of adjacencyList[node]) {
        currentBranch.push(child);
        findRecursive(child, currentBranch);
        currentBranch.pop();
      }
    }

    findRecursive(nodeName, [nodeName]);
    return branches;
  }

  getBranchToEndOfGraph(nodeName: string, maxNodesForBranch: number = 20): string[] {
    const branch: string[] = [];
    let currentNode = nodeName;
    let nodesVisited = 0;

    while (currentNode) {
      if (nodesVisited >= maxNodesForBranch) {
        return branch;
      }

      branch.push(currentNode);
      nodesVisited++;

      if (!this.adjacencyList[currentNode]) {
        return branch;
      }

      currentNode = this.adjacencyList[currentNode][0];
    }

    return null;
  }

  private static async decodeZippedGraph(compressedGraph: string): Promise<string> {
    return (await promisify(unzip)(Buffer.from(compressedGraph, "base64"))).toString();
  }
}

export type DotNode<T extends Record<string, string>> = Partial<T> & { id: string };

interface DotEdge {
  v: string;
  w: string;
}
