import { DockerfileParser, From, Instruction, JSONInstruction, PropertyInstruction } from "dockerfile-ast";
import { last } from "lodash";
import { ImageDetail } from "../../entitis/cloudTypes";
import loggerImport from "../../logger";
import { ImageAnalysis, MatchResultString } from "./RepositoryMatcher";
const logger = loggerImport.getDebugLogger();

export class DockerMatchingService {
  private readonly dockerfiles: Array<{ repo: string; commands: ParsedDockerCommand[]; filePath: string }> = [];

  parseDockerfile(repoIdentifier: string, dockerfileContent: string, filePath: string): void {
    try {
      const parsedInstructions = DockerfileParser.parse(dockerfileContent).getInstructions();
      const stages: Array<{ image: string | null; alias: string | null; instructions: ParsedDockerCommand[] }> = [];
      for (const instruction of parsedInstructions) {
        const keyword = instruction.getKeyword();
        if (keyword === "FROM") {
          const from = instruction as From;
          stages.push({ image: from.getImage(), alias: from.getBuildStage(), instructions: [] });
        } else if (!stages.length) {
        } else {
          stages[stages.length - 1].instructions.push({ command: keyword, args: this.parseCommand(instruction) });
        }
      }
      const finalReversedInstructions: ParsedDockerCommand[] = [];
      for (let i = stages.length - 1, refStage = stages[i].alias; i >= 0; i--) {
        const stage = stages[i];
        if (stage.alias === refStage) {
          finalReversedInstructions.push(...stage.instructions.reverse());
          refStage = stage.image;
        }
      }
      this.dockerfiles.push({ repo: repoIdentifier, commands: finalReversedInstructions, filePath });
      logger.info(`[${DockerMatchingService.name}] Parsed Dockerfile ${filePath} from repository ${repoIdentifier}`);
    } catch (err) {
      logger.warn(`[${DockerMatchingService.name}] Could not parse Dockerfile ${filePath} from repository ${repoIdentifier}`, err);
    }
  }

  matchInstructions(imageDetails: ImageDetail, imageAnalysis?: ImageAnalysis, repoId?: string): MatchResultString {
    if (!imageAnalysis?.dockerCommands?.length) {
      return;
    }
    const imageInstructions = imageAnalysis.dockerCommands;
    const dockerfiles = repoId ? this.dockerfiles.filter(d => d.repo.split("|").at(1) === repoId) : this.dockerfiles;
    let matchedDockerfile: { repo: string; commands: ParsedDockerCommand[]; filePath: string };
    for (const dockerfile of dockerfiles) {
      let isMatch = true;
      instructionsLoop: for (let i = 0; i < imageInstructions.length; i++) {
        if (i >= 2 && imageInstructions[i] && !dockerfile.commands[i]) {
          logger.info(`[${DockerMatchingService.name}] All commands in dockerfile ${dockerfile.filePath} match image ${imageDetails.name}`);
          return `${dockerfile.repo}|${dockerfile.filePath}`;
        }
        if (dockerfile.commands[i]?.command !== imageInstructions[i]?.command) {
          isMatch = false;
          break instructionsLoop;
        }
        // Last arg of COPY/ADD is the destination, and should match
        if (["COPY", "ADD"].includes(dockerfile.commands[i]?.command)) {
          if (last(dockerfile.commands[i].args) !== last(imageInstructions[i].args)) {
            isMatch = false;
            break instructionsLoop;
          }
        } else {
          for (let j = 0; j < dockerfile.commands[i].args.length; j++) {
            if (dockerfile.commands[i].args[j] !== imageInstructions[i].args[j]) {
              isMatch = false;
              break instructionsLoop;
            }
          }
        }
      }
      if (isMatch) {
        logger.info(`[${DockerMatchingService.name}] All commands in dockerfile ${dockerfile.filePath} match image ${imageDetails.name}`);
        if (!repoId) {
          return `${dockerfile.repo}|${dockerfile.filePath}`;
        }
        if (!matchedDockerfile) {
          matchedDockerfile = dockerfile;
        } else {
          logger.info(`[${DockerMatchingService.name}] Multiple dockerfiles match image ${imageDetails.name}`);
          return;
        }
      }
    }
    if (matchedDockerfile) {
      return `${matchedDockerfile.repo}|${matchedDockerfile.filePath}`;
    }
  }

  private parseCommand(instruction: Instruction): string[] {
    switch (instruction.getKeyword()) {
      case "ARG":
      case "ENV":
      case "LABEL":
        return (instruction as PropertyInstruction).getProperties()?.map(p => p.getName());
      case "CMD":
      case "ENTRYPOINT":
      case "VOLUME":
        const args = (instruction as JSONInstruction).getJSONStrings().map(s => s.getJSONValue());
        return args.length ? args : instruction.getArgumentsContent()?.split(" ") ?? [];
      case "COPY":
      case "ADD":
      case "WORKDIR":
      case "USER":
        return instruction.getArgumentsContent()?.replace(/\s+/g, " ").trim().split(" ") ?? [];
      case "RUN":
        return instruction.getArgumentsContent()?.replace(/\s+/g, " ").trim().split(" ").slice(0, 5) ?? [];
      case "EXPOSE":
        return [...instruction.getArgumentsContent()?.replace(/\s+/g, " ").trim().matchAll(/(\d+)/g)].map(r => r[1]).sort() ?? [];
      default:
        return [];
    }
  }
}

export interface ParsedDockerCommand {
  command: string;
  args: string[];
}
