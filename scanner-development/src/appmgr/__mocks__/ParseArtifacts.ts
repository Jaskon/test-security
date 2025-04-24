import { artifactSchema, artifactType } from "../../entitis/ArtifactTypes";

import * as fs from "fs";

export async function parseArtifacts(family, file): Promise<any> {
  const failedResult = {
    success: false,
    output: [] as artifactType[],
  };
  // Generate application data
  try {
    switch (family) {
      case "tfstate":
      case "any":
        {
          const parsingResult: artifactType[] = JSON.parse(fs.readFileSync("./tests/src/AppFlow/Artifacts.json", "utf8"));
          return { success: true, output: parsingResult };
        }
        break;
      case "docker": // BC
        {
          // Not testing BC
        }
        break;
    }

    return failedResult;
  } catch (err) {}

  return failedResult;
}
