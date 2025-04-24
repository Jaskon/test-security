import { artifactType } from "../../entitis/ArtifactTypes";
import loggerImport from "../../logger";

const logger = loggerImport.getDebugLogger();
import YAML from "yaml";

const workflowAnalyzer = () => {
  return {
    extendDockRegistryName: async (artifact: artifactType, workflowFileContent: string) => {
      if (workflowFileContent) {
        const requiresAnalysis = workflowFileContent.match(/docker.*--tag\s+([a-z0-9_/:.-]+)\s+.*/);

        if (requiresAnalysis && requiresAnalysis.length > 1) {
          artifact.name = requiresAnalysis[1].split(":")[0];
        }
      }
    },

    extendSAMLambdaDetection: async (artifact: artifactType, templateYamlFile: string): Promise<artifactType[]> => {
      const samArtifacts: artifactType[] = [artifact];

      if (templateYamlFile) {
        try {
          const yamlFile = YAML.parse(templateYamlFile, { logLevel: "silent" });

          for (const key in yamlFile.Resources) {
            const resource = yamlFile.Resources[key];

            if (resource.Type === "AWS::Serverless::Function") {
              const copyArtifact = { ...artifact };
              copyArtifact.name = `([a-zA-Z0-9-_]+)?${key}([a-zA-Z0-9-_]{13})`;
              samArtifacts.push(copyArtifact);
            }
          }
        } catch (e) {
          logger.error(`extendSAMLambdaDetection: ${e}`);
        }

        return samArtifacts;
      }
    },
  };
};

export default workflowAnalyzer;
