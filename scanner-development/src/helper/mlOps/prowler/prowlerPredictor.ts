import * as fs from "fs";
import loggerImport from "../../../logger";
const logger = loggerImport.getDebugLogger();

// currently works only for the old prowler flow.
const prowlerPredictor = () => {
  const readRules = (): {
    ruleId: string;
    ruleLatency: number;
  }[] => {
    try {
      let rulesBuffer: Buffer = fs.readFileSync(process.cwd() + "/src/helper/mlOps/prowler/ProwlerPredictionV3.json");
      const rules = JSON.parse(rulesBuffer.toString());
      return rules;
    } catch (e) {
      logger.error("prowlerPredictor: Error reading prowler prediction rules: ", e);
      return [];
    }
  };

  const rules = readRules();

  return {
    predict: (inputRule: string): boolean => {
      try {
        const foundRuleLatency = rules[inputRule];
        if (foundRuleLatency) {
          if (parseInt(foundRuleLatency) > 50) {
            return true; // use heavy queue
          } else {
            return false; // use light queue
          }
        } else {
          logger.info(`prowlerPredictor: Rule not found in prediction rules: ${inputRule}`);
          return false; // use light queue
        }
      } catch (e) {
        return false; // use light queue
      }
    },
  };
};

let instance: ReturnType<typeof prowlerPredictor>;

const getProwlerPredictorInstance = () => {
  if (!instance) {
    instance = prowlerPredictor();
    return instance;
  }
  return instance;
};

export default getProwlerPredictorInstance;
