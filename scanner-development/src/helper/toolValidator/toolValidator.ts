import { z } from "zod";
import loggerImport from "../../logger";
import StatesHelper from "../statesHelper";
export * from "./semgrepValidator";

const logger = loggerImport.getDebugLogger();

export class ToolValidator {
  static validateToolResult<T>(toolName: string, toolResult: unknown, schema: z.ZodType<T>): T {
    try {
      const validationResult = schema.parse(toolResult);
      return validationResult;
    } catch (err) {
      if (StatesHelper.Instance.validateToolSchema) {
        logger.error(`${toolName} result validation failed`, err);
        throw this.normaliseError(err);
      } else {
        logger.warn(`${toolName} result validation failed`, err);
        return toolResult as T;
      }
    }
  }

  private static normaliseError(err: z.ZodError): Error {
    const normalisedErr = new Error(err.errors.map(e => `${e.message} at ${e.path.join(".")}`).join(", "));
    normalisedErr.stack = err.stack;
    return normalisedErr;
  }
}
