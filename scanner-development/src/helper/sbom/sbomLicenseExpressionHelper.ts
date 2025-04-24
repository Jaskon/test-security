import spdxCorrect from "spdx-correct";
import spdxParse from "spdx-expression-parse";
import loggerImport from "../../logger";

const logger = loggerImport.getDebugLogger();

export type ValidatedLicenseExpression = {
  valid: boolean;
  expression: string;
  originalExpression: string;
};

export class SbomLicenseExpressionHelper {
  static normalizeZlib = (expression: string) => {
    return expression.replace("zlib", "Zlib");
  };

  static normalizeApache = (expression: string) => {
    // variations encountered in the wild
    const apacheVariations = [
      "Apache License, Version 2.0",
      "Apache License 2.0",
      "Apache-2.0 license",
      "APACHE-2.0",
      "Apache 2.0",
      "Apache 2",
    ];

    const ApacheSpdxId = "Apache-2.0";

    for (const variation of apacheVariations) {
      if (expression.includes(variation)) {
        return expression.replace(variation, ApacheSpdxId);
      }
    }
    return expression;
  };

  static normalizeDelimiters = (expression: string) => {
    return expression
      .replace(/ and /g, " AND ")
      .replace(/ or /g, " OR ")
      .replace(/ -or- /g, " OR ")
      .replace(/, /g, " AND ");
  };

  // we treat Public Domain as MIT per our business logic
  static normalizePublicDoman = license => {
    return license.replace("Public Domain", "MIT").replace("Public-Domain", "MIT");
  };

  // apply our own logic derived from various encounters of expressions in the wild
  static normalize(expression: string): string {
    const normalizers = [
      SbomLicenseExpressionHelper.normalizeApache,
      SbomLicenseExpressionHelper.normalizeZlib,
      SbomLicenseExpressionHelper.normalizePublicDoman,
      SbomLicenseExpressionHelper.normalizeDelimiters,
    ];

    return normalizers.reduce((result, normalizer) => normalizer(result), expression);
  }

  // `spdx-correct` package doesn't handle ANDs and ORs correctly
  // so we need to process each part of the expression separately
  static recursiveSpdxCorrect(expression: string): string {
    if (expression.includes(" AND ")) {
      return expression
        .split(" AND ")
        .filter(part => part.length > 0)
        .map(part => SbomLicenseExpressionHelper.recursiveSpdxCorrect(part))
        .join(" AND ");
    }

    // ORs between bracket groups not supported: never encountered
    if (expression.includes(" OR ")) {
      const isBracketed = expression.startsWith("(") && expression.endsWith(")");
      const toProcess = isBracketed ? expression.slice(1, expression.length - 1) : expression;
      const processed = toProcess
        .split(" OR ")
        .filter(part => part.length > 0)
        .map(part => SbomLicenseExpressionHelper.recursiveSpdxCorrect(part))
        .join(" OR ");

      return isBracketed ? `(${processed})` : processed;
    }

    const corrected = spdxCorrect(expression);

    return corrected == null ? expression : corrected;
  }

  static normalizeAndCorrect(expression: string) {
    return SbomLicenseExpressionHelper.recursiveSpdxCorrect(SbomLicenseExpressionHelper.normalize(expression));
  }

  public static toValidatedExpression(expression: string): ValidatedLicenseExpression {
    try {
      spdxParse(expression);
      return { valid: true, expression, originalExpression: expression };
    } catch (e) {
      logger.debug(`failed to spdx parse original expression. original: ${expression}`);
      return {
        valid: false,
        expression: "non-standard",
        originalExpression: expression,
      };
    }
  }
}
