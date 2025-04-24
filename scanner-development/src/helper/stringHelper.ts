import { createHash } from "node:crypto";
import loggerImport from "../logger";
const logger = loggerImport.getDebugLogger();

export class StringHelper {
  replaceAll(str, items) {
    try {
      let temp = str;
      for (const item of items) {
        temp = temp.replace(item.replace, item.replaceTo);
      }

      return temp;
    } catch (err) {
      logger.error(`err: ${err}, str: ${str}, items: ${JSON.stringify(items)}`);
    }
    return str;
  }

  replaceAllRegex(str, find, replace) {
    return str.replace(new RegExp(find, "g"), replace);
  }

  static capitalizeFirstLetter(str) {
    return str[0].toUpperCase() + str.slice(1);
  }

  static combineStrings(...strings: string[]) {
    try {
      return strings.join("-");
    } catch (e) {
      logger.error(`failed to combine string, error: ${e}`);
    }
    return "";
  }

  static hashMd5(str: string) {
    try {
      return createHash("md5").update(str).digest("hex");
    } catch (e) {
      logger.error(`failed to hash md5, string: ${str}, error: ${e}`);
    }
  }

  /** Extract list of words, no matter what case is the sentence */
  static extractWords(input: string): string[] {
    if (!input?.length) return [];
    return input
      .toLowerCase()
      .replace(/([a-z])([A-Z])/g, "$1 $2") // Resolve camel case
      .replace(/[_-]/g, " ") // Resolve kebab and snake case
      .replace(/\s+/g, " ") // Fix multiple spaces
      .trim()
      .split(" ");
  }

  static compareWords(input1: string[], input2: string[]): boolean {
    if (!input1?.length || input1?.length !== input2?.length) {
      return false;
    }
    for (let i = 0; i < input1.length; i++) {
      if (input1[i] !== input2[i]) {
        return false;
      }
    }
    return true;
  }

  static ensureNoStartChar(string: string, char: string): string {
    return string.charAt(0) === char ? StringHelper.ensureNoStartChar(string.substring(1), char) : string;
  }
}

export default StringHelper;
