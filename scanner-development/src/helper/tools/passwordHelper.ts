import loggerImport from "../../logger";
import { isDevelopment } from "../envUtils";
const logger = loggerImport.getDebugLogger();
const maxPassObfuscateLength = 100;

class PasswordHelper {
  getObfuscatedPass(secretsToObfuscate: string[], pass: string, repoName: string): string {
    try {
      if (!pass) {
        return pass;
      }
      if (pass.length == 1) {
        logger.info(`len is small`);
        return "**********";
      }

      if (pass.includes("BEGIN PRIVATE KEY") || pass.includes("BEGIN PUBLIC KEY")) {
        let passLength = pass.length / 2;
        let newPass = pass.substring(0, passLength);
        let buff = [];
        if (passLength > maxPassObfuscateLength) {
          passLength = maxPassObfuscateLength;
        }
        while (passLength > 0) {
          passLength--;
          buff.push("*");
        }
        newPass += buff.join("");
        return newPass;
      }

      let hasObfuscated: boolean = false;
      let newPass = pass;
      secretsToObfuscate.forEach(secretToObfuscate => {
        if (!secretToObfuscate) {
          return;
        }
        if (!pass.includes(secretToObfuscate)) {
          return;
        }

        const halfSecretLength = Math.floor(secretToObfuscate.length / 2);
        if (halfSecretLength > 1) {
          const firstPortionInfo = secretToObfuscate.substring(0, halfSecretLength);

          const arr = [];
          let counter = secretToObfuscate.length - halfSecretLength;
          if (counter > maxPassObfuscateLength) {
            counter = maxPassObfuscateLength;
          }
          while (counter > 0) {
            arr.push("*");
            counter--;
            hasObfuscated = true;
          }
          const secretAfterObfuscation = firstPortionInfo + arr.join("");
          newPass = newPass.replace(secretToObfuscate, secretAfterObfuscation);
        }
      });

      if (!hasObfuscated) {
        // fall back if the obfuscation didn't happened, obfuscate the last third of the string
        const thirdSecretLength = Math.floor(newPass.length / 3);
        const firstPortionInfo = newPass.substring(0, thirdSecretLength + 1);
        const secondPortionInfo = "*".repeat(thirdSecretLength);
        newPass = firstPortionInfo + secondPortionInfo;
      }
      return newPass;
    } catch (err) {
      logger.error(`get obfuscated pass : ${pass}, repoName: ${repoName}, err: ${err}`);
    }
    return pass;
  }
}
export default PasswordHelper;

export function getObfuscatedPassForContainer(pass: string): string {
  try {
    if (!pass) {
      return pass;
    }
    if (pass.length == 1) {
      logger.info(`len is small`);
      return "**********";
    }

    let passLength = pass.length / 2;
    let newPass = pass.substring(0, passLength);
    let buff = [];
    if (passLength > maxPassObfuscateLength) {
      passLength = maxPassObfuscateLength;
    }
    while (passLength > 0) {
      passLength--;
      buff.push("*");
    }
    newPass += buff;
    return newPass;
  } catch (err) {
    logger.error(`get obfuscated pass : ${pass}, err: ${err}`);
  }
  return pass;
}
