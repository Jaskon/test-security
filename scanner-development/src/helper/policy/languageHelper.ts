import loggerImport from "../../logger";
import SastLangs from "../../policy/org/config/sastLanguages.json";
const logger = loggerImport.getDebugLogger();

class LanguageHelper {
  uuid: string;
  constructor(uuid: string) {
    this.uuid = uuid;
  }
  // this is for some policies, we filter the repo languages to get only sast langs, then we sum langs percentages.
  isSastDominant(languages, percentage = 33) {
    try {
      let sastLangs = SastLangs.languages.map(i => i.toLowerCase());

      const repoSastLangs = languages.filter(language => sastLangs.includes(language.language.toLowerCase()));

      const result = repoSastLangs.reduce((acc, obj) => {
        return acc + obj.languagePercentage;
      }, 0);

      if (result < percentage) {
        return false;
      }
      return true;
    } catch (e) {
      logger.error(`failed on function isSastDominant: ${e}`);
    }
    return false;
  }
}

export default LanguageHelper;
