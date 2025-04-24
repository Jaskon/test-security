import PolicyRulesBase from "./policyRulesBase";
import { AlertSeverity, Repo, VCSType } from "../../../entitis/codeRepoTypes";
import TimeHelper from "../../../helper/timeHelper";
import loggerImport from "../../../logger";
import Constant from "../../../entitis/constant";

const logger = loggerImport.getDebugLogger();

class PolicyNoCicd extends PolicyRulesBase {
  async eval(jsonData) {
    if (!jsonData.code_repo.realRepo) {
      return [];
    }

    if (jsonData?.citool?.jobs?.length) {
      if (jsonData?.citool?.jobs?.length > 0) {
        return [];
      }
    }

    const repo: Repo = jsonData.code_repo;
    if (repo.vcsType == VCSType.tfvc) {
      return [];
    }

    const cicdToolsFromArgs = this.getValueFromRuleArgs("cicd");
    if (!Array.isArray(cicdToolsFromArgs)) {
      throw `cicd is  not array type, ${cicdToolsFromArgs.toString()}`;
    }
    const minBP = this.getValueFromRuleArgs("minBP");
    if (!minBP) {
      throw `minbp is not exist`;
    }

    // low BP - bail
    if (repo.repoImportance.total < minBP) {
      return [];
    }

    // if 33% or more of the languages are not in SAST, ignore this policy for the repo.
    const isSastDominant = this.languageHelper.isSastDominant(jsonData.code_repo.languages);

    if (!isSastDominant) {
      return [];
    }

    const enableSecurityTools = [];
    for (const cicdToolFromArgs of cicdToolsFromArgs) {
      for (const cicd of jsonData.code_repo.cicd) {
        if (cicd.toLowerCase() === cicdToolFromArgs.toLowerCase()) {
          enableSecurityTools.push(cicd);
        }
      }
    }
    const issueOwners = this.getOwnersFromUsers(jsonData);
    if (enableSecurityTools.length > 0) {
      return [];
    }

    let authApp: string = "";
    if (cicdToolsFromArgs.length == 1) {
      authApp = `The authorized CI/CD app is ${cicdToolsFromArgs[0]}`;
    } else {
      let apps: string = cicdToolsFromArgs.join(", ");
      authApp = `The list of authorized CI/CD apps are ${apps}`;
    }

    let newVi = "Missing CI/CD pipeline";
    let appDeploy: string = `Please assign to the repo an authorized CI/CD app. ${authApp}`;
    if (jsonData.code_repo.ownerName != "") {
      appDeploy = `Please ask ${jsonData.code_repo.ownerName} to assign an authorized CI/CD app to the repo. ${authApp}`;
    }

    let res = [];
    const replaceInfo = [];

    // repoImprtance is your baseline severity and then the date MAY change it.
    // But never increase it.

    const repoImportance = Math.trunc(jsonData.code_repo.repoImportance.total);

    if (repoImportance >= 1 && repoImportance <= 50) {
      this.policyRuleMetadata.severity = AlertSeverity.Low;
    } else if (repoImportance >= 51 && repoImportance <= 75) {
      this.policyRuleMetadata.severity = AlertSeverity.Medium;
    } else if (repoImportance >= 76) {
      this.policyRuleMetadata.severity = AlertSeverity.High;
    }

    // get last code change in days
    const timeHelper = new TimeHelper(this.uuid);
    const lastCodeChangeInDays = timeHelper.getTimeIntervalFronNowInDays(jsonData.code_repo.lastPushTime);

    // set a severity based on last code change
    let severityBasedOnLastCodeChange = 0;

    if (lastCodeChangeInDays < 14) {
      severityBasedOnLastCodeChange = AlertSeverity.Critical;
    } else if (lastCodeChangeInDays < 30) {
      severityBasedOnLastCodeChange = AlertSeverity.High;
    } else if (lastCodeChangeInDays < 60) {
      severityBasedOnLastCodeChange = AlertSeverity.Medium;
    } else if (lastCodeChangeInDays >= 60) {
      severityBasedOnLastCodeChange = AlertSeverity.Low;
    }

    // take the lowest severity between repoImportance and lastCodeChange
    this.policyRuleMetadata.severity = Math.min(this.policyRuleMetadata.severity, severityBasedOnLastCodeChange);

    res = [
      this.generateItemForReport(
        true,
        newVi,
        "",
        newVi,
        appDeploy,
        "CI/CD",
        "CI/CD",
        replaceInfo,
        "",
        true,
        "",
        [],
        [Constant.cicdPosture],
        ["UNKNOWN"], // roman fill cicd
        [],
        this.getGeneralIssueId(),
        issueOwners,
      ),
    ];

    return res;
  }
}

export default PolicyNoCicd;
