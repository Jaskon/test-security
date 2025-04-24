import loggerImport from "../../logger";
import { SecInfra } from "../reportTypes";
const logger = loggerImport.getDebugLogger();

export enum ToolNameForUI {
  gitleaks = "Gitleaks",
  devskim = "DevSkim",
  checkov = "Checkov",
  bandit = "Bandit",
  trivy = "Trivy",
  trivysbom = "Trivy-Sbom",
  terrascan = "TerraScan",
  tflint = "TfLint",
  hadolint = "HadoLint",
  cfnlint = "CfnLint",
  semgrep = "SemGrep",
  codeql = "CodeQL",
  prowler = "Prowler",
  cxsast = "CxSAST",
  cxsca = "CxSCA",
  dependabot = "Dependabot",
  snyk = "Snyk",
  eslint = "ESLint",
  ansiblelint = "Ansible Lint",
  sonarqube = "SonarQube",
  prismacspm = "Prisma CSPM",
  prismaartifacts = "Prisma Artifacts",
  blackduck = "Black Duck",
  gitlabSast = "GitLab SAST",
  gitlabSecretDetection = "GitLab Secret Detection",
  githubSast = "GitHub SAST",
  githubSecretDetection = "GitHub Secret Detection",
  gitLabDependencyScanning = "GitLab Dependency Scanning",
  containerScanning = "OX Container Security",
}

export function getStringFromEnumSecInfra(type: string) {
  if (type.toUpperCase() === "SECRETS") {
    return "secrets";
  }
  if (type.toUpperCase() === SecInfra.SCA.toUpperCase()) {
    return "sca";
  }
  if (type.toUpperCase() === SecInfra.SAST.toUpperCase()) {
    return "sast";
  }
  if (type.toUpperCase() === SecInfra.IAC.toUpperCase()) {
    return "iac";
  }
  if (type.toUpperCase() === "CSPM") {
    return "cspm";
  }
  return "";
}
