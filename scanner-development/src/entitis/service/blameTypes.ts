import { OxTagId } from "@oxappsec/ox-consolidated-tags";
import { isDevelopment } from "../../helper/envUtils";
import { DependencyType } from "../../mongo/sbom/types";
import { CweObject, Dependency, SecurityAlertType } from "../codeRepoTypes";
import { ExtraInfo } from "../issuesTypes";
import { Frameworks } from "../apiTypes";

export enum SeverityChange {
  Unchanged = "Unchanged",
  Increased = "Increased",
  Decreased = "Decreased",
  NotApplicable = "Not Applicable",
}

export enum SeverityFactorType {
  Repo = "Repo",
  Artifact = "Artifact",
  Cloud = "Cloud",
}

export class ChangeReason {
  tagId?: OxTagId;
  changeNumber: number = 0;
  reason: string;
  shortName: string;
  changeCategory: string;
  changePlusReasonFacet: string;
  extraInfo: ExtraInfo[];
  requiredHits: number = 0;
  shouldBeSeverityFactor: boolean = true;
  severityFactorType: SeverityFactorType;
  framework: Frameworks;

  constructor(
    shortName: string,
    reason: string,
    changeNumber: number,
    changeCategory: string,
    type: SeverityFactorType = SeverityFactorType.Repo,
    shouldBeSeverityFactor: boolean = true,
    tagId: OxTagId = null,
    framework: Frameworks = null,
  ) {
    this.shortName = shortName;
    this.reason = reason;
    this.changeNumber = changeNumber;
    this.changeCategory = changeCategory;
    this.requiredHits = 0;
    this.changePlusReasonFacet = this.changeNumber.toString() + "|" + this.shortName;
    this.extraInfo = [];
    this.shouldBeSeverityFactor = shouldBeSeverityFactor;
    this.severityFactorType = type;
    this.tagId = tagId;
    this.framework = framework;
  }

  // Static copy method
  public static copy(source: ChangeReason): ChangeReason {
    const copy = new ChangeReason(source.shortName, source.reason, source.changeNumber, source.changeCategory);

    copy.tagId = source.tagId;
    copy.requiredHits = source.requiredHits ?? 0;
    copy.changePlusReasonFacet = source.changePlusReasonFacet;
    copy.extraInfo = [];
    copy.shouldBeSeverityFactor = source.shouldBeSeverityFactor;
    copy.severityFactorType = source.severityFactorType;
    return copy;
  }
}

export enum ChangeCategory {
  Exploitable = "Exploitable",
  Reachable = "Reachable",
  Damage = "Damage",
  SaaS = "SaaS",
  Framework = "Framework",
  DevopsTool = "DevopsTool",
}

export const severityReasons = {
  // semgrep
  highConfidenceDetection: new ChangeReason(
    "High Confidence Detection",
    "The identified vulnerability or issue is most likely accurate and not a false positive.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  mediumConfidenceDetection: new ChangeReason(
    "Medium Confidence Detection",
    "There is a reasonable chance the detected issue or vulnerability is accurate, but there may be some uncertainty or room for false positives.",
    -1,
    ChangeCategory.Exploitable,
  ),
  lowConfidenceDetection: new ChangeReason(
    "Low Confidence Detection",
    "The detected potential vulnerability or issue has significant uncertainty and a higher possibility of being a false positive.",
    -2,
    ChangeCategory.Exploitable,
  ),
  fixAdoption: new ChangeReason(
    "High CVE Mitigation Development",
    "The issue is associated with a CVE that has a substantial number of commits referencing it, indicating a high level of patch adoption, active developer involvement and recognition of the vulnerability.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  severityChangedByUser: new ChangeReason(
    `Manual severity changed`,
    `The severity of the policy was changed through policies page`,
    0,
    ChangeCategory.Exploitable,
  ),
  communityAwareness: new ChangeReason(
    "Community Buzz",
    "The issue is associated with a CVE that has generated significant discussion and interest across chat groups and developer forums, indicating heightened awareness.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  exploitDiversity: new ChangeReason(
    "Many Public Exploits",
    "The issue is associated with a CVE that has a wide variety of public exploits available, raising the probability of attackers exploiting the library.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  criticalCvssScore: new ChangeReason(
    "Critical CVSS Score",
    "NIST defines CVSS scores between 9.0 and 10.0 as critical severity.",
    0.01,
    ChangeCategory.Damage,
  ),
  highCvssScore: new ChangeReason(
    "High CVSS Score",
    "NIST defines CVSS scores between 7.0 and 8.9 as high severity.",
    0.01,
    ChangeCategory.Damage,
  ),
  mediumCvssScore: new ChangeReason(
    "Medium CVSS Score",
    "NIST defines CVSS scores between 4.0 and 6.9 as medium severity.",
    0,
    ChangeCategory.Damage,
  ),
  lowCvssScore: new ChangeReason(
    "Low CVSS Score",
    "NIST defines CVSS scores between 0.1 and 3.9 as low severity.",
    -0.01,
    ChangeCategory.Damage,
  ),
  extremelyFrequentlyExpolitITW: new ChangeReason(
    "Widespread Active Attack Usage",
    "This CVE is frequently exploited in real-world attacks, increasing risk and prioritization urgency.",
    1,
    ChangeCategory.Exploitable,
  ),
  frequentlyExpolitITW: new ChangeReason(
    "Active Attack Usage",
    "This CVE is exploited in real-world attacks.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  rarelyExpolitITW: new ChangeReason(
    "No Known Attack Usage",
    "There are no reports of any exploit attempts utilizing this library in the wild by threat actors.",
    -1,
    ChangeCategory.Exploitable,
  ),
  noPublicExpolit: new ChangeReason(
    "Public Exploit Unavailable",
    "A public exploit is unavailable. This reduces the likelihood of exploitation.",
    -1,
    ChangeCategory.Exploitable,
  ),
  hasPublicExpolit: new ChangeReason(
    "Public Exploit Available",
    "At least one public exploit exists, making it easier for attackers to weaponize the exploit.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  netExposed: new ChangeReason(
    "Public Internet Exposure",
    "The resource is publicly exposed to the internet, significantly increasing the risk of unauthorized access and potential exploitation from a wide array of potential attackers.",
    0.01,
    ChangeCategory.Reachable,
  ),
  availableForRegistry: new ChangeReason(
    "Public Registry Name Squatting",
    "An organization's artifact name is unclaimed or not reserved in a public repository. If not safeguarded, there's a potential for malicious actors to register the artifact name and upload tainted versions.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  userAccount: new ChangeReason(
    "User Account Misconfiguration",
    "User accounts are managed with settings or configurations that do not adhere to best practices, leading to potential vulnerabilities that can be exploited to gain unauthorized access or escalate privileges.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  serverless: new ChangeReason(
    "Serverless Misconfiguration",
    "Serverless function is set up with configurations that do not follow best practices, leading to potential vulnerabilities that could expose sensitive data or allow unauthorized execution of functions.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  computeInstanceGroup: new ChangeReason(
    "Cloud Instance Group Misconfiguration",
    "The cloud instance group is configured improperly, not aligning with industry best practices, leading to potential vulnerabilities that may expose sensitive information or enable unauthorized access.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  serviceAccount: new ChangeReason(
    "Service Account Misconfiguration",
    "Service accounts are managed with settings or configurations that do not adhere to best practices, leading to potential vulnerabilities that can be exploited to gain unauthorized access or escalate privileges.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  virtualMachine: new ChangeReason(
    "VM Misconfiguration",
    "The Virtual Machine is configured improperly, not aligning with industry best practices, leading to potential vulnerabilities that may expose sensitive information or enable unauthorized access.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  kubernetes: new ChangeReason(
    "K8s Misconfiguration",
    "Kubernetes is configured improperly, not aligning with industry best practices, leading to potential vulnerabilities that may expose sensitive information or enable unauthorized access.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  adminPrivilege: new ChangeReason(
    "Execution with Admin Privilege",
    "The resource is running under administrative privileges, a configuration that presents significant security risks, providing an avenue for potential attackers to gain full control over the system if exploited.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  highPrivilege: new ChangeReason(
    "Execution with High Privilege",
    "The resource is operating with high privileges, creating a security concern that could allow unauthorized users to exploit these elevated permissions, potentially leading to unauthorized access or control.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  potentialRCE: new ChangeReason(
    "Remote Code Execution",
    "Vulnerabilities exist that can cause Remote Code Execution (RCE).",
    0.01,
    ChangeCategory.Damage,
  ),
  oldUnmaintainedCode: new ChangeReason(
    "Old and Unmaintained Code",
    "Old and unmaintained code is often a hidden gem for attackers to exploit unpublished vulnerabilities.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  UnpopularLib: new ChangeReason(
    "Unpopular Library",
    "Be cautious when using unpopular libraries as they may contain unreported vulnerabilities that can be exploited by attackers or lure adversaries to plant a backdoor in your runtime environment. That is why It is recommended to use well-known and trusted libraries whenever possible.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  licIssue: new ChangeReason(
    "Problematic License",
    "Uncontrolled usage of problematic license potentially requiring disclosure of proprietary code or face legal consequences.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  dos: new ChangeReason("Denial-of-Service", "Vulnerabilities exist that can cause Denial-of-Service (DoS).", 0.01, ChangeCategory.Damage),
  improperAccessControl: new ChangeReason(
    "Improper Access Control",
    "Due to improper access control an adversary may gain unwanted access to your cloud environment.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  sqlInjection: new ChangeReason(
    "SQL Injection",
    "Vulnerabilities exist that can cause SQL Injection (SQLi) which can lead to data breaches and other security compromises.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  overPrivilegedAccess: new ChangeReason(
    "Over-Privileged Access",
    "Due to Execution with Over-Privileges an adversary may gain unwanted high-privileged access to your cloud environment.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  insufficientLogging: new ChangeReason(
    "Insufficient Logging",
    "Insufficient logging may lead to a situation where an adversary can perform malicious actions without being detected and making the incident response process much more complicated.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  dataAtRest: new ChangeReason(
    "Unencrypted Data at Rest",
    "Anyone who has storage access to the device can read the data, even if they do not have authorization for it.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  dataInTransit: new ChangeReason(
    "Unencrypted Data in Transit",
    "Unencrypted data in transit is data that is transmitted over a network in plaintext, or unencrypted, format. This means that anyone who is able to intercept the network traffic can read the data, even if they do not have authorization.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  weakCryptography: new ChangeReason(
    "Weak Cryptography",
    "Weak cryptography can be exploited by an adversary to decrypt sensitive information or bypass authentication controls.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  crossSiteScripting: new ChangeReason(
    "Cross-Site Scripting",
    "Vulnerabilities exist that can cause Cross-Site Scripting (XSS) which can lead to data breaches and other security compromises.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  lackOfSecurityContorl: new ChangeReason(
    "Lack of Security Control",
    "The resource is not protected by common practice security control, making it an easier target to exploit.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  lateralMovement: new ChangeReason(
    "Lateral Movement",
    "Security issues that may allow an attacker to move laterally across your infrastructure.",
    0.01,
    ChangeCategory.Damage,
  ),
  hasCriticalRCE: new ChangeReason(
    "Critical RCE Vulnerability",
    "A critical vulnerability that allows Remote Code Execution (RCE) has been identified, enabling unauthorized attackers to execute arbitrary code on the affected system, leading to full system compromise.",
    0.01,
    ChangeCategory.Damage,
  ),
  hasHighRCE: new ChangeReason(
    "High RCE Vulnerability",
    "A high-severity vulnerability enabling Remote Code Execution (RCE) has been detected, allowing unauthorized attackers to execute code on the target system, posing a serious risk to its security and integrity.",
    0.01,
    ChangeCategory.Damage,
  ),
  publishedPackage: new ChangeReason(
    "Published Package",
    "The package is published in a registry, making it more likely to be used by other applications, increasing the likelihood of embedded vulnerabilities exploit.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  directDependency: new ChangeReason(
    "Direct Dependency",
    "An issue exists within a direct dependency of the system, meaning a library that the system directly relies upon. This poses a more immediate and critical risk compared to vulnerabilities in first-level or deeper dependencies. The direct interaction with this component amplifies the potential for exploitation and system compromise.",
    0.01,
    ChangeCategory.Reachable,
  ),
  firstLevelIndirectDependency: new ChangeReason(
    "Indirect Dependency: First Level",
    "An issue exists within a first-level indirect dependency, meaning a library relied upon by another direct dependency, but not directly by the system itself. This poses a lower risk compared to a direct dependency vulnerability, but it still represents a potential avenue for exploitation and system impact.",
    -1,
    ChangeCategory.Reachable,
  ),
  deepLevelIndirectDependency: new ChangeReason(
    "Indirect Dependency: >1 Level",
    "An issue exists within an indirect dependency that is more than one level removed from the system, meaning a library relied upon by another indirect dependency. This poses an even lower risk compared to first-level indirect or direct dependency vulnerabilities, as the distance from the core system reduces the likelihood of successful exploitation.",
    -2,
    ChangeCategory.Reachable,
  ),
  devDependency: new ChangeReason(
    "Development Dependency",
    "An issue exists within a development dependency, meaning a library used only in the development environment and not in the production system. This typically poses minimal to no risk to the operational system, as the vulnerable component does not impact the live, production environment.",
    -4,
    ChangeCategory.Reachable,
  ),
  activeSecret: new ChangeReason(
    "Active Secret Exposure",
    "An active secret has been found and has been confirmed as live by using it to connect to the system it was generated for. This represents a significant risk, as the exposure of an operational secret could enable unauthorized access to sensitive systems, leading to potential data breaches and other security compromises.",
    0.5,
    ChangeCategory.Exploitable,
  ),
  inactiveSecret: new ChangeReason(
    "Inactive Secret",
    "An inactive secret has been found and has been confirmed as inactive by attempting to connect to the system it was generated for without success. This represents a lower risk compared to an active secret, as the secret is no longer operational and cannot be used to gain unauthorized access to sensitive systems.",
    -4,
    ChangeCategory.Exploitable,
  ),
  secretInCodeHistory: new ChangeReason(
    "Secret in Code History",
    "Secrets have been discovered within the code/GIT history. Although these secrets may not be present in the current code, their existence in the history can expose sensitive information to unauthorized individuals. This may lead to potential unauthorized access if those secrets are still active.",
    -1,
    ChangeCategory.Reachable,
  ),
  piiInCode: new ChangeReason(
    "PII in Active Code Branch",
    "A PII has been discovered within the active branch of a repository, potentially exposing sensitive information. As this is the actively used portion of the code, the risk is heightened, and it may enable unauthorized access to the systems that rely on this secret if not promptly addressed.",
    0.1,
    ChangeCategory.Reachable,
  ),
  piiInCodeHistory: new ChangeReason(
    "PII in Code History",
    "PII have been discovered within the code/GIT history. Although these PII may not be present in the current code, their existence in the history can expose sensitive information to unauthorized individuals. This may lead to potential unauthorized access if those PII are still active.",
    -1,
    ChangeCategory.Reachable,
  ),
  saasSecret: new ChangeReason(
    "Secret of a SaaS",
    "The secret was generated for a service publicly accessible via the internet. Attackers with knowledge of this secret can access the system from anywhere.",
    0.01,
    ChangeCategory.Reachable,
  ),
  singleFactorAuthentication: new ChangeReason(
    "Single Factor Authentication",
    "The secret was generated for a SaaS publicly accessible via the internet. With this token an attacker is able to bypass all MFA solution for this service authentication you may have in place.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  testFileInFinding: new ChangeReason(
    "Secret in Test Folder",
    "This secret was found in a folder that is most likely used for tests only. The secret may not have access to critical resources.",
    -3,
    ChangeCategory.Reachable,
  ),
  secretInCode: new ChangeReason(
    "Secret in Active Code Branch",
    "A secret has been discovered within the active branch of a repository, potentially exposing sensitive information. As this is the actively used portion of the code, the risk is heightened, and it may enable unauthorized access to the systems that rely on this secret if not promptly addressed.",
    0.1,
    ChangeCategory.Reachable,
  ),
  secretInPublicRepo: new ChangeReason(
    "Secret in a Public Repo",
    "The secret exists in a public repository visible to all. This normally is a super critical issue.",
    1,
    ChangeCategory.Reachable,
  ),
  piiInPublicRepo: new ChangeReason(
    "PII in a Public Repo",
    "The PII exists in a public repository visible to all. This normally is a super critical issue.",
    1,
    ChangeCategory.Reachable,
  ),
  vulnInPublicRepo: new ChangeReason(
    "Vulnerability in a Public Repo",
    "The vulnerabilty exists in a public repository visible to all. This could be leveraged by an adversary as a reconnaissance step toward an attack.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  secretInPrivateRepo: new ChangeReason(
    "Secret in a Private Repo",
    "The secret exists in a private repository visible only to the repository users.",
    0,
    ChangeCategory.Reachable,
  ),
  piiInPrivateRepo: new ChangeReason(
    "PII in a Private Repo",
    "The PII exists in a private repository visible only to the repository users.",
    0,
    ChangeCategory.Reachable,
  ),
  additionalInfoRequired: new ChangeReason(
    "Secret Exploitation Needs Extra Info",
    "Additional information is required for an attacker to exploit this secret.",
    -1,
    ChangeCategory.Exploitable,
  ),
  runningInCloud: new ChangeReason(
    "Cloud-Deployed Container",
    "The container is deployed in a cloud environment, heightening the risk profile due to potential cloud-specific attack vectors and the broad accessibility of the cloud platform.",
    0.01,
    ChangeCategory.Reachable,
    SeverityFactorType.Cloud,
  ),
  cloudAccountOffline: new ChangeReason(
    "Disconnected Account/System",
    "The findings related to the account or system may be outdated as there is no active connection.",
    0,
    ChangeCategory.Reachable,
    SeverityFactorType.Cloud,
  ),
  Lambda: new ChangeReason("Lambda Function Execution", "Lambda function execution in runtime", 0, ChangeCategory.Reachable),
  appContainerVull: new ChangeReason(
    "Application Layer",
    "This is the part of the container that contains your application code and any dependencies it might need to run.",
    0.01,
    ChangeCategory.Reachable,
    SeverityFactorType.Artifact,
  ),
  osVull: new ChangeReason(
    "Operating System Layer",
    "The layer in which the Operating System was included. Note: only shown when the base image layer which includes the operating system could not be identified.",
    -1,
    ChangeCategory.Reachable,
    SeverityFactorType.Artifact,
  ),
  userInstructionsContainerVull: new ChangeReason(
    "User Instruction Layer",
    "Layers added by user commands in a Dockerfile that customize the container, such as installing software or configuring settings.",
    0.01,
    ChangeCategory.Reachable,
    SeverityFactorType.Artifact,
  ),
  baseContainerVull: new ChangeReason(
    "Base Image Layer",
    "The foundational layer of a container that includes the operating system and essential system libraries upon which everything else is built.",
    -1,
    ChangeCategory.Reachable,
    SeverityFactorType.Artifact,
  ),
  deployedInsecureConfiguration: new ChangeReason(
    "Insecure IaC Config in Cloud",
    "This insecure IaC configuration was found in your cloud account.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  undeployedInsecureConfiguration: new ChangeReason(
    "Insecure IaC Config not in Cloud",
    "This insecure IaC configuration was not found in your cloud account.",
    -1,
    ChangeCategory.Exploitable,
  ),
  containerDriftLessTwoWeeks: new ChangeReason(
    "Code-Container Drift < 2 Weeks",
    "The container was built at least 2 weeks before the latest code change. The container is up-to-date.",
    -0.1,
    ChangeCategory.Exploitable,
  ),
  containerDriftLessOneMonth: new ChangeReason(
    "Code-Container Drift < 1 Month",
    "The container was built at least 1 month before the latest code change. The container is relatively up-to-date.",
    0,
    ChangeCategory.Exploitable,
  ),
  containerDriftMoreOneMonth: new ChangeReason(
    "Code-Container Drift > 1 Month",
    "The container was built more than 1 month before the latest code change. The container needs to be updated.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  containerDriftMoreSixMonth: new ChangeReason(
    "Code-Container Drift > 6 Months",
    "The container was built more than 6 months before the latest code change. The container needs to be updated urgently.",
    0.1,
    ChangeCategory.Exploitable,
  ),

  // Database tags
  mongoDB: new ChangeReason("MongoDB Connected", "This application interacts with MongoDB", 0.1, ChangeCategory.Damage),
  mongoDBAtlas: new ChangeReason(
    "MongoDB Atlas Connected",
    "This application interacts with MongoDB Atlas Database",
    0.1,
    ChangeCategory.Damage,
  ),
  azureSQLDB: new ChangeReason("Azure SQL DB Connected", "This application interacts with Azure SQL Database", 0.1, ChangeCategory.Damage),
  mssql: new ChangeReason("MSSQL Connected", "This application interacts with Microsoft SQL Database", 0.1, ChangeCategory.Damage),
  postgres: new ChangeReason("PostgreSQL Connected", "This application interacts with PostgreSQL Database", 0.1, ChangeCategory.Damage),
  snowflake: new ChangeReason("Snowflake Connected", "This application interacts with Snowflake Database", 0.1, ChangeCategory.Damage),
  oracle: new ChangeReason("Oracle Connected", "This application interacts with Oracle Database", 0.1, ChangeCategory.Damage),
  mysql: new ChangeReason("MySQL Connected", "This application interacts with MySQL Database", 0.1, ChangeCategory.Damage),
  influxDB: new ChangeReason("InfluxDB Connected", "This application interacts with Influx Database", 0.1, ChangeCategory.Damage),
  redis: new ChangeReason("Redis Connected", "This application interacts with Redis Database", 0.1, ChangeCategory.Damage),
  couchbase: new ChangeReason("Couchbase Connected", "This application interacts with Couchbase Database", 0.1, ChangeCategory.Damage),
  neo4j: new ChangeReason("Neo4j Connected", "This application interacts with Neo4j Database", 0.1, ChangeCategory.Damage),

  // Framework Tags
  flask: new ChangeReason(
    "Flask Used",
    "This application uses Flask framework",
    0.1,
    ChangeCategory.Framework,
    SeverityFactorType.Repo,
    false,
    "ox_tag_16",
    Frameworks.flask,
  ),
  django: new ChangeReason(
    "Django Used",
    "This application uses Django framework",
    0.1,
    ChangeCategory.Framework,
    SeverityFactorType.Repo,
    false,
    "ox_tag_17",
    Frameworks.django,
  ),
  pyramid: new ChangeReason("Pyramid Used", "This application uses Pyramid framework", 0.1, ChangeCategory.Framework),
  fastapi: new ChangeReason(
    "FastAPI Used",
    "This application uses FastAPI framework",
    0.1,
    ChangeCategory.Framework,
    SeverityFactorType.Repo,
    false,
    "ox_tag_19",
    Frameworks.fastapi,
  ),
  bottle: new ChangeReason("Bottle Used", "This application uses Bottle framework", 0.1, ChangeCategory.Framework),
  spring: new ChangeReason("Spring Used", "This application uses Spring framework", 0.1, ChangeCategory.Framework),
  springBoot: new ChangeReason(
    "Spring Boot Used",
    "This application uses Spring Boot framework",
    0.1,
    ChangeCategory.Framework,
    SeverityFactorType.Repo,
    false,
    "ox_tag_22",
    Frameworks.springBoot,
  ),
  jakarta: new ChangeReason("Jakarta Used", "This application uses Jakarta framework", 0.1, ChangeCategory.Framework),
  play: new ChangeReason("Play Used", "This application uses Play framework", 0.1, ChangeCategory.Framework),
  struts: new ChangeReason("Struts Used", "This application uses Apache Struts framework", 0.1, ChangeCategory.Framework),
  vertx: new ChangeReason("Vertx Used", "This application uses Vertx framework", 0.1, ChangeCategory.Framework),
  ktor: new ChangeReason("Ktor Used", "This application uses Ktor framework", 0.1, ChangeCategory.Framework),
  angular: new ChangeReason("Angular Used", "This application uses Angular framework", 0.1, ChangeCategory.Framework),
  expressJS: new ChangeReason(
    "Express.js Used",
    "This application uses Express.js framework",
    0.1,
    ChangeCategory.Framework,
    SeverityFactorType.Repo,
    false,
    "ox_tag_29",
    Frameworks.expressJS,
  ),
  react: new ChangeReason("React Used", "This application uses React framework", 0.1, ChangeCategory.Framework),
  nextJS: new ChangeReason("Next.js Used", "This application uses Next.js framework", 0.1, ChangeCategory.Framework),
  vueJS: new ChangeReason("Vue.js Used", "This application uses Vue.js framework", 0.1, ChangeCategory.Framework),
  nestJS: new ChangeReason(
    "NestJS Used",
    "This application uses NestJS framework",
    0.1,
    ChangeCategory.Framework,
    SeverityFactorType.Repo,
    false,
    "ox_tag_33",
    Frameworks.nestJS,
  ),
  koa: new ChangeReason(
    "Koa Used",
    "This application uses Koa framework",
    0.1,
    ChangeCategory.Framework,
    SeverityFactorType.Repo,
    false,
    "ox_tag_34",
    Frameworks.koa,
  ),
  fastify: new ChangeReason("Fastify Used", "This application uses Fastify framework", 0.1, ChangeCategory.Framework),
  gin: new ChangeReason(
    "Gin Used",
    "This application uses Gin framework",
    0.1,
    ChangeCategory.Framework,
    SeverityFactorType.Repo,
    false,
    "ox_tag_36",
    Frameworks.gin,
  ),
  echo: new ChangeReason("Echo Used", "This application uses Echo framework", 0.1, ChangeCategory.Framework),
  iris: new ChangeReason("Iris Used", "This application uses Iris framework", 0.1, ChangeCategory.Framework),
  beego: new ChangeReason("Beego Used", "This application uses Beego framework", 0.1, ChangeCategory.Framework),
  revel: new ChangeReason("Revel Used", "This application uses Revel framework", 0.1, ChangeCategory.Framework),
  fiber: new ChangeReason("Fiber Used", "This application uses Fiber framework", 0.1, ChangeCategory.Framework),

  // SaaS Tags
  jira: new ChangeReason(
    "Jira Used",
    "This application uses Jira SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_42",
  ),
  slack: new ChangeReason(
    "Slack Used",
    "This application uses Slack SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_43",
  ),
  datadog: new ChangeReason(
    "Datadog Used",
    "This application uses Datadog SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_44",
  ),
  logzio: new ChangeReason(
    "Logz.io Used",
    "This application uses Logz.io SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_45",
  ),
  codecov: new ChangeReason(
    "Codecov Used",
    "This application uses Codecov SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_46",
  ),
  monday: new ChangeReason(
    "Monday Used",
    "This application uses Monday SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_47",
  ),
  airtable: new ChangeReason(
    "Airtable Used",
    "This application uses Airtable SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_48",
  ),
  algolia: new ChangeReason(
    "Algolia Used",
    "This application uses Algolia SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_49",
  ),
  notion: new ChangeReason(
    "Notion Used",
    "This application uses Notion SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_50",
  ),
  zendesk: new ChangeReason(
    "Zendesk Used",
    "This application uses Zend",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_51",
  ),
  grafana: new ChangeReason(
    "Grafana Used",
    "This application uses Grafana SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_52",
  ),
  heroku: new ChangeReason(
    "Heroku Used",
    "This application uses Heroku SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_53",
  ),
  hubspot: new ChangeReason(
    "Hubspot Used",
    "This application uses Hubspot SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_54",
  ),
  mailchimp: new ChangeReason(
    "Mailchimp Used",
    "This application uses Mailchimp SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_55",
  ),
  mailgun: new ChangeReason(
    "Mailgun Used",
    "This application uses Mailgun SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_56",
  ),
  airbrake: new ChangeReason(
    "Airbrake Used",
    "This application uses Airbrake SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_57",
  ),
  bitgo: new ChangeReason(
    "Bitgo Used",
    "This application uses Bitgo SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_58",
  ),
  consul: new ChangeReason(
    "Consul Used",
    "This application uses Consul SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_59",
  ),
  crashlytics: new ChangeReason(
    "Crashlytics Used",
    "This application uses Crashlytics SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_60",
  ),
  equifax: new ChangeReason(
    "Equifax Used",
    "This application uses Equifax SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_61",
  ),
  frontegg: new ChangeReason(
    "Frontegg Used",
    "This application uses Frontegg SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_62",
  ),
  googlemaps: new ChangeReason(
    "GoogleMaps Used",
    "This application uses GoogleMaps SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_63",
  ),
  kanbanize: new ChangeReason(
    "Kanbanize Used",
    "This application uses Kanbanize SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_64",
  ),
  newrelic: new ChangeReason(
    "NewRelic Used",
    "This application uses NewRelic SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_65",
  ),
  openai: new ChangeReason(
    "OpenAI Used",
    "This application uses OpenAI SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_66",
  ),
  opsgenie: new ChangeReason(
    "OpsGenie Used",
    "This application uses OpsGenie SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_67",
  ),
  recaptcha: new ChangeReason(
    "ReCaptcha Used",
    "This application uses ReCaptcha SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_68",
  ),
  sendgrid: new ChangeReason(
    "Sendgrid Used",
    "This application uses Sendgrid SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_69",
  ),
  xignite: new ChangeReason(
    "Xignite Used",
    "This application uses Xignite SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_70",
  ),
  youtube: new ChangeReason(
    "YouTube Used",
    "This application uses YouTube SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_71",
  ),
  alibaba: new ChangeReason(
    "Alibaba Used",
    "This application uses Alibaba SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_72",
  ),
  asana: new ChangeReason(
    "Asana Used",
    "This application uses Asana SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_73",
  ),
  digitalocean: new ChangeReason(
    "DigitalOcean Used",
    "This application uses DigitalOcean SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_74",
  ),
  databricks: new ChangeReason(
    "Databricks Used",
    "This application uses Databricks SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_75",
  ),
  twitter: new ChangeReason(
    "Twitter Used",
    "This application uses Twitter SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_76",
  ),
  yandex: new ChangeReason(
    "Yandex Used",
    "This application uses Yandex SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_77",
  ),
  twocaptcha: new ChangeReason(
    "Twocaptcha Used",
    "This application uses Twocaptcha SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_78",
  ),
  squarespace: new ChangeReason(
    "Squarespace Used",
    "This application uses Squarespace SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_79",
  ),
  shippo: new ChangeReason(
    "Shippo Used",
    "This application uses Shippo SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_80",
  ),
  rapidapi: new ChangeReason(
    "RapidApi Used",
    "This application uses RapidApi SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_81",
  ),
  postman: new ChangeReason(
    "Postman Used",
    "This application uses Postman SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_82",
  ),
  planetscale: new ChangeReason(
    "Planetscale Used",
    "This application uses Planetscale SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_83",
  ),
  plaid: new ChangeReason(
    "Plaid Used",
    "This application uses Plaid SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_84",
  ),
  linkedin: new ChangeReason(
    "Linkedin Used",
    "This application uses Linkedin SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_85",
  ),
  intercom: new ChangeReason(
    "Intercom Used",
    "This application uses Intercom SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_86",
  ),
  freshbooks: new ChangeReason(
    "Freshbooks Used",
    "This application uses Freshbooks SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_87",
  ),
  figma: new ChangeReason(
    "Figma Used",
    "This application uses Figma SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_88",
  ),
  docusign: new ChangeReason(
    "Docusign Used",
    "This application uses Docusign SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_89",
  ),
  dropbox: new ChangeReason(
    "Dropbox Used",
    "This application uses Dropbox SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_90",
  ),
  discord: new ChangeReason(
    "Discord Used",
    "This application uses Discord SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_91",
  ),
  trello: new ChangeReason(
    "Trello Used",
    "This application uses Trello SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_106",
  ),
  wrike: new ChangeReason(
    "Wrike Used",
    "This application uses Wrike SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_107",
  ),
  clickup: new ChangeReason(
    "Clickup Used",
    "This application uses Clickup SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_108",
  ),
  basecamp: new ChangeReason(
    "Basecamp Used",
    "This application uses Basecamp SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_109",
  ),
  microsoftPlanner: new ChangeReason(
    "Microsoft Planner Used",
    "This application uses Microsoft Planner SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_110",
  ),
  smartsheet: new ChangeReason(
    "Smartsheet Used",
    "This application uses Smartsheet SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_111",
  ),
  workfront: new ChangeReason(
    "Workfront Used",
    "This application uses Workfront SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_112",
  ),
  teamwork: new ChangeReason(
    "Teamwork Used",
    "This application uses Teamwork SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_113",
  ),
  podio: new ChangeReason(
    "Podio Used",
    "This application uses Podio SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_114",
  ),
  zoho: new ChangeReason(
    "Zoho Projects Used",
    "This application uses Zoho Projects SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_115",
  ),
  meisterTask: new ChangeReason(
    "MeisterTask Used",
    "This application uses MeisterTask SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_116",
  ),
  favro: new ChangeReason(
    "Favro Used",
    "This application uses Favro SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_117",
  ),
  todoist: new ChangeReason(
    "Todoist Used",
    "This application uses Todoist SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_118",
  ),
  liquidPlanner: new ChangeReason(
    "LiquidPlanner Used",
    "This application uses LiquidPlanner SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_119",
  ),
  axosoft: new ChangeReason(
    "Axosoft Used",
    "This application uses Axosoft SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_120",
  ),
  teamGantt: new ChangeReason(
    "TeamGantt Used",
    "This application uses TeamGantt SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_121",
  ),
  clarizen: new ChangeReason(
    "Clarizen Used",
    "This application uses Clarizen SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_122",
  ),
  hive: new ChangeReason(
    "Hive Used",
    "This application uses Hive SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_123",
  ),
  redbooth: new ChangeReason(
    "Redbooth Used",
    "This application uses Redbooth SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_124",
  ),
  bitrix24: new ChangeReason(
    "Bitrix24 Used",
    "This application uses Bitrix24 SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_125",
  ),
  telegram: new ChangeReason(
    "Telegram Used",
    "This application uses Telegram SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_127",
  ),
  promotexter: new ChangeReason(
    "Promotexter Used",
    "This application uses Promotexter SaaS",
    0.1,
    ChangeCategory.SaaS,
    SeverityFactorType.Repo,
    false,
    "ox_tag_128",
  ),

  // DevOps Tool Tags
  ansible: new ChangeReason("ansible", "ansible", 0, ChangeCategory.DevopsTool, SeverityFactorType.Repo, false, "ox_tag_95"),
  vagrant: new ChangeReason("vagrant", "vagrant", 0, ChangeCategory.DevopsTool, SeverityFactorType.Repo, false, "ox_tag_126"),
  chef: new ChangeReason("chef", "chef", 0, ChangeCategory.DevopsTool, SeverityFactorType.Repo, false, "ox_tag_96"),
  puppet: new ChangeReason("puppet", "puppet", 0, ChangeCategory.DevopsTool, SeverityFactorType.Repo, false, "ox_tag_97"),
  terraform: new ChangeReason("terraform", "terraform", 0, ChangeCategory.DevopsTool, SeverityFactorType.Repo, false, "ox_tag_98"),
  cloudformation: new ChangeReason(
    "cloudformation",
    "cloudformation",
    0,
    ChangeCategory.DevopsTool,
    SeverityFactorType.Repo,
    false,
    "ox_tag_99",
  ),
  helm: new ChangeReason("helm", "helm", 0, ChangeCategory.DevopsTool, SeverityFactorType.Repo, false, "ox_tag_100"),
  pulumi: new ChangeReason("pulumi", "pulumi", 0, ChangeCategory.DevopsTool, SeverityFactorType.Repo, false, "ox_tag_101"),
  argocd: new ChangeReason("argocd", "argocd", 0, ChangeCategory.DevopsTool, SeverityFactorType.Repo, false, "ox_tag_102"),
  karpenter: new ChangeReason("karpenter", "karpenter", 0, ChangeCategory.DevopsTool, SeverityFactorType.Repo, false, "ox_tag_103"),
  arn: new ChangeReason("arn", "arn", 0, ChangeCategory.DevopsTool, SeverityFactorType.Repo, false, "ox_tag_104"),
  saltstack: new ChangeReason("saltstack", "saltstack", 0, ChangeCategory.DevopsTool, SeverityFactorType.Repo, false, "ox_tag_105"),

  // Repo Tags
  piiProcessing: new ChangeReason(
    "PII Processing",
    "This application is processing Personally Identifiable Information (PII).",
    0.1,
    ChangeCategory.Damage,
  ),
  loginInCode: new ChangeReason("Login Management", "This application is responsible for login processing.", 0.1, ChangeCategory.Damage),
  paymentInCode: new ChangeReason(
    "Payment Processing",
    "This application is responsible for payment processing.",
    0.1,
    ChangeCategory.Damage,
  ),

  // Business priority
  criticalBusinessPriority: new ChangeReason(
    "Critical Business Priority",
    "Applications deemed as Critical Business Priority are those identified by OX or the user as vitally important. Issues found in such apps may have elevated severity.",
    0.5,
    ChangeCategory.Damage,
  ),
  highBusinessPriority: new ChangeReason(
    "High Business Priority",
    "Applications deemed as High Business Priority are those identified by OX or the user as important. Issues found in such apps may have elevated severity.",
    0.1,
    ChangeCategory.Damage,
  ),
  mediumBusinessPriority: new ChangeReason(
    "Medium Business Priority",
    "Applications deemed as High Business Priority are those identified by OX or the user as moderately important. Issues found in such apps will not normally have more than high severity.",
    -1,
    ChangeCategory.Damage,
  ),
  lowBusinessPriority: new ChangeReason(
    "Low Business Priority",
    "Applications deemed as Low Business Priority are those identified by OX or the user as relatively unimportant. Issues found in such apps will normally have decreased severity.",
    -2,
    ChangeCategory.Damage,
  ),

  // SCA Validation
  exploitApplicable: new ChangeReason(
    "Exploit Applicable",
    "For the vulnerabilties OX has simulated a concrate exploit againt your application.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  exploitNotApplicable: new ChangeReason(
    "Exploit Not Applicable",
    "For the following vulnerabilities OX determines there is not active risk of an exploit.",
    -2,
    ChangeCategory.Exploitable,
  ),
  vulnerableFnUsed: new ChangeReason(
    "Vulnerable Function Used",
    "A vulnerable function is accessed in your code.",
    0.1,
    ChangeCategory.Reachable,
  ),
  vulnerableFnNotUsed: new ChangeReason(
    "Vulnerable Function Not Used",
    "A vulnerable function is not accessed in your code.",
    -2,
    ChangeCategory.Reachable,
  ),
  packageUsed: new ChangeReason("Dependency Used", "The vulnerable dependency is accessed in your code.", 0.1, ChangeCategory.Reachable),
  packageNotUsed: new ChangeReason(
    "Dependency Not Used",
    "The vulnerable dependency is not accessed in your code.",
    -2,
    ChangeCategory.Reachable,
  ),
  packageImported: new ChangeReason(
    "Dependency Imported",
    "The vulnerable dependency is included in the repository dependency list and imported in your code.",
    0.1,
    ChangeCategory.Reachable,
  ),
  packageNotImported: new ChangeReason(
    "Dependency Not Imported",
    "The vulnerable dependency is included in the repository dependency list, however, it is not used in your code.",
    -2,
    ChangeCategory.Reachable,
  ),
  CloudResourceExistInDeploymentFile: new ChangeReason(
    "Cloud Resource Found in Deployment File",
    "The cloud resource was found in an deployment file.",
    0,
    ChangeCategory.Reachable,
  ),

  // Git Posture
  WayTooManyOwners: new ChangeReason("Excessive Number of Owners", "75% of all users are owners.", 1, ChangeCategory.Reachable),
  WayTooManyAdmins: new ChangeReason("Excessive Number of Admins", "75% of all users are admins.", 1, ChangeCategory.Reachable),
  LargeNumberOfUsers: new ChangeReason("High User Count", "More than 100 users for just 1 owner.", 1, ChangeCategory.Reachable),
  noCodeReview: new ChangeReason("No Code Review", "There was no code review done.", 1, ChangeCategory.Exploitable),

  // Secret Types
  base64Secret: new ChangeReason(
    "Base64 Encoded Secret",
    "Base64 is not an encryption algorithm, it's an encoding scheme. It can be reversed easily which is a common mistake to think it is not.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  keyMgmtSecret: new ChangeReason(
    "Key Management Secret",
    "Exposure to this key management secret may lead to a wide breach of your users' data.",
    1,
    ChangeCategory.Damage,
  ),
  userMgmtSecret: new ChangeReason(
    "User Management Secret",
    "Exposure to this user management secret may lead to a wide breach of your users' data.",
    1,
    ChangeCategory.Damage,
  ),
  iacSecret: new ChangeReason(
    "IaC Deployment Secret",
    "Exposure of this IaC deployment secret may lead to DoS or abuse of your cloud infrastructure.",
    1,
    ChangeCategory.Damage,
  ),
  quotaSecret: new ChangeReason(
    "Quota Abuse Potential",
    "Exposure of this token may lead to quota abuse of this premium paid API, leading to DoS or financial loss.",
    0.01,
    ChangeCategory.Damage,
  ),
  scmSecret: new ChangeReason(
    "SCM Secret",
    "Exposure of this source control management secret may lead to source code leaks.",
    1,
    ChangeCategory.Damage,
  ),
  registrySecret: new ChangeReason(
    "Registry Secret",
    "Exposure of this registry secret may lead to source code leaks and poisoning of your private packages.",
    1,
    ChangeCategory.Damage,
  ),
  databaseSecret: new ChangeReason(
    "Database Access Secret",
    "Exposure of this database access secret may lead to data leaks and jeopardize the integrity of your data.",
    0.2,
    ChangeCategory.Damage,
  ),
  ciSecret: new ChangeReason(
    "CI Secret",
    "Exposure of this continuous integration (CI) system secret may lead to data leaks and jeopardize the integrity of your builds.",
    1,
    ChangeCategory.Damage,
  ),
  cloudSecret: new ChangeReason(
    "Cloud Provider Secret",
    "Exposure of this cloud provider secret may lead to an attacker moving laterally across your cloud infrastructure.",
    0.5,
    ChangeCategory.Damage,
  ),
  paymentProviderSecret: new ChangeReason(
    "Payment Provider Secret",
    "An attacker can perform unauthorized transactions, manipulate payment processes, gain access to sensitive customer data.",
    1,
    ChangeCategory.Damage,
  ),
  hostingProviderSecret: new ChangeReason(
    "Hosting Provider Secret",
    "An attacker can access private servers or services.",
    1,
    ChangeCategory.Damage,
  ),
  fileHostingSecret: new ChangeReason(
    "File Hosting Service Secret",
    "An attacker can access confidential data.",
    0.5,
    ChangeCategory.Damage,
  ),
  cryptoExchangeSecret: new ChangeReason(
    "Cryptocurrency Exchange Secret",
    "Cryptocurrency tokens can be stolen.",
    0.5,
    ChangeCategory.Damage,
  ),
  securitySystemSecret: new ChangeReason(
    "Security System Secret",
    "Security systems contain a lot of sensitive data such as vulnerabilities or infrastructure private information.",
    0.5,
    ChangeCategory.Damage,
  ),
  lmsSecret: new ChangeReason(
    "Log Management System Secret",
    "Typically Log Management Systems contain applications and infrastructure sensitive information.",
    0.1,
    ChangeCategory.Damage,
  ),
  observPlatformSecret: new ChangeReason(
    "Observability Platform Secret",
    "Typically Observability Platform can contain sensistive infromation.",
    0.1,
    ChangeCategory.Damage,
  ),
  emailServiceSecret: new ChangeReason(
    "Email Service Provider Secret",
    "Email Services can be used to perform phishing attacks.",
    0,
    ChangeCategory.Damage,
  ),
  messengerSecret: new ChangeReason(
    "Messenger Secret",
    "It can lead to unauthorized access to personal or sensitive conversations, potential impersonation or privacy violations.",
    0,
    ChangeCategory.Damage,
  ),
  socialMediaSecret: new ChangeReason(
    "Social Media Secret",
    "It can result in unauthorized access to personal information, private messages, sensitive data or phishing attacks.",
    0,
    ChangeCategory.Damage,
  ),
  lowImpactSecret: new ChangeReason(
    "Low Impact Secret",
    "Disclosure of this secret is unlikely to have a significant impact on your organization.",
    -2,
    ChangeCategory.Damage,
  ),
  onPremSecret: new ChangeReason(
    "On-Premise System Secret",
    "The secret for an on-premise system is typically generated for a service that is not publicly accessible via the internet.",
    -1,
    ChangeCategory.Reachable,
  ),
  prodSecret: new ChangeReason(
    "Production System Secret",
    "The secret is for a live, operational system that serves real users or customers.",
    0.01,
    ChangeCategory.Damage,
  ),
  nonProdSecret: new ChangeReason(
    "Non-Production System Secret",
    "The secret is for a development, testing or staging system that typically will not serve real customers.",
    -1,
    ChangeCategory.Damage,
  ),
  hashedPassword: new ChangeReason(
    "Hashed Password",
    "Typically retrieving a password from the hash is hard but still possible if weak algorithms is in use.",
    -1,
    ChangeCategory.Exploitable,
  ),

  // CI/CD Posture
  ghActionsOff: new ChangeReason("GitHub Actions Disabled", "GitHub Actions is disabled.", -3, ChangeCategory.Exploitable),
  defaultWorkflowPermissionOff: new ChangeReason(
    "GitHub Actions: No PR Creation/Approval",
    "GitHub Actions cannot create and approve pull requests.",
    -1,
    ChangeCategory.Exploitable,
  ),
  twoFactorOff: new ChangeReason(
    "2FA is Not Enforced",
    "Two Factor Authentication (2FA) is not enforced. This makes it easier to compromise an account.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  twoFactorOn: new ChangeReason(
    "2FA is Enforced",
    "Two Factor Authentication (2FA) is enforced. This makes it harder to compromise an account.",
    -1,
    ChangeCategory.Exploitable,
  ),
  repoNameSimilarity: new ChangeReason(
    "Repo Name Similarity",
    "User’s personal repo has a similar name to your org repo.",
    1,
    ChangeCategory.Exploitable,
  ),
  noRepoMatch: new ChangeReason(
    "No Repo Match",
    "The user’s personal repo does not seem to match any organizational repo.",
    -1,
    ChangeCategory.Exploitable,
  ),
  repoForked: new ChangeReason("Repo forked", "Organization repo was forked outside of the organization", 1, ChangeCategory.Exploitable),
  repoForkedSetting: new ChangeReason(
    "Fork Broken - Repo Public",
    "The repo was a private fork that is now public. This may mean a leak of company data.",
    4,
    ChangeCategory.Exploitable,
  ),
  repoForkedFormerUser: new ChangeReason(
    "Fork from Former User",
    "The user is no longer a member of your organization.",
    1,
    ChangeCategory.Exploitable,
  ),
  repoCopiedFormerUser: new ChangeReason(
    "Copied from Former User",
    "The user is no longer a member of your organization.",
    1,
    ChangeCategory.Exploitable,
  ),
  orgRepoAccessDenied: new ChangeReason(
    "Org Repo Access Denied",
    "The user does not have access to the org private repo anymore.",
    0,
    ChangeCategory.Reachable,
  ),
  outsideCollaborator: new ChangeReason("Outside Collaborator", "The user is an outside collaborator.", 1, ChangeCategory.Exploitable),
  privateRepo: new ChangeReason("Private User Repo", "The user's repo is private.", 0, ChangeCategory.Reachable),
  publicRepo: new ChangeReason("Public User Repo", "The user's repo is public.", 0.1, ChangeCategory.Reachable),

  // SBOM
  lowStarsCount: new ChangeReason(
    "Unpopular 3rd party Action",
    "3rd party Action used by GitHub Actions is unpopular.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  mediumStarsCount: new ChangeReason(
    "Moderately Popular 3rd Party Action",
    "3rd party Action used by GitHub Actions is moderately popular.",
    0,
    ChangeCategory.Exploitable,
  ),
  highStarsCount: new ChangeReason(
    "Very Popular 3rd Party Action",
    "3rd party Action used by GitHub Actions is popular.",
    -1,
    ChangeCategory.Exploitable,
  ),
  verifiedOrg: new ChangeReason(
    "Verified Creator",
    "3rd Party Action was created by a GitHub Verified Creator.",
    -1,
    ChangeCategory.Exploitable,
  ),
  unverifiedOrg: new ChangeReason(
    "Unverified Creator",
    "3rd Party Action was created by a creator who was not verified by GitHub.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  highMatchJaking: new ChangeReason(
    "Strong Metadata Match",
    "Library metadata is extremely similar to that of a well known library.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  midMatchJaking: new ChangeReason(
    "Good Metadata Match",
    "Library metadata is similar to that of a well known library.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  lowhMatchJaking: new ChangeReason(
    "Weak Metadata Match",
    "Library metadata is only slightly similar to that of a well known library.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  internetExposedSystem: new ChangeReason(
    "K8s Workload in Internet-exposed Cluster",
    "The workload is deployed to a K8s cluster that is internet exposed. This increases the risk of unauthorized access and potential exploitation.",
    0.1,
    ChangeCategory.Reachable,
  ),
  internetNotExposedSystem: new ChangeReason(
    "K8s Workload in Internet-blocked Cluster",
    "The workload is deployed to a system that is not accesible from public internet. This reduces the risk of unauthorized access and potential exploitation.",
    -0.1,
    ChangeCategory.Reachable,
  ),
  internetdExposedAPI: new ChangeReason(
    // Example: K8s ingress, Load balancer, API gateway, Lambda with public url, K8s service with public IP
    "K8s Workload has Internet-exposed API",
    "The workload exposes an API to the internet. This increases the risk of unauthorized access and potential exploitation.",
    0.1,
    ChangeCategory.Reachable,
  ),
  internetNotExposedAPI: new ChangeReason(
    // Examples: K8s jobs, Lambda functions, services that are not exposed to the internet (via ingress or load balancer)
    "K8s Workload has no Internet Access",
    "Workload does not recieve internet traffic. This reduces the risk of unauthorized access and potential exploitation.",
    -0.1,
    ChangeCategory.Reachable,
  ),
  LongRunningProcess: new ChangeReason(
    "Long-Running K8s Workload",
    "A persistent workload like a Kubernetes service broadens the attack surface, consequently elevating the risk of unauthorized access and potential exploitation.",
    0.1,
    ChangeCategory.Reachable,
  ),
  ShortRunningProcess: new ChangeReason(
    "Short-Lived K8s Workload",
    "A short-lived workload like a Kubernetes job or Lambda function reduces the attack surface, consequently lowering the risk of unauthorized access and potential exploitation.",
    0,
    ChangeCategory.Reachable,
  ),
  codeExposedByAPI: new ChangeReason(
    "Exposed by API",
    "There is a direct function call sequence from an API implementation to a vulnerable function in code.",
    0.1,
    ChangeCategory.Reachable,
  ),
  hotspotsPii: new ChangeReason("Hotspots PII", "Hotspots PII", 0, ChangeCategory.Reachable),
  hotspotsAPI: new ChangeReason("Hotspots API", "Hotspots API", 0, ChangeCategory.Reachable),
  hotspotsEncryption: new ChangeReason("Hotspots encryption", "Hotspots encryption", 0, ChangeCategory.Reachable),
  hotspotsDeveloper: new ChangeReason("Hotspots new developer", "Hotspots new developer", 0, ChangeCategory.Reachable),
  hotspotsCodeChanges: new ChangeReason("Hotspots Change in Old Code", "Hotspots change in old code", 0, ChangeCategory.Reachable),
  hotspotsSaaS: new ChangeReason("Hotspots SaaS Usage", "Hotspots SaaS usage", 0, ChangeCategory.Reachable),
  hotspotsDB: new ChangeReason("Hotspots DB Usage", "Hotspots DB usage", 0, ChangeCategory.Reachable),
  hotspotsFinance: new ChangeReason("Hotspots Finance", "Hotspots Finance", 0, ChangeCategory.Reachable),
  configuredSevIsHigher: new ChangeReason(
    `The configured severity was changed to be higher than the default severity`,
    `The severity of the policy was changed through policies page to be higher than the default severity`,
    0.1,
    ChangeCategory.Exploitable,
  ),
  configuredSevIsLower: new ChangeReason(
    `The configured severity was changed to be lower than the default severity`,
    `The severity of the policy was changed through policies page to be lower than the default severity`,
    -0.1,
    ChangeCategory.Exploitable,
  ),

  //*           New Vectors
  //? =======================================
  publicToolsExploit: new ChangeReason(
    "Publicly Available Exploit Tools",
    "This vulnerability can be easily exploited with tools that are readily available online, posing a significant risk.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  complianceImpact: new ChangeReason(
    "Compliance Impact",
    "This vulnerability risks non-compliance with industry standards, potentially affecting regulatory obligations and leading to penalties",
    0.01,
    ChangeCategory.Damage,
  ),
  AWSSecScoreCritical: new ChangeReason(
    "AWS Security Hub Critical Severity",
    "The AWS security hub score indicates the severity score for this CRITICAL - 'The issue must be remediated immediately to avoid it escalating'. This vulnerability is also not aligned with the AWS Well-Architected Framework Security Pillar and has a high level of security vulnerabilities.",
    0.01,
    ChangeCategory.Damage,
  ),
  AWSSecScoreHigh: new ChangeReason(
    "AWS Security Hub High Severity",
    "The AWS security hub score indicates the severity score for this HIGH - 'The issue must be addressed as a priority'. This vulnerability is also not aligned with the AWS Well-Architected Framework Security Pillar and has a high level of security vulnerabilities.",
    0.01,
    ChangeCategory.Damage,
  ),
  AWSSecScoreMedium: new ChangeReason(
    "AWS Security Hub Medium Severity",
    "The AWS security hub score indicates the severity score for this MEDIUM - 'The issue must be addressed but not urgently'. This vulnerability is also not aligned with the AWS Well-Architected Framework Security Pillar and has a medium level of security vulnerabilities.",
    0.01,
    ChangeCategory.Damage,
  ),
  AWSSecScoreLow: new ChangeReason(
    "AWS Security Hub Low Severity",
    "The AWS security hub score indicates the severity score for this LOW - 'The issue does not require action on its own.'. This vulnerability is also not aligned with the AWS Well-Architected Framework Security Pillar and has a low level of security vulnerabilities.",
    0.01,
    ChangeCategory.Damage,
  ),
  AWSSecScoreInformational: new ChangeReason(
    "AWS Security Hub Informational Severity",
    "The AWS security hub score indicates the severity score for this INFORMATIONAL - 'No issue was found'.",
    0.01,
    ChangeCategory.Damage,
  ),
  commonAttackVector: new ChangeReason(
    "Common Attack Vector",
    "This vulnerability is widely known and actively discussed in developer communities, indicating a high level of awareness. This increases the likelihood of attackers exploiting the library, posing a significant risk and requiring urgent prioritization.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  additionalCloudInfoRequired: new ChangeReason(
    "Cloud Exploitation Needs Extra Info",
    "Additional information is required for an attacker to exploit this vulnerability.",
    -1,
    ChangeCategory.Exploitable,
  ),

  //*         CVSS 4.0 Based Reasons
  //? =======================================
  networkAttackVectorCvssScore: new ChangeReason(
    "Network Attack Vector",
    "CVSS 4.0 - Attack Vector: Network - Vulnerabilities with this rating can be exploited remotely, even over the Internet.",
    0.1,
    ChangeCategory.Reachable,
  ),
  adjacentNetworkAttackVectorCvssScore: new ChangeReason(
    "Adjacent Network Attack Vector",
    "CVSS 4.0 - Attack Vector: Adjacent Network - The vulnerable component is limited to attacks originating from the same network or secure administrative domain. An example is a local network attack, such as an ARP or neighbor discovery flood, causing a denial of service on the LAN segment.",
    0.01,
    ChangeCategory.Reachable,
  ),
  localAttackVectorCvssScore: new ChangeReason(
    "Local Attack Vector",
    "CVSS 4.0 - Attack Vector: Local - The vulnerable component is not bound to the network stack and the attacker can exploit it through local or remote access, or by tricking a user into performing actions that exploit the vulnerability.",
    -0.01,
    ChangeCategory.Reachable,
  ),
  physicalAttackVectorCvssScore: new ChangeReason(
    "Physical Attack Vector",
    "CVSS 4.0 - Attack Vector: Physical - The attack requires physical interaction with the vulnerable component, such as touching or manipulating it. Examples include physical access attacks, which can lead to unauthorized tampering or extraction of sensitive data.",
    -0.1,
    ChangeCategory.Reachable,
  ),
  attackComplexityLowCvssScore: new ChangeReason(
    "Low Attack Complexity",
    "CVSS 4.0 - Attack Complexity: Low - Attacks on the vulnerable component are consistently successful without any specialized access conditions or extenuating circumstances.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  attackComplexityHighCvssScore: new ChangeReason(
    "High Attack Complexity",
    "CVSS 4.0 - Attack Complexity: High - A successful attack requires significant effort from the attacker to gather knowledge about the target environment, prepare the target environment for exploit reliability, or intercept and modify communications. This poses a high risk and should be prioritized by Product Managers.",
    -0.1,
    ChangeCategory.Exploitable,
  ),
  attackRequirementsNoneCvssScore: new ChangeReason(
    "No Attack Requiement",
    "The successful attack is independent of the deployment and execution conditions of the vulnerable system. The attacker can reliably exploit the vulnerability in all or most instances.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  attackRequirementsPresentCvssScore: new ChangeReason(
    "Present Attack Requiement",
    "CVSS 4.0 - Attack Requirements: Present - The successful attack depends on specific deployment and execution conditions of the vulnerable system. These conditions include winning a race condition, relying on execution conditions beyond the attacker's control, potentially requiring multiple attempts, and network injection.",
    -0.01,
    ChangeCategory.Exploitable,
  ),
  privilegesRequiredNoneCvssScore: new ChangeReason(
    "No Privileges Required",
    "The attacker does not require any prior authorization or access to system settings or files to carry out the attack.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  privilegesRequiredLowCvssScore: new ChangeReason(
    "Low Privileges Required",
    "The attacker requires basic user privileges that normally impacting only user-owned resources. Alternatively, an attacker with Low privileges has the ability to access only non-sensitive resources.",
    -0.01,
    ChangeCategory.Exploitable,
  ),
  privilegesRequiredHighCvssScore: new ChangeReason(
    "High Privileges Required",
    "The attacker requires high user privileges (administrative control) reducing the number of potential attackers.",
    -0.1,
    ChangeCategory.Exploitable,
  ),
  userInteractionNoneCvssScore: new ChangeReason(
    "No User Interaction",
    "CVSS 4.0 - User Interaction: None - The vulnerable system can be exploited without interaction from any user.",
    0.1,
    ChangeCategory.Reachable,
  ),
  userInteractionRequiredCvssScore: new ChangeReason(
    "Required User Interaction",
    "CVSS 4.0 - User Interaction: Required - The vulnerable system can be exploited only through interaction from a user.For instance, the vulnerability may only be exploitable during the installation of an application by a system administrator.",
    -0.1,
    ChangeCategory.Reachable,
  ),

  // *          CIA Impact Metrics
  //? =======================================

  confidentialityImpactHighCvssScore: new ChangeReason(
    "High Confidentiality Impact",
    "CVSS 4.0 - Confidentiality Impact: High - There is a complete loss of confidentiality, exposing all resources within the impacted component to the attacker. Alternatively, the attacker gains access to restricted information with a direct and significant impact, such as stealing the administrator's password or private encryption keys of a web server.",
    0.1,
    ChangeCategory.Damage,
  ),
  confidentialityImpactLowCvssScore: new ChangeReason(
    "Low Confidentiality Impact",
    "CVSS 4.0 - Confidentiality Impact: Low - Partial loss of confidentiality. The attacker gains access to restricted information, but the extent and type of information obtained are limited. The disclosure does not result in a significant loss to the affected component.",
    0.01,
    ChangeCategory.Damage,
  ),
  confidentialityImpactNoneCvssScore: new ChangeReason(
    "No Confidentiality Impact",
    "CVSS 4.0 - Confidentiality Impact: None - Confidentiality not impacted",
    0,
    ChangeCategory.Damage,
  ),
  integrityImpactHighCvssScore: new ChangeReason(
    "High Integrity Impact",
    "CVSS 4.0 - Integrity Impact: High - There is a complete loss of integrity or protection, allowing the attacker to modify all protected files or causing serious consequences with limited file modification.",
    0.1,
    ChangeCategory.Damage,
  ),
  integrityImpactLowCvssScore: new ChangeReason(
    "Low Integrity Impact",
    "CVSS 4.0 - Integrity Impact: Low - Data modification is possible, but the impact and extent of the modification are limited, resulting in no direct, significant consequences for the affected component.",
    0.01,
    ChangeCategory.Damage,
  ),
  integrityImpactNoneCvssScore: new ChangeReason(
    "Integrity Impact: None",
    "CVSS 4.0 - Integrity Impact: None Integrity not impacted.",
    0,
    ChangeCategory.Damage,
  ),
  availabilityImpactHighCvssScore: new ChangeReason(
    "High Availability Impact",
    "CVSS 4.0 - Availability Impact: High - There is a complete loss of availability, resulting in the attacker being able to fully deny access to resources in the impacted component. This loss can be sustained or persistent. Alternatively, the attacker can deny some availability, but the loss presents a direct and serious consequence to the impacted component.",
    0.1,
    ChangeCategory.Damage,
  ),
  availabilityImpactLowCvssScore: new ChangeReason(
    "Low Availability Impact",
    "CVSS 4.0 - Availability Impact: Low - Performance is degraded or resource availability is interrupted. The vulnerability can be exploited repeatedly, but the attacker cannot completely deny service to legitimate users. The impacted component's resources are either partially available at all times or fully available only intermittently, resulting in no significant direct consequences.",
    0.01,
    ChangeCategory.Damage,
  ),
  availabilityImpactNoneCvssScore: new ChangeReason(
    "No Availability Impact",
    "CVSS 4.0 - Availability Impact: None - Availability not impacted.",
    0,
    ChangeCategory.Damage,
  ),
  safePresentCvssScore: new ChangeReason(
    "Present Saftey",
    "CVSS 4.0 - Saftey: Present - The vulnerability has safety consequences aligned with 'marginal,' 'critical,' or 'catastrophic' as per IEC 61508, impacting human safety.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  safeNegligibleCvssScore: new ChangeReason(
    "Negligible Safety",
    "CVSS 4.0 - Saftey: Negligible - The vulnerability has safety consequences aligned with 'negligible' as per IEC 61508, indicating minimal risk to human safety.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  automateableNocvssScore: new ChangeReason(
    "Not Automateable",
    "CVSS 4.0 - Automateable: No - Attackers cannot fully automate all 4 steps of the kill chain for this vulnerability. These steps include reconnaissance, weaponization, delivery, and exploitation.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  automateableYesCvssScore: new ChangeReason(
    "Automateable",
    "CVSS 4.0 - Automateable: Yes - Attackers can fully automate all 4 steps of the kill chain: reconnaissance, weaponization, delivery, and exploitation.",
    0.01,
    ChangeCategory.Exploitable,
  ),
  recoveryAutomaticCvssScore: new ChangeReason(
    "Automatic Recovery",
    "CVSS 4.0 - Recovery: Automatic - Automatic recovery for this vulnerability.",
    -0.1,
    ChangeCategory.Damage,
  ),
  recoveryUserCvssScore: new ChangeReason(
    "User Recovery",
    "CVSS 4.0 - Recovery: User - User intervention is required to mitigate the risk associated with this vulnerability.",
    -0.01,
    ChangeCategory.Damage,
  ),
  recoveryIrrecoverableCvssScore: new ChangeReason(
    "Irrecoverable Recovery",
    "Recovery is not feasible for this vulnerability.",
    0.1,
    ChangeCategory.Damage,
  ),
  valueDensityConcentratedCvssScore: new ChangeReason(
    "Concentrated Value Density",
    "CVSS 4.0 - Value Density: Concentrated - The vulnerability resides in a high-value asset, like a central server, which if compromised, could grant significant control or access to an attacker, increasing the vulnerability's criticality.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  valueDensityDiffuseCvssScore: new ChangeReason(
    "Diffuse Value Density",
    "CVSS 4.0 - Value Density: Diffuse - The vulnerability affects a system with limited resources or value, reducing the potential impact and the overall risk associated with the vulnerability.",
    -0.1,
    ChangeCategory.Exploitable,
  ),
  valueResponseEffortLowCvssScore: new ChangeReason(
    "Low Value Response Effort",
    "CVSS 4.0 - Value Response Effort: Low -  Minimal effort required for responding to this vulnerability, such as simple configuration changes or updates.",
    -0.01,
    ChangeCategory.Exploitable,
  ),
  valueResponseEffortModerateCvssScore: new ChangeReason(
    "Moderate Value Response Effort",
    "CVSS 4.0 - Value Response Effort: Moderate - Moderate effort required for vulnerability mitigation",
    0.01,
    ChangeCategory.Damage,
  ),
  valueResponseEffortHighCvssScore: new ChangeReason(
    "High Value Response Effort",
    "CVSS 4.0 - Value Response Effort: High - High effort required for vulnerability mitigation",
    0.01,
    ChangeCategory.Damage,
  ),
  providerUrgencyRedCvssScore: new ChangeReason(
    "Red Provider Urgency",
    "CVSS 4.0 - Provider Urgency: Red - Provider indicates highest urgency for addressing this vulnerability.",
    0.1,
    ChangeCategory.Damage,
  ),
  providerUrgencyAmberCvssScore: new ChangeReason(
    "Amber Provider Urgency",
    "CVSS 4.0 - Provider Urgency: Amber - Provider indicates medium urgency for addressing this vulnerability.",
    0.01,
    ChangeCategory.Damage,
  ),
  providerUrgencyGreenCvssScore: new ChangeReason(
    "Green Provider Urgency",
    "CVSS 4.0 - Provider Urgency: Green - Provider indicates low urgency for addressing this vulnerability.",
    -0.01,
    ChangeCategory.Damage,
  ),
  providerUrgencyClearCvssScore: new ChangeReason(
    "Clear Provider Urgency",
    "CVSS 4.0 - Provider Urgency: Clear - Provider assesses no immediate urgency for addressing this vulnerability.",
    -0.1,
    ChangeCategory.Damage,
  ),
  exploitMaturityAttackedCvssScore: new ChangeReason(
    "Attacked Exploit Maturity",
    "CVSS 4.0 - Exploit Code Maturity: Attacked - Threat intelligence indicates that this vulnerability has been targeted by attacks, or solutions to exploit it are readily available.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  exploitMaturityProofOfConceptCvssScore: new ChangeReason(
    "Proof of Concept Exploit Maturity",
    "CVSS 4.0 - Exploit Code Maturity: PoC - Proof-of-concept exploit code is publicly available, indicating a higher likelihood of exploit but may require customization to work in all situations.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  exploitMaturityUnprovenCvssScore: new ChangeReason(
    "Unproven Exploit Maturity",
    "CVSS 4.0 - Exploit Code Maturity: Unproven - No known exploit code or reported attacks, suggesting lower immediate risk from this vulnerability.",
    -0.1,
    ChangeCategory.Exploitable,
  ),

  // * Offered - Review Required
  // ? =======================================
  crossAccountAccess: new ChangeReason(
    "Cross-Account Access",
    "Configurations that allow cross-account access can be misused to gain unauthorized access to sensitive resources, increasing the reachability impact if not strictly managed and audited potentially leading to security incidents.",
    0.01,
    ChangeCategory.Reachable,
  ),
  externalAccessRequired: new ChangeReason(
    "External Access Required",
    "This vulnerability requires external access to the system.",
    0.01,
    ChangeCategory.Reachable,
  ),
  privilegeEscalation: new ChangeReason(
    "Privilege Escalation",
    "Security issues that may allow an attacker to escalate its privileges within the cloud environment can lead to unauthorized access and potential exploitation of sensitive resources.",
    0.1,
    ChangeCategory.Exploitable,
  ),
  wildcardPermissions: new ChangeReason(
    "Wildcard Permissions",
    "Use of wildcards in role permissions, access policies, or resource policies  significantly broadens access scope can lead to unintended access, and unauthorized actions within the AWS environment.",
    0.1,
    ChangeCategory.Reachable,
  ),
  certificateExpirationImpact: new ChangeReason(
    "Expired Certificate Impact",
    "Expiring  certificates can lead to service interruption and service outages and disrupt service communications, affecting both internal operations and customer-facing services. Ensuring timely renewal and management of certificates is crucial to maintaining service availability and trust.",
    0.01,
    ChangeCategory.Reachable,
  ),
  misconfiguredStorage: new ChangeReason(
    "Misconfigured Cloud Storage",
    "Improperly configured cloud storage, such as open S3 buckets, can be easily discovered and accessed by unauthorized users, leading to data leakage.",
    0.1,
    ChangeCategory.Reachable,
  ),
  lackOfNetworkSegmentation: new ChangeReason(
    "Lack of Network Segmentation",
    "Insufficient network segmentation within the cloud environment can allow lateral movement, increasing the impact radius of an attack.",
    0.01,
    ChangeCategory.Reachable,
  ),
  inadequateSecurityGroupsRules: new ChangeReason(
    "Inadequate SecurityGroups Rules",
    "Insufficiently defined SecurityGroups rules can inadvertently expose internal services to the public internet, increasing the attack surface.",
    -0.01,
    ChangeCategory.Reachable,
  ),
};

export const secretTagMapping = {
  high: severityReasons.highConfidenceDetection,
  medium: severityReasons.mediumConfidenceDetection,
  low: severityReasons.lowConfidenceDetection,
  quota: severityReasons.quotaSecret,
  scm: severityReasons.scmSecret,
  saas: severityReasons.saasSecret,
  sfa: severityReasons.singleFactorAuthentication,
  onprem: severityReasons.onPremSecret,
  payment: severityReasons.paymentProviderSecret,
  pii: severityReasons.piiProcessing,
  login: severityReasons.loginInCode,
  iac: severityReasons.iacSecret,
  auth: severityReasons.userMgmtSecret,
  keyMgmt: severityReasons.keyMgmtSecret,
  registry: severityReasons.registrySecret,
  db: severityReasons.databaseSecret,
  cicd: severityReasons.ciSecret,
  cloud: severityReasons.cloudSecret,
  hash: severityReasons.hashedPassword,
  hosting: severityReasons.hostingProviderSecret,
  fileHosting: severityReasons.fileHostingSecret,
  crypto: severityReasons.cryptoExchangeSecret,
  securityTool: severityReasons.securitySystemSecret,
  logging: severityReasons.lmsSecret,
  monitoring: severityReasons.observPlatformSecret,
  emailService: severityReasons.emailServiceSecret,
  messaging: severityReasons.messengerSecret,
  socialMedia: severityReasons.socialMediaSecret,
  lowImpact: severityReasons.lowImpactSecret,
  base64: severityReasons.base64Secret,
};

export const LATERAL_MOVEMENT_GROUPS = ["cicd", "scm", "iac", "auth", "keyMgmt", "registry", "cloud"];

export class BlameResponse {
  commitSha: string;
  commitDate: string;
  commiterName: string;
  commiterEmail: string;
  commitDescription: string;
  eduVideoLink: string;
  summaryTitle: string;
  detailedTitle: string;
  hasPublicExploit: boolean;
  rarelySeenExploit: boolean;
  productionSecret: boolean;
  someSeenExploit: boolean;
  frequentPublicExploit: boolean;
  publicExploitLink: string;
  publishedExploitDate: string;
  vulnerableFunction: string;
  dependencyType: string;
  cvssScore: number;
  cvssVersion: string;
  attackVector: string;
  cve: string;
  fileName: string;
  exploitType: string;
  cwe: string[] = [];
  ruleId: string;
  uid: string;
  triggerPackage: Dependency;
  triggerPackagesList: Dependency[];
  language: string;
  cweList: CweObject[] = [];
  securityAlertType: SecurityAlertType;
  securityAlertSubType: SecurityAlertType;
  snippetLineNumber: number;
  dependencyChain: Dependency[] = [];
  dependencyChainList: Dependency[][] = [];
  fromCommitHistory: boolean;
  cveDescription: string = "";
  versionsPageUrl: string = "";
  fixedVersion: string = "";
  verifiedFp: boolean = false;
  epss: number;
  percentile: number;
  fixAdoption: number;
  communityAwareness: number;
  exploitDiversity: number;
  githubCommits: number;
  githubIssues: number;
  githubRepos: number;
  githubCode: number;

  severityChangedReason: ChangeReason[] = [];

  //Overwrite
  lineContent: string = "";
  snippetContent: string = "";
  fixes: any[] = [];
  severityStr: string;
  severity: any;
  title: string;
  link: string = "";
  startLineNumber: number;
  endLineNumber: any;
  recommendation: string;
  pkgManager: string = "";
  registry: string = "";
  installedVersion: string = "";
  pkgName: string = "";

  askedOnce: boolean = false;
  runtime: Runtime;
  graphExists: boolean = false;
  oxRecommendationExists: boolean = false;
  commitInfoExists: boolean = false;
  checkedForDirectIndirect: boolean = false;

  success: boolean = false;
}

export function getDependencyType(dependencyType: string) {
  if (!dependencyType) {
    return DependencyType.Unknown;
  } else if (dependencyType === DependencyType.Direct) {
    return DependencyType.Direct;
  } else if (dependencyType === DependencyType.Indirect) {
    return DependencyType.Indirect;
  } else if (dependencyType === "dev") {
    return DependencyType.Development;
  }
  return DependencyType.Unknown;
}

export class BlameRequest {
  cloneDir: string;
  fileName: string;
  match: string;
  category: string;
  pkgName: string;
  pkgManager: string;
  fixedVersion: string;
  installedVersion: string;
  uid: string;
  ruleId: string;
  snippet: string;
  cve: string;
  cwe: string[];
  title: string;
  commitSha: string;
  fromCommitHistory: boolean;
  startLineNumber: number;
  repoFullName: string;
  isOS: boolean;
  triggerPackageName: string;
  triggerPackageVersion: string;
  toolName: string;
}
export interface Runtime {
  languageInfo: LanguageInfo;
  osInfo: OsInfo;
}

export interface LanguageInfo {
  name: string;
  version: string;
}

export interface OsInfo {
  name: string;
  version: string;
}

export interface FixIssue {
  fixType: FixType;
  fixTitle?: string;
  fixDescription?: string;
  fixPR?: FixPR;
  isFixApplied?: boolean;
  fixAppliedBy?: string;
  activeFix: ActiveFix;
}
export interface ActiveFix {
  fixId: string;
  fixURL: string;
}

export interface FixPR {
  issueBranch: string;
  commitMessage: string;
  fixFiles: FixFile[];
}
export interface FixFile {
  filePath: string;
  newFileContent: string;
}
export enum FixType {
  PullRequest = "pullRequest",
}

severityReasons.piiProcessing.tagId = "ox_tag_1";
severityReasons.loginInCode.tagId = "ox_tag_2";
severityReasons.paymentInCode.tagId = "ox_tag_3";
severityReasons.mongoDBAtlas.tagId = "ox_tag_4";
severityReasons.mongoDB.tagId = "ox_tag_5";
severityReasons.azureSQLDB.tagId = "ox_tag_6";
severityReasons.mssql.tagId = "ox_tag_7";
severityReasons.postgres.tagId = "ox_tag_8";
severityReasons.snowflake.tagId = "ox_tag_9";
severityReasons.oracle.tagId = "ox_tag_10";
severityReasons.mysql.tagId = "ox_tag_11";
severityReasons.influxDB.tagId = "ox_tag_12";
severityReasons.redis.tagId = "ox_tag_13";
severityReasons.couchbase.tagId = "ox_tag_14";
severityReasons.neo4j.tagId = "ox_tag_15";
severityReasons.flask.tagId = "ox_tag_16";
severityReasons.django.tagId = "ox_tag_17";
severityReasons.pyramid.tagId = "ox_tag_18";
severityReasons.fastapi.tagId = "ox_tag_19";
severityReasons.bottle.tagId = "ox_tag_20";
severityReasons.spring.tagId = "ox_tag_21";
severityReasons.springBoot.tagId = "ox_tag_22";
severityReasons.jakarta.tagId = "ox_tag_23";
severityReasons.play.tagId = "ox_tag_24";
severityReasons.struts.tagId = "ox_tag_25";
severityReasons.vertx.tagId = "ox_tag_26";
severityReasons.ktor.tagId = "ox_tag_27";
severityReasons.angular.tagId = "ox_tag_28";
severityReasons.expressJS.tagId = "ox_tag_29";
severityReasons.react.tagId = "ox_tag_30";
severityReasons.nextJS.tagId = "ox_tag_31";
severityReasons.vueJS.tagId = "ox_tag_32";
severityReasons.nestJS.tagId = "ox_tag_33";
severityReasons.koa.tagId = "ox_tag_34";
severityReasons.fastify.tagId = "ox_tag_35";
severityReasons.gin.tagId = "ox_tag_36";
severityReasons.echo.tagId = "ox_tag_37";
severityReasons.iris.tagId = "ox_tag_38";
severityReasons.beego.tagId = "ox_tag_39";
severityReasons.revel.tagId = "ox_tag_40";
severityReasons.fiber.tagId = "ox_tag_41";
severityReasons.internetExposedSystem.tagId = "ox_tag_92";
severityReasons.internetdExposedAPI.tagId = "ox_tag_93";
severityReasons.publishedPackage.tagId = "ox_tag_94";

severityReasons.piiProcessing.requiredHits = 2;
severityReasons.loginInCode.requiredHits = 2;
severityReasons.paymentInCode.requiredHits = 2;
severityReasons.mongoDBAtlas.requiredHits = 1;
severityReasons.mongoDB.requiredHits = 2;
severityReasons.azureSQLDB.requiredHits = 1;
severityReasons.mssql.requiredHits = 1;
severityReasons.postgres.requiredHits = 1;
severityReasons.snowflake.requiredHits = 2;
severityReasons.oracle.requiredHits = 2;
severityReasons.mysql.requiredHits = 1;
severityReasons.influxDB.requiredHits = 2;
severityReasons.redis.requiredHits = 2;
severityReasons.couchbase.requiredHits = 2;
severityReasons.neo4j.requiredHits = 2;
severityReasons.flask.requiredHits = 2;
severityReasons.django.requiredHits = 2;
severityReasons.pyramid.requiredHits = 2;
severityReasons.fastapi.requiredHits = 2;
severityReasons.bottle.requiredHits = 2;
severityReasons.spring.requiredHits = 2;
severityReasons.springBoot.requiredHits = 1;
severityReasons.jakarta.requiredHits = 2;
severityReasons.play.requiredHits = 2;
severityReasons.struts.requiredHits = 2;
severityReasons.vertx.requiredHits = 2;
severityReasons.ktor.requiredHits = 2;
severityReasons.angular.requiredHits = 2;
severityReasons.expressJS.requiredHits = 2;
severityReasons.react.requiredHits = 2;
severityReasons.nextJS.requiredHits = 2;
severityReasons.vueJS.requiredHits = 2;
severityReasons.nestJS.requiredHits = 2;
severityReasons.koa.requiredHits = 2;
severityReasons.fastify.requiredHits = 2;
severityReasons.gin.requiredHits = 2;
severityReasons.echo.requiredHits = 2;
severityReasons.iris.requiredHits = 2;
severityReasons.beego.requiredHits = 2;
severityReasons.revel.requiredHits = 2;
severityReasons.fiber.requiredHits = 2;

severityReasons.flask.shouldBeSeverityFactor = false;
severityReasons.django.shouldBeSeverityFactor = false;
severityReasons.pyramid.shouldBeSeverityFactor = false;
severityReasons.fastapi.shouldBeSeverityFactor = false;
severityReasons.bottle.shouldBeSeverityFactor = false;
severityReasons.spring.shouldBeSeverityFactor = false;
severityReasons.springBoot.shouldBeSeverityFactor = false;
severityReasons.jakarta.shouldBeSeverityFactor = false;
severityReasons.play.shouldBeSeverityFactor = false;
severityReasons.struts.shouldBeSeverityFactor = false;
severityReasons.vertx.shouldBeSeverityFactor = false;
severityReasons.ktor.shouldBeSeverityFactor = false;
severityReasons.angular.shouldBeSeverityFactor = false;
severityReasons.expressJS.shouldBeSeverityFactor = false;
severityReasons.react.shouldBeSeverityFactor = false;
severityReasons.nextJS.shouldBeSeverityFactor = false;
severityReasons.vueJS.shouldBeSeverityFactor = false;
severityReasons.nestJS.shouldBeSeverityFactor = false;
severityReasons.koa.shouldBeSeverityFactor = false;
severityReasons.fastify.shouldBeSeverityFactor = false;
severityReasons.gin.shouldBeSeverityFactor = false;
severityReasons.echo.shouldBeSeverityFactor = false;
severityReasons.iris.shouldBeSeverityFactor = false;
severityReasons.beego.shouldBeSeverityFactor = false;
severityReasons.revel.shouldBeSeverityFactor = false;
severityReasons.fiber.shouldBeSeverityFactor = false;
