import { AlertSeverity, SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { Token } from "../../entitis/collectorEntitisTypes";
import { CloudSecurityEvent } from "../../entitis/cloudTypes";

import axios, { AxiosResponse, AxiosRequestConfig, AxiosError } from "axios";
import PromisePool from "@supercharge/promise-pool/dist";

import loggerImport from "../../logger";
import JsonApplicationDiscoveryOverview from "../../policy/reporting/jsonApplicationDiscoveryOverview";
import ExternalSecurityProviderBase from "../base/externalSecurityProviderBase";
import { capitalizeFirstLetter, getLanFromPkgManager } from "../../helper/commonUtils";

const logger = loggerImport.getDebugLogger();

const LOG_NAME = "SemgrepEnterprise";

const PAGE_SIZE = {
  DEPLOYMENTS: 100,
  FINDINGS: 100,
  VULNERABILITIES: 100,
};

interface SemgrepDeploymentsFindings {
  url: string;
}

interface SemgrepDeployments {
  id: number;
  name: string;
  slug: string;
  findings: SemgrepDeploymentsFindings;
}

interface SemgrepFindingsRepository {
  name: string;
  url: string | null; // The source url from which this repository last scanned
}

interface SemgrepFindingsLocation {
  file_path: string; // File path of the relevant line and column numbers.
  line: number; // Line at which the target starts.
  column: number; // Column at which the target starts.
  end_line: number; // Line at which the target ends.
  end_column: number; // Column at which the target ends.
}

interface SemgrepFindingsSourcingPolicy {
  id: number; // Unique numerical identifier of the policy.
  name: string; // Human readable name.
  slug: string; // Sanitized machine-readable name.
}

interface SemgrepFindings {
  id: number; // Unique ID of this finding
  ref: string | null; // External reference to the source of this finding (e.g. PR)
  first_seen_scan_id: number;
  syntactic_id: string;
  match_based_id: string | null; // ID calculated based on a finding's file path, rule id, and the rule index.
  state: SemgrepFindingsState; // Status of the finding's resolution.
  repository: SemgrepFindingsRepository; // Which repository is this finding a part of, defined via name.
  triage_state: SemgrepTriageState; // Status of the finding's triaging
  severity: SemgrepFindingsSeverities; // Severity of the rule that triggered the finding. Ranges from low, which would correlate to info, up to high which would correlate to error.
  confidence: SemgrepFindingsConfidence; // Confidence of the rule that triggered the finding.
  categories: any[] | null; // The categories of the finding as classified by the associated rule metdata.
  relevant_since: string | null;
  rule_name: string; //
  rule_message: string; // Rule message on the time of rule triggering. Older findings might have the value missing/removed.
  location: SemgrepFindingsLocation | null; // Location of the record in a file, as reported by Semgrep. If null, then the information does not exist or lacks integrity (older or broken scans).
  sourcing_policy: SemgrepFindingsSourcingPolicy | null; // Reference to a policy, with some basic information. If null, then the information does not exist or lacks integrity (older or broken scans).
  triaged_at: string | null;
  triage_comment: string | null;
  state_updated_at: string | null; // When this issues' state was last updated
}

interface SemgrepVulnerabilityAdvisoryReference {
  cveIds: string[];
  cweIds: string[];
  owaspIds: string[];
  urls: string[];
}

interface SemgrepVulnerabilityAdvisoryDependency {
  name: string; // String identifier of dependency
  versionSpecifier: string; // Version specifier of dependency.
}

interface SemgrepVulnerabilityAdvisory {
  ruleId: string; // Unique identifier for the rule.
  title: string; // Human-readable title for the vulnerability.
  description: string; // Description for the vulnerability.
  ecosystem: SemgrepEcoSystem;
  severity: SemgrepVulnerabilitySeverity;
  references: SemgrepVulnerabilityAdvisoryReference;
  announcedAt: string; // Date the advisory was announced.
  ruleText: string; // The text of the rule.
  reachability: SemgrepVulnerabilityAdvisoryReachability;
  reachableIf: string; // Conditions that if true would mean vulnerability applies. set if reachability == MANUAL_REVIEW_REACHABLE
  vulnerableDependencies: SemgrepVulnerabilityAdvisoryDependency[]; // Version specifiers of vulnerable dependencies.
  safeDependencies: SemgrepVulnerabilityAdvisoryDependency[]; // ersion specifiers of safe dependencies
}

interface SemgrepVulnerabilityDependencyFileLocation {
  path: string; // Path to a file.
  startLine: string; // Starting line number (1 indexed).
  startCol: string; // Starting column number (1 indexed).
  endLine: string; // Ending line number (1 indexed).
  endCol: string; // Ending column number (1 indexed).
  url: string; // URL to code location if available, otherwise empty.
  committedAt: string; // Timestamp when code file was last modified, if available.
}

interface SemgrepVulnerabilityUsageTicket {
  url: string; // URL of the external ticket.
  externalSlug: string; // Identifier of the external ticket (e.g. for Jira, something like OPS-158).
}

interface SemgrepVulnerabilityUsage {
  findingId: string;
  location: SemgrepVulnerabilityDependencyFileLocation;
  externalTicket: SemgrepVulnerabilityUsageTicket;
}

interface SemgrepVulnerabilityTriage {
  status: SemgrepVulnerabilityStatus;
  dismissReason: SemgrepVulnerabilityTriageDismissReason;
  issueUrl: string;
  prUrl: string;
}

interface SemgrepVulnerability {
  title: string; // Human-readable title for the vulnerability.
  advisory: SemgrepVulnerabilityAdvisory;
  exposureType: SemgrepVulnerabilityExposureType;
  repositoryId: string; // The ID of the repository where the vulnerability was found.
  subdirectory: string; // Subdirectory where the vulnerability was found.
  matchedDependency: SemgrepVulnerabilityAdvisoryDependency; // A specific dependency.
  dependencyFileLocation: SemgrepVulnerabilityDependencyFileLocation; // Specific location in a file.
  usages: SemgrepVulnerabilityUsage[]; // Direct usages of the dependency in code. only defined if exposure_type == REACHABLE
  triage: SemgrepVulnerabilityTriage;
  groupKey: string; // generated from repository_id, subdirectory, and advisory.rule_id
  packageManager: SemgrepPackageManager;
  closestSafeDependency: SemgrepVulnerabilityAdvisoryDependency;
  repositoryName: string; // Plaintext name of repository this vulnerability belongs to. makes it easier to filter vulns by repo name
  openedAt: string; // Date the vulnerability was first found.
  firstTriagedAt: string; // Date the vulnerability was first triaged.
  transitivity: SemgrepVulnerabilityTransitivity;
}

interface SemgrepVulnerabilityCursor {
  vulnOffset: string;
  issueOffset: string;
}

enum SemgrepFindingsState {
  Muted = "muted",
  Fixed = "fixed",
  Removed = "removed",
  Unresolved = "unresolved",
}

enum SemgrepTriageState {
  Untriaged = "untriaged",
  Ignored = "ignored",
  Reopened = "reopened",
}

enum SemgrepFindingsConfidence {
  Low = "low",
  Medium = "medium",
  High = "high",
}

enum SemgrepFindingsSeverities {
  Low = "low",
  Medium = "medium",
  High = "high",
  Critical = "critical",
}

enum SemgrepVulnerabilityStatus {
  UnknownStatus = "UNKNOWN_STATUS",
  New = "NEW",
  InProgress = "IN_PROGRESS",
  Ignored = "IGNORED",
  Closed = "CLOSED",
}

enum SemgrepVulnerabilitySeverity {
  UnknownSeverity = "UNKNOWN_SEVERITY",
  Low = "LOW",
  Medium = "MEDIUM",
  High = "HIGH",
  Critical = "CRITICAL",
}

enum SemgrepVulnerabilityAdvisoryReachability {
  UnknownRuleType = "UNKNOWN_RULE_TYPE",
  VersionSpecifier = "VERSION_SPECIFIER",
  Reachability = "REACHABILITY",
  AlwaysReachable = "ALWAYS_REACHABLE",
  ManualReviewReachable = "MANUAL_REVIEW_REACHABLE",
}

enum SemgrepVulnerabilityExposureType {
  UnknownExposure = "UNKNOWN_EXPOSURE",
  Unreachable = "UNREACHABLE",
  Reachable = "REACHABLE",
}

enum SemgrepVulnerabilityTriageDismissReason {
  UnknownReason = "UNKNOWN_REASON",
  FalsePositive = "FALSE_POSITIVE",
  AcceptableRisk = "ACCEPTABLE_RISK",
  NoTimeToFix = "NO_TIME_TO_FIX",
}

enum SemgrepVulnerabilityTransitivity {
  UnknownTransitivity = "UNKNOWN_TRANSITIVITY",
  Transitive = "TRANSITIVE",
  Direct = "DIRECT",
}

enum SemgrepPackageManager {
  NoPackageManager = "no_package_manager",
  NPM = "npm",
  YARN = "yarn",
  PIPENV = "pipenv",
  POETRY = "poetry",
  GO = "go",
  CARGO = "cargo",
  MAVEN = "maven",
  GEM = "gem",
  BUNDLER = "bundler",
  COMPOSER = "composer",
  NUGET = "nuget",
  PUB = "pub",
  SWIFTPM = "swiftpm",
}

enum SemgrepEcoSystem {
  NoPackageManager = "no_package_manager",
  NPM = "npm",
  PYPI = "pypi",
  GOMOD = "gomod",
  CARGO = "cargo",
  MAVEN = "maven",
  GEM = "gem",
  COMPOSER = "composer",
  NUGET = "nuget",
  PUB = "pub",
  SWIFTPM = "swiftpm",
}

class SemgrepAPI {
  private token: Token;

  private apiUrl: string;
  private apiToken: string;

  public isValidToken: boolean = false;

  private TIME_UNITS = {
    SEC: 1000,
    MIN: 60 * 1000,
  };

  private TIME_OUTS = {
    SHORT: 30 * this.TIME_UNITS.SEC,
    MEDIUM: 2 * this.TIME_UNITS.MIN,
    LONG: 5 * this.TIME_UNITS.MIN,
  };

  constructor(token: Token) {
    this.isValidToken = false;

    this.token = token;
    this.apiToken = this.token.password;

    if (this.token.host.endsWith("/")) {
      const i = this.token.host.lastIndexOf("/");

      this.apiUrl = this.token.host.substring(0, i);
      logger.info(`${LOG_NAME} - removing slash from apiUrl: ${this.apiUrl}`);
    } else {
      this.apiUrl = this.token.host;
    }

    logger.info(`${LOG_NAME} - Setting the apiUrl : ${this.apiUrl}`);
  }

  /**
   *  Auth
   *
   *    The API supports authentication with an API token with the "Web API" permission, without limited scopes of access.
   *
   *  Note  : Currently the Auth API is not available , we are using the deployments api for the authentication purpose
   */
  async auth() {
    const errMessage = `${LOG_NAME} - Authenticate Failed : for token ${this.token}, host: ${this.apiUrl}, err: `;

    logger.info(`${LOG_NAME} - Authentication ** Begin **`);

    try {
      const url = `${this.apiUrl}/deployments`;
      const result: AxiosResponse<any> = await axios.get(url, {
        timeout: this.TIME_OUTS.MEDIUM,
        headers: {
          Authorization: `Bearer ${this.apiToken}`,
          "Content-Type": "application/json",
        },
      });

      if (result.status == 200) {
        this.isValidToken = true;
      } else {
        logger.error(`${errMessage} ${result}`);
      }
    } catch (e) {
      logger.error(`${errMessage} ${e}`);
    }

    logger.info(`${LOG_NAME} - Authentication ** Completed **`);
  }

  async getVulnerabilityApi(cursor: SemgrepVulnerabilityCursor, severity: string, deployment: SemgrepDeployments) {
    const errMessage = `${LOG_NAME} - Error in fetching deployment , err : `;
    try {
      const url = `${this.apiUrl}/deployments/${deployment.id}/ssc-vulns`;
      let body = {
        page_size: PAGE_SIZE.VULNERABILITIES,
        severities: [severity],
      };

      if (cursor) {
        body["cursor"] = cursor;
      }

      const result: AxiosResponse<any> = await axios.post(url, body, {
        timeout: this.TIME_OUTS.MEDIUM,
        headers: {
          Authorization: `Bearer ${this.apiToken}`,
          "Content-Type": "application/json",
        },
      });

      if (result.status == 200) {
        return result && result.data;
      } else {
        //StatesHelper.Instance.globalApisFails.add("wiz-cspm");
        logger.error(`${errMessage} ${result.status}!`);
      }
    } catch (error: any) {
      logger.error(`${errMessage} ${error}`);
      //StatesHelper.Instance.globalApisFails.add("wiz-cspm");
    }
  }

  async getVulnerability(severity: string, deployment: SemgrepDeployments, vulnerabilities: SemgrepVulnerability[]) {
    let currPage = 0;
    let cursor: SemgrepVulnerabilityCursor;

    let retryCount = 3;
    while (true) {
      try {
        this.logInfo(currPage, 0, `Vulnerability with Severity ${severity}`, PAGE_SIZE.FINDINGS);

        const result = await this.getVulnerabilityApi(cursor, severity, deployment);
        if (result) {
          // Reset retry count
          retryCount = 3;

          if (result.vulns && result.vulns.length > 0) {
            vulnerabilities.push(...result.vulns);
          } else {
            break;
          }

          if (result.hasMore) {
            cursor = result.cursor;
          } else {
            break;
          }

          currPage += 1;
        } else {
          logger.error(`${LOG_NAME} - Error in getVulnerability - Error : No Result , retryCount : ${retryCount}`);

          if (retryCount < 1) {
            break;
          }

          retryCount = retryCount - 1;
        }
      } catch (e) {
        logger.error(`${LOG_NAME} - Error in getVulnerability - Error : ${e} , retryCount : ${retryCount}`);

        if (retryCount < 1) {
          break;
        }

        retryCount = retryCount - 1;
      }
    }
  }

  async getVulnerabilities(deployment: SemgrepDeployments, vulnerabilities: SemgrepVulnerability[]) {
    logger.info(`${LOG_NAME} - Getting All Vulnerabilities ** Begin **`);

    const severities = [
      SemgrepVulnerabilitySeverity.UnknownSeverity,
      SemgrepVulnerabilitySeverity.Low,
      SemgrepVulnerabilitySeverity.Medium,
      SemgrepVulnerabilitySeverity.High,
      SemgrepVulnerabilitySeverity.Critical,
    ];

    try {
      await PromisePool.for(severities)
        .withConcurrency(1)
        .process(async (severity: string) => {
          try {
            await this.getVulnerability(severity, deployment, vulnerabilities);
          } catch (err) {
            logger.error(`${LOG_NAME} - Error in getVulnerabilities with severity : ${severity} , err: ${err}`);
          }
        });
    } catch (err) {
      logger.error(`${LOG_NAME} - Error in getVulnerabilities , err: ${err}`);
    }

    logger.info(`${LOG_NAME} - Getting All Vulnerabilities ** End **`);
  }

  async getFindingApi(page: number, severity: string, deployment: SemgrepDeployments) {
    const errMessage = `${LOG_NAME} - Error in fetching deployment , err : `;
    try {
      const url = `${this.apiUrl}/deployments/${deployment.slug}/findings`;
      const params = {
        page_size: PAGE_SIZE.FINDINGS,
        page: page,
        severities: severity,
      };

      const result: AxiosResponse<any> = await axios.get(url, {
        params: params,
        timeout: this.TIME_OUTS.MEDIUM,
        headers: {
          Authorization: `Bearer ${this.apiToken}`,
          "Content-Type": "application/json",
        },
      });

      if (result.status == 200) {
        return result && result.data;
      } else {
        //StatesHelper.Instance.globalApisFails.add("");
        logger.error(`${errMessage} ${result.status}!`);
      }
    } catch (error: any) {
      logger.error(`${errMessage} ${error}`);
      //StatesHelper.Instance.globalApisFails.add("");
    }
  }

  async getFinding(severity: string, deployment: SemgrepDeployments, findings: SemgrepFindings[]) {
    let currPage = 0;

    let retryCount = 3;
    while (true) {
      try {
        this.logInfo(currPage, 0, `Findings with Severity ${severity}`, PAGE_SIZE.FINDINGS);

        const result = await this.getFindingApi(currPage, severity, deployment);
        if (result) {
          // Reset retry count
          retryCount = 3;

          if (result.findings && result.findings.length > 0) {
            findings.push(...result.findings);
          } else {
            break;
          }

          currPage += 1;
        } else {
          logger.error(`${LOG_NAME} - Error in getFinding - Error : No Result , retryCount : ${retryCount}`);

          if (retryCount < 1) {
            break;
          }

          retryCount = retryCount - 1;
        }
      } catch (e) {
        logger.error(`${LOG_NAME} - Error in getFinding - Error : ${e} , retryCount : ${retryCount}`);

        if (retryCount < 1) {
          break;
        }

        retryCount = retryCount - 1;
      }
    }
  }

  async getFindings(deployment: SemgrepDeployments, findings: SemgrepFindings[]) {
    logger.info(`${LOG_NAME} - Getting All Findings ** Begin **`);

    const severities = [
      SemgrepFindingsSeverities.Low,
      SemgrepFindingsSeverities.Medium,
      SemgrepFindingsSeverities.High,
      SemgrepFindingsSeverities.Critical,
    ];

    try {
      await PromisePool.for(severities)
        .withConcurrency(1)
        .process(async (severity: string) => {
          try {
            await this.getFinding(severity, deployment, findings);
          } catch (err) {
            logger.error(`${LOG_NAME} - Error in getFindings with severity : ${severity} , err: ${err}`);
          }
        });
    } catch (err) {
      logger.error(`${LOG_NAME} - Error in getFindings , err: ${err}`);
    }

    logger.info(`${LOG_NAME} - Getting All Findings ** End **`);
  }

  logInfo(currPage, totalCount, title, page_size) {
    const start = currPage * page_size;
    let end = start + page_size;
    if (totalCount != 0) {
      end = end > totalCount ? totalCount : end;
    }

    logger.info(`${LOG_NAME} - Getting ${title} from ${start} - ${end}`);
  }

  async getDeploymentAPI() {
    const errMessage = `${LOG_NAME} - Error in fetching deployment , err : `;
    try {
      const url = `${this.apiUrl}/deployments`;
      const result: AxiosResponse<any> = await axios.get(url, {
        timeout: this.TIME_OUTS.MEDIUM,
        headers: {
          Authorization: `Bearer ${this.apiToken}`,
          "Content-Type": "application/json",
        },
      });

      if (result.status == 200) {
        return result && result.data;
      } else {
        //StatesHelper.Instance.globalApisFails.add("wiz-cspm");
        logger.error(`${errMessage} ${result.status}!`);
      }
    } catch (error: any) {
      logger.error(`${errMessage} ${error}`);
      //StatesHelper.Instance.globalApisFails.add("wiz-cspm");
    }
  }

  async getDeployments(deployments: SemgrepDeployments[]) {
    logger.info(`${LOG_NAME} - Getting Deployments ** Begin **`);

    try {
      const result = await this.getDeploymentAPI();

      if (result?.deployments) {
        deployments.push(...result.deployments);
      } else {
        // fail handle
      }
    } catch (e) {
      logger.error(`${LOG_NAME} - Error in Fetching Deployments! : ${e}`);
    }

    logger.info(`${LOG_NAME} - Getting Deployments ** Completed **`);
  }

  setSASTIssue(issue: SemgrepFindings, securityEvents: SecurityEvent[]) {
    try {
      if ([SemgrepFindingsState.Fixed, SemgrepFindingsState.Removed, SemgrepFindingsState.Muted].includes(issue.state)) {
        logger.info(`${LOG_NAME} - setSASTIssue , Skipping Issue : ${issue.rule_name} , with state : ${issue.state}`);
        return;
      }

      // Example : javascript.express.security.audit.express-cookie-settings.express-cookie-session-default-name
      // We will extract only `express-cookie-session-default-name`
      const rule_name = issue.rule_name.substring(issue.rule_name.lastIndexOf(".") + 1, issue.rule_name.length);

      // Example : back-component/docker-compose.yml
      let type: SecurityAlertType;
      if (issue.location?.file_path.search("docker") > -1) {
        type = SecurityAlertType.iac;
      } else {
        type = SecurityAlertType.sast;
      }

      const securityEvent = new SecurityEvent(
        "Semgrep-Enterprise",
        true,
        "",
        issue.relevant_since,
        "",
        "",
        "",
        rule_name,
        issue.rule_message,
        issue.location.file_path,
        issue.severity,
        "",
        issue.location.line,
        AlertSeverity[AlertSeverity.High],
        type,
        "",
        "",
        "",
        issue.location.end_line,
        false,
        false,
        "",
        "",
        "",
        "",
        rule_name,
        "",
        "",
        issue.repository.name,
        "",
        issue.location.file_path,
        "semgrep-enterprise",
      );

      if (issue.ref) {
        securityEvent.version = issue.ref;
      }
      securityEvent.realMatch = issue.match_based_id;

      // @todo nikunj , need to search for this
      securityEvent.linkToExternalProduct = ``;

      securityEvents.push(securityEvent);
    } catch (e) {
      logger.error(`${LOG_NAME} - Error in setSASTIssue , Error : ${e} , Issue Details : ${issue}`);
    }
  }

  getCVEsFromRuleText(ruleText: string) {
    try {
      const rules = JSON.parse(ruleText.replace(/\\n/g, "").replace(/\n/g, "").replace(/  /g, ""));
      if (rules?.metadata && rules?.metadata["sca-vuln-database-identifier"]) {
        return rules.metadata["sca-vuln-database-identifier"];
      }
    } catch (e) {}
  }

  setSCAIssue(issue: SemgrepVulnerability, securityEvents: SecurityEvent[]) {
    try {
      const securityEvent = new SecurityEvent(
        "Semgrep-Enterprise",
        true,
        "",
        issue.openedAt,
        "",
        "",
        "",
        issue.advisory.title,
        issue.advisory.description,
        issue.dependencyFileLocation.path,
        issue.advisory.severity,
        "",
        parseInt(issue.dependencyFileLocation.startLine),
        AlertSeverity[AlertSeverity.High],
        SecurityAlertType.sca,
        ``,
        `${issue.matchedDependency.name}@${issue.matchedDependency.versionSpecifier}`,
        `${issue.matchedDependency.name}@${issue.matchedDependency.versionSpecifier}`,
        parseInt(issue.dependencyFileLocation.endLine),
        false,
        false,
        "",
        "",
        "",
        "",
        issue.advisory.ruleId,
        "",
        "",
        issue.repositoryName,
        "",
        issue.dependencyFileLocation.url,
        "semgrep-enterprise",
      );

      securityEvent.pkgManager = issue.packageManager;
      if (securityEvent.pkgManager) {
        securityEvent.language = getLanFromPkgManager(securityEvent.pkgManager).toLowerCase();
        securityEvent.language = capitalizeFirstLetter(securityEvent.language);
      }

      securityEvent.pkgName = issue.matchedDependency.name;
      securityEvent.installedVersion = issue.matchedDependency.versionSpecifier;
      securityEvent.fixedVersion = issue.closestSafeDependency?.versionSpecifier;

      if (issue.advisory?.references?.cveIds?.length > 0) {
        securityEvent.cves.push(...issue.advisory.references.cveIds);
        securityEvent.ruleId = issue.advisory.references.cveIds[0];
      } else {
        const githubAdvisoryId = this.getCVEsFromRuleText(issue.advisory.ruleText);
        if (githubAdvisoryId) {
          securityEvent.cves.push(githubAdvisoryId);
          securityEvent.ruleId = githubAdvisoryId;
        }
      }

      const cweList = [];
      for (const cwe of issue.advisory.references.cweIds) {
        let desc = "";
        let c = cwe;
        if (cwe.includes(":")) {
          const spited = cwe.split(":");
          desc = spited[1];
          c = spited[0];
        }
        cweList.push({
          shortName: c,
          name: c,
          url: "",
          description: desc,
        });
      }
      securityEvent.blame.cweList = cweList;
      securityEvent.blame.publishedExploitDate = issue.advisory.announcedAt;
      securityEvent.blame.cveDescription = issue.advisory.description;

      //securityEvent.linkToExternalProduct = `${repo.link}/security/dependabot/${alert.number}`;

      securityEvent.realMatch = `${issue.matchedDependency.name}@${issue.matchedDependency.versionSpecifier}`;

      securityEvents.push(securityEvent);
    } catch (e) {
      logger.error(`${LOG_NAME} - Error in setSCAIssue , Error : ${e} , Issue Details : ${issue}`);
    }
  }

  async getAllAlerts(securityEvents: SecurityEvent[]) {
    try {
      const deployments: SemgrepDeployments[] = [];
      await this.getDeployments(deployments);

      const findings: SemgrepFindings[] = [];
      const vulnerabilities: SemgrepVulnerability[] = [];

      for (const deployment of deployments) {
        await this.getFindings(deployment, findings);
        await this.getVulnerabilities(deployment, vulnerabilities);
      }

      for (const finding of findings) {
        this.setSASTIssue(finding, securityEvents);
      }

      for (const vulnerability of vulnerabilities) {
        this.setSCAIssue(vulnerability, securityEvents);
      }

      logger.info(`${LOG_NAME} - getAllAlerts finished with count of total ${securityEvents.length} securityEvents`);
    } catch (e) {
      logger.error(`${LOG_NAME} - Error in getAllAlerts , Error : ${e}`);
    }
  }
}

class SemgrepEnterprise extends ExternalSecurityProviderBase {
  public token: Token;
  private clientApi: SemgrepAPI;

  constructor(
    token: Token,
    uuid: string,
    orgName: string,
    policyConfiguration: any,
    jsonApplicationDiscoveryOverview: JsonApplicationDiscoveryOverview,
  ) {
    super(token, uuid, orgName, policyConfiguration, jsonApplicationDiscoveryOverview);

    this.token = token;
  }

  async initLib() {
    try {
      logger.info(`set ${this.token.name}, host: ${this.token.host}`);
      logger.info(`${LOG_NAME} - ** Begin **`);
      this.clientApi = new SemgrepAPI(this.token);

      await this.clientApi.auth();
    } catch (err) {
      logger.error(`failed to initialize ${this.token.name}, host: ${this.token.host}, err: ${err}`);
    }
  }

  async securityEvents() {
    const securityEvents: SecurityEvent[] = [];

    if (this.clientApi.isValidToken) {
      await this.clientApi.getAllAlerts(securityEvents);
    }

    logger.info(`${LOG_NAME} - ** Completed **`);

    return securityEvents;
  }
}

export default SemgrepEnterprise;
