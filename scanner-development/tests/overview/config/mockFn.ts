import loggerImport from "../../../src/logger";
const logger = loggerImport.getDebugLogger() as any;

export const finaJs = {
  version: "6.02",
  usage: "scan_report_overview",
  secInfrastructure: [
    {
      label: "SAST",
      clientCoverage: 0,
      oxCoverage: 0,
      noCoverage: 0,
      notApplicable: 0,
    },
    {
      label: "Secret Search",
      clientCoverage: 0,
      oxCoverage: 0,
      noCoverage: 0,
      notApplicable: 0,
    },
    {
      label: "IaC",
      clientCoverage: 0,
      oxCoverage: 0,
      noCoverage: 0,
      notApplicable: 0,
    },
    {
      label: "SCA",
      clientCoverage: 0,
      oxCoverage: 0,
      noCoverage: 0,
      notApplicable: 0,
    },
    {
      label: "Container Security",
      clientCoverage: 0,
      oxCoverage: 0,
      noCoverage: 0,
      notApplicable: 0,
    },
    {
      label: "API Security",
      clientCoverage: 0,
      oxCoverage: 0,
      noCoverage: 0,
      notApplicable: 0,
    },
    {
      label: "Vulnerability Scan",
      clientCoverage: 0,
      oxCoverage: 0,
      noCoverage: 0,
      notApplicable: 0,
    },
    {
      label: "CSPM",
      clientCoverage: 0,
      oxCoverage: 0,
      noCoverage: 0,
      notApplicable: 0,
    },
  ],
};

export function applySecInfra(total) {
  try {
    const currentAppCount = total;

    for (const obj of finaJs.secInfrastructure) {
      obj.oxCoverage = Math.round((obj.oxCoverage * 100) / currentAppCount);
      obj.clientCoverage = Math.round((obj.clientCoverage * 100) / currentAppCount);
      obj.noCoverage = Math.round((obj.noCoverage * 100) / currentAppCount);
      obj.notApplicable = Math.round((obj.notApplicable * 100) / currentAppCount);
    }
  } catch (err) {
    logger.error(`failed on function applySecInfra for overview json error: ${err}`);
  }
}

export function getSecInfraObj(label: string) {
  const res = finaJs.secInfrastructure.find(i => i.label.toLowerCase() === label.toLowerCase());
  if (res == undefined) {
    return null;
  }
  return res as any;
}

export function setSecInfra(applications) {
  try {
    const appData = applications.collectorData;
    const appCloud = applications.cloud;

    // sast
    const sast = getSecInfraObj("sast");
    if (!appData.unprotectedSastDevLanguages.length && appData.languages.length) {
      sast.oxCoverage++;
    }

    if (appData.unprotectedSastDevLanguages.length && appData.languages.length) {
      sast.noCoverage++;
    }

    if (!appData.unprotectedSastDevLanguages.length && !appData.languages.length) {
      sast.notApplicable++;
    }

    // sca
    const sca = getSecInfraObj("sca");
    if (!appData.unprotectedSastDevLanguages.length && appData.languages.length) {
      sca.oxCoverage++;
    }

    if (appData.unprotectedSastDevLanguages.length && appData.languages.length) {
      sca.noCoverage++;
    }

    if (!appData.unprotectedSastDevLanguages.length && !appData.languages.length) {
      sca.notApplicable++;
    }

    // iac
    const iac = getSecInfraObj("iac");
    if (appData.oxSecurityTools.oxIacTools.length) {
      iac.oxCoverage++;
    }

    if (!appData.oxSecurityTools.oxIacTools.length) {
      iac.noCoverage++;
    }

    //cspm
    const cspm = getSecInfraObj("cspm");
    if (appCloud != null && allTools["cloudSecurityTools"].enabled.length) {
      cspm.oxCoverage++;
    }

    if (appCloud != null && !allTools["cloudSecurityTools"].enabled.length) {
      cspm.noCoverage++;
    }

    if (appCloud === null) {
      cspm.notApplicable++;
    }

    // secrets
    const secretSearch = getSecInfraObj("secret search");
    if (appData.oxSecurityTools.oxSecretsTools.length) {
      secretSearch.oxCoverage++;
    }

    if (!appData.oxSecurityTools.oxSecretsTools.length) {
      secretSearch.noCoverage++;
    }

    // container security
    const containerSecurity = getSecInfraObj("container security");
    if (appData.containerFiles > 0 && appData.oxSecurityTools.oxContainerTools.length) {
      containerSecurity.oxCoverage++;
    }

    if (appData.containerFiles > 0 && !appData.oxSecurityTools.oxContainerTools.length) {
      containerSecurity.noCoverage++;
    }

    if (appData.containerFiles === 0) {
      containerSecurity.notApplicable++;
    }
  } catch (err) {
    logger.error(`failed on function setSecInfra for overview json error: ${err}`);
  }
}

export const allTools = {
  codeSecurityTools: {
    disabled: [
      {
        name: "Bandit",
        fileNameAutomaticallyCreated: "false",
        localSshToolName: 'bandit -r "CLONEDIR" -o "OUTPUTPATH" -f sarif',
        command: 'bandit -r "CLONEDIR" -o "OUTPUTPATH" -f sarif',
        onPrem: 'ssh -p PORT root@HOST bandit -r "CLONEDIR" -o "OUTPUTPATH" -f sarif',
        fileNameOutput: "bandit.sarif",
        env_sqs_url: "BANDIT_SQS_URL",
        env_redis_url: "BANDIT_QUEUE_KEY",
        envPort: "OX_BANDIT_PORT",
        envHost: "OX_BANDIT_HOST",
        severityConfigName: "banditSeverity.json",
        defaultSeverity: "low",
        defaultType: "sast",
        supportedTypes: ["sast"],
        dynamicIdentifyType: false,
        timeout: 900000,
        scanGitHistory: false,
        disableByOx: false,
        pullingFromDisk: false,
      },
      {
        name: "DevSkim",
        localSshToolName: 'C:\\Users\\Roman\\Pictures\\TTTTT\\js\\DevSkim_win_0.6.1\\devskim.exe analyze "CLONEDIR" "OUTPUTPATH" -f sarif',
        fileNameAutomaticallyCreated: "false",
        command: 'devskim analyze "CLONEDIR" "OUTPUTPATH" -f sarif',
        onPrem: 'ssh -p PORT root@HOST devskim analyze "CLONEDIR" "OUTPUTPATH" -f sarif',
        fileNameOutput: "devskim.sarif",
        env_sqs_url: "DEVSKIM_SQS_URL",
        env_redis_url: "DEVSKIM_QUEUE_KEY",
        envPort: "OX_DEVSKIM_PORT",
        envHost: "OX_DEVSKIM_HOST",
        severityConfigName: "devSkimSeverity.json",
        defaultSeverity: "low",
        defaultType: "sast",
        supportedTypes: ["sast"],
        dynamicIdentifyType: false,
        timeout: 900000,
        scanGitHistory: false,
        disableByOx: false,
        pullingFromDisk: false,
      },
      {
        name: "Gitleaks",
        command:
          'megalinter_exec --input "CLONEDIR" --output "OUTPUTPATHgitleaks/megalinter-report.sarif" --capture-std "OUTPUTPATH/megalinter_gitleaks.log"',
        localSshToolName:
          "docker run --rm -e REPORT_OUTPUT_FOLDER=/output -e DEFAULT_WORKSPACE=/megalinter -v OUTPUTPATH:/output -v CLONEDIR:/megalinter megalinter/megalinter-only-repository_gitleaks:v6-alpha python -m megalinter.run",
        onPrem: 'ssh -p PORT root@HOST gitleaks detect --source="CLONEDIR" -v -r="OUTPUTPATH" -f sarif',
        fileNameAutomaticallyCreated: "true",
        fileNameOutput: "gitleaks/megalinter-report.sarif",
        env_sqs_url: "GITLEAKS_SQS_URL",
        env_redis_url: "GITLEAKS_QUEUE_KEY",
        envPort: "OX_GITLEAKS_PORT",
        envHost: "OX_GITLEAKS_HOST",
        severityConfigName: "",
        defaultSeverity: "critical",
        defaultType: "secret",
        supportedTypes: ["secret"],
        dynamicIdentifyType: false,
        timeout: 900000,
        scanGitHistory: true,
        disableByOx: false,
        pullingFromDisk: false,
      },
      {
        name: "Trivy",
        command: 'trivy fs -o "OUTPUTPATH" -f json "CLONEDIR"',
        localSshToolName:
          'docker run --rm -v C:\\t:/root/.cache/ -v C:\\CLONE\\b:/datacc aquasec/trivy:0.21.3 fs -f json /datacc > "OUTPUTPATH"',
        onPrem: 'ssh -p PORT root@HOST trivy fs -o "OUTPUTPATH" -f json "CLONEDIR"',
        fileNameAutomaticallyCreated: "false",
        fileNameOutput: "trivy.json",
        env_sqs_url: "TRIVY_SQS_URL",
        env_redis_url: "TRIVY_QUEUE_KEY",
        severityConfigName: "",
        envPort: "OX_TRIVY_PORT",
        envHost: "OX_TRIVY_HOST",
        defaultSeverity: "low",
        defaultType: "sca",
        supportedTypes: ["sca"],
        dynamicIdentifyType: false,
        timeout: 900000,
        scanGitHistory: false,
        disableByOx: false,
        pullingFromDisk: false,
      },
      {
        name: "megalinter_bandit",
        command: 'megalinter_exec --input "CLONEDIR" --output "OUTPUTPATH" --capture-std "OUTPUTPATH/megalinter_bandit.log"',
        localSshToolName:
          "docker run --rm -e REPORT_OUTPUT_FOLDER=/output -e DEFAULT_WORKSPACE=/megalinter -v OUTPUTPATH:/output -v CLONEDIR:/megalinter megalinter/megalinter-only-python_bandit:v6-alpha python -m megalinter.run",
        fileNameAutomaticallyCreated: "true",
        fileNameOutput: "megalinter-report.sarif",
        env_sqs_url: "MEGALINTERBANDIT_SQS_URL",
        env_redis_url: "MEGALINTERBANDIT_QUEUE_KEY",
        severityConfigName: "",
        onPrem: "",
        envPort: "OX_BANDIT_PORT",
        envHost: "OX_BANDIT_HOST",
        defaultSeverity: "low",
        defaultType: "sast",
        supportedTypes: ["sast"],
        dynamicIdentifyType: false,
        timeout: 600000,
        scanGitHistory: false,
        disableByOx: true,
        pullingFromDisk: true,
      },
      {
        name: "megalinter_terrascan",
        command:
          'megalinter_exec --input "CLONEDIR" --output "OUTPUTPATHterrascan/megalinter-report.sarif" --capture-std "OUTPUTPATH/megalinter_terrascan.log"',
        localSshToolName:
          "docker run --rm -e REPORT_OUTPUT_FOLDER=/output/terrascan -e DEFAULT_WORKSPACE=/megalinter -v OUTPUTPATH:/output -v CLONEDIR:/megalinter megalinter/megalinter-only-terraform_terrascan:v6-alpha python -m megalinter.run",
        fileNameAutomaticallyCreated: "true",
        onPrem: "",
        fileNameOutput: "terrascan/megalinter-report.sarif",
        env_sqs_url: "TERRASCAN_SQS_URL",
        env_redis_url: "TERRASCAN_QUEUE_KEY",
        severityConfigName: "",
        envPort: "OX_TERRASCAN_PORT",
        envHost: "OX_TERRASCAN_HOST",
        defaultSeverity: "low",
        defaultType: "IAC",
        supportedTypes: ["iac"],
        dynamicIdentifyType: false,
        timeout: 600000,
        scanGitHistory: false,
        disableByOx: false,
        pullingFromDisk: true,
      },
      {
        name: "megalinter_tflint",
        command:
          'megalinter_exec --input "CLONEDIR" --output "OUTPUTPATHtflint/megalinter-report.sarif" --capture-std "OUTPUTPATH/megalinter_tflint.log"',
        localSshToolName:
          "docker run --rm -e REPORT_OUTPUT_FOLDER=/output/tflint -e DEFAULT_WORKSPACE=/megalinter -v OUTPUTPATH:/output -v CLONEDIR:/megalinter megalinter/megalinter-only-terraform_tflint:v6-alpha python -m megalinter.run",
        onPrem: "",
        fileNameAutomaticallyCreated: "true",
        fileNameOutput: "tflint/megalinter-report.sarif",
        env_sqs_url: "TFLINT_SQS_URL",
        env_redis_url: "TFLINT_QUEUE_KEY",
        severityConfigName: "",
        envPort: "OX_TFLINT_PORT",
        envHost: "OX_TFLINT_HOST",
        defaultSeverity: "low",
        defaultType: "iac",
        supportedTypes: ["iac"],
        dynamicIdentifyType: false,
        timeout: 600000,
        scanGitHistory: false,
        disableByOx: false,
        pullingFromDisk: true,
      },
      {
        name: "megalinter_hadolint",
        command:
          'megalinter_exec --input "CLONEDIR" --output "OUTPUTPATHhadolint/megalinter-report.sarif" --capture-std "OUTPUTPATH/megalinter_hadolint.log"',
        localSshToolName:
          "docker run --rm -e REPORT_OUTPUT_FOLDER=/output/hadolint -e DEFAULT_WORKSPACE=/megalinter -v OUTPUTPATH:/output -v CLONEDIR:/megalinter megalinter/megalinter-only-dockerfile_hadolint:v6-alpha python -m megalinter.run",
        onPrem: "",
        fileNameAutomaticallyCreated: "true",
        fileNameOutput: "hadolint/megalinter-report.sarif",
        env_sqs_url: "HADOLINT_SQS_URL",
        env_redis_url: "HADOLINT_QUEUE_KEY",
        severityConfigName: "",
        envPort: "OX_HADOLINT_PORT",
        envHost: "OX_HADOLINT_HOST",
        defaultSeverity: "low",
        defaultType: "iac",
        supportedTypes: ["iac"],
        dynamicIdentifyType: false,
        timeout: 600000,
        scanGitHistory: false,
        disableByOx: false,
        pullingFromDisk: true,
      },
      {
        name: "megalinter_cfn-lint",
        command:
          'megalinter_exec --input "CLONEDIR" --output "OUTPUTPATHcfn/megalinter-report.sarif" --capture-std "OUTPUTPATH/megalinter_cfn-lint.log"',
        localSshToolName:
          "docker run --rm -e REPORT_OUTPUT_FOLDER=/output/cfn -e DEFAULT_WORKSPACE=/megalinter -v OUTPUTPATH:/output -v CLONEDIR:/megalinter megalinter/megalinter-only-cloudformation_cfn_lint:v6-alpha python -m megalinter.run",
        onPrem: "",
        fileNameAutomaticallyCreated: "true",
        fileNameOutput: "cfn/megalinter-report.sarif",
        env_sqs_url: "CFNLINT_SQS_URL",
        env_redis_url: "CFNLINT_QUEUE_KEY",
        severityConfigName: "",
        envPort: "OX_CFNLINT_PORT",
        envHost: "OX_CFNLINT_HOST",
        defaultSeverity: "low",
        defaultType: "iac",
        supportedTypes: ["iac"],
        dynamicIdentifyType: false,
        timeout: 600000,
        scanGitHistory: false,
        disableByOx: false,
        pullingFromDisk: true,
      },
      {
        name: "SemGrep",
        command:
          '\'semgrep --config=/var/semgrep-rules/bash --config=/var/semgrep-rules/c --config=/var/semgrep-rules/ocaml --config=/var/semgrep-rules/problem-based-packs --config=/var/semgrep-rules/csharp --config=/var/semgrep-rules/go --config=/var/semgrep-rules/java --config=/var/semgrep-rules/javascript --config=/var/semgrep-rules/python --config=/var/semgrep-rules/kotlin --config=/var/semgrep-rules/php --config=/var/semgrep-rules/python --config=/var/semgrep-rules/ruby --config=/var/semgrep-rules/scala --config=/var/semgrep-rules/typescript "CLONEDIR" -q --json -o "OUTPUTPATH"\'',
        localSshToolName:
          'docker run --rm -v "CLONEDIR":/src returntocorp/semgrep --debug --config="CLONEDIR\\semgrep-rules\\java" --time --timeout-threshold 2 > "OUTPUTPATH"',
        onPrem: 'ssh -p PORT root@HOST \'semgrep --config p/owasp-top-ten "CLONEDIR" -q --json -o "OUTPUTPATH"\'',
        fileNameAutomaticallyCreated: "false",
        fileNameOutput: "semgrep.json",
        envPort: "OX_SEMGREP_PORT",
        envHost: "OX_SEMGREP_HOST",
        env_redis_url: "SEMGREP_QUEUE_KEY",
        env_sqs_url: "SEMGREP_SQS_URL",
        severityConfigName: "semgrepSeverity.json",
        defaultSeverity: "low",
        defaultType: "sast",
        supportedTypes: ["sast", "secret"],
        dynamicIdentifyType: true,
        timeout: 900000,
        scanGitHistory: false,
        disableByOx: false,
        pullingFromDisk: false,
      },
    ],
    enabled: [
      {
        name: "Checkov",
        fileNameAutomaticallyCreated: "false",
        localSshToolName: 'checkov --directory "CLONEDIR" --quiet --compact --output json > "OUTPUTPATH"',
        command: '\'checkov --directory "CLONEDIR" --quiet --compact --output json > "OUTPUTPATH"\'',
        onPrem: 'ssh -p PORT root@HOST \'checkov --directory "CLONEDIR" --quiet --compact --output json > "OUTPUTPATH"\'',
        fileNameOutput: "checkov.sarif",
        env_sqs_url: "CHECKOV_SQS_URL",
        env_redis_url: "CHECKOV_QUEUE_KEY",
        envPort: "OX_CHECKOV_PORT",
        envHost: "OX_CHECKOV_HOST",
        severityConfigName: "checkovSeverity.json",
        defaultSeverity: "low",
        defaultType: "iac",
        supportedTypes: ["iac", "secret", "container"],
        dynamicIdentifyType: true,
        timeout: 900000,
        scanGitHistory: false,
        disableByOx: false,
        pullingFromDisk: false,
      },
    ],
    count: 1,
  },
  cloudSecurityTools: {
    enabled: [
      {
        name: "Prowler",
        localSshToolName:
          "docker run --env=AWS_ACCESS_KEY_ID --env=AWS_SECRET_ACCESS_KEY --env=AWS_SESSION_TOKEN --rm -v {MAPDIR}:/prowler/output -v prowler toniblyx/prowler:latest -b -F {ID} -c {ID} -M json-asff",
        command:
          "AWS_ACCESS_KEY_ID={KEY} AWS_SECRET_ACCESS_KEY={SECRET} AWS_SESSION_TOKEN={SESSION} prowler -o {MAPDIR} -b -F {ID} -c {ID} -M json-asff",
        onPrem: "",
        fileNameOutput: "prowler.sarif",
        env_sqs_url: "PROWLER_SQS_URL",
        env_redis_url: "PROWLER_QUEUE_KEY",
        envPort: "OX_PROWLER_PORT",
        envHost: "OX_PROWLER_HOST",
        severityConfigName: "",
        defaultSeverity: "low",
        defaultType: "cspm",
        supportedTypes: ["cspm"],
        dynamicIdentifyType: false,
        timeout: 900000,
        scanGitHistory: false,
        disableByOx: false,
        pullingFromDisk: false,
        fileNameAutomaticallyCreated: "true",
      },
    ],
    disabled: [],
    count: 0,
  },
};
