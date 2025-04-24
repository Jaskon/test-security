import { SourceToolType } from "@oxappsec/ox-consolidated-categories/lib/src/ox-categories/config/categories-config";

export class Constant {
  public static bytesInGB = 1073741824;
  public static programmingLangExtRegex = new RegExp(
    "\\.(py|js|ts|tsx|jsx|jsp|go|java|php|cs|rs|html|swift|rb|c|cpp|scala|dart|txt|json|toml|kt|kts|m)$",
    "i",
  );
  public static currentDate = new Date();
  public static oneYearAgo = Constant.currentDate.setFullYear(Constant.currentDate.getFullYear() - 1);

  public static gitPosture = SourceToolType["Git Posture"];
  public static cicdPosture = SourceToolType["CI/CD Posture"];

  public static Dependabot = "Dependabot";
  public static SnykCli = "Snyk CLI";
  public static securityEventsResource = "securityEvents";
  public static DeploymentFile = "Deployment File";
  public static Username = "Username";
  public static PipelineName = "Pipeline ID";
  public static BuildName = "Job Name";
  public static MAX_AGG_ITEMS = 1000;

  public static formerUserId = 1234;

  public static oxCloudConnectorName = "cloudAWS";
  public static MATCH_CHARS_LIMIT = 300;
  public static SNIPPET_CHARS_LIMIT = 2000;

  public static lowRegex: RegExp = new RegExp("low|minor|imminent|low severity", "i");
  public static infoRegex: RegExp = new RegExp(
    "note|BestPractice|Informational|none|review|note severity|best-practice|manual-review|INFO",
    "i",
  );
  public static mediumRegex: RegExp = new RegExp("medium|medium severity|unknown|MODERATE|moderate severity|warning|warning severity", "i");
  public static highRegex: RegExp = new RegExp("high|hazardous|major|high severity|error|Important|error severity|severe", "i");
  public static criticalRegex: RegExp = new RegExp("critical|blocker|critical severity", "i");
  public static applRegex: RegExp = new RegExp("Appoxalypse", "i");
  public static dockerRegex: RegExp = new RegExp("DockerFile", "i");
  public static ignoreGeneralFiles: RegExp = new RegExp("readme.md|test|example", "i");
  public static ignoreSastFiles: RegExp = new RegExp("\\.json$|\\.txt$|\\.yaml|\\.yml|\\.tf|terraform|pipeline", "i");

  public static testAppsToIgnore: RegExp = new RegExp("(^|[\\-_])?(test|tests|testingrepo|testing|automation)([\\-_]|\\s+|\\/|$)?");
  public static testFileToIgnore: RegExp = new RegExp(
    "(^|[\\-_])?(test|tests|testingrepo|research|development|testing|automation)([\\-_]|\\s+|\\/|$)?",
  );

  public static ignoreLineInfo: RegExp = new RegExp("example |test ", "i");
  public static intevalReportUpdate: number = 5;

  public static secretIdentifierRegex: RegExp = new RegExp("(^|[^a-z])(secrets?|credentials|key|password|token)([^a-z]|$)", "i");

  public static orca = "Orca";
  public static wiz = "WIZ";
  public static spectral = "Spectral";
  public static hcl = "HCL";
  public static fortify = "Fortify";
  public static gitlabSecurityCenter = "Gitlab security center";
  public static gitlabSast = "GitLab SAST";
  public static githubSast = "GitHub SAST";
  public static githubSecretsDetection = "GitHub Secret Detection";
  public static gitlabSecretDetection = "GitLab Secret Detection";
  public static gitLabDependencyScanning = "GitLab Dependency Scanning";

  public static scaInfoSeverity = "oxPolicy_securityScan_23";
  public static scaLowSeverity = "oxPolicy_securityScan_11";
  public static scaMidSeverity = "oxPolicy_securityScan_12";
  public static scaHighSeverity = "oxPolicy_securityScan_10";
  public static scaCriticalSeverity = "oxPolicy_securityScan_9";
  public static scaAppoxlSeverity = "oxPolicy_securityScan_30";

  public static scaDockerInfoSeverity = "oxPolicy_deployment_20";
  public static scaDockerLowSeverity = "oxPolicy_deployment_11";
  public static scaDockerMidSeverity = "oxPolicy_deployment_12";
  public static scaDockerHighSeverity = "oxPolicy_deployment_10";
  public static scaDockerCriticalSeverity = "oxPolicy_deployment_19";
  public static scaDockerAppoxlSeverity = "oxPolicy_deployment_9";

  public static generalCICDInfoSeverity = "oxPolicy_CICD_general_2";
  public static generalCICDLowSeverity = "oxPolicy_CICD_general_3";
  public static generalCICDMidSeverity = "oxPolicy_CICD_general_4";
  public static generalCICDHighSeverity = "oxPolicy_CICD_general_5";
  public static generalCICDCriticalSeverity = "oxPolicy_CICD_general_6";
  public static generalCICDAppoxSeverity = "oxPolicy_CICD_general_7";

  //Secrets history policy id
  public static secretHistoryInfoSeverity = "oxPolicy_securityScan_29";
  public static secretHistoryLowSeverity = "oxPolicy_securityScan_19";
  public static secretHistoryMidSeverity = "oxPolicy_securityScan_20";
  public static secretHistoryHighSeverity = "oxPolicy_securityScan_18";
  public static secretHistoryCriticalSeverity = "oxPolicy_securityScan_17";
  public static secretHistoryAppoxSeverity = "oxPolicy_securityScan_22";
  //Secrets policy id
  public static secretInfoSeverity = "oxPolicy_securityScan_24";
  public static secretLowSeverity = "oxPolicy_securityScan_15";
  public static secretMidSeverity = "oxPolicy_securityScan_16";
  public static secretHighSeverity = "oxPolicy_securityScan_14";
  public static secretCriticalSeverity = "oxPolicy_securityScan_13";
  public static secretAppoxSeverity = "oxPolicy_securityScan_21";
  //Iac policy id
  public static iacInfoSeverity = "oxPolicy_securityScan_26";
  public static iactLowSeverity = "oxPolicy_securityScan_3";
  public static iacMidSeverity = "oxPolicy_securityScan_4";
  public static iacHighSeverity = "oxPolicy_securityScan_2";
  public static iacCriticalSeverity = "oxPolicy_securityScan_1";
  public static iacAppoxSeverity = "oxPolicy_securityScan_102";
  //Sast policy id
  public static sastInfoSeverity = "oxPolicy_securityScan_25";
  public static sasttLowSeverity = "oxPolicy_securityScan_7";
  public static sastMidSeverity = "oxPolicy_securityScan_8";
  public static sastHighSeverity = "oxPolicy_securityScan_6";
  public static sastCriticalSeverity = "oxPolicy_securityScan_5";
  public static sastAppoxSeverity = "oxPolicy_securityScan_206";

  public static iacIdentifierRegex: RegExp = new RegExp("(^|[^a-z])(terraform|docker|dockerfile)([^a-z]|$)", "i");
  public static snykCLItool = "snyk-cli";

  public static NO_REVIEWER = "not reviewed";

  public static PREFIX_DELIM = "(^|[\\W_])";
  public static MIDDLE_DELIM = "[\\W_]";
  public static SUFFIX_DELIM = "([\\W_]|$)";
  public static NO_AZURECI_REPO = "no-project";
  public static cloudDeploymentsRegex = {
    AWS: {
      pattern: new RegExp(
        `${Constant.PREFIX_DELIM}(aws|fargate|cloudfront|awscli|(us|eu|me|sa|ca|ap|af)-(east|west|south|north)-[123])${Constant.SUFFIX_DELIM}`,
        "i",
      ),
      subType: {
        fargate: new RegExp(`${Constant.PREFIX_DELIM}fargate${Constant.SUFFIX_DELIM}`, "i"),
        ec2: new RegExp(`${Constant.PREFIX_DELIM}ec2${Constant.SUFFIX_DELIM}`, "i"),
        cloudtrail: new RegExp(`${Constant.PREFIX_DELIM}cloudtrail${Constant.SUFFIX_DELIM}`, "i"),
        configservice: new RegExp(`${Constant.PREFIX_DELIM}configservice${Constant.SUFFIX_DELIM}`, "i"),
        s3: new RegExp(`${Constant.PREFIX_DELIM}(s3|s3fs)${Constant.SUFFIX_DELIM}`, "i"),
        kms: new RegExp(`${Constant.PREFIX_DELIM}kms${Constant.SUFFIX_DELIM}`, "i"),
        vpc: new RegExp(`${Constant.PREFIX_DELIM}vpc${Constant.SUFFIX_DELIM}`, "i"),
        ecr: new RegExp(`${Constant.PREFIX_DELIM}ecr${Constant.SUFFIX_DELIM}`, "i"),
        rds: new RegExp(`${Constant.PREFIX_DELIM}rds${Constant.SUFFIX_DELIM}`, "i"),
        elb: new RegExp(`${Constant.PREFIX_DELIM}elb${Constant.SUFFIX_DELIM}`, "i"),
        redshift: new RegExp(`${Constant.PREFIX_DELIM}redshift${Constant.SUFFIX_DELIM}`, "i"),
        macie: new RegExp(`${Constant.PREFIX_DELIM}macie${Constant.SUFFIX_DELIM}`, "i"),
        guardduty: new RegExp(`${Constant.PREFIX_DELIM}guardduty${Constant.SUFFIX_DELIM}`, "i"),
        cloudfront: new RegExp(`${Constant.PREFIX_DELIM}cloudfront${Constant.SUFFIX_DELIM}`, "i"),
        es: new RegExp(`${Constant.PREFIX_DELIM}es${Constant.SUFFIX_DELIM}`, "i"),
        route53: new RegExp(`${Constant.PREFIX_DELIM}route53${Constant.SUFFIX_DELIM}`, "i"),
        lambda: new RegExp(`${Constant.PREFIX_DELIM}(lambda|serverless deploy)${Constant.SUFFIX_DELIM}`, "i"),
        apigateway: new RegExp(`${Constant.PREFIX_DELIM}apigateway${Constant.SUFFIX_DELIM}`, "i"),
        acm: new RegExp(`${Constant.PREFIX_DELIM}acm${Constant.SUFFIX_DELIM}`, "i"),
        trustedadvisor: new RegExp(`${Constant.PREFIX_DELIM}trustedadvisor${Constant.SUFFIX_DELIM}`, "i"),
        sqs: new RegExp(`${Constant.PREFIX_DELIM}sqs${Constant.SUFFIX_DELIM}`, "i"),
        sns: new RegExp(`${Constant.PREFIX_DELIM}sns${Constant.SUFFIX_DELIM}`, "i"),
        cloudformation: new RegExp(`${Constant.PREFIX_DELIM}cloudformation${Constant.SUFFIX_DELIM}`, "i"),
        ecs: new RegExp(`${Constant.PREFIX_DELIM}ecs${Constant.SUFFIX_DELIM}`, "i"),
        accessanalyzer: new RegExp(`${Constant.PREFIX_DELIM}accessanalyzer${Constant.SUFFIX_DELIM}`, "i"),
        autoscaling: new RegExp(`${Constant.PREFIX_DELIM}autoscaling${Constant.SUFFIX_DELIM}`, "i"),
        eks: new RegExp(`${Constant.PREFIX_DELIM}eks${Constant.SUFFIX_DELIM}`, "i"),
        securityhub: new RegExp(`${Constant.PREFIX_DELIM}securityhub${Constant.SUFFIX_DELIM}`, "i"),
        sagemaker: new RegExp(`${Constant.PREFIX_DELIM}sagemaker${Constant.SUFFIX_DELIM}`, "i"),
        glue: new RegExp(`${Constant.PREFIX_DELIM}glue${Constant.SUFFIX_DELIM}`, "i"),
        ssm: new RegExp(`${Constant.PREFIX_DELIM}ssm${Constant.SUFFIX_DELIM}`, "i"),
        dynamodb: new RegExp(`${Constant.PREFIX_DELIM}dynamodb${Constant.SUFFIX_DELIM}`, "i"),
        efs: new RegExp(`${Constant.PREFIX_DELIM}efs${Constant.SUFFIX_DELIM}`, "i"),
        cloudwatch: new RegExp(`${Constant.PREFIX_DELIM}cloudwatch${Constant.SUFFIX_DELIM}`, "i"),
        glacier: new RegExp(`${Constant.PREFIX_DELIM}glacier${Constant.SUFFIX_DELIM}`, "i"),
      },
    },
    GCP: {
      pattern: new RegExp(`${Constant.PREFIX_DELIM}(gcloud|gcp|Google${Constant.MIDDLE_DELIM}?Cloud)${Constant.SUFFIX_DELIM}`, "i"),
      subType: {
        computeEngine: new RegExp(`${Constant.PREFIX_DELIM}compute${Constant.MIDDLE_DELIM}?Engine${Constant.SUFFIX_DELIM}`, "i"),
        kubernetesEngine: new RegExp(`${Constant.PREFIX_DELIM}kubernetes${Constant.MIDDLE_DELIM}?Engine${Constant.SUFFIX_DELIM}`, "i"),
        appEngine: new RegExp(`${Constant.PREFIX_DELIM}app${Constant.MIDDLE_DELIM}?Engine${Constant.SUFFIX_DELIM}`, "i"),
        cloudFunctions: new RegExp(`${Constant.PREFIX_DELIM}cloud${Constant.MIDDLE_DELIM}?Functions?${Constant.SUFFIX_DELIM}`, "i"),
        cloudConsole: new RegExp(`${Constant.PREFIX_DELIM}cloud${Constant.MIDDLE_DELIM}?Console${Constant.SUFFIX_DELIM}`, "i"),
        stackdriver: new RegExp(`${Constant.PREFIX_DELIM}stack${Constant.MIDDLE_DELIM}?driver${Constant.SUFFIX_DELIM}`, "i"),
        trace: new RegExp(`${Constant.PREFIX_DELIM}trace${Constant.SUFFIX_DELIM}`, "i"),
        logging: new RegExp(`${Constant.PREFIX_DELIM}logging${Constant.SUFFIX_DELIM}`, "i"),
        debugger: new RegExp(`${Constant.PREFIX_DELIM}debugger${Constant.SUFFIX_DELIM}`, "i"),
        monitoring: new RegExp(`${Constant.PREFIX_DELIM}monitoring${Constant.SUFFIX_DELIM}`, "i"),
        cloudLoadBalancing: new RegExp(
          `${Constant.PREFIX_DELIM}cloud${Constant.MIDDLE_DELIM}?Load${Constant.MIDDLE_DELIM}?Balancing${Constant.SUFFIX_DELIM}`,
          "i",
        ),
        cloudCdn: new RegExp(`${Constant.PREFIX_DELIM}cloud${Constant.MIDDLE_DELIM}?Cdn${Constant.SUFFIX_DELIM}`, "i"),
        cloudDns: new RegExp(`${Constant.PREFIX_DELIM}cloud${Constant.MIDDLE_DELIM}?Dns${Constant.SUFFIX_DELIM}`, "i"),
        firewallRules: new RegExp(`${Constant.PREFIX_DELIM}firewall${Constant.MIDDLE_DELIM}?Rules${Constant.SUFFIX_DELIM}`, "i"),
        cloudInterconnect: new RegExp(`${Constant.PREFIX_DELIM}cloud${Constant.MIDDLE_DELIM}?Interconnect${Constant.SUFFIX_DELIM}`, "i"),
        cloudVpn: new RegExp(`${Constant.PREFIX_DELIM}cloud${Constant.MIDDLE_DELIM}?Vpn${Constant.SUFFIX_DELIM}`, "i"),
        cloudBigtable: new RegExp(`${Constant.PREFIX_DELIM}Bigtable${Constant.SUFFIX_DELIM}`, "i"),
        cloudDatastore: new RegExp(`${Constant.PREFIX_DELIM}Datastore${Constant.SUFFIX_DELIM}`, "i"),
        cloudSpanner: new RegExp(`${Constant.PREFIX_DELIM}Spanner${Constant.SUFFIX_DELIM}`, "i"),
        cloudSql: new RegExp(`${Constant.PREFIX_DELIM}cloudSql${Constant.SUFFIX_DELIM}`, "i"),
        cloudStorage: new RegExp(`${Constant.PREFIX_DELIM}cloud${Constant.MIDDLE_DELIM}?Storage${Constant.SUFFIX_DELIM}`, "i"),
        bigQuery: new RegExp(`${Constant.PREFIX_DELIM}bigQuery${Constant.SUFFIX_DELIM}`, "i"),
        cloudDataflow: new RegExp(`${Constant.PREFIX_DELIM}Dataflow${Constant.SUFFIX_DELIM}`, "i"),
        cloudDataprep: new RegExp(`${Constant.PREFIX_DELIM}Dataprep${Constant.SUFFIX_DELIM}`, "i"),
        cloudDataproc: new RegExp(`${Constant.PREFIX_DELIM}Dataproc${Constant.SUFFIX_DELIM}`, "i"),
        cloudIotCore: new RegExp(`${Constant.PREFIX_DELIM}IotCore${Constant.SUFFIX_DELIM}`, "i"),
        cloudIam: new RegExp(`${Constant.PREFIX_DELIM}Iam${Constant.SUFFIX_DELIM}`, "i"),
        cloudEndpoints: new RegExp(`${Constant.PREFIX_DELIM}cloud${Constant.MIDDLE_DELIM}?Endpoints${Constant.SUFFIX_DELIM}`, "i"),
        vpc: new RegExp(`${Constant.PREFIX_DELIM}vpc${Constant.SUFFIX_DELIM}`, "i"),
        identityAwareProxy: new RegExp(
          `${Constant.PREFIX_DELIM}identity${Constant.MIDDLE_DELIM}?Aware${Constant.MIDDLE_DELIM}?Proxy${Constant.SUFFIX_DELIM}`,
          "i",
        ),
        kms: new RegExp(`${Constant.PREFIX_DELIM}kms${Constant.SUFFIX_DELIM}`, "i"),
        dataLossPrevention: new RegExp(`${Constant.PREFIX_DELIM}dataLoss${Constant.SUFFIX_DELIM}`, "i"),
        cloudMl: new RegExp(`${Constant.PREFIX_DELIM}cloudMl${Constant.SUFFIX_DELIM}`, "i"),
        naturalLanguageApi: new RegExp(`${Constant.PREFIX_DELIM}naturalLanguageApi${Constant.SUFFIX_DELIM}`, "i"),
        cloudSpeechApi: new RegExp(`${Constant.PREFIX_DELIM}cloudSpeechApi${Constant.SUFFIX_DELIM}`, "i"),
        cloudVisionApi: new RegExp(`${Constant.PREFIX_DELIM}cloudVisionApi${Constant.SUFFIX_DELIM}`, "i"),
        cloudTranslateApi: new RegExp(`${Constant.PREFIX_DELIM}cloudTranslateApi${Constant.SUFFIX_DELIM}`, "i"),
        cloudRun: new RegExp(`${Constant.PREFIX_DELIM}g?cloud${Constant.MIDDLE_DELIM}?Run${Constant.SUFFIX_DELIM}`, "i"),
      },
    },
    Azure: {
      pattern: new RegExp(`${Constant.PREFIX_DELIM}(az|azure)${Constant.SUFFIX_DELIM}`, "i"),
      subType: {
        devOps: new RegExp(
          `${Constant.PREFIX_DELIM}(visualStudio|AzureDevOps|dev${Constant.MIDDLE_DELIM}azure)${Constant.SUFFIX_DELIM}`,
          "i",
        ),
        devTestLabs: new RegExp(`${Constant.PREFIX_DELIM}devTestLabs${Constant.SUFFIX_DELIM}`, "i"),
        vsapp: new RegExp(`${Constant.PREFIX_DELIM}vsapp${Constant.SUFFIX_DELIM}`, "i"),
        hockeyApp: new RegExp(`${Constant.PREFIX_DELIM}hockeyApp${Constant.SUFFIX_DELIM}`, "i"),
        developerTools: new RegExp(`${Constant.PREFIX_DELIM}developerTools${Constant.SUFFIX_DELIM}`, "i"),
        azurePortal: new RegExp(`${Constant.PREFIX_DELIM}azurePortal${Constant.SUFFIX_DELIM}`, "i"),
        schedular: new RegExp(`${Constant.PREFIX_DELIM}schedular${Constant.SUFFIX_DELIM}`, "i"),
        operationsManagement: new RegExp(`${Constant.PREFIX_DELIM}operationsManagement${Constant.SUFFIX_DELIM}`, "i"),
        automation: new RegExp(`${Constant.PREFIX_DELIM}automation${Constant.SUFFIX_DELIM}`, "i"),
        logAnalytics: new RegExp(`${Constant.PREFIX_DELIM}logAnalytics${Constant.SUFFIX_DELIM}`, "i"),
        keyVault: new RegExp(`${Constant.PREFIX_DELIM}keyVault${Constant.SUFFIX_DELIM}`, "i"),
        securityCenter: new RegExp(`${Constant.PREFIX_DELIM}securityCenter${Constant.SUFFIX_DELIM}`, "i"),
        virtualMachines: new RegExp(`${Constant.PREFIX_DELIM}virtualMachines${Constant.SUFFIX_DELIM}`, "i"),
        virtualMachinesScale: new RegExp(`${Constant.PREFIX_DELIM}virtualMachinesScale${Constant.SUFFIX_DELIM}`, "i"),
        cloudService: new RegExp(`${Constant.PREFIX_DELIM}cloudService${Constant.SUFFIX_DELIM}`, "i"),
        batch: new RegExp(`${Constant.PREFIX_DELIM}batch${Constant.SUFFIX_DELIM}`, "i"),
        serviceFabric: new RegExp(`${Constant.PREFIX_DELIM}serviceFabric${Constant.SUFFIX_DELIM}`, "i"),
        containerSecurity: new RegExp(`${Constant.PREFIX_DELIM}containerSecurity${Constant.SUFFIX_DELIM}`, "i"),
        webApps: new RegExp(`${Constant.PREFIX_DELIM}webApp${Constant.SUFFIX_DELIM}`, "i"),
        mobileApps: new RegExp(`${Constant.PREFIX_DELIM}mobileApps${Constant.SUFFIX_DELIM}`, "i"),
        logicApps: new RegExp(`${Constant.PREFIX_DELIM}logicApps${Constant.SUFFIX_DELIM}`, "i"),
        apiApps: new RegExp(`${Constant.PREFIX_DELIM}api${Constant.MIDDLE_DELIM}?Apps${Constant.SUFFIX_DELIM}`, "i"),
        apiManagement: new RegExp(`${Constant.PREFIX_DELIM}apiManagement${Constant.SUFFIX_DELIM}`, "i"),
        notificationsHubs: new RegExp(`${Constant.PREFIX_DELIM}notificationsHubs${Constant.SUFFIX_DELIM}`, "i"),
        mobileEngagement: new RegExp(`${Constant.PREFIX_DELIM}mobileEngagement${Constant.SUFFIX_DELIM}`, "i"),
        functions: new RegExp(`${Constant.PREFIX_DELIM}(functions|functionapp)${Constant.SUFFIX_DELIM}`, "i"),
        sqlDatabase: new RegExp(`${Constant.PREFIX_DELIM}sqlDatabase${Constant.SUFFIX_DELIM}`, "i"),
        documentDb: new RegExp(`${Constant.PREFIX_DELIM}documentDb${Constant.SUFFIX_DELIM}`, "i"),
        redisCache: new RegExp(`${Constant.PREFIX_DELIM}redisCache${Constant.SUFFIX_DELIM}`, "i"),
        storage: new RegExp(`${Constant.PREFIX_DELIM}blob${Constant.SUFFIX_DELIM}`, "i"),
        storSimple: new RegExp(`${Constant.PREFIX_DELIM}storSimple${Constant.SUFFIX_DELIM}`, "i"),
        sqlDataWarehouse: new RegExp(`${Constant.PREFIX_DELIM}sqlDataWarehouse${Constant.SUFFIX_DELIM}`, "i"),
        sqlServerStretch: new RegExp(`${Constant.PREFIX_DELIM}sqlServerStretch${Constant.SUFFIX_DELIM}`, "i"),
        dataLakeAnalytics: new RegExp(`${Constant.PREFIX_DELIM}dataLakeAnalytics${Constant.SUFFIX_DELIM}`, "i"),
        dataLakeStore: new RegExp(`${Constant.PREFIX_DELIM}dataLakeStore${Constant.SUFFIX_DELIM}`, "i"),
        hdInsights: new RegExp(`${Constant.PREFIX_DELIM}hdInsights${Constant.SUFFIX_DELIM}`, "i"),
        machineLearning: new RegExp(`${Constant.PREFIX_DELIM}machineLearning${Constant.SUFFIX_DELIM}`, "i"),
        streamAnalytics: new RegExp(`${Constant.PREFIX_DELIM}streamAnalytics${Constant.SUFFIX_DELIM}`, "i"),
        dataFactory: new RegExp(`${Constant.PREFIX_DELIM}dataFactory${Constant.SUFFIX_DELIM}`, "i"),
        powerBi: new RegExp(`${Constant.PREFIX_DELIM}powerBi${Constant.SUFFIX_DELIM}`, "i"),
        iotSuite: new RegExp(`${Constant.PREFIX_DELIM}iotSuite${Constant.SUFFIX_DELIM}`, "i"),
        iotHub: new RegExp(`${Constant.PREFIX_DELIM}iotHub${Constant.SUFFIX_DELIM}`, "i"),
        eventHubs: new RegExp(`${Constant.PREFIX_DELIM}eventHubs${Constant.SUFFIX_DELIM}`, "i"),
        cortana: new RegExp(`${Constant.PREFIX_DELIM}cortana${Constant.SUFFIX_DELIM}`, "i"),
        cognitiveService: new RegExp(`${Constant.PREFIX_DELIM}cognitiveService${Constant.SUFFIX_DELIM}`, "i"),
        mediaService: new RegExp(`${Constant.PREFIX_DELIM}mediaService${Constant.SUFFIX_DELIM}`, "i"),
        contentDelivery: new RegExp(`${Constant.PREFIX_DELIM}contentDelivery${Constant.SUFFIX_DELIM}`, "i"),
        activeDir: new RegExp(`${Constant.PREFIX_DELIM}activeDir${Constant.SUFFIX_DELIM}`, "i"),
        b2c: new RegExp(`${Constant.PREFIX_DELIM}b2c${Constant.SUFFIX_DELIM}`, "i"),
        domainService: new RegExp(`${Constant.PREFIX_DELIM}domainService${Constant.SUFFIX_DELIM}`, "i"),
        multiFactor: new RegExp(`${Constant.PREFIX_DELIM}multiFactor${Constant.SUFFIX_DELIM}`, "i"),
      },
    },
  };

  public static secretRegex: RegExp = new RegExp("([a-z\\-]+\\d+-?){2,}", "i");
  public static trustedWebhooks: string[] = ["https://app.codacy.com", "https://api.snyk.io/", "https://snyk.io/", "https://app.snyk.io/"];

  public static scaIdentifierRegex: RegExp = new RegExp("dependency", "i");

  public static firstNonSpaceRegex = new RegExp("^\\s+");

  public static regexProwlerPolicyCategory = "- (.*)\\[";
  public static regexProwlerPolicyName = "](.*)-";

  public static codeToolType = "code";
  public static cloudToolType = "cloud";
  public static artifactoryToolType = "artifactory";
  public static artifactoryDownloadType = "artifactory_download";

  public static maxTimeToPrintWarnInLog = 1000 * 60 * 10;
  public static dockerUserInstructions = ["apt-get", "apk update", "apk add", "apk detch"];
  public static ignoreRuleBasedOnSeverity = "none";

  public static piiCollectLimit = 15;

  public static otherLanguages = {
    ".ts": "TypeScript",
    ".tsx": "TypeScript",
    ".js": "JavaScript",
    ".jsx": "JavaScript",
    ".go": "Go",
    ".py": "Python",
    ".java": "Java",
    ".rb": "Ruby",
    ".rs": "Rust",
    ".twb": "Tableau",
    ".twbx": "Tableau",
    ".tpl": "Terraform",
    ".cs": "C#",
    ".ipynb": "Jupyter Notebook",
    ".h": "C",
    ".sql": "SQL",
  };

  public static languageRenameMap = {
    HCL: "Terraform",
    Smarty: "Terraform",
    Smalltalk: "C#",
  };

  public static execType = {
    duringScan: "during_scan",
    codeSecurityExecutionAgain: "code_security_execution_again",
    endScan: "end_scan",
  };

  public static sourceControlCICD = ["gitlab", "github", "bitbucket"];

  private static yamlClassification = [
    {
      name: "Codecov",
      pathPattern: new RegExp("codecov"),
    },
    {
      name: "GitHub Actions",
      pathPattern: new RegExp("\\.github"),
    },
    {
      name: "GitLab CI/CD",
      pathPattern: new RegExp("\\.gitlab-ci"),
    },
    {
      name: "Drone CI",
      pathPattern: new RegExp("\\.drone"),
      contentPattern: new RegExp("kind:spipeline"),
    },
    {
      name: "Travis CI",
      pathPattern: new RegExp("\\.travis.*\\.ya?ml"),
    },
    {
      name: "Circle CI",
      pathPattern: new RegExp("\\.CircleCI"),
    },
    {
      name: "Azure Pipelines",
      pathPattern: RegExp("azure-pipelines?.*\\.ya?ml"),
    },
    {
      name: "Cloud Build",
      pathPattern: RegExp("cloudbuild.*\\.ya?ml"),
    },
    {
      name: "Buildkite",
      pathPattern: RegExp("\\.buildkite"),
    },
    {
      name: "Docker Compose",
      pathPattern: RegExp("docker-compose[\\w_\\-\\.]*\\.ya?ml"),
    },
    {
      name: "Swagger",
      contentPattern: new RegExp("swagger(Version)?:\\s"),
    },
    {
      name: "OpenAPI",
      contentPattern: new RegExp("openapi:\\s"),
    },
    {
      name: "Helm",
      pathPattern: RegExp("Chart\\.ya?ml", "i"),
    },
    {
      name: "Kubernetes",
      contentPattern: new RegExp("apiVersion:\\s"),
    },
    {
      name: "Cassandra",
      contentPattern: new RegExp("cluster_name:\\s"),
    },
    {
      name: "Codecov",
      pathPattern: new RegExp("codecov\\.ya?ml"),
    },
    {
      name: "Conda",
      pathPattern: new RegExp("environment\\.ya?ml"),
    },
    {
      name: "hadolint",
      contentPattern: new RegExp("\\.hadolint\\.ya?ml"),
    },
    {
      name: "pre-commit",
      pathPattern: new RegExp("\\.pre-commit-hooks\\.ya?ml"),
    },
    {
      name: "Filebeat",
      pathPattern: new RegExp("filebeat\\.ya?ml"),
      contentPattern: new RegExp("filebeat.inputs:\\s"),
    },
    {
      name: "Logstash",
      pathPattern: new RegExp("logstash\\.ya?ml"),
      contentPattern: new RegExp("pipeline:\\s"),
    },
    {
      name: "Ansible",
      pathPattern: new RegExp("(ansible|vars\\.ya?ml|playbook\\.ya?ml)", "i"),
      contentPattern: new RegExp("(hosts:\\s|include_role:\\s)"),
    },
  ];

  private static jsonClassification = [
    {
      name: "Swagger",
      contentPattern: new RegExp('"swagger":\\s'),
    },
    {
      name: "OpenAPI",
      contentPattern: new RegExp('"openapi":\\s'),
    },
    {
      name: "Postman",
      contentPattern: new RegExp('"_postman_id":\\s'),
    },
  ];

  public static fileDeepClassfication = {
    ".yaml": Constant.yamlClassification,
    ".yml": Constant.yamlClassification,
    ".json": Constant.jsonClassification,
  };

  public static artifactoryPushCmd: ArtifactoryPushCmd[] = [
    {
      name: "docker",
      pattern: new RegExp("docker\\s+push"),
      isSharedModule: false,
      language: "Dockerfile",
    },
    {
      name: "twine",
      pattern: new RegExp("(twine[\\W\\s][\\w\\W]{0,70}(upload|register)|(TWINE_PASSWORD|TWINE_USERNAME))"),
      isSharedModule: true,
      language: "Python",
    },
    {
      name: "npm",
      pattern: new RegExp("[^p]npm[\\W\\s][\\w\\W]{0,70}publish"),
      isSharedModule: true,
      language: "JavaScript",
    },
    {
      name: "yarn",
      pattern: new RegExp("yarn[\\W\\s][\\w\\W]{0,70}publish"),
      isSharedModule: true,
      language: "JavaScript",
    },
    {
      name: "pnpm",
      pattern: new RegExp("pnpm[\\W\\s][\\w\\W]{0,70}publish"),
      isSharedModule: true,
      language: "JavaScript",
    },
    {
      name: "maven",
      pattern: new RegExp("mvn[\\W\\s][\\w\\W]{0,70}deploy"),
      isSharedModule: true,
      language: "Java",
    },
    {
      name: "gradle",
      pattern: new RegExp("gradle[\\W\\s][\\w\\W]{0,70}publish"),
      isSharedModule: true,
      language: "Java",
    },
    {
      name: "dotnet",
      pattern: new RegExp("dotnet[\\W\\s][\\w\\W]{0,70}publish"),
      isSharedModule: true,
      language: "C#",
    },
  ];
  //run: twine register dist/*.tar.gz
  //run: mvn deploy
  //run: gradle publish
  //run: npm publish
  //run: npm unpuablish
  file: "/templates/npm_package/.gitlab-ci-ox-shared-library.yml";
  public static artifactoryList = [
    {
      name: "GitLab",
      pattern: new RegExp("gitlab", "i"),
    },
    {
      name: "AWS CodeArtifact",
      pattern: new RegExp("codeartifact", "i"),
    },
    {
      name: "AWS ECR",
      pattern: new RegExp(`(AWS${Constant.PREFIX_DELIM}DOCKER|${Constant.PREFIX_DELIM}ecr${Constant.PREFIX_DELIM})`, "i"),
    },
    {
      name: "Google Artifact Registry",
      pattern: new RegExp(`(${Constant.PREFIX_DELIM}GCP${Constant.PREFIX_DELIM}|pkg\\.dev)`, "i"),
    },
    {
      name: "JFrog",
      pattern: new RegExp(`${Constant.PREFIX_DELIM}jfrog${Constant.PREFIX_DELIM}`, "i"),
    },
  ];

  public static kubernetesKinds = [
    {
      kind: "Pod",
      kindPattern: new RegExp("kind:\\s+Pod", "i"),
      lookupPattern: new RegExp("image:\\s+", "i"),
    },
    {
      kind: "Deployment",
      kindPattern: new RegExp("kind:\\s+Deployment", "i"),
      lookupPattern: new RegExp("image:\\s+", "i"),
    },
    {
      kind: "Service",
      kindPattern: new RegExp("kind:\\s+Service", "i"),
      lookupPattern: new RegExp("image:\\s+", "i"),
    },
    {
      kind: "Secret",
      kindPattern: new RegExp("kind:\\s+Secret", "i"),
      lookupPattern: new RegExp("name:\\s+", "i"),
    },
    {
      kind: "PersistentVolume",
      kindPattern: new RegExp("kind:\\s+PersistentVolume", "i"),
      lookupPattern: new RegExp("name:\\s+", "i"),
    },
    {
      kind: "Ingress",
      kindPattern: new RegExp("kind:\\s+Ingress", "i"),
      lookupPattern: new RegExp("host:\\s+", "i"),
    },
    {
      kind: "CronJob",
      kindPattern: new RegExp("kind:\\s+CronJob", "i"),
      lookupPattern: new RegExp("name:\\s+", "i"),
    },
    {
      kind: "Cluster",
      kindPattern: new RegExp("kind:\\s+Cluster", "i"),
      lookupPattern: new RegExp("name:\\s+", "i"),
    },
  ];
}

export enum SettingType {
  setRepoToPrivate = "setRepoToPrivate",
  archiveRepo = "archiveRepo",
  setRepoBranchProtectionUnReviewedCode = "setRepoBranchProtectionUnReviewedCode",
  setRepoBranchProtectionForDeletionOnBranch = "setRepoBranchProtectionForDeletionOnBranch",
  setRepoBranchProtectionForAddingSignedCommits = "setRepoBranchProtectionForAddingSignedCommits",
  changeRepoCollaboratorStatus = "changeRepoCollaboratorStatus",
  changeOrgUserStatus = "changeOrgUserStatus",
  changeForkSettings = "changeForkSettings",
  changeWorkflowsPerm = "changeWorkflowsPerm",
  changeCiCdBot = "changeCiCdBot",
  changeWebhookSSL = "changeWebhookSSL",
  deleteWebhook = "deleteWebhook",
  upgradeOrgUserRole = "upgradeOrgUserRole",
}

export enum OXtools {
  dockerScanner = "docker-file-scan",
  pip2poetry = "pip2poertry",
  dependencyG = "dependencyG",
  trivyCode = "trivy",
  trivyArtifact = "trivy-artifact",
  depConfusionScopes = "dep-confusion-scopes",
  depConfusionAlert = "dep-confusion-alert",
  depJacking = "dep-jacking",
  typosquatting = "typos-quatting",
  cloner = "cloner",
  recommendation = "recommendation",
  attackPath = "attackPath",
  autoFix = "autoFix",
  semgrep = "semgrep",
  gitleaks = "gitleaks",
  checkov = "checkov",
  semgrepEnterprise = "semgrep-enterprise",
  blame = "blame",
  iacValidator = "iacValidator",
  scaValidator = "scaValidator",
  secretValidator = "secretValidator",
  apiDiscovery = "apiDiscovery",
  callGraph = "callGraph",
  resolveIssue = "resolveIssue",
  llmClient = "llmClient",
}

export enum InputType {
  users = "users",
  repos = "repos",
  permissions = "permissions",
  branch = "branch",
  settingsOption = "type of settings",
  hooks = "webhooks",
}

export default Constant;

export interface ArtifactoryPushCmd {
  name: string;
  pattern: RegExp;
  isSharedModule: boolean;
  language: string;
}
