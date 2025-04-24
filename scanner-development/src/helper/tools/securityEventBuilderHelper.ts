import { SecurityAlertType, SecurityEvent } from "../../entitis/codeRepoTypes";
import { Tool } from "../../policy/rules/code/policyRulesBase";

// Security Event builder
interface SecurityEventBuilder {
  setSecurityProvider(provider: string): void;
  setStatus(status: boolean): void;
  setLink(link: string): void;
  setCreationTime(creationTime: string): void;
  setClosureTime(closureTime: string): void;
  setTitle(title: string): void;
  setFileName(fileName: string): void;
  setSeverity(severity: string): void;
  setStartLine(startLine: number): void;
  setLineContent(lineContent: string): void;
  setRuleId(ruleId: string): void;
  setMoreInfoLink(moreInfoLink: string): void;
}

export class SimpleSecurityEventBuilder implements SecurityEventBuilder {
  private securityProvider: string = "";
  private status: boolean = false;
  private link: string = "";
  private creationTime: string = "";
  private closureTime: string = "";
  private title: string = "";
  private fileName: string = "";
  private severity: string = "";
  private startLine: number = -1;
  private lineContent: string = "";
  private ruleId: string = "";
  private moreInfoLink: string = "";
  private issueType: SecurityAlertType = SecurityAlertType.Unknown;
  private recommendation: string = "";
  private snippetContent: string = "";
  private endLineNumber: number = -1;
  private isOurTool: boolean = false;
  private fromCommitHistory: boolean = false;
  private committerName: string = "";
  private committerSha: string = "";
  private committerEmail: string = "";
  private commitDate: string = "";
  private closeDissmisser: string = "";
  private closeReason: string = "";
  private violationInfo: string = "";
  private additionalInfo: string = "";
  private cloneDir: string = "";
  private repoFullName: string = "";
  private insideFolderForMonoRepo: string = "";
  private tool: Tool = "UNKNOWN";

  constructor() {}

  public setSecurityProvider(provider: string): void {
    this.securityProvider = provider;
  }

  public setStatus(status: boolean): void {
    this.status = status;
  }
  public setLink(link: string): void {
    this.link = link;
  }
  public setCreationTime(creationTime: string): void {
    this.creationTime = creationTime;
  }
  public setClosureTime(closureTime: string): void {
    this.closureTime = closureTime;
  }
  public setTitle(title: string): void {
    this.title = title;
  }
  public setFileName(fileName: string): void {
    this.fileName = fileName;
  }
  public setSeverity(severity: string): void {
    this.severity = severity;
  }
  public setStartLine(startLine: number): void {
    this.startLine = startLine;
  }
  public setLineContent(lineContent: string): void {
    this.lineContent = lineContent;
  }
  public setRuleId(ruleId: string): void {
    this.ruleId = ruleId;
  }
  public setMoreInfoLink(moreInfoLink: string): void {
    this.moreInfoLink = moreInfoLink;
  }
  public setSecurityAlertType(issueType: SecurityAlertType): void {
    this.issueType = issueType;
  }
  public setRecommendation(recommendation: string): void {
    this.recommendation = recommendation;
  }
  public setSnippetContent(snippetContent: string): void {
    this.snippetContent = snippetContent;
  }
  public setEndLineNumber(endLineNumber: number): void {
    this.endLineNumber = endLineNumber;
  }
  public setIsOurTool(isOurTool: boolean): void {
    this.isOurTool = isOurTool;
  }
  public setFromCommitHistory(fromCommitHistory: boolean): void {
    this.fromCommitHistory = fromCommitHistory;
  }
  public setCommitterName(committerName: string): void {
    this.committerName = committerName;
  }
  public setCommitterSha(committerSha: string): void {
    this.committerSha = committerSha;
  }
  public setCommitterEmail(committerEmail: string): void {
    this.committerEmail = committerEmail;
  }
  public setCommitDate(commitDate: string): void {
    this.commitDate = commitDate;
  }
  public setCloseDissmisser(closeDissmisser: string): void {
    this.closeDissmisser = closeDissmisser;
  }
  public setCloseReason(closeReason: string): void {
    this.closeReason = closeReason;
  }
  public setViolationInfo(violationInfo: string): void {
    this.violationInfo = violationInfo;
  }
  public setCloneDir(cloneDir: string): void {
    this.cloneDir = cloneDir;
  }
  public setRepoFullName(repoFullName: string): void {
    this.repoFullName = repoFullName;
  }
  public setInsideFolderForMonoRepo(insideFolderForMonoRepo: string): void {
    this.insideFolderForMonoRepo = insideFolderForMonoRepo;
  }

  public generateSecurityEvent(): SecurityEvent {
    const securityEvent: SecurityEvent = new SecurityEvent(
      this.securityProvider,
      this.status,
      this.link,
      this.creationTime,
      this.closureTime,
      this.closeDissmisser,
      this.closeReason,
      this.violationInfo,
      this.title,
      this.fileName,
      this.severity,
      this.additionalInfo,
      this.startLine,
      this.severity,
      this.issueType,
      this.recommendation,
      this.lineContent,
      this.snippetContent,
      this.endLineNumber,
      this.isOurTool,
      this.fromCommitHistory,
      this.committerName,
      this.committerSha,
      this.committerEmail,
      this.commitDate,
      this.ruleId,
      this.moreInfoLink,
      this.cloneDir,
      this.repoFullName,
      this.insideFolderForMonoRepo,
      this.fileName,
      this.tool,
    );
    return securityEvent;
  }
}
