export interface GetSettingsRequestsRes {
  getSettings: {
    settings: Settings[];
  };
}

export interface SubSubSettings {
  inputText?: string;
  idSubSetting: string;
}

export interface SubSettings {
  settings: SubSubSettings[];
}

export interface Settings {
  enabled?: boolean;
  settingsType: SettingsType;
  settingsSubType: SettingsSubType;
  configured?: number;
  valueList?: string[];
  inputText?: string;
  subSettings?: SubSettings[];
}

export enum SettingsType {
  Scan = "Scan",
  Usability = "Usability",
}

export enum SettingsSubType {
  ChatGPT = "ChatGPT",
  ChatGPTCodeSnippet = "ChatGPTCodeSnippet",
  PRChatGPT = "PRChatGPT",
  Monorepo = "Monorepo",
  MonorepoSplitBy = "MonorepoSplitBy",
  ScheduleScan = "ScheduleScan",
  AdvancedOptionsToolTip = "AdvancedOptionsToolTip",
  ConfiguredIrrelevantAppsTime = "ConfiguredIrrelevantAppsTime",
  ConfiguredIrrelevantImagesTime = "ConfiguredIrrelevantImagesTime",
  ConfiguredAdvancedOptionsToolTipTime = "ConfiguredAdvancedOptionsToolTipTime",
  ExcludeFiles = "ExcludeFiles",
  GithubTopics = "GithubTopics",
  DefineBranch = "DefineBranch",
}

export enum SourceControlId {
  gitlab = "1",
  github = "4",
}
