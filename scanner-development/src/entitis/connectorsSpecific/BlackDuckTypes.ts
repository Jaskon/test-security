interface META {
  allow: [];
  href: string;
  links: [];
}

export interface BD_PROJECT_DETAIL {
  name: string;
  projectLevelAdjustments: string;
  cloneCategories: [];
  customSignatureEnabled: string;
  customSignatureDepth: string;
  deepLicenseDataEnabled: string;
  snippetAdjustmentApplied: string;
  licenseConflictsEnabled: string;
  projectGroup: string;
  createdAt: string;
  createdBy: string;
  createdByUser: string;
  updatedAt: string;
  updatedBy: string;
  updatedByUser: string;
  source: string;
  _meta: META;
}

export interface BD_VERISON_DETAIL {
  versionName: string;
  phase: string;
  distribution: string;
  license: [];
  createdAt: string;
  createdBy: string;
  createdByUser: string;
  settingUpdatedAt: string;
  settingUpdatedBy: string;
  settingUpdatedByUser: string;
  source: string;
  _meta: META;
}

export interface BD_REST_API_RESPONSE {
  totalCount: Number;
  items: [];
  appliedFilters: [];
  _meta: META;
}

export interface BD_PROJECTS_API_RESPONSE {
  totalCount: Number;
  items: BD_PROJECT_DETAIL[];
  appliedFilters: [];
  _meta: META;
}

export interface BD_VERSIONS_API_RESPONSE {
  totalCount: Number;
  items: BD_VERISON_DETAIL[];
  appliedFilters: [];
  _meta: META;
}

interface BD_NOTIFICATION_DETAILS_CONTENT_VULNERABILUTY {
  source: string;
  vulnerabilityId: string;
  vulnerability: string;
  relatedVulnerabilityId?: string;
  relatedVulnerability?: string;
  severity: string;
}

interface BD_NOTIFICATION_DETAILS_CONTENT_PROJECT {
  projectVersion: string;
  projectName: string;
  projectVersionName: string;
  componentIssueUrl: string;
  bomComponent: string;
}

interface BD_NOTIFICATION_DETAILS_CONTENT {
  componentName: string;
  versionName: string;

  componentVersionOriginId: string;
  componentVersionOriginName: string;
  componentVersion: string;

  newVulnerabilityCount: number;
  updatedVulnerabilityCount: number;
  deletedVulnerabilityCount: number;

  newVulnerabilityIds: BD_NOTIFICATION_DETAILS_CONTENT_VULNERABILUTY[];
  updatedVulnerabilityIds: BD_NOTIFICATION_DETAILS_CONTENT_VULNERABILUTY[];
  deletedVulnerabilityIds: BD_NOTIFICATION_DETAILS_CONTENT_VULNERABILUTY[];

  affectedProjectVersions: BD_NOTIFICATION_DETAILS_CONTENT_PROJECT[];

  vulnerabilityNotificationCause: string;
  eventSource: string;
}

export interface BD_NOTIFICATION_DETAIL {
  content: BD_NOTIFICATION_DETAILS_CONTENT;

  contentType: string;
  type: string;

  createdAt: string;

  _meta: META;
}

export interface BD_NOTIFICATION_DETAILS extends Array<BD_NOTIFICATION_DETAIL> {}

interface BD_NOTIFICATION_DETAILS_CONTENT_COMPONENT {
  componentName: string;
  versionName: string;

  componentVersionOriginId: string;
  componentVersionOriginName: string;
  componentVersion: string;
}

export interface BD_NOTIFICATION {
  project: BD_NOTIFICATION_DETAILS_CONTENT_PROJECT;
  component: BD_NOTIFICATION_DETAILS_CONTENT_COMPONENT;
  vulnerability: BD_NOTIFICATION_DETAILS_CONTENT_VULNERABILUTY;

  contentType: string;
  type: string;

  createdAt: string;

  _meta: META;
}

export interface BD_NOTIFICATIONS extends Array<BD_NOTIFICATION> {}

export class BlackDuckAPIException extends Error {
  public status: number;
  public message: string;

  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.message = message;
  }
}
