import loggerImport from "../logger";
import { repoType } from "../entitis/codeRepoTypes";

const logger = loggerImport.getDebugLogger();

class RoleHelper {
  uuid: string;

  constructor(uuid: string) {
    this.uuid = uuid;
  }

  getGitRoles = (git: repoType) => {
    try {
      const roles = {
        github: {
          org: {
            admin: "Owner",
            member: "Member",
            maintainer: "Maintainer",
            reporter: "Reporter",
          },
          repo: {
            admin: "Admin",
            maintainer: "Maintainer",
            write: "Write",
            triage: "Triage",
            read: "Read",
          },
        },
        gitlab: {
          org: {
            admin: "Owner",
            maintainer: "Maintainer",
            reporter: "Reporter",
          },
          repo: {
            admin: "Owner",
            maintainer: "Maintainer",
            write: "Write",
            triage: "Triage",
            read: "Read",
          },
        },
        bitbucket: {
          org: {
            admin: "Owner",
            collaborator: "Collaborator",
          },
          repo: {
            admin: "Admin",
            write: "Write",
            read: "Read",
          },
        },
        ["azure repos (git)"]: {
          org: { admin: "Owner" },
          repo: {
            admin: "Admin",
            write: "Write",
            read: "Read",
          },
        },
        bitbucketStash: {
          org: {
            admin: "Owner",
            collaborator: "Collaborator",
          },
          repo: {
            admin: "Admin",
            write: "Write",
            read: "Read",
          },
        },
      };

      return roles[git];
    } catch (e) {
      logger.error(`RoleHelper grtGitRoles err: ${e}`);
    }
    return {};
  };
}

export default RoleHelper;
