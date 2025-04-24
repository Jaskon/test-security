export interface ToolVersion {
  major: number;
  minor: number;
  patch: number;
  build: number;
}

export const versionUtils = (version: string) => {
  const parseVersion = (version: string): ToolVersion => {
    const currentVersion: ToolVersion = {
      major: 0,
      minor: 0,
      patch: 0,
      build: 0,
    };

    if (version.includes(".") && version.split(".").length === 4) {
      const versionStr: string[] = version.split(".");
      currentVersion.major = parseInt(versionStr[0]);
      currentVersion.minor = parseInt(versionStr[1]);
      currentVersion.patch = parseInt(versionStr[2]);
      currentVersion.build = parseInt(versionStr[3]);
    } else {
      currentVersion.build = parseInt(version);
    }

    return currentVersion;
  };

  return {
    getVersion: (): ToolVersion => {
      return parseVersion(version);
    },

    toString(): string {
      return version;
    },

    isGreaterThan: (otherVersion: string): boolean => {
      if (otherVersion === undefined || otherVersion === null) {
        return true;
      }

      const currentVersion: ToolVersion = parseVersion(version);
      const otherVersionParsed: ToolVersion = parseVersion(otherVersion);
      return (
        currentVersion.major > otherVersionParsed.major ||
        (currentVersion.major === otherVersionParsed.major && currentVersion.minor > otherVersionParsed.minor) ||
        (currentVersion.major === otherVersionParsed.major &&
          currentVersion.minor === otherVersionParsed.minor &&
          currentVersion.patch > otherVersionParsed.patch) ||
        (currentVersion.major === otherVersionParsed.major &&
          currentVersion.minor === otherVersionParsed.minor &&
          currentVersion.patch === otherVersionParsed.patch &&
          currentVersion.build > otherVersionParsed.build)
      );
    },

    isMajorVersionGreaterThan: (otherVersion: string): boolean => {
      const currentVersion: ToolVersion = parseVersion(version);
      const otherVersionParsed: ToolVersion = parseVersion(otherVersion);
      return currentVersion.major > otherVersionParsed.major;
    },

    isMajorVersionParsedGreaterThan: (otherVersion: ToolVersion): boolean => {
      const currentVersion: ToolVersion = parseVersion(version);
      return currentVersion.major > otherVersion.major;
    },
  };
};

export const guessVersionFromPath = (path: string): string => {
  const emptyVersion = "";

  try {
    const versionGuessRegEx = /.*(\d{1,2}\.\d{1,2}\.\d{1,2}).tgz/g;
    const regex = new RegExp(versionGuessRegEx, "g");
    const match = regex.exec(path);
    if (match !== null) {
      return match[1]; // return a version
    }
  } catch (err) {
    //...
  }

  return emptyVersion;
};

export const isVersionString = (str: string): boolean => {
  if (str) {
    const shortVersionRegex = /^\d+\.\d+$/;
    const midVersionRegex = /^\d+\.\d+\.\d+$/;
    const longVersionRegex = /^\d+\.\d+\.\d+\.\d+$/;

    return shortVersionRegex.test(str) || midVersionRegex.test(str) || longVersionRegex.test(str);
  }

  return false;
};

export const compareVersions = (version1: string, version2: string): number => {
  const components1 = version1.split(".").map(Number);
  const components2 = version2.split(".").map(Number);

  for (let i = 0; i < Math.max(components1.length, components2.length); i++) {
    const component1 = components1[i] || 0;
    const component2 = components2[i] || 0;

    if (component1 < component2) {
      return -1; // version1 is lower
    } else if (component1 > component2) {
      return 1; // version1 is higher
    }
  }

  return 0; // versions are equal
};
