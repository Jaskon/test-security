import { ServerEnvironmentType } from "../entitis/commonTypes";

const isLocalDevelopment = (): boolean => {
  return getEnvironmentType() === ServerEnvironmentType.Local;
};

const isDevelopment = (): boolean => {
  return getEnvironmentType() === ServerEnvironmentType.Development;
};

export const isStaging = () => {
  return getEnvironmentType() === ServerEnvironmentType.Staging;
};

export const isProd = () => {
  return getEnvironmentType() === ServerEnvironmentType.Production;
};

const isTesting = (): boolean => {
  return getEnvironmentType() === ServerEnvironmentType.Testing;
};

const isOnPrem = (): boolean => {
  return getEnvironmentType() === ServerEnvironmentType.OnPrem;
};

const getEnvironmentType = (): ServerEnvironmentType => {
  return process.env.SERVER_ENVIRONMENT as ServerEnvironmentType;
};

const isUploadToS3 = (): boolean => {
  return isStaging() || isDevelopment();
};

function isK8Mode() {
  let runningOnK8 = false;
  try {
    if (process.env.SCANNER_RUN_AS_TASK) {
      runningOnK8 = process.env.SCANNER_RUN_AS_TASK.toLowerCase() === "true";
    }
  } catch (err) {
    console.info(`failed check if k8 mode, err: ${err}`);
  }
  return runningOnK8;
}

export { isLocalDevelopment, isDevelopment, isTesting, isOnPrem, getEnvironmentType, isK8Mode, isUploadToS3 };
