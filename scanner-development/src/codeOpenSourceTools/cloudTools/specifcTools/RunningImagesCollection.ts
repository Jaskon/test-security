import loggerImport from "../../../logger";
const logger = loggerImport.getDebugLogger();

const RunningImagesCollection = () => {
  const runningImages = new Set<string>();
  const runningImagesIS = new Map<string, string>();

  return {
    isRunning: (image: string, tag: string) => {
      return runningImages.has(`${image}:${tag}`);
    },

    add: (image: string, tag: string, description = "") => {
      runningImages.add(`${image}:${tag}`);
      runningImagesIS.set(`${image}:${tag}`, description);
    },

    remove: (image: string, tag: string) => {
      runningImages.delete(`${image}:${tag}`);
      runningImagesIS.delete(`${image}:${tag}`);
    },

    get: () => {
      return runningImages;
    },

    getIS: (imageAndTag: string): string | undefined => {
      return runningImagesIS.get(imageAndTag);
    },
  };
};

let instance: ReturnType<typeof RunningImagesCollection>;

const getRunningImagesCollection = () => {
  if (!instance) {
    instance = RunningImagesCollection();
    return instance;
  }
  return instance;
};

export default getRunningImagesCollection;
