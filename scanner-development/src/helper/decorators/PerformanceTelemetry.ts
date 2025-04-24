import loggerImport from "../../logger";
const logger = loggerImport.getDebugLogger();

/**
 * Class method decorator to log performance of the method
 */
export function PerformanceTelemetry(category?: string) {
  return function (target: any, funcName: string, descriptor: PropertyDescriptor): PropertyDescriptor {
    const originalMethod = descriptor.value;
    const logMetadata = { "ox-perf-name": `${target.constructor.name}.${funcName}`, "ox-perf-category": category };

    descriptor.value = function (...args: any[]) {
      const startTime = Date.now();
      const result = originalMethod.apply(this, args);
      if (typeof result?.then !== "function") {
        // logger.info(`[PerformanceTelemetry]`, { ...logMetadata, "ox-perf-time": Date.now() - startTime });
        return result;
      }
      return result.then((res: any) => {
        // logger.info(`[PerformanceTelemetry]`, { ...logMetadata, "ox-perf-time": Date.now() - startTime });
        return res;
      });
    };
    return descriptor;
  };
}
