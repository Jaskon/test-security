import { performance } from "perf_hooks";
import MemoryMonitorHelper from "./IO/memoryMonitorHelper";

export function millisToTimeStr(millis: number) {
  const minutes = Math.floor(millis / 60000);
  const seconds = ((millis % 60000) / 1000).toFixed(0);
  if (minutes === 0 && seconds === "0") {
    return `${millis} milliseconds`;
  }
  return minutes + ":" + (parseInt(seconds) < 10 ? "0" : "") + seconds;
}

export const TimeOp = () => {
  let startTime = 0;
  let endTime = 0;

  return {
    start: () => {
      startTime = performance.now();
    },

    end: (): string => {
      endTime = performance.now();
      return millisToTimeStr(endTime - startTime);
    },
  };
};

export const perfOp = () => {
  const start = performance.now();

  return {
    timeMe: (): number => {
      const end = performance.now();
      return (end - start) / 60000;
    },
  };
};

export const perfOpExp = () => {
  let startTime = 0;
  let endTime = 0;

  return {
    start: () => {
      startTime = performance.now();
    },

    end: (): number => {
      endTime = performance.now();
      return (endTime - startTime) / 60000;
    },
  };
};
