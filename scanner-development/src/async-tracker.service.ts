import { AsyncLocalStorage } from "node:async_hooks";

export const OX_STORE_PREFIX = "ox-";

export class AsyncTracker {
  private static readonly asyncLocalStorage = new AsyncLocalStorage<Map<string, unknown>>();

  static runWithAsyncTracker<TArgs extends unknown[], TResult>(func: (...args: TArgs) => TResult, ...args: TArgs): TResult {
    return this.asyncLocalStorage.run<TResult, TArgs>(new Map(this.asyncLocalStorage.getStore()), func, ...args);
  }

  static setValue(key: string, val: unknown): void {
    this.asyncLocalStorage.getStore()?.set(key, val);
  }

  static getValue(key: string): unknown {
    return this.asyncLocalStorage.getStore()?.get(key);
  }

  /**
   * Will return an object containing all entries of the store that have key prefixed with "ox-"
   */
  static getLoggerInfo(): Record<string, unknown> | undefined {
    const store = this.asyncLocalStorage.getStore();
    if (!store) {
      return {};
    }
    return Object.fromEntries([...store.entries()].filter(([key]) => key.startsWith(OX_STORE_PREFIX)));
  }
}
