import { ClassicLevel } from "classic-level";
import * as fs from "fs";
import { setTimeout } from "node:timers/promises";
import { SecurityEvent } from "../entitis/codeRepoTypes";
import loggerImport from "../logger";

const logger = loggerImport.getDebugLogger();

export interface Session {
  uuid: string; // Scan Id
  orgId: string; // Organization Id
  repoId: string; // Repo Id
}

export class DiskDB {
  private db: ClassicLevel<string, SecurityEvent[]> | undefined;
  private initializedSession: Session;
  private initialized: boolean;
  public fullPath: string = "";

  constructor() {
    this.initialized = false;
  }

  private getPath(session: Session, isMountedForLocalDevelopment = false): string {
    if (this.fullPath === "") {
      try {
        this.fullPath = `${process.env.OX_SHARED_DATA}/${session.orgId}/scan_${session.uuid.replaceAll("-", "_")}/${session.repoId}/db`;
        if (!fs.existsSync(this.fullPath)) {
          fs.mkdirSync(this.fullPath, { recursive: true });
        }
      } catch (e) {
        logger.error(`Failed to create path folder with error: ${e}`);
      }
    }

    return this.fullPath;
  }

  public async initialize(session: Session, initPath = ""): Promise<void> {
    if (!this.initialized) {
      this.db = new ClassicLevel<string, any>(`${initPath ? initPath : this.getPath(session)}`, {
        valueEncoding: "json",
      });
      this.initializedSession = session;
      this.initialized = true;
    }
    await this.waitForDBToOpen();
  }

  public async get(key: string): Promise<SecurityEvent[] | undefined> {
    try {
      if (this.db) {
        await this.waitForOpenDb();
        return await this.db.get(key);
      }
    } catch (error: any) {
      if ("code" in error) {
        if (error.code === "LEVEL_NOT_FOUND") {
          return;
        }
      }
      logger.error(`failed to get ${key} from disk DB: `, error);
    }
  }

  public async set(key: string, value: SecurityEvent[]): Promise<void> {
    try {
      if (this.db) {
        await this.waitForOpenDb();
        await this.db.put(key, value);
      }
    } catch (error) {
      logger.error(`failed to set (${key}) with error ${error}`);
    }
  }

  public async delete(key: string): Promise<void> {
    try {
      if (this.db) {
        await this.waitForOpenDb();
        await this.db.del(key);
      }
    } catch (error) {
      logger.error(`failed to delete ${key} `, error);
    }
  }

  public async close(): Promise<void> {
    try {
      if (this.db) {
        await this.waitForOpenDb();
        await this.db.close();
      }
    } catch (error) {
      logger.error("failed to close db", error);
    }
  }

  public async deleteDB(): Promise<void> {
    try {
      if (this.db) {
        fs.rmSync(`${this.getPath(this.initializedSession)}`, {
          recursive: true,
        });
      }
    } catch (error) {
      logger.error("failed to delete db", error);
    }
  }

  private async waitForDBToOpen() {
    while (this.db && this.db.status === "opening") {
      await setTimeout(500);
    }
  }

  private async waitForOpenDb(): Promise<void> {
    if (this.db.status !== "open") {
      logger.info("db is not open, trying to open it");
      await this.db.open();
    }
  }
}
