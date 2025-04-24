export interface IRecord {
  id: string;
}

export interface IMultiRecord {
  id: string;
  values: any[];
}

export interface IDatabase<T extends IRecord> {
  set(newValue: T): Promise<void>;
  get(id: string): Promise<T | null>;
  visit(visitor: (record: T) => void): void;
}

export class memoryDB<T extends IRecord> implements IDatabase<T> {
  private db: Map<string, T> = new Map<string, T>();

  public async set(newValue: T): Promise<void> {
    this.db.set(newValue.id, newValue);
  }

  public async get(id: string): Promise<T | null> {
    return this.db.get(id) || null;
  }

  public visit(visitor: (record: T) => void): void {
    for (const record of this.db.values()) {
      visitor(record);
    }
  }
}

export class multiMapDB<T extends IMultiRecord> {
  private db: Map<string, IMultiRecord> = new Map<string, IMultiRecord>();

  public async set(newValue: T): Promise<void> {
    if (this.db.has(newValue.id)) {
      this.db.get(newValue.id).values.push(newValue);
    } else {
      this.db.set(newValue.id, { id: newValue.id, values: [newValue] });
    }
  }

  public async get(id: string): Promise<IMultiRecord | null> {
    return this.db.get(id) || null;
  }

  public visit(visitor: (record: IMultiRecord) => void): void {
    for (const record of this.db.values()) {
      visitor(record);
    }
  }

  public thisMap(): Map<string, IMultiRecord> {
    return this.db;
  }
}
