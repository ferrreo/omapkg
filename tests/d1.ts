import { Database } from 'bun:sqlite';

class Prepared {
  constructor(private readonly database: Database, private readonly sql: string, private readonly values: unknown[] = []) {}

  bind(...values: unknown[]): Prepared {
    return new Prepared(this.database, this.sql, values);
  }

  run(): { success: true; meta: { changes: number; last_row_id: number } } {
    const result = this.database.query(this.sql).run(...(this.values as any[]));
    return { success: true, meta: { changes: Number(result.changes), last_row_id: Number(result.lastInsertRowid) } };
  }

  all<T>(): { results: T[] } {
    return { results: this.database.query(this.sql).all(...(this.values as any[])) as T[] };
  }

  first<T>(): T | null {
    return (this.database.query(this.sql).get(...(this.values as any[])) as T | undefined) ?? null;
  }
}

export class TestD1 {
  private readonly database: Database;

  constructor(schema?: string) {
    this.database = new Database(':memory:');
    if (schema) this.database.exec(schema);
  }

  prepare(sql: string): Prepared {
    return new Prepared(this.database, sql);
  }

  exec(sql: string): void {
    this.database.exec(sql);
  }

  batch(statements: Prepared[]): unknown[] {
    const execute = this.database.transaction(() => statements.map((statement) => statement.run()));
    return execute();
  }

  close(): void {
    this.database.close();
  }
}

export function asD1(database: TestD1): D1Database {
  return database as unknown as D1Database;
}
