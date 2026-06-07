/**
 * Database access. The ONLY way to query tenant data is `withOrg`, which opens a
 * transaction and sets the per-transaction GUC `app.current_org`. RLS policies
 * key on that GUC; a missing GUC returns ZERO rows (fail closed). The raw db
 * handle is intentionally NOT exported, so no code path can query without a
 * tenant context.
 *
 * The runtime connection uses the NON-owner, no-BYPASSRLS role (DATABASE_URL).
 * `prepare: false` keeps us compatible with transaction-mode poolers (PgBouncer/
 * Neon), where prepared statements and session state do not survive across
 * pooled connections — only the explicit transaction below does.
 */
import postgres from "postgres";
import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import { sql } from "drizzle-orm";
import * as schema from "./schema";

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

export type Db = PostgresJsDatabase<typeof schema>;

let _sql: ReturnType<typeof postgres> | null = null;

function pg() {
  if (!_sql) {
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error("DATABASE_URL is not set");
    _sql = postgres(url, { max: 10, prepare: false });
  }
  return _sql;
}

/**
 * Run `fn` inside a transaction scoped to a single org. Sets `app.current_org`
 * locally (transaction-lifetime) so RLS isolates every query to this tenant.
 */
export async function withOrg<T>(orgId: string, fn: (db: Db) => Promise<T>): Promise<T> {
  if (!UUID_RE.test(orgId)) throw new Error("withOrg: orgId is not a uuid");
  const db = drizzle(pg(), { schema });
  return db.transaction(async (tx) => {
    // set_config(key, value, is_local=true) — reset at transaction end.
    await tx.execute(sql`select set_config('app.current_org', ${orgId}, true)`);
    return fn(tx as unknown as Db);
  });
}

/**
 * For NON-tenant tables only (account/auth bootstrap, organization provisioning).
 * No org GUC is set, so any tenant-scoped table is invisible/empty under RLS —
 * that's the point: system code cannot accidentally read tenant rows in bulk.
 */
export async function withSystem<T>(fn: (db: Db) => Promise<T>): Promise<T> {
  const db = drizzle(pg(), { schema });
  return fn(db);
}

/** Close the pool (tests / graceful shutdown). */
export async function closeDb(): Promise<void> {
  if (_sql) {
    await _sql.end({ timeout: 5 });
    _sql = null;
  }
}
