/**
 * Hosted-mode boot posture assertion. The SAME binary runs self-host and hosted,
 * so configuration drift could leave a security wall down. In DEPLOY_MODE=hosted
 * the platform MUST NOT START unless every load-bearing control is verified:
 *
 *   1. KEK is a real KMS (a bare on-disk master key is rejected).
 *   2. The runtime DB role is NOT a table owner / superuser, and FORCE RLS is on
 *      for every tenant table (probed live).
 *   3. Billing + meter dependencies (Stripe, Upstash) are configured.
 *
 * Self-host mode only WARNS (e.g. about file-KEK being a weaker guarantee).
 */
import postgres from "postgres";
import { deployMode } from "./deployMode.js";
import { TENANT_TABLES } from "../db/schema.js";

export class PostureError extends Error {}

async function probeRls(): Promise<void> {
  const url = process.env.DATABASE_URL;
  if (!url) throw new PostureError("DATABASE_URL not set");
  const sql = postgres(url, { max: 1, prepare: false });
  try {
    const me = await sql<{ u: string }[]>`select current_user as u`;
    const meName = me[0]!.u;

    // SUPERUSER / BYPASSRLS bypass ALL RLS regardless of ownership or FORCE RLS.
    // current_user is the effective role for the connection, and BYPASSRLS is
    // not inherited through membership, so checking current_user is sufficient.
    const attrs = await sql<{ rolsuper: boolean; rolbypassrls: boolean }[]>`
      select rolsuper, rolbypassrls from pg_roles where rolname = ${meName}`;
    if (attrs[0]?.rolsuper) {
      throw new PostureError(`runtime role '${meName}' is SUPERUSER — RLS is bypassed entirely.`);
    }
    if (attrs[0]?.rolbypassrls) {
      throw new PostureError(`runtime role '${meName}' has BYPASSRLS — RLS is bypassed entirely.`);
    }

    // current_user must not own ANY tenant table (RLS is inert for the owner
    // unless FORCE is set, and we should not depend on that for the owner role).
    const owners = await sql<{ tablename: string; tableowner: string }[]>`
      select tablename, tableowner from pg_tables
      where tablename = any(${TENANT_TABLES as unknown as string[]})`;
    const owned = owners.find((o) => o.tableowner === meName);
    if (owned) {
      throw new PostureError(
        `runtime role '${meName}' OWNS tenant table '${owned.tablename}' — use a non-owner role.`,
      );
    }
    // FORCE RLS must be on for every tenant table.
    const rows = await sql<{ relname: string; relrowsecurity: boolean; relforcerowsecurity: boolean }[]>`
      select relname, relrowsecurity, relforcerowsecurity
      from pg_class where relname = any(${TENANT_TABLES as unknown as string[]})`;
    const byName = new Map(rows.map((r) => [r.relname, r]));
    for (const t of TENANT_TABLES) {
      const r = byName.get(t);
      if (!r || !r.relrowsecurity || !r.relforcerowsecurity) {
        throw new PostureError(`table '${t}' missing ENABLE+FORCE row level security`);
      }
    }
  } finally {
    await sql.end({ timeout: 5 });
  }
}

export async function assertPosture(): Promise<void> {
  const mode = deployMode();

  if (mode === "self_host") {
    if ((process.env.KEK_PROVIDER ?? "file") === "file") {
      // eslint-disable-next-line no-console
      console.warn(
        "[posture] self-host + file KEK: the key sits next to the ciphertext. " +
          "A DB dump PLUS the key file = full recovery. Prefer your own KMS/Vault.",
      );
    }
    return;
  }

  // hosted — fail closed.
  const failures: string[] = [];

  if (process.env.KEK_PROVIDER !== "kms") {
    failures.push("KEK_PROVIDER must be 'kms' in hosted mode (file KEK rejected)");
  }
  if (!process.env.KMS_KEY_ID) failures.push("KMS_KEY_ID required in hosted mode");
  if (!process.env.STRIPE_SECRET_KEY) failures.push("STRIPE_SECRET_KEY required in hosted mode");
  if (!process.env.STRIPE_WEBHOOK_SECRET) failures.push("STRIPE_WEBHOOK_SECRET required");
  if (!process.env.UPSTASH_REDIS_REST_URL) failures.push("UPSTASH_REDIS_REST_URL required");
  if (!process.env.UPSTASH_REDIS_REST_TOKEN) failures.push("UPSTASH_REDIS_REST_TOKEN required");
  if (!process.env.INGEST_ID_PEPPER) failures.push("INGEST_ID_PEPPER required");

  try {
    await probeRls();
  } catch (e) {
    failures.push(e instanceof Error ? e.message : String(e));
  }

  if (failures.length) {
    throw new PostureError(
      "Hosted posture assertion FAILED — refusing to boot:\n  - " + failures.join("\n  - "),
    );
  }
}

// Runnable as a script: `npm run posture:assert`
const invokedDirectly = process.argv[1]?.endsWith("assertPosture.ts");
if (invokedDirectly) {
  assertPosture()
    .then(() => {
      // eslint-disable-next-line no-console
      console.log("✅ posture OK");
    })
    .catch((e) => {
      // eslint-disable-next-line no-console
      console.error("❌", e instanceof Error ? e.message : e);
      process.exit(1);
    });
}
