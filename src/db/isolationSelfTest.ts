/**
 * Cross-tenant isolation self-test. Runs AS THE RUNTIME ROLE (DATABASE_URL).
 *
 * It creates two throwaway orgs, inserts a project under each, and asserts:
 *   1. with app.current_org = A, only A's project is visible
 *   2. with app.current_org = B, only B's project is visible
 *   3. with NO GUC set (the production withSystem / out-of-context path), ZERO
 *      projects are visible AND no error is raised (true fail-closed via NULL)
 *
 * If any assertion fails it exits non-zero. Wire this into hosted boot and CI:
 * the platform must REFUSE TO START if isolation is not actually enforced (e.g.
 * the app accidentally connected as the table owner, or FORCE RLS was skipped).
 *
 * Org rows are created with their ids pre-generated client-side and the GUC set
 * to the org's own id, so the INSERT (WITH CHECK true) succeeds. We avoid
 * INSERT ... RETURNING under a NULL GUC, which Postgres rejects because the new
 * row would fail the organization SELECT policy (id = current_org).
 */
import { randomUUID } from "node:crypto";
import postgres from "postgres";

class IsolationError extends Error {}

async function main() {
  const url = process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_URL required (must be the NON-owner runtime role)");
  const sql = postgres(url, { max: 1, prepare: false });

  const tag = `selftest-${Date.now()}-${Math.floor(Math.random() * 1e6)}`;
  const orgA = randomUUID();
  const orgB = randomUUID();

  try {
    // Create each org within its own org context (GUC = its own id). No RETURNING.
    for (const [org, suffix] of [
      [orgA, "A"],
      [orgB, "B"],
    ] as const) {
      await sql.begin(async (tx) => {
        await tx`select set_config('app.current_org', ${org}, true)`;
        await tx`
          insert into organization (id, name, wrapped_dek, kek_key_id)
          values (${org}, ${tag + "-" + suffix}, ${Buffer.from("x")}, 'selftest')`;
        await tx`insert into project (org_id, name) values (${org}, ${tag + "-p" + suffix})`;
      });
    }

    // (1) org A sees only its project.
    await sql.begin(async (tx) => {
      await tx`select set_config('app.current_org', ${orgA}, true)`;
      const rows = await tx`select org_id from project where name like ${tag + "%"}`;
      if (rows.length !== 1 || rows[0]!.org_id !== orgA) {
        throw new IsolationError(`org A saw ${rows.length} rows (expected 1, only A's)`);
      }
    });

    // (2) org B sees only its project.
    await sql.begin(async (tx) => {
      await tx`select set_config('app.current_org', ${orgB}, true)`;
      const rows = await tx`select org_id from project where name like ${tag + "%"}`;
      if (rows.length !== 1 || rows[0]!.org_id !== orgB) {
        throw new IsolationError(`org B saw ${rows.length} rows (expected 1, only B's)`);
      }
    });

    // (3) NO GUC set -> the GUC is NULL -> `org_id = NULL` -> ZERO rows, NO error.
    // This is the exact production path (withSystem / any query outside withOrg).
    // A fail-OPEN (owner connection / FORCE RLS off / BYPASSRLS) would instead
    // return both projects and trip the assertion.
    await sql.begin(async (tx) => {
      const rows = await tx`select org_id from project where name like ${tag + "%"}`;
      if (rows.length !== 0) {
        throw new IsolationError(
          `FAIL-OPEN: with no org context, ${rows.length} rows were visible. ` +
            `RLS is NOT enforced — likely connected as table owner, FORCE RLS missing, ` +
            `or the role has BYPASSRLS/SUPERUSER.`,
        );
      }
    });

    // eslint-disable-next-line no-console
    console.log("✅ isolation self-test passed (A/B isolated, missing-GUC fails closed via NULL)");
  } catch (e) {
    // eslint-disable-next-line no-console
    console.error("❌ ISOLATION SELF-TEST FAILED:", e instanceof Error ? e.message : e);
    process.exitCode = 1;
  } finally {
    // Best-effort cleanup of throwaway rows (each within its own org context).
    try {
      for (const org of [orgA, orgB]) {
        await sql.begin(async (tx) => {
          await tx`select set_config('app.current_org', ${org}, true)`;
          await tx`delete from project where org_id = ${org}`;
          await tx`delete from organization where id = ${org}`;
        });
      }
    } catch {
      /* ignore cleanup errors */
    }
    await sql.end({ timeout: 5 });
  }
}

main();
