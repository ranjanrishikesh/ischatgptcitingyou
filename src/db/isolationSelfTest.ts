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
        await tx`
          insert into source (org_id, project_id, ingest_id_public, bearer_hash)
          values (${org}, (select id from project where org_id = ${org} and name = ${tag + "-p" + suffix}),
                  ${tag + "-ingest-" + suffix}, ${"hash-" + suffix})`;
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

    // (4) ingest_resolve (SECURITY DEFINER) MUST return exactly the one matching
    // source row WITHOUT an org GUC — proving the resolver-read policy lets the
    // definer read source under FORCE RLS. A regression here = drain auth dead.
    await sql.begin(async (tx) => {
      const rows = await tx`select org_id, status from ingest_resolve(${tag + "-ingest-A"})`;
      if (rows.length !== 1 || rows[0]!.org_id !== orgA) {
        throw new IsolationError(
          `ingest_resolve returned ${rows.length} rows for A's id (expected 1, org A). ` +
            `FORCE RLS likely binds the definer with no resolver-read policy -> drain auth dead.`,
        );
      }
      // And it must NOT leak across ids: B's id returns B, never A.
      const rb = await tx`select org_id from ingest_resolve(${tag + "-ingest-B"})`;
      if (rb.length !== 1 || rb[0]!.org_id !== orgB) {
        throw new IsolationError(`ingest_resolve cross-id mismatch for B`);
      }
    });

    // (5) destination isolation: create a destination per org; B cannot see A's.
    const destA = randomUUID();
    const destB = randomUUID();
    for (const [org, id, suffix] of [
      [orgA, destA, "A"],
      [orgB, destB, "B"],
    ] as const) {
      await sql.begin(async (tx) => {
        await tx`select set_config('app.current_org', ${org}, true)`;
        await tx`insert into destination (id, org_id, kind, label, status)
                 values (${id}, ${org}, 'posthog', ${tag + "-d" + suffix}, 'active')`;
      });
    }
    await sql.begin(async (tx) => {
      await tx`select set_config('app.current_org', ${orgB}, true)`;
      const rows = await tx`select id from destination where id = ${destA}`;
      if (rows.length !== 0) throw new IsolationError("org B can see org A's destination");
    });

    // (6) route triple-equality trigger: org A wiring its source to org B's
    // destination must be REJECTED (the destination is invisible/NULL under A's
    // RLS, so the trigger raises).
    const srcRows = await sql.begin(async (tx) => {
      await tx`select set_config('app.current_org', ${orgA}, true)`;
      return tx`select id from source where org_id = ${orgA} limit 1`;
    });
    const srcA = srcRows[0]!.id as string;
    let rejected = false;
    try {
      await sql.begin(async (tx) => {
        await tx`select set_config('app.current_org', ${orgA}, true)`;
        await tx`insert into route (org_id, source_id, destination_id)
                 values (${orgA}, ${srcA}, ${destB})`;
      });
    } catch (e) {
      // Must be the TRIGGER, not an unrelated error (grant loss, FK, etc.).
      if (!(e instanceof Error) || !/route org mismatch/i.test(e.message)) throw e;
      rejected = true;
    }
    if (!rejected) {
      throw new IsolationError("cross-org route insert was NOT rejected by the trigger");
    }

    // (6b) Positive control: a SAME-org route MUST insert (trigger doesn't reject all).
    await sql.begin(async (tx) => {
      await tx`select set_config('app.current_org', ${orgA}, true)`;
      await tx`insert into route (org_id, source_id, destination_id)
               values (${orgA}, ${srcA}, ${destA})`;
    });

    // (7) Append-only: UPDATE on ledger_entry must affect ZERO rows (RLS denies).
    await sql.begin(async (tx) => {
      await tx`select set_config('app.current_org', ${orgA}, true)`;
      await tx`insert into ledger_entry (org_id, kind, amount_micros) values (${orgA}, 'adjustment', 0)`;
      const upd = await tx`update ledger_entry set amount_micros = 1 where org_id = ${orgA}`;
      if (upd.count !== 0) {
        throw new IsolationError(`ledger_entry not append-only: UPDATE affected ${upd.count} rows`);
      }
    });

    // eslint-disable-next-line no-console
    console.log(
      "✅ isolation self-test passed (A/B isolated, missing-GUC fails closed, ingest_resolve id-scoped, destination isolated, cross-org route rejected via trigger, same-org route ok, ledger append-only)",
    );
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
