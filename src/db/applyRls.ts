/**
 * Apply Row Level Security. Run as the OWNER role (DATABASE_OWNER_URL) after
 * migrations: `npm run db:rls`.
 *
 * For every tenant table:
 *   - ENABLE + FORCE ROW LEVEL SECURITY  (FORCE so even the table owner is bound)
 *   - a policy keyed on current_setting('app.current_org', true)::uuid
 *     -> a MISSING GUC evaluates to NULL -> no rows -> FAIL CLOSED.
 *
 * Special cases:
 *   - `organization` keys on `id` (it IS the boundary); INSERT is unrestricted
 *     (creating a new boundary leaks nothing), read/update/delete are scoped.
 *   - `ledger_entry` is APPEND-ONLY: SELECT + INSERT policies only. With FORCE
 *     RLS and no UPDATE/DELETE policy, those commands are denied by default.
 *
 * Optionally GRANTs DML to the runtime role if RUNTIME_DB_ROLE is set.
 */
import postgres from "postgres";
import { TENANT_TABLES } from "./schema.js";

const GUC = "current_setting('app.current_org', true)::uuid";

async function main() {
  const url = process.env.DATABASE_OWNER_URL ?? process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_OWNER_URL (or DATABASE_URL) required");
  const sql = postgres(url, { max: 1 });

  const runtimeRole = process.env.RUNTIME_DB_ROLE;

  try {
    for (const table of TENANT_TABLES) {
      const col = table === "organization" ? "id" : "org_id";
      await sql.unsafe(`ALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY;`);
      await sql.unsafe(`ALTER TABLE "${table}" FORCE ROW LEVEL SECURITY;`);
      await sql.unsafe(`DROP POLICY IF EXISTS tenant_isolation ON "${table}";`);
      await sql.unsafe(`DROP POLICY IF EXISTS tenant_select ON "${table}";`);
      await sql.unsafe(`DROP POLICY IF EXISTS tenant_insert ON "${table}";`);

      if (table === "ledger_entry") {
        // Append-only: read + insert within your org; no update/delete policy.
        await sql.unsafe(
          `CREATE POLICY tenant_select ON "ledger_entry" FOR SELECT USING (${col} = ${GUC});`,
        );
        await sql.unsafe(
          `CREATE POLICY tenant_insert ON "ledger_entry" FOR INSERT WITH CHECK (${col} = ${GUC});`,
        );
      } else if (table === "organization") {
        // Creating a new boundary is unrestricted; everything else is scoped.
        await sql.unsafe(
          `CREATE POLICY tenant_select ON "organization" FOR SELECT USING (${col} = ${GUC});`,
        );
        await sql.unsafe(`CREATE POLICY tenant_insert ON "organization" FOR INSERT WITH CHECK (true);`);
        await sql.unsafe(
          `CREATE POLICY tenant_isolation ON "organization" FOR UPDATE USING (${col} = ${GUC}) WITH CHECK (${col} = ${GUC});`,
        );
        await sql.unsafe(`DROP POLICY IF EXISTS tenant_delete ON "organization";`);
        await sql.unsafe(`CREATE POLICY tenant_delete ON "organization" FOR DELETE USING (${col} = ${GUC});`);
      } else {
        await sql.unsafe(
          `CREATE POLICY tenant_isolation ON "${table}" USING (${col} = ${GUC}) WITH CHECK (${col} = ${GUC});`,
        );
      }

      if (runtimeRole) {
        const dml =
          table === "ledger_entry" ? "SELECT, INSERT" : "SELECT, INSERT, UPDATE, DELETE";
        await sql.unsafe(`GRANT ${dml} ON "${table}" TO "${runtimeRole}";`);
      }
      // eslint-disable-next-line no-console
      console.log(`RLS applied: ${table} (FORCE, keyed on ${col})`);
    }
    // eslint-disable-next-line no-console
    console.log("All tenant tables forced + isolated.");
  } finally {
    await sql.end({ timeout: 5 });
  }
}

main().catch((e) => {
  // eslint-disable-next-line no-console
  console.error("applyRls failed:", e);
  process.exit(1);
});
