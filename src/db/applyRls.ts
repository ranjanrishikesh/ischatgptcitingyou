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
import { TENANT_TABLES } from "./schema";

const GUC = "current_setting('app.current_org', true)::uuid";

async function main() {
  const url = process.env.DATABASE_OWNER_URL ?? process.env.DATABASE_URL;
  if (!url) throw new Error("DATABASE_OWNER_URL (or DATABASE_URL) required");
  const sql = postgres(url, { max: 1 });

  const runtimeRole = process.env.RUNTIME_DB_ROLE;
  // If a separate owner role is in use, the runtime role MUST be named or it
  // receives no grants/EXECUTE and the app is broken (fails closed, but silently).
  if (
    process.env.DATABASE_OWNER_URL &&
    process.env.DATABASE_OWNER_URL !== process.env.DATABASE_URL &&
    !runtimeRole
  ) {
    throw new Error(
      "RUNTIME_DB_ROLE must be set (= the DATABASE_URL login role) when DATABASE_OWNER_URL " +
        "differs from DATABASE_URL — otherwise the runtime role gets no grants.",
    );
  }

  try {
    for (const table of TENANT_TABLES) {
      const col = table === "organization" ? "id" : "org_id";
      await sql.unsafe(`ALTER TABLE "${table}" ENABLE ROW LEVEL SECURITY;`);
      await sql.unsafe(`ALTER TABLE "${table}" FORCE ROW LEVEL SECURITY;`);
      await sql.unsafe(`DROP POLICY IF EXISTS tenant_isolation ON "${table}";`);
      await sql.unsafe(`DROP POLICY IF EXISTS tenant_select ON "${table}";`);
      await sql.unsafe(`DROP POLICY IF EXISTS tenant_insert ON "${table}";`);

      if (table === "ledger_entry" || table === "audit_log") {
        // Append-only: read + insert within your org; no update/delete policy.
        await sql.unsafe(`CREATE POLICY tenant_select ON "${table}" FOR SELECT USING (${col} = ${GUC});`);
        await sql.unsafe(
          `CREATE POLICY tenant_insert ON "${table}" FOR INSERT WITH CHECK (${col} = ${GUC});`,
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
        // Append-only tables deny the privilege outright (belt), not just via the
        // absence of an UPDATE/DELETE policy (suspenders).
        const appendOnly = table === "ledger_entry" || table === "audit_log";
        const dml = appendOnly ? "SELECT, INSERT" : "SELECT, INSERT, UPDATE, DELETE";
        await sql.unsafe(`GRANT ${dml} ON "${table}" TO "${runtimeRole}";`);
      }
      // eslint-disable-next-line no-console
      console.log(`RLS applied: ${table} (FORCE, keyed on ${col})`);
    }
    // Ingest routing lookup. The drain endpoint must resolve a source by its
    // PUBLIC opaque id BEFORE it knows the org (so it can't set the RLS GUC yet).
    // A SECURITY DEFINER function owned by the table owner does this safely: it
    // returns ONLY the single row matching the exact opaque id (the caller has
    // already proven knowledge of that id), exposing org_id/source_id/status and
    // the bearer HASH (not reversible) — never a decryptable secret.
    await sql.unsafe(`
      CREATE OR REPLACE FUNCTION ingest_resolve(p_ingest_id text)
      RETURNS TABLE (org_id uuid, source_id uuid, bearer_hash text, status text)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
        SELECT s.org_id, s.id, s.bearer_hash, s.status
        FROM source s WHERE s.ingest_id_public = p_ingest_id LIMIT 1;
      $$;
    `);
    await sql.unsafe(`REVOKE ALL ON FUNCTION ingest_resolve(text) FROM PUBLIC;`);
    if (runtimeRole) {
      await sql.unsafe(`GRANT EXECUTE ON FUNCTION ingest_resolve(text) TO "${runtimeRole}";`);
    }

    // CRITICAL: `ingest_resolve` is SECURITY DEFINER and runs as the OWNER role,
    // but FORCE ROW LEVEL SECURITY binds the owner too — so without a policy the
    // function's `SELECT ... FROM source` returns ZERO rows (no GUC -> NULL) and
    // every drain would 401. This permissive SELECT policy is scoped `TO <owner>`
    // ONLY, so the definer can read source rows; the non-owner RUNTIME role is
    // still bound by tenant_isolation (org_id = current_org) and cannot read
    // cross-tenant. The owner is the trusted migration role; granting it source
    // read is no new authority. The function still returns only the id-matched row.
    const owner = (await sql<{ u: string }[]>`select current_user as u`)[0]!.u;
    await sql.unsafe(`DROP POLICY IF EXISTS source_resolver_read ON "source";`);
    await sql.unsafe(
      `CREATE POLICY source_resolver_read ON "source" FOR SELECT TO "${owner}" USING (true);`,
    );
    // eslint-disable-next-line no-console
    console.log(`ingest_resolve() created (SECURITY DEFINER, id-scoped); resolver-read policy -> ${owner}`);

    // Membership resolver — auth must map a user to their orgs BEFORE any org GUC
    // is set (same bootstrap as source). Definer reads membership; the runtime
    // role stays scoped by tenant_isolation. The function is user-id-scoped.
    await sql.unsafe(`DROP POLICY IF EXISTS membership_resolver_read ON "membership";`);
    await sql.unsafe(
      `CREATE POLICY membership_resolver_read ON "membership" FOR SELECT TO "${owner}" USING (true);`,
    );
    await sql.unsafe(`
      CREATE OR REPLACE FUNCTION user_memberships(p_user_id text)
      RETURNS TABLE (org_id uuid, role text)
      LANGUAGE sql STABLE SECURITY DEFINER SET search_path = public AS $$
        SELECT m.org_id, m.role::text FROM membership m
        WHERE m.user_id = p_user_id
        ORDER BY m.created_at ASC, m.org_id ASC;
      $$;
    `);
    await sql.unsafe(`REVOKE ALL ON FUNCTION user_memberships(text) FROM PUBLIC;`);
    if (runtimeRole) {
      await sql.unsafe(`GRANT EXECUTE ON FUNCTION user_memberships(text) TO "${runtimeRole}";`);
      // Non-tenant tables (auth + Stripe idempotency + org-deletion forensics).
      // org_deletion_log deliberately has NO FK to organization, so it survives a
      // crypto-shred; grant insert/select only (forensic record is append-only).
      for (const t of ["user", "session", "account", "verification", "processed_stripe_event"]) {
        await sql.unsafe(`GRANT SELECT, INSERT, UPDATE, DELETE ON "${t}" TO "${runtimeRole}";`);
      }
      await sql.unsafe(`GRANT SELECT, INSERT ON "org_deletion_log" TO "${runtimeRole}";`);
    }
    // eslint-disable-next-line no-console
    console.log("user_memberships() created; auth-table grants applied");

    // Route triple-equality DB backstop: a route's org MUST match both its source
    // and destination org. Runs as invoker, so under RLS a cross-org source/dest
    // is invisible (NULL) and rejected. Belt to the app-layer existence checks.
    await sql.unsafe(`
      CREATE OR REPLACE FUNCTION route_triple_equality() RETURNS trigger
      LANGUAGE plpgsql AS $$
      DECLARE s_org uuid; d_org uuid;
      BEGIN
        SELECT org_id INTO s_org FROM source WHERE id = NEW.source_id;
        SELECT org_id INTO d_org FROM destination WHERE id = NEW.destination_id;
        IF s_org IS NULL OR d_org IS NULL OR NEW.org_id <> s_org OR NEW.org_id <> d_org THEN
          RAISE EXCEPTION 'route org mismatch: source/destination must belong to the route org';
        END IF;
        RETURN NEW;
      END;
      $$;
    `);
    await sql.unsafe(`DROP TRIGGER IF EXISTS route_triple_equality_trg ON "route";`);
    await sql.unsafe(
      `CREATE TRIGGER route_triple_equality_trg BEFORE INSERT OR UPDATE ON "route" FOR EACH ROW EXECUTE FUNCTION route_triple_equality();`,
    );
    // eslint-disable-next-line no-console
    console.log("route_triple_equality trigger created");

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
