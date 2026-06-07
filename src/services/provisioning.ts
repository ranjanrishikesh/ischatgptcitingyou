/**
 * Org provisioning. Runs once per new user (Better Auth create hook): mints a
 * per-tenant DEK, creates the organization + owner membership + default project,
 * and grants the $1 free credit — all in ONE transaction so an org can never
 * exist without its grant.
 *
 * IDEMPOTENT on userId: Better Auth's after-hook can re-fire for an already
 * committed user (transient error + request retry). We short-circuit if the user
 * already has an org, so a retry never mints a second tenant or a second grant.
 */
import { randomUUID } from "node:crypto";
import { sql } from "drizzle-orm";
import { withOrg, withSystem } from "../db/client";
import { organization, membership, project } from "../db/schema";
import { provisionTenantDek } from "../crypto/tenantSecrets";
import { getKekProvider } from "../crypto/kek";
import { appendLedgerTx } from "../billing/ledger";
import { FREE_GRANT_MICROS } from "../billing/money";

async function existingOrgForUser(userId: string): Promise<string | null> {
  const rows = await withSystem((db) =>
    db.execute(sql`select org_id from user_memberships(${userId}) limit 1`),
  );
  const r = (rows as unknown as Array<Record<string, unknown>>)[0];
  return r ? String(r.org_id) : null;
}

export async function provisionOrg(userId: string, name: string): Promise<string> {
  // Idempotent: a user who already has an org keeps it (no second tenant/grant).
  const existing = await existingOrgForUser(userId);
  if (existing) return existing;

  const orgId = randomUUID();
  const wrapped = await provisionTenantDek(getKekProvider(), orgId);

  await withOrg(orgId, async (db) => {
    await db.insert(organization).values({
      id: orgId,
      name,
      wrappedDek: wrapped.ciphertext,
      kekKeyId: wrapped.keyId,
    });
    await db.insert(membership).values({ orgId, userId, role: "owner" });
    await db.insert(project).values({ orgId, name: "Default" });
    // $1 (= 10,000 events) signup grant, atomic with the org. Keyed on userId so
    // even a racing duplicate can't double-grant.
    await appendLedgerTx(db, orgId, {
      kind: "free_grant",
      amountMicros: FREE_GRANT_MICROS,
      idempotencyKey: `free_grant:user:${userId}`,
      meta: { reason: "signup" },
    });
  });

  return orgId;
}
