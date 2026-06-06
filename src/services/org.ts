/**
 * Org lifecycle. Deletion is CRYPTO-SHREDDING: removing the organization row
 * destroys the wrapped per-tenant DEK and cascades to all tenant data. With the
 * DEK gone, every encrypted secret — including copies in database backups/WAL —
 * is permanently undecryptable. This is the only erasure that reaches immutable
 * backups, so it is the authoritative "forget this tenant" operation.
 *
 * Because the cascade also wipes the org's audit_log, the deletion is recorded
 * FIRST in `org_deletion_log` — a non-tenant, non-cascading table that survives
 * the shred — so the most destructive op is never untraceable. An advisory lock
 * serializes the delete against in-flight ledger appends / auto-recharge (which
 * take the same per-org lock), and the org's hot-meter Redis keys are purged so
 * the reconcile cron stops touching the gone org.
 */
import { sql, eq } from "drizzle-orm";
import { withOrg, withSystem } from "../db/client";
import { organization, orgDeletionLog } from "../db/schema";
import { purgeOrgKeys } from "../billing/balance";
import { invalidateDestinationCaches } from "../destinations/dispatch";
import { invalidateSourceCache } from "../ingest/resolveSource";

export async function deleteOrg(orgId: string, actorId?: string): Promise<void> {
  // 1. Forensic record OUTSIDE the tenant boundary (survives the cascade).
  await withSystem((db) => db.insert(orgDeletionLog).values({ orgId, actorId: actorId ?? null }));

  // 2. Serialize against in-flight ledger/recharge, then crypto-shred.
  await withOrg(orgId, async (db) => {
    await db.execute(sql`select pg_advisory_xact_lock(hashtext(${orgId}))`);
    await db.delete(organization).where(eq(organization.id, orgId));
  });

  // 3. Stop the cron/recharge from touching the gone org + drop cached creds.
  await purgeOrgKeys(orgId);
  invalidateDestinationCaches(orgId);
  invalidateSourceCache(); // ingest ids unknown here; clear all (deletion is rare)
}
