/**
 * Reconciliation. Runs on a cron, off the request path. For each org with
 * unflushed usage: write ONE usage ledger debit for the consumed amount, re-seed
 * the Redis working balance from the authoritative Postgres balance, and trigger
 * auto-recharge if low. The hot drain path never touches Postgres or Stripe.
 */
import { appendLedger, getBalanceMicros } from "./ledger";
import {
  beginFlush,
  endFlush,
  setHotBalance,
  reconOrgs,
  reconClearIfDrained,
  markReconcileRun,
} from "./balance";
import { maybeAutoRecharge } from "./recharge";

export async function reconcileOrg(orgId: string): Promise<void> {
  // Capture consumed usage into a durable pending slot with a stable flush id.
  const { flushId, micros } = await beginFlush(orgId);
  if (micros > 0) {
    // Idempotent usage debit: a concurrent or post-crash retry uses the SAME
    // flushId, so the ledger's (org, key) unique index dedupes it -> no
    // double-debit. endFlush only clears the pending slot AFTER the commit.
    await appendLedger(orgId, {
      kind: "usage",
      amountMicros: BigInt(-micros),
      idempotencyKey: `usage:${orgId}:${flushId}`,
    });
    await endFlush(orgId);
  }
  const bal = await getBalanceMicros(orgId);
  await setHotBalance(orgId, bal); // reseed working balance from source of truth
  await maybeAutoRecharge(orgId, bal);
}

/**
 * Reconcile every queued org within a wall-clock budget. The serverless runtime
 * hard-kills us at maxDuration — stopping ourselves first means no org is ever
 * cut off mid-charge (which would wedge its recharge-pending marker for the
 * TTL). Unprocessed orgs simply stay in RECON_SET for the next tick; the order
 * is shuffled so a repeatedly-binding budget can't starve the same tail.
 */
export async function reconcileAll(budgetMs = 50_000): Promise<{
  orgs: number;
  errors: number;
  skipped: number;
}> {
  const deadline = Date.now() + budgetMs;
  const orgs = await reconOrgs();
  for (let i = orgs.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    [orgs[i], orgs[j]] = [orgs[j]!, orgs[i]!];
  }
  let errors = 0;
  let processed = 0;
  for (const orgId of orgs) {
    if (Date.now() >= deadline) break;
    processed++;
    try {
      await reconcileOrg(orgId);
      await reconClearIfDrained(orgId); // keep queued if a debit raced the flush
    } catch (e) {
      errors++;
      console.error("reconcile failed", { orgId, err: (e as Error).message });
    }
  }
  const skipped = orgs.length - processed;
  if (skipped > 0) console.warn("reconcile budget exhausted", { processed, skipped });
  await markReconcileRun();
  return { orgs: processed, errors, skipped };
}
