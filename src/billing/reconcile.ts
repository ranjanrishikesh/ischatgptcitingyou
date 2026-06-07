/**
 * Reconciliation. Runs on a cron, off the request path. For each org with
 * unflushed usage: write ONE usage ledger debit for the consumed amount, re-seed
 * the Redis working balance from the authoritative Postgres balance, and trigger
 * auto-recharge if low. The hot drain path never touches Postgres or Stripe.
 */
import { appendLedger, getBalanceMicros } from "./ledger";
import { beginFlush, endFlush, setHotBalance, reconOrgs, reconClearIfDrained } from "./balance";
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

export async function reconcileAll(): Promise<{ orgs: number; errors: number }> {
  const orgs = await reconOrgs();
  let errors = 0;
  for (const orgId of orgs) {
    try {
      await reconcileOrg(orgId);
      await reconClearIfDrained(orgId); // keep queued if a debit raced the flush
    } catch (e) {
      errors++;
      console.error("reconcile failed", { orgId, err: (e as Error).message });
    }
  }
  return { orgs: orgs.length, errors };
}
