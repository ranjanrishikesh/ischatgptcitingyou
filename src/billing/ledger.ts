/**
 * The money ledger. Append-only: every credit (+) and usage debit (-) is a row.
 * The `balance` table is a materialized cache (= sum of the ledger) updated in
 * the SAME transaction as each append, so it can never drift from the ledger.
 *
 * Idempotency: an append may carry an `idempotencyKey`. A retry with the same
 * key is a no-op (ON CONFLICT DO NOTHING) — so a Stripe webhook redelivery or a
 * retried auto-recharge never double-credits. This is the Postgres source of
 * truth; the Redis hot balance (balance.ts) is a fast working copy reconciled
 * against it.
 */
import { sql } from "drizzle-orm";
import { withOrg } from "../db/client";
import { ledgerEntry, balance } from "../db/schema";
import { FREE_GRANT_MICROS } from "./money";

export type LedgerKind =
  | "free_grant"
  | "purchase"
  | "recharge"
  | "usage"
  | "refund"
  | "adjustment";

export interface AppendInput {
  kind: LedgerKind;
  /** Signed micro-dollars: + for credit, - for usage. */
  amountMicros: bigint;
  idempotencyKey?: string;
  stripePaymentIntentId?: string;
  meta?: Record<string, unknown>;
}

export interface AppendResult {
  applied: boolean; // false if the idempotency key already existed
  balanceMicros: bigint;
}

/** Append a ledger entry and reconcile the materialized balance, atomically. */
type LedgerDb = Parameters<Parameters<typeof withOrg>[1]>[0];

/**
 * Append + reconcile balance WITHIN an existing org transaction. Lets callers
 * (e.g. provisioning) commit the ledger entry atomically with other writes.
 */
export async function appendLedgerTx(
  db: LedgerDb,
  orgId: string,
  input: AppendInput,
): Promise<AppendResult> {
  // CREDITS must be idempotent. Usage debits intentionally carry no key (every
  // batch applies); any credit (purchase/recharge/refund/grant/adjustment)
  // without a key would get NO double-credit protection (NULLs are distinct in
  // the unique index), so a retried Stripe webhook could double-credit. Fail loud.
  if (input.kind !== "usage" && !input.idempotencyKey) {
    throw new Error(`appendLedger: credit kind '${input.kind}' requires an idempotencyKey`);
  }
  const inserted = await db
    .insert(ledgerEntry)
    .values({
      orgId,
      kind: input.kind,
      amountMicros: input.amountMicros,
      idempotencyKey: input.idempotencyKey ?? null,
      stripePaymentIntentId: input.stripePaymentIntentId ?? null,
      meta: input.meta ?? {},
    })
    .onConflictDoNothing({ target: [ledgerEntry.orgId, ledgerEntry.idempotencyKey] })
    .returning({ id: ledgerEntry.id });

  if (inserted.length === 0) {
    const cur = await currentBalance(db, orgId); // idempotent no-op
    return { applied: false, balanceMicros: cur };
  }

  const updated = await db
    .insert(balance)
    .values({ orgId, balanceMicros: input.amountMicros })
    .onConflictDoUpdate({
      target: balance.orgId,
      set: {
        balanceMicros: sql`${balance.balanceMicros} + ${input.amountMicros}`,
        updatedAt: sql`now()`,
      },
    })
    .returning({ b: balance.balanceMicros });

  return { applied: true, balanceMicros: updated[0]!.b };
}

export async function appendLedger(orgId: string, input: AppendInput): Promise<AppendResult> {
  return withOrg(orgId, (db) => appendLedgerTx(db, orgId, input));
}

async function currentBalance(
  db: Parameters<Parameters<typeof withOrg>[1]>[0],
  orgId: string,
): Promise<bigint> {
  const rows = await db
    .select({ b: balance.balanceMicros })
    .from(balance)
    .where(sql`${balance.orgId} = ${orgId}`);
  return rows[0]?.b ?? 0n;
}

/** Read the authoritative (Postgres) balance for an org. */
export async function getBalanceMicros(orgId: string): Promise<bigint> {
  return withOrg(orgId, (db) => currentBalance(db, orgId));
}

/** Grant the one-time free signup credit ($1). Idempotent per org. */
export async function grantFreeCredit(orgId: string): Promise<AppendResult> {
  return appendLedger(orgId, {
    kind: "free_grant",
    amountMicros: FREE_GRANT_MICROS,
    idempotencyKey: `free_grant:${orgId}`,
    meta: { reason: "signup" },
  });
}
