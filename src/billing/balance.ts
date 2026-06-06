/**
 * Hot balance meter (Redis / Upstash). The drain request path must NOT touch
 * Postgres or Stripe per event — that would be ruinously expensive. Instead:
 *
 *   - the working balance lives in Redis as integer micro-dollars
 *   - each batch does ONE atomic debit of (events * 100 µ$)
 *   - a cron periodically reconciles Redis -> Postgres ledger and triggers
 *     auto-recharge off the hot path
 *
 * Redis is a cache, not the source of truth; Postgres (ledger.ts) is. Small
 * overshoot before reconciliation is acceptable for billing and corrected later.
 *
 * `singleFlightRecharge` ensures one below-threshold dip fires exactly one
 * recharge even under concurrent batches — a correctness guard, NOT a cap
 * (the founder chose no recharge cap).
 */
import { randomUUID } from "node:crypto";
import { Redis } from "@upstash/redis";
import { eventCostMicrosNumber } from "./money";

let _redis: Redis | null = null;

function redis(): Redis {
  if (!_redis) {
    const url = process.env.UPSTASH_REDIS_REST_URL;
    const token = process.env.UPSTASH_REDIS_REST_TOKEN;
    if (!url || !token) throw new Error("Upstash Redis env not configured");
    _redis = new Redis({ url, token });
  }
  return _redis;
}

const balKey = (orgId: string) => `bal:{${orgId}}`; // hash-tag => same slot for per-tenant ops
const lockKey = (orgId: string) => `lock:recharge:{${orgId}}`;

// Debit ONLY if the key already exists. If it is absent (never seeded, evicted,
// lost on failover) we must NOT let DECRBY create it at a negative value — that
// would also wedge the NX seed forever. Return a sentinel so the caller reseeds
// from Postgres and retries.
const DEBIT_LUA = `
if redis.call('EXISTS', KEYS[1]) == 0 then return 'NOSEED' end
return redis.call('DECRBY', KEYS[1], ARGV[1])
`;

// Release a lock only if we still own it (fenced token), so a worker whose lock
// already expired cannot delete a lock a different worker now holds.
const RELEASE_LUA = `
if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end
`;

/** Seed the hot balance from the authoritative value if not already present. */
export async function seedHotBalance(orgId: string, authoritativeMicros: bigint): Promise<void> {
  // NX: only set if missing, so we never clobber in-flight decrements.
  await redis().set(balKey(orgId), Number(authoritativeMicros), { nx: true });
}

/** Force-set the hot balance (used by the reconciliation cron after a flush). */
export async function setHotBalance(orgId: string, micros: bigint): Promise<void> {
  await redis().set(balKey(orgId), Number(micros));
}

export interface DebitResult {
  /** Balance AFTER the debit, in micro-dollars. May be negative (overshoot). */
  balanceMicros: number;
  /** True if there were still funds before this debit. */
  hadFunds: boolean;
  /** True if the hot key was absent — caller must seed from Postgres and retry. */
  needsSeed: boolean;
}

/**
 * Debit the cost of N forwarded events from the hot balance. One Redis op.
 * Validates `events` (integer, non-negative, no overflow) before touching Redis.
 * Returns the new balance; caller decides whether to keep forwarding.
 */
export async function debitEvents(orgId: string, events: number): Promise<DebitResult> {
  if (events <= 0) {
    const cur = await redis().get<number>(balKey(orgId));
    if (cur === null || cur === undefined) {
      return { balanceMicros: 0, hadFunds: false, needsSeed: true };
    }
    return { balanceMicros: Number(cur), hadFunds: Number(cur) > 0, needsSeed: false };
  }
  const cost = eventCostMicrosNumber(events); // throws on non-integer / negative / overflow
  const res = await redis().eval(DEBIT_LUA, [balKey(orgId)], [cost]);
  if (res === "NOSEED") {
    return { balanceMicros: 0, hadFunds: false, needsSeed: true };
  }
  const after = Number(res);
  return { balanceMicros: after, hadFunds: after + cost > 0, needsSeed: false };
}

export async function getHotBalance(orgId: string): Promise<number> {
  return Number((await redis().get<number>(balKey(orgId))) ?? 0);
}

/**
 * Replay/idempotency gate for a drain batch. Vercel log drains are at-least-once
 * (retried on non-2xx / timeout, can redeliver), so the SAME batch can arrive
 * twice and must be debited only ONCE. Returns true if this token is NEW (debit
 * it), false if already seen (a replay — skip the debit). TTL covers the
 * redelivery window. Token should be a content hash of the raw batch body.
 */
export async function markBatchSeen(
  orgId: string,
  token: string,
  ttlSeconds: number,
): Promise<boolean> {
  const ok = await redis().set(`seen:{${orgId}}:${token}`, "1", { nx: true, ex: ttlSeconds });
  return ok === "OK";
}

/**
 * Record events that could NOT be metered (Redis down, seed/retry exhausted), so
 * silent free usage is visible/alertable instead of vanishing into a log line.
 * Best-effort: never throws.
 */
export async function incrUnmetered(orgId: string, events: number): Promise<void> {
  try {
    await redis().incrby(`unmetered:{${orgId}}`, events);
  } catch {
    /* best-effort visibility only */
  }
}

/**
 * Run `fn` only if no recharge for this org is already in flight. Lock auto-
 * expires after ttlMs so a crashed worker can't wedge recharges forever, and is
 * released only by the worker that owns it (fenced token). Returns true if we
 * held the lock and ran fn, false if skipped.
 *
 * NOTE: ttlMs MUST exceed worst-case Stripe latency, or an expired lock lets a
 * second worker recharge concurrently (double charge). Size it generously.
 */
export async function singleFlightRecharge(
  orgId: string,
  ttlMs: number,
  fn: () => Promise<void>,
): Promise<boolean> {
  const token = randomUUID();
  const ok = await redis().set(lockKey(orgId), token, { nx: true, px: ttlMs });
  if (ok !== "OK") return false;
  try {
    await fn();
    return true;
  } finally {
    // Compare-and-delete: only release our own lock. Swallow release errors so
    // they cannot mask an error thrown by fn().
    try {
      await redis().eval(RELEASE_LUA, [lockKey(orgId)], [token]);
    } catch {
      /* ignore release failure */
    }
  }
}
