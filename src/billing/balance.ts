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
const usedKey = (orgId: string) => `used:{${orgId}}`; // monotonic consumed µ$ since last flush
const pendingKey = (orgId: string) => `flush:{${orgId}}`; // in-progress flush (crash-safe)
const seqKey = (orgId: string) => `flushseq:{${orgId}}`; // monotonic flush id
const lockKey = (orgId: string) => `lock:recharge:{${orgId}}`;
const rechargePendingKey = (orgId: string) => `recharge:pending:{${orgId}}`;

// Money must never silently lose precision crossing the bigint->Number boundary.
function toSafeNumber(micros: bigint): number {
  const lim = BigInt(Number.MAX_SAFE_INTEGER);
  if (micros > lim || micros < -lim) throw new RangeError("balance exceeds safe integer range");
  return Number(micros);
}

// Debit ONLY if the balance key exists (else 'NOSEED'). Atomically: bump the
// monotonic `used` counter (KEYS[2]), enqueue the org for reconciliation
// (KEYS[3]=RECON_SET), and decrement the working balance (KEYS[1]). Folding SADD
// in keeps used-increment and reconcile-membership atomic — no stranded usage.
//
// FLOOR: once the balance is already <= 0 the caller will NOT forward, so we
// must not meter either ('NOFUNDS', no debit) — a customer is never billed for
// events that were dropped. The org is still SADD'd so the reconcile cron keeps
// seeing it and auto-recharge fires. Overshoot is therefore bounded to the one
// batch that crosses zero (acceptable by design), not a whole out-of-funds
// window — which matters now that reconcile cadence can degrade to daily.
const DEBIT_LUA = `
if redis.call('EXISTS', KEYS[1]) == 0 then return 'NOSEED' end
if tonumber(redis.call('GET', KEYS[1])) <= 0 then
  redis.call('SADD', KEYS[3], ARGV[2])
  return 'NOFUNDS'
end
redis.call('INCRBY', KEYS[2], ARGV[1])
redis.call('SADD', KEYS[3], ARGV[2])
return redis.call('DECRBY', KEYS[1], ARGV[1])
`;

// Capture the consumed amount into a durable pending slot with a stable flush id,
// atomically, so the reconcile ledger write is idempotent across crashes AND
// concurrent runs: a re-entry while a flush is pending returns the SAME id+amount
// (so the ledger key dedupes), and `used` is decremented by exactly the captured
// amount (preserving usage accrued concurrently).
const BEGIN_FLUSH_LUA = `
local p = redis.call('GET', KEYS[2])
if p then return p end
local u = tonumber(redis.call('GET', KEYS[1]) or '0')
if u <= 0 then return '0:0' end
local id = redis.call('INCR', KEYS[3])
redis.call('DECRBY', KEYS[1], u)
local v = id .. ':' .. u
redis.call('SET', KEYS[2], v)
return v
`;

// Remove the org from RECON_SET ONLY if it is fully drained (no used, no pending),
// so a debit racing the reconcile keeps the org queued.
const RECON_CLEAR_LUA = `
if tonumber(redis.call('GET', KEYS[1]) or '0') <= 0 and redis.call('EXISTS', KEYS[2]) == 0 then
  redis.call('SREM', KEYS[3], ARGV[1])
  return 1
end
return 0
`;

// Release a lock only if we still own it (fenced token), so a worker whose lock
// already expired cannot delete a lock a different worker now holds.
const RELEASE_LUA = `
if redis.call('get', KEYS[1]) == ARGV[1] then return redis.call('del', KEYS[1]) else return 0 end
`;

/** Seed the hot balance from the authoritative value if not already present. */
export async function seedHotBalance(orgId: string, authoritativeMicros: bigint): Promise<void> {
  // NX: only set if missing, so we never clobber in-flight decrements.
  await redis().set(balKey(orgId), toSafeNumber(authoritativeMicros), { nx: true });
}

/** Force-set the hot balance (used by the reconciliation cron after a flush). */
export async function setHotBalance(orgId: string, micros: bigint): Promise<void> {
  await redis().set(balKey(orgId), toSafeNumber(micros));
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
  const res = await redis().eval(DEBIT_LUA, [balKey(orgId), usedKey(orgId), RECON_SET], [cost, orgId]);
  if (res === "NOSEED") {
    return { balanceMicros: 0, hadFunds: false, needsSeed: true };
  }
  if (res === "NOFUNDS") {
    // Out of credits: nothing was metered (events won't be forwarded either).
    return { balanceMicros: 0, hadFunds: false, needsSeed: false };
  }
  const after = Number(res);
  return { balanceMicros: after, hadFunds: after + cost > 0, needsSeed: false };
}

/** Set of orgs with unflushed usage / possible recharge need (reconcile cron). */
export const RECON_SET = "recon:orgs";
export async function reconOrgs(): Promise<string[]> {
  return (await redis().smembers(RECON_SET)) as string[];
}

/**
 * Reconcile freshness marker. The cron cadence can silently degrade (external
 * trigger misconfigured/disabled -> daily Vercel backstop only), and auto-
 * recharge fires ONLY from the cron — so staleness must be observable.
 * /api/health asserts this is recent; point an uptime monitor at it.
 */
const RECON_LAST_RUN_KEY = "recon:last_run_ms";
export async function markReconcileRun(): Promise<void> {
  try {
    await redis().set(RECON_LAST_RUN_KEY, Date.now());
  } catch {
    /* visibility only — never fail the reconcile over it */
  }
}
export async function reconcileAgeMs(): Promise<number | null> {
  const t = await redis().get<number>(RECON_LAST_RUN_KEY);
  return t === null || t === undefined ? null : Date.now() - Number(t);
}

export interface FlushCapture {
  flushId: string;
  micros: number;
}

/**
 * Atomically capture the consumed amount for flushing. Returns a stable flushId
 * (so the ledger write is idempotent across retries/crashes) and the captured
 * micros. `endFlush` clears the pending slot AFTER the ledger commit.
 */
export async function beginFlush(orgId: string): Promise<FlushCapture> {
  const v = String(
    await redis().eval(BEGIN_FLUSH_LUA, [usedKey(orgId), pendingKey(orgId), seqKey(orgId)], []),
  );
  const [id, micros] = v.split(":");
  return { flushId: id ?? "0", micros: Number(micros ?? 0) };
}

export async function endFlush(orgId: string): Promise<void> {
  await redis().del(pendingKey(orgId));
}

/** Remove the org from RECON_SET only if fully drained (no used, no pending). */
export async function reconClearIfDrained(orgId: string): Promise<void> {
  await redis().eval(RECON_CLEAR_LUA, [usedKey(orgId), pendingKey(orgId), RECON_SET], [orgId]);
}

export async function getHotBalance(orgId: string): Promise<number> {
  return Number((await redis().get<number>(balKey(orgId))) ?? 0);
}

/** Read the consumed counter (µ$) without resetting. */
export async function getUsed(orgId: string): Promise<number> {
  return Number((await redis().get<number>(usedKey(orgId))) ?? 0);
}

/**
 * Subtract an already-flushed amount from the consumed counter. The reconcile
 * cron does get -> write-ledger -> subtract (NOT getdel), so a ledger-write
 * failure leaves the counter intact for retry, and usage accrued concurrently
 * during the flush is preserved.
 */
export async function subUsed(orgId: string, micros: number): Promise<void> {
  if (micros > 0) await redis().decrby(usedKey(orgId), micros);
}

/**
 * Recharge-pending marker. Set when an off-session charge is initiated and
 * cleared by the webhook when the credit lands. While set, no new auto-recharge
 * starts — closing the window where the credit hasn't yet hit the ledger and the
 * next reconcile tick would otherwise charge again. A TTL bounds a lost webhook.
 */
export async function setRechargePending(orgId: string, ttlSeconds: number): Promise<boolean> {
  const ok = await redis().set(rechargePendingKey(orgId), "1", { nx: true, ex: ttlSeconds });
  return ok === "OK";
}
export async function clearRechargePending(orgId: string): Promise<void> {
  await redis().del(rechargePendingKey(orgId));
}

/** Purge all hot-meter/billing Redis keys for a deleted org (best-effort). */
export async function purgeOrgKeys(orgId: string): Promise<void> {
  try {
    await redis().del(
      balKey(orgId),
      usedKey(orgId),
      pendingKey(orgId),
      seqKey(orgId),
      rechargePendingKey(orgId),
    );
    await redis().srem(RECON_SET, orgId);
  } catch {
    /* best-effort */
  }
}

/** Count auto-recharges this hour for an org (spike detection). */
export async function bumpRechargeCount(orgId: string): Promise<number> {
  const hour = Math.floor(Date.now() / 3_600_000);
  const key = `recharge:count:{${orgId}}:${hour}`;
  const n = await redis().incr(key);
  if (n === 1) await redis().expire(key, 7200);
  return n;
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
 * Release a batch claim so a redelivery can be metered again. Called when
 * metering fails AFTER the claim was taken, so a transient error doesn't make a
 * batch permanently free-but-forwarded for the whole replay window.
 */
export async function deleteBatchSeen(orgId: string, token: string): Promise<void> {
  try {
    await redis().del(`seen:{${orgId}}:${token}`);
  } catch {
    /* best-effort */
  }
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
