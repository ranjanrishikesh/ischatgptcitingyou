/**
 * Hash-chained, append-only audit log. Each entry chains to the previous via
 * hash = sha256(prevHash || canonical(entry)). Editing or deleting a MIDDLE row,
 * or a seq gap, is detected by verifyAuditChain. Truncating the TIP (deleting the
 * latest rows) leaves a self-consistent prefix, so it is only detectable against
 * an out-of-band high-water mark (pass expectedTip to verifyAuditChain). Per-org
 * appends are serialized with a transaction advisory lock so writers can't fork.
 *
 * NEVER pass secrets in `meta` — it is redacted before hashing/storage, but the
 * discipline is identifiers + action types only.
 */
import { createHash } from "node:crypto";
import { sql, eq, desc, asc } from "drizzle-orm";
import { withOrg } from "../db/client";
import { auditLog } from "../db/schema";
import { redactForLog } from "../crypto/secret";

export interface AuditInput {
  actorId?: string;
  action: string;
  targetType?: string;
  targetId?: string;
  meta?: Record<string, unknown>;
}

/**
 * Deterministic serializer: object keys are sorted recursively. This makes the
 * hash independent of key order — critical because `meta` round-trips through a
 * Postgres jsonb column, which re-emits keys in its own (length, bytewise) order,
 * NOT insertion order. Without this, verify would false-alarm on untampered data.
 */
export function stableStringify(v: unknown): string {
  if (v === null || typeof v !== "object") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(stableStringify).join(",") + "]";
  const obj = v as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return "{" + keys.map((k) => JSON.stringify(k) + ":" + stableStringify(obj[k])).join(",") + "}";
}

function canonical(
  orgId: string,
  seq: bigint,
  i: { actorId: string | null; action: string; targetType: string | null; targetId: string | null; meta: unknown },
): string {
  return stableStringify({
    orgId,
    seq: seq.toString(),
    actorId: i.actorId,
    action: i.action,
    targetType: i.targetType,
    targetId: i.targetId,
    meta: i.meta,
  });
}

/** Append an audit entry. Best-effort callers should catch — but the chain is
 *  consistent whenever it does write. */
export async function appendAudit(orgId: string, input: AuditInput): Promise<void> {
  const meta = redactForLog(input.meta ?? {});
  await withOrg(orgId, async (db) => {
    // Serialize per-org appends so prevHash can't fork.
    await db.execute(sql`select pg_advisory_xact_lock(hashtext(${orgId}))`);
    const last = await db
      .select({ seq: auditLog.seq, hash: auditLog.hash })
      .from(auditLog)
      .where(eq(auditLog.orgId, orgId))
      .orderBy(desc(auditLog.seq))
      .limit(1);
    const prevHash = last[0]?.hash ?? null;
    const seq = (last[0]?.seq ?? 0n) + 1n;
    const row = {
      actorId: input.actorId ?? null,
      action: input.action,
      targetType: input.targetType ?? null,
      targetId: input.targetId ?? null,
      meta,
    };
    const hash = createHash("sha256")
      .update((prevHash ?? "") + canonical(orgId, seq, row))
      .digest("hex");
    await db.insert(auditLog).values({ orgId, seq, prevHash, hash, ...row });
  });
}

/** Append an audit entry, swallowing errors (audit must not break the op). */
export async function auditSafe(orgId: string, input: AuditInput): Promise<void> {
  try {
    await appendAudit(orgId, input);
  } catch (e) {
    console.error("audit append failed", { orgId, action: input.action, err: (e as Error).message });
  }
}

export interface ChainResult {
  ok: boolean;
  entries: number;
  reason?: string;
  brokenAtSeq?: string;
  /** The current tip (seq, hash) — persist out-of-band to detect tip truncation. */
  tip?: { seq: string; hash: string };
}

/**
 * Recompute and verify the whole chain for an org. Detects middle-row tampering
 * (hash/prevHash mismatch) AND gaps (non-contiguous seq). Tip truncation (the
 * latest rows deleted) leaves a self-consistent prefix, so it can only be caught
 * with an out-of-band high-water mark — pass `expectedTip` (the last-known seq+
 * hash) to assert the chain hasn't been shortened.
 */
export async function verifyAuditChain(
  orgId: string,
  expectedTip?: { seq: string; hash: string },
): Promise<ChainResult> {
  return withOrg(orgId, async (db) => {
    const rows = await db
      .select()
      .from(auditLog)
      .where(eq(auditLog.orgId, orgId))
      .orderBy(asc(auditLog.seq));

    let prev: string | null = null;
    let expectedSeq = 1n;
    for (const r of rows) {
      if (r.seq !== expectedSeq) {
        return { ok: false, entries: rows.length, reason: "gap", brokenAtSeq: r.seq.toString() };
      }
      expectedSeq += 1n;
      const expected: string = createHash("sha256")
        .update(
          (prev ?? "") +
            canonical(orgId, r.seq, {
              actorId: r.actorId,
              action: r.action,
              targetType: r.targetType,
              targetId: r.targetId,
              meta: r.meta,
            }),
        )
        .digest("hex");
      if (r.prevHash !== prev || r.hash !== expected) {
        return { ok: false, entries: rows.length, reason: "hash", brokenAtSeq: r.seq.toString() };
      }
      prev = r.hash;
    }

    const tip = rows.length ? { seq: rows[rows.length - 1]!.seq.toString(), hash: prev! } : undefined;
    if (expectedTip) {
      if (!tip || tip.seq !== expectedTip.seq || tip.hash !== expectedTip.hash) {
        return { ok: false, entries: rows.length, reason: "tip-truncated", tip };
      }
    }
    return { ok: true, entries: rows.length, tip };
  });
}
