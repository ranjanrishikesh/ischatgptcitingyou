/**
 * Resolve a source by its public ingest id, via the SECURITY DEFINER
 * `ingest_resolve` function (see applyRls.ts). Returns the routing row needed to
 * authenticate and attribute a drain batch — org id, source id, bearer HASH,
 * and status. Never returns a decryptable secret.
 *
 * Results are cached in-process for a short TTL so a flood against one (valid)
 * id collapses to a single DB read while the instance is warm.
 */
import { sql } from "drizzle-orm";
import { withSystem } from "../db/client";

export interface ResolvedSource {
  orgId: string;
  sourceId: string;
  bearerHash: string;
  status: string;
}

// SECURITY TTL, not just a perf knob: this caches the auth-bearing `bearerHash`
// and `status`, so it bounds how long a rotated/revoked credential keeps working.
// Kept short. Positive hits cache a bit longer than negatives (a freshly
// provisioned source should become usable fast). When rotation/revocation ships
// (M4), it MUST call invalidateSourceCache AND publish a cross-process signal
// (Redis pub/sub or a versioned key) — a per-process delete alone is not enough
// for a multi-instance hosted deploy. TODO(M4): cross-process invalidation.
const POS_TTL_MS = 5_000;
const NEG_TTL_MS = 2_000;
const cache = new Map<string, { value: ResolvedSource | null; expires: number }>();

export async function resolveSource(ingestIdPublic: string): Promise<ResolvedSource | null> {
  const now = Date.now();
  const hit = cache.get(ingestIdPublic);
  if (hit && hit.expires > now) return hit.value;

  const rows = await withSystem((db) =>
    db.execute(
      sql`select org_id, source_id, bearer_hash, status from ingest_resolve(${ingestIdPublic})`,
    ),
  );
  const r = (rows as unknown as Array<Record<string, unknown>>)[0];
  const value: ResolvedSource | null = r
    ? {
        orgId: String(r.org_id),
        sourceId: String(r.source_id),
        bearerHash: String(r.bearer_hash),
        status: String(r.status),
      }
    : null;

  cache.set(ingestIdPublic, { value, expires: now + (value ? POS_TTL_MS : NEG_TTL_MS) });
  return value;
}

/** Test/admin seam: drop a cache entry (e.g. after rotating a bearer). */
export function invalidateSourceCache(ingestIdPublic?: string): void {
  if (ingestIdPublic) cache.delete(ingestIdPublic);
  else cache.clear();
}
