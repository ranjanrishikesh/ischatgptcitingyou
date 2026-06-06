/**
 * Destination dispatch. Given a SOURCE's classified AI events, resolve the
 * destinations wired to THAT source (route edges), decrypt each credential
 * just-in-time, and forward via the SSRF-safe egress. Forwarding runs in BOTH
 * modes (it is the core product); only metering is hosted-only.
 *
 * Failures go to a best-effort dead-letter list (Redis) carrying the event
 * count + a credential REFERENCE (destination id) — never the secret — and are
 * also logged so a 100%-failing destination is observable without inspecting Redis.
 */
import { createHash } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { Redis } from "@upstash/redis";
import { withOrg } from "../db/client";
import { route as routeTbl, destination, organization } from "../db/schema";
import { getKekProvider } from "../crypto/kek";
import { decryptTenantSecret } from "../crypto/tenantSecrets";
import { Secret } from "../crypto/secret";
import { buildLLMPageviewEvents, sendToPostHog, type AiEvent } from "./posthog";

interface PhConfig {
  host?: string;
  siteUrl?: string;
}

interface ResolvedDest {
  destId: string;
  rowOrgId: string; // the destination row's OWN org_id (independent of the request org)
  config: PhConfig;
  ciphertext: Buffer | null;
  secretType: string | null;
}

interface ResolvedOrg {
  dests: ResolvedDest[];
  wrappedDek: Buffer;
  kekKeyId: string;
}

// --- caches (short TTL) ----------------------------------------------------
const DEST_TTL_MS = 30_000;
const KEY_TTL_MS = 30_000;
// Keyed on (orgId, sourceId) so one source's destination set never serves another.
const destCache = new Map<string, { value: ResolvedOrg | null; expires: number }>();
// Keyed on (destId, ciphertext-hash) so a rotated credential busts the entry.
const keyCache = new Map<string, { secret: Secret<string>; expires: number }>();

function sweepKeyCache(now: number): void {
  for (const [k, v] of keyCache) if (v.expires <= now) keyCache.delete(k);
}

async function resolveDestinations(orgId: string, sourceId: string): Promise<ResolvedOrg | null> {
  const now = Date.now();
  const cacheKey = `${orgId}:${sourceId}`;
  const hit = destCache.get(cacheKey);
  if (hit && hit.expires > now) return hit.value;

  const value = await withOrg(orgId, async (db) => {
    const rows = await db
      .select({
        destId: destination.id,
        rowOrgId: destination.orgId,
        config: destination.config,
        ciphertext: destination.secretCiphertext,
        secretType: destination.secretType,
      })
      .from(routeTbl)
      .innerJoin(destination, eq(routeTbl.destinationId, destination.id))
      .where(
        and(
          eq(routeTbl.orgId, orgId),
          eq(routeTbl.sourceId, sourceId), // only destinations wired to THIS source
          eq(routeTbl.enabled, true),
          eq(destination.kind, "posthog"),
          eq(destination.status, "active"),
        ),
      );
    const orgRows = await db
      .select({ wrappedDek: organization.wrappedDek, kekKeyId: organization.kekKeyId })
      .from(organization)
      .where(eq(organization.id, orgId));
    const org = orgRows[0];
    if (!org || !rows.length) return null;
    return {
      dests: rows.map((r) => ({
        destId: r.destId,
        rowOrgId: String(r.rowOrgId),
        config: (r.config as PhConfig) ?? {},
        ciphertext: r.ciphertext ?? null,
        secretType: r.secretType ?? null,
      })),
      wrappedDek: org.wrappedDek,
      kekKeyId: org.kekKeyId,
    };
  });

  destCache.set(cacheKey, { value, expires: now + DEST_TTL_MS });
  return value;
}

async function decryptKey(orgId: string, org: ResolvedOrg, d: ResolvedDest): Promise<Secret<string>> {
  const now = Date.now();
  sweepKeyCache(now); // evict expired so idle keys don't linger past TTL
  const cipherHash = createHash("sha256").update(d.ciphertext!).digest("hex").slice(0, 16);
  const cacheKey = `${d.destId}:${cipherHash}`; // busts on credential rotation
  const hit = keyCache.get(cacheKey);
  if (hit && hit.expires > now) return hit.secret;

  // ref.tenantId = the row's OWN org (independent source); authenticatedTenantId
  // = the request org. decryptTenantSecret refuses if they differ -> a confused
  // org would have to corrupt two independently-sourced values.
  const secret = await decryptTenantSecret(
    getKekProvider(),
    { keyId: org.kekKeyId, ciphertext: org.wrappedDek },
    { tenantId: d.rowOrgId, secretType: d.secretType ?? "posthog_project_key", recordId: d.destId },
    d.ciphertext!,
    orgId,
  );
  keyCache.set(cacheKey, { secret, expires: now + KEY_TTL_MS });
  return secret;
}

// --- DLQ (best-effort) -----------------------------------------------------
let _redis: Redis | null = null;
let _redisChecked = false;
function redis(): Redis | null {
  if (_redisChecked) return _redis;
  _redisChecked = true;
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (url && token) _redis = new Redis({ url, token });
  return _redis;
}

async function dlqPush(orgId: string, destId: string, count: number, status: number, err?: string) {
  // Always emit a structured log so a failing destination is observable even if
  // the DLQ backend is absent. Never log the credential.
  console.error("forward failed", { orgId, destId, status, count, err: err?.slice(0, 120) });
  const r = redis();
  if (!r) return;
  try {
    await r.rpush(
      `dlq:posthog:{${orgId}}`,
      JSON.stringify({ destId, count, status, err: err?.slice(0, 200), at: Date.now() }),
    );
    await r.ltrim(`dlq:posthog:{${orgId}}`, -1000, -1); // bound the list
  } catch {
    /* best-effort */
  }
}

/**
 * Forward classified AI events to the destinations wired to this source. Never
 * throws to the caller — destination/credential failures go to the DLQ + log.
 */
export async function forwardAiEvents(
  orgId: string,
  sourceId: string,
  aiEvents: AiEvent[],
): Promise<void> {
  if (!aiEvents.length) return;
  const resolved = await resolveDestinations(orgId, sourceId);
  if (!resolved) return;

  for (const d of resolved.dests) {
    if (!d.ciphertext) continue; // credential not configured yet
    try {
      const key = await decryptKey(orgId, resolved, d);
      const batch = buildLLMPageviewEvents(sourceId, aiEvents, d.config.siteUrl);
      const res = await sendToPostHog(d.config.host, key.expose(), batch);
      if (!res.ok) await dlqPush(orgId, d.destId, batch.length, res.status);
    } catch (e) {
      // method+host+status only — never the credential or body.
      await dlqPush(orgId, d.destId, aiEvents.length, -1, (e as Error).message);
    }
  }
}

/** Test/admin seam: clear caches (e.g. after rotating a destination credential). */
export function invalidateDestinationCaches(orgId?: string): void {
  if (orgId) {
    for (const k of destCache.keys()) if (k.startsWith(`${orgId}:`)) destCache.delete(k);
    keyCache.clear(); // keyed by destId:hash, not org — clear all (rotation is rare)
  } else {
    destCache.clear();
    keyCache.clear();
  }
}
