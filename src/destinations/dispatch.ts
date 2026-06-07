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
import { and, eq, inArray } from "drizzle-orm";
import { Redis } from "@upstash/redis";
import { withOrg } from "../db/client";
import { route as routeTbl, destination, organization } from "../db/schema";
import { getKekProvider } from "../crypto/kek";
import { decryptTenantSecret, encryptTenantSecret } from "../crypto/tenantSecrets";
import { Secret } from "../crypto/secret";
import { buildLLMPageviewEvents, sendToPostHog, type AiEvent } from "./posthog";
import { refreshAccessToken } from "./google/oauth";
import { appendRows, eventsToRows } from "./google/sheets";

type DestKind = "posthog" | "google_sheets";

interface DestConfig {
  host?: string;
  siteUrl?: string;
  spreadsheetId?: string;
  sheetName?: string;
}

interface ResolvedDest {
  destId: string;
  kind: DestKind;
  rowOrgId: string; // the destination row's OWN org_id (independent of the request org)
  config: DestConfig;
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
// Short-lived Google access tokens, keyed by (destId, ciphertext-hash) so a
// rotated/replaced refresh token busts the entry like keyCache.
const ACCESS_TTL_MS = 50 * 60 * 1000;
const accessCache = new Map<string, { secret: Secret<string>; expires: number }>();
// Negative cache: after an invalid_grant/refresh failure, stop hammering Google's
// (shared, platform-level) token endpoint per batch for a short window.
const ACCESS_NEG_TTL_MS = 60_000;
const accessNegCache = new Map<string, number>(); // destId -> retry-after ms

function sweepCaches(now: number): void {
  for (const [k, v] of keyCache) if (v.expires <= now) keyCache.delete(k);
  for (const [k, v] of accessCache) if (v.expires <= now) accessCache.delete(k);
  for (const [k, v] of accessNegCache) if (v <= now) accessNegCache.delete(k);
}

/**
 * Persist a refresh token Google ROTATED on us, so the destination doesn't break
 * permanently the next time the old token is invalidated. Re-encrypts under the
 * row's own org and updates the destination row, then busts caches.
 */
async function persistRotatedRefresh(
  orgId: string,
  org: ResolvedOrg,
  d: ResolvedDest,
  newRefresh: Secret<string>,
): Promise<void> {
  // org.wrappedDek belongs to the REQUEST org; the AAD binds to the row's own
  // org. They must be the same tenant (RLS scopes resolveDestinations to orgId),
  // so assert rather than silently mixing crypto contexts.
  if (d.rowOrgId !== orgId) throw new Error("persistRotatedRefresh: tenant mismatch");
  const ct = await encryptTenantSecret(
    getKekProvider(),
    { keyId: org.kekKeyId, ciphertext: org.wrappedDek },
    { tenantId: d.rowOrgId, secretType: d.secretType ?? "google_refresh_token", recordId: d.destId },
    newRefresh,
  );
  await withOrg(orgId, (db) =>
    db
      .update(destination)
      .set({ secretCiphertext: ct, lastRotatedAt: new Date() })
      .where(eq(destination.id, d.destId)),
  );
  invalidateDestinationCaches(orgId); // next read picks up the new ciphertext
}

/** Mint/cache a Google access token from a stored refresh token. */
async function getAccessToken(
  orgId: string,
  org: ResolvedOrg,
  d: ResolvedDest,
  cipherHash: string,
  refresh: Secret<string>,
): Promise<Secret<string>> {
  const now = Date.now();
  const neg = accessNegCache.get(d.destId);
  if (neg && neg > now) throw new Error("google refresh recently failed; backing off");
  const cacheKey = `${orgId}:${d.destId}:${cipherHash}`;
  const hit = accessCache.get(cacheKey);
  if (hit && hit.expires > now) return hit.secret;

  let t;
  try {
    t = await refreshAccessToken(refresh);
  } catch (e) {
    accessNegCache.set(d.destId, now + ACCESS_NEG_TTL_MS);
    throw e;
  }
  if (t.refreshToken) {
    // Best-effort: a failed persist must not block forwarding this batch.
    try {
      await persistRotatedRefresh(orgId, org, d, t.refreshToken);
    } catch (e) {
      console.error("persist rotated refresh failed", { destId: d.destId, err: (e as Error).message });
    }
  }
  // Guard a malformed/short expiry so we don't cache a 0-ms TTL and then refresh
  // on every batch (hammering Google's token endpoint).
  const expSec = Number.isFinite(t.expiresInSec) && t.expiresInSec > 0 ? t.expiresInSec : 3600;
  const ttl = Math.min(ACCESS_TTL_MS, Math.max(0, (expSec - 60) * 1000));
  accessCache.set(cacheKey, { secret: t.accessToken, expires: now + ttl });
  return t.accessToken;
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
        kind: destination.kind,
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
          inArray(destination.kind, ["posthog", "google_sheets"]),
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
        kind: r.kind as DestKind,
        rowOrgId: String(r.rowOrgId),
        config: (r.config as DestConfig) ?? {},
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

function cipherHashOf(ciphertext: Buffer): string {
  return createHash("sha256").update(ciphertext).digest("hex").slice(0, 16);
}

async function decryptKey(
  orgId: string,
  org: ResolvedOrg,
  d: ResolvedDest,
  cipherHash: string,
): Promise<Secret<string>> {
  const now = Date.now();
  sweepCaches(now); // evict expired so idle secrets don't linger past TTL
  // Org-scoped (defence-in-depth): even if RLS ever leaked a cross-org row, a
  // cache hit can never hand org B a credential cached under org A.
  const cacheKey = `${orgId}:${d.destId}:${cipherHash}`; // busts on credential rotation
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
    const cipherHash = cipherHashOf(d.ciphertext);
    try {
      const cred = await decryptKey(orgId, resolved, d, cipherHash);
      if (d.kind === "posthog") {
        const batch = buildLLMPageviewEvents(sourceId, aiEvents, d.config.siteUrl);
        const res = await sendToPostHog(d.config.host, cred.expose(), batch);
        if (!res.ok) await dlqPush(orgId, d.destId, batch.length, res.status);
      } else if (d.kind === "google_sheets") {
        if (!d.config.spreadsheetId) {
          // Active sheets dest with no spreadsheetId = misconfig — surface it.
          await dlqPush(orgId, d.destId, aiEvents.length, -1, "google_sheets missing spreadsheetId");
          continue;
        }
        const access = await getAccessToken(orgId, resolved, d, cipherHash, cred); // cred = refresh token
        await appendRows(access, d.config.spreadsheetId, d.config.sheetName ?? "Logs", eventsToRows(aiEvents));
      }
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
    accessCache.clear();
  } else {
    destCache.clear();
    keyCache.clear();
    accessCache.clear();
  }
}
