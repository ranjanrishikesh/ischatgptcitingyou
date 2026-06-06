/**
 * Drain ingest endpoint: POST /api/drain/{ingestId}
 *
 * Order is security-critical (cheapest + safest checks first; never do real
 * work for an unauthenticated caller):
 *   1. verify ingest id MAC      — O(1), constant-time, ZERO DB, never throws
 *   2. pre-auth IP rate limit    — before any DB / body read (trusted IP only)
 *   3. verify per-source bearer  — constant-time; uniform 401 on any failure
 *      (unknown id and bad bearer return the SAME status/body, and we always
 *       run a constant-time compare so there is no validity/timing oracle)
 *   4. read body with a STREAMING byte cap — only AFTER auth
 *   5. classify in memory        — keep bot/AI, drop browsers/assets
 *   6. meter (hosted)            — replay-idempotent debit, off the Postgres path
 *   7. forward                   — deferred to M2; for now classify + drop
 *
 * Stores NO traffic. Nothing here persists a path or user-agent.
 */
import { createHash } from "node:crypto";
import { verifyIngestId, verifyBearer, bearerFromHeader, hashBearer } from "@/ingest/ingestId";
import { resolveSource } from "@/ingest/resolveSource";
import { rateLimitIp, clientIp } from "@/ingest/ratelimit";
import { parseNdjson, readBodyCapped } from "@/ingest/parse";
import { classify } from "@/ingest/classify";
import { isHosted } from "@/config/deployMode";
import { debitEvents, seedHotBalance, markBatchSeen, incrUnmetered } from "@/billing/balance";
import { getBalanceMicros } from "@/billing/ledger";

export const runtime = "nodejs";

// Window (seconds) a replayed/redelivered identical batch is deduped within.
const REPLAY_TTL_SECONDS = 600;

// A fixed hash to compare against when there is no real source, so the bearer
// check runs in constant time whether or not the id resolved (no timing oracle).
function hashBearerSafe(s: string): string {
  try {
    return hashBearer(s);
  } catch {
    return "0".repeat(64);
  }
}
const DUMMY_HASH = hashBearerSafe("dummy");

function verifyHeaders(req: Request): Record<string, string> {
  const v = req.headers.get("x-vercel-verify");
  return v ? { "x-vercel-verify": v } : {};
}

function unauthorized(headers: Record<string, string>): Response {
  return new Response("unauthorized", { status: 401, headers });
}

export async function GET(req: Request): Promise<Response> {
  // Vercel drain verification handshake echoes x-vercel-verify.
  return new Response("ok", { status: 200, headers: verifyHeaders(req) });
}

export async function POST(
  req: Request,
  ctx: { params: Promise<{ ingestId: string }> },
): Promise<Response> {
  const headers = verifyHeaders(req);
  const { ingestId } = await ctx.params;

  // 1. Self-validating id check — no DB, never throws (fails closed to 401).
  if (!verifyIngestId(ingestId)) return unauthorized(headers);

  // 2. Pre-auth IP rate limit — before any DB/body work. Keyed on the TRUSTED IP.
  const rl = await rateLimitIp(clientIp(req.headers));
  if (!rl.allowed) return new Response("rate limited", { status: 429, headers });

  // 3. Authenticate the per-source bearer (constant-time, uniform failure).
  const bearer = bearerFromHeader(req.headers.get("authorization"));
  const src = await resolveSource(ingestId);
  // Always run a constant-time compare (dummy when no source) — no oracle.
  const hashToCheck = src && src.status === "active" ? src.bearerHash : DUMMY_HASH;
  const authed = verifyBearer(bearer ?? "", hashToCheck);
  if (!bearer || !src || src.status !== "active" || !authed) {
    return unauthorized(headers);
  }

  // 4. Read body with a streaming hard byte cap (enforced before full buffering).
  const raw = await readBodyCapped(req);
  if (raw === null) return new Response("payload too large", { status: 413, headers });
  const parsed = parseNdjson(raw);

  // 5. Classify in memory. Count billable (kept) events; bucket for M2 routing.
  let aiCount = 0;
  let otherCount = 0;
  for (const rec of parsed.records) {
    const c = classify(rec);
    if (!c.keep) continue;
    if (c.bucket === "ai") aiCount++;
    else otherCount++;
  }
  const billable = aiCount + otherCount;

  // 6. Meter (hosted only; best-effort, never blocks ingest in M1).
  if (isHosted() && billable > 0) {
    try {
      // Replay/redelivery dedup: content hash of the raw batch, scoped per org.
      const token = createHash("sha256").update(src.orgId + ":" + raw).digest("hex");
      const fresh = await markBatchSeen(src.orgId, token, REPLAY_TTL_SECONDS);
      if (fresh) {
        let d = await debitEvents(src.orgId, billable);
        let tries = 0;
        while (d.needsSeed && tries++ < 3) {
          await seedHotBalance(src.orgId, await getBalanceMicros(src.orgId));
          d = await debitEvents(src.orgId, billable);
        }
        if (d.needsSeed) {
          await incrUnmetered(src.orgId, billable);
          console.error("debit unmetered: seed/retry exhausted", { orgId: src.orgId, billable });
        }
        // M2 will use d.hadFunds to gate forwarding. M1 only meters.
      }
      // else: replay — already metered, skip the debit.
    } catch (e) {
      // Metering failure must not break the pipeline; record + log metadata only.
      await incrUnmetered(src.orgId, billable);
      console.error("debit failed", { orgId: src.orgId, billable, err: (e as Error).message });
    }
  }

  // 7. Forwarding to the destination is M2. For now, classify-and-drop.
  console.log("DRAIN ok", { sourceId: src.sourceId, ai: aiCount, other: otherCount, bad: parsed.badLines });

  return new Response("ok", { status: 200, headers });
}
