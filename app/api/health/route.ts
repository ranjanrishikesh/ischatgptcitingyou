/**
 * Liveness + reconcile-freshness probe. Auto-recharge and usage flushing run
 * ONLY from the reconcile cron, and that cadence can silently degrade (external
 * trigger misconfigured, GitHub schedule disabled, secrets rotated). This makes
 * the degradation observable: point a free uptime monitor at /api/health and a
 * stale reconcile becomes a page instead of a surprise on a customer invoice.
 *
 * Unauthenticated by design — it exposes only mode + reconcile age, no tenant
 * data, no balances, no configuration.
 */
import { isHosted } from "@/config/deployMode";
import { reconcileAgeMs } from "@/billing/balance";

export const runtime = "nodejs";

// Reconcile is expected every ~5-30 min; beyond this it is degraded enough
// that forwarding for out-of-credit orgs is stalled and alerts should fire.
const STALE_AFTER_MS = 45 * 60 * 1000;

export async function GET(): Promise<Response> {
  if (!isHosted()) {
    return Response.json({ ok: true, mode: "self_host" });
  }
  let ageMs: number | null = null;
  try {
    ageMs = await reconcileAgeMs();
  } catch {
    // Redis unreachable — the hot meter itself is down, definitely not healthy.
    return Response.json({ ok: false, mode: "hosted", reason: "redis unreachable" }, { status: 503 });
  }
  // null = never ran (fresh deploy before the first tick): report but don't page.
  const stale = ageMs !== null && ageMs > STALE_AFTER_MS;
  return Response.json(
    {
      ok: !stale,
      mode: "hosted",
      reconcileAgeSeconds: ageMs === null ? null : Math.round(ageMs / 1000),
    },
    { status: stale ? 503 : 200 },
  );
}
