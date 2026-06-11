/** Reconciliation cron. Flushes usage to the ledger and triggers auto-recharge.
 *  Triggered every ~30 min by GitHub Actions (.github/workflows/reconcile.yml)
 *  plus a daily Vercel cron backstop (vercel.json — Hobby allows daily only).
 *  Safe to invoke concurrently/late: flush ids + ledger idempotency keys dedupe,
 *  and out-of-funds batches are floored (never metered) on the drain path.
 *  Freshness is observable at /api/health. Protected by CRON_SECRET. */
import { reconcileAll } from "@/billing/reconcile";
import { constantTimeEqual } from "@/crypto/envelope";

export const runtime = "nodejs";
export const maxDuration = 60;

export async function GET(req: Request): Promise<Response> {
  const secret = process.env.CRON_SECRET;
  // Fail CLOSED: a missing secret on a charge-triggering endpoint is a hard error,
  // never "open".
  if (!secret) return new Response("cron not configured", { status: 500 });
  const auth = req.headers.get("authorization") ?? "";
  if (!constantTimeEqual(Buffer.from(auth), Buffer.from(`Bearer ${secret}`))) {
    return new Response("unauthorized", { status: 401 });
  }
  const result = await reconcileAll();
  return Response.json(result);
}
