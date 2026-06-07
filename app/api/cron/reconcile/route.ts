/** Reconciliation cron (Vercel Cron, every 5 min). Flushes usage to the ledger
 *  and triggers auto-recharge. Protected by CRON_SECRET. */
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
