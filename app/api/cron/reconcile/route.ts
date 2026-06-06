/** Reconciliation cron (Vercel Cron, every 5 min). Flushes usage to the ledger
 *  and triggers auto-recharge. Protected by CRON_SECRET. */
import { timingSafeEqual } from "node:crypto";
import { reconcileAll } from "@/billing/reconcile";

export const runtime = "nodejs";
export const maxDuration = 60;

function constantTimeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  if (ab.length !== bb.length) return false;
  return timingSafeEqual(ab, bb);
}

export async function GET(req: Request): Promise<Response> {
  const secret = process.env.CRON_SECRET;
  // Fail CLOSED: a missing secret on a charge-triggering endpoint is a hard error,
  // never "open".
  if (!secret) return new Response("cron not configured", { status: 500 });
  const auth = req.headers.get("authorization") ?? "";
  if (!constantTimeEqual(auth, `Bearer ${secret}`)) {
    return new Response("unauthorized", { status: 401 });
  }
  const result = await reconcileAll();
  return Response.json(result);
}
