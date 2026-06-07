/** POST /api/billing/buy-pack — purchase a one-time credit pack ($50/$100). */
import { authorizeOrgAdmin, errorResponse, parseMicros } from "@/services/apiAuth";
import { createPackPaymentIntent } from "@/billing/stripe";
import { rateLimitAction } from "@/ingest/ratelimit";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<Response> {
  try {
    const body = (await req.json()) as { orgId?: string; packMicros?: string };
    const { orgId } = await authorizeOrgAdmin(body.orgId);
    if (!(await rateLimitAction(`billing:${orgId}`, 10, 60))) {
      return new Response("rate limited", { status: 429 });
    }
    const micros = parseMicros(body.packMicros); // length-capped, integer-only
    const clientSecret = await createPackPaymentIntent(orgId, micros);
    return new Response(JSON.stringify({ clientSecret }), {
      status: 200,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  } catch (e) {
    return errorResponse(e);
  }
}
