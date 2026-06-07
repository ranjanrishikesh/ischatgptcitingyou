/** POST /api/billing/setup-intent — start saving a card (off-session). */
import { authorizeOrgAdmin, errorResponse } from "@/services/apiAuth";
import { createSetupIntent } from "@/billing/stripe";
import { rateLimitAction } from "@/ingest/ratelimit";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<Response> {
  try {
    const body = (await req.json()) as { orgId?: string };
    const { orgId } = await authorizeOrgAdmin(body.orgId);
    if (!(await rateLimitAction(`billing:${orgId}`, 10, 60))) {
      return new Response("rate limited", { status: 429 });
    }
    const clientSecret = await createSetupIntent(orgId);
    return new Response(JSON.stringify({ clientSecret }), {
      status: 200,
      headers: { "content-type": "application/json", "cache-control": "no-store" },
    });
  } catch (e) {
    return errorResponse(e);
  }
}
