/** POST /api/billing/auto-recharge — enable/configure auto-recharge (admin only). */
import { authorizeOrgAdmin, errorResponse, parseMicros } from "@/services/apiAuth";
import { setAutoRechargeConfig } from "@/billing/autoRecharge";
import { rateLimitAction } from "@/ingest/ratelimit";
import { auditSafe } from "@/services/audit";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<Response> {
  try {
    const body = (await req.json()) as {
      orgId?: string;
      enabled?: boolean;
      thresholdMicros?: string;
      targetMicros?: string;
    };
    const { orgId, userId } = await authorizeOrgAdmin(body.orgId);
    if (!(await rateLimitAction(`billing:${orgId}`, 10, 60))) {
      return new Response("rate limited", { status: 429 });
    }
    await setAutoRechargeConfig(orgId, {
      enabled: !!body.enabled,
      thresholdMicros: body.thresholdMicros ? parseMicros(body.thresholdMicros) : undefined,
      targetMicros: body.targetMicros ? parseMicros(body.targetMicros) : undefined,
    });
    await auditSafe(orgId, {
      actorId: userId,
      action: "billing.auto_recharge.set",
      meta: { enabled: !!body.enabled },
    });
    return new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  } catch (e) {
    return errorResponse(e);
  }
}
