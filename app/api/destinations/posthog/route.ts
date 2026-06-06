/** POST /api/destinations/posthog — connect a PostHog destination (key encrypted). */
import { authorizeOrg, errorResponse } from "@/services/apiAuth";
import { createPostHogDestination } from "@/services/destinations";
import { auditSafe } from "@/services/audit";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<Response> {
  try {
    const body = (await req.json()) as {
      orgId?: string;
      label?: string;
      projectKey?: string;
      host?: string;
      siteUrl?: string;
    };
    const { orgId, userId } = await authorizeOrg(body.orgId);
    if (!body.projectKey || !body.label) return errorResponse(new Error("missing fields"));

    const { destId } = await createPostHogDestination(orgId, {
      label: body.label,
      projectKey: body.projectKey,
      host: body.host,
      siteUrl: body.siteUrl,
    });
    await auditSafe(orgId, {
      actorId: userId,
      action: "destination.create",
      targetType: "destination",
      targetId: destId,
      meta: { kind: "posthog" },
    });
    return new Response(JSON.stringify({ destId }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  } catch (e) {
    return errorResponse(e);
  }
}
