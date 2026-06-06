/**
 * POST /api/sources — create a source. Returns the bearer ONCE (no-store), then
 * never again. The response also includes the drain URL to configure in Vercel.
 */
import { authorizeOrg, errorResponse } from "@/services/apiAuth";
import { createSource } from "@/services/sources";
import { auditSafe } from "@/services/audit";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<Response> {
  try {
    const body = (await req.json()) as { orgId?: string; projectId?: string; name?: string };
    const { orgId, userId } = await authorizeOrg(body.orgId);
    if (!body.projectId) return errorResponse(new Error("projectId required"));

    const created = await createSource(orgId, body.projectId, body.name);
    await auditSafe(orgId, {
      actorId: userId,
      action: "source.create",
      targetType: "source",
      targetId: created.sourceId,
    });
    const base = process.env.BETTER_AUTH_URL ?? "";
    return new Response(
      JSON.stringify({
        sourceId: created.sourceId,
        ingestId: created.ingestId,
        drainUrl: `${base}/api/drain/${created.ingestId}`,
        bearer: created.bearer.expose(), // shown ONCE — not retrievable again
      }),
      { status: 201, headers: { "content-type": "application/json", "cache-control": "no-store" } },
    );
  } catch (e) {
    return errorResponse(e);
  }
}
