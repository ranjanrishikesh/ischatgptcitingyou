/** POST /api/routes — wire a source to a destination (triple-equality enforced). */
import { authorizeOrg, errorResponse } from "@/services/apiAuth";
import { createRoute } from "@/services/routes";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<Response> {
  try {
    const body = (await req.json()) as {
      orgId?: string;
      sourceId?: string;
      destinationId?: string;
    };
    const { orgId } = await authorizeOrg(body.orgId);
    if (!body.sourceId || !body.destinationId) return errorResponse(new Error("missing fields"));

    const { routeId } = await createRoute(orgId, body.sourceId, body.destinationId);
    return new Response(JSON.stringify({ routeId }), {
      status: 201,
      headers: { "content-type": "application/json" },
    });
  } catch (e) {
    return errorResponse(e);
  }
}
