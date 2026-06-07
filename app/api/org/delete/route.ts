/**
 * POST /api/org/delete — crypto-shredding org deletion (OWNER only). Destroys the
 * per-tenant DEK + cascades all tenant data. Requires `confirm` == orgId so it
 * can't fire by accident.
 */
import { authorizeOrgAdmin, errorResponse } from "@/services/apiAuth";
import { NotFoundError } from "@/services/errors";
import { deleteOrg } from "@/services/org";

export const runtime = "nodejs";

export async function POST(req: Request): Promise<Response> {
  try {
    const body = (await req.json()) as { orgId?: string; confirm?: string };
    const { orgId, userId, role } = await authorizeOrgAdmin(body.orgId);
    if (role !== "owner") throw new NotFoundError("not found"); // owner-only
    if (body.confirm !== orgId) return errorResponse(new Error("confirm must equal orgId"));
    await deleteOrg(orgId, userId); // forensic record captures the actor
    return Response.json({ deleted: true });
  } catch (e) {
    return errorResponse(e);
  }
}
