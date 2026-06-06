/**
 * Shared API-route authorization. Resolves the session user, asserts membership
 * of the body's org (404 if not), and maps NotFoundError to a 404 Response.
 */
import { requireUser, requireOrgMember } from "../auth/session";
import { NotFoundError } from "./errors";

export async function authorizeOrg(orgId: unknown): Promise<{ userId: string; orgId: string }> {
  if (typeof orgId !== "string" || !orgId) throw new NotFoundError("org not found");
  const user = await requireUser();
  await requireOrgMember(user.id, orgId);
  return { userId: user.id, orgId };
}

export function errorResponse(e: unknown): Response {
  if (e instanceof NotFoundError) {
    return new Response(JSON.stringify({ error: "not_found" }), {
      status: 404,
      headers: { "content-type": "application/json" },
    });
  }
  return new Response(JSON.stringify({ error: "bad_request" }), {
    status: 400,
    headers: { "content-type": "application/json" },
  });
}
