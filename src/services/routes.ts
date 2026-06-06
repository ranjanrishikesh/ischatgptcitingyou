/**
 * Route (source -> destination) management. Enforces the triple-equality
 * invariant: source.org == destination.org == request org. RLS already scopes
 * both reads to the request org, and the existence checks return 404 (never 403)
 * for a cross-org/unknown id so there is no existence oracle.
 */
import { and, eq } from "drizzle-orm";
import { withOrg } from "../db/client";
import { route as routeTbl, source, destination } from "../db/schema";
import { NotFoundError } from "./errors";

export async function createRoute(
  orgId: string,
  sourceId: string,
  destId: string,
): Promise<{ routeId: string }> {
  return withOrg(orgId, async (db) => {
    const s = await db
      .select({ id: source.id })
      .from(source)
      .where(and(eq(source.id, sourceId), eq(source.orgId, orgId)));
    const d = await db
      .select({ id: destination.id })
      .from(destination)
      .where(and(eq(destination.id, destId), eq(destination.orgId, orgId)));
    if (!s.length || !d.length) throw new NotFoundError("source or destination not found");

    const rows = await db
      .insert(routeTbl)
      .values({ orgId, sourceId, destinationId: destId, enabled: true })
      .onConflictDoNothing({ target: [routeTbl.sourceId, routeTbl.destinationId] })
      .returning({ id: routeTbl.id });
    // If the edge already existed, fetch it.
    if (rows.length) return { routeId: rows[0]!.id };
    const existing = await db
      .select({ id: routeTbl.id })
      .from(routeTbl)
      .where(and(eq(routeTbl.sourceId, sourceId), eq(routeTbl.destinationId, destId)));
    return { routeId: existing[0]!.id };
  });
}

export async function listRoutes(orgId: string) {
  return withOrg(orgId, (db) =>
    db
      .select({
        id: routeTbl.id,
        sourceId: routeTbl.sourceId,
        destinationId: routeTbl.destinationId,
        enabled: routeTbl.enabled,
      })
      .from(routeTbl)
      .where(eq(routeTbl.orgId, orgId)),
  );
}

export async function setRouteEnabled(orgId: string, routeId: string, enabled: boolean) {
  await withOrg(orgId, async (db) => {
    const rows = await db
      .update(routeTbl)
      .set({ enabled })
      .where(and(eq(routeTbl.id, routeId), eq(routeTbl.orgId, orgId)))
      .returning({ id: routeTbl.id });
    if (!rows.length) throw new NotFoundError("route not found");
  });
}
