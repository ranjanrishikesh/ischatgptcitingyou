import { and, eq } from "drizzle-orm";
import { withOrg } from "../db/client";
import { membership, user } from "../db/schema";

/** Email of the org's owner, for billing notifications. */
export async function getOrgOwnerEmail(orgId: string): Promise<string | null> {
  const rows = await withOrg(orgId, (db) =>
    db
      .select({ email: user.email })
      .from(membership)
      .innerJoin(user, eq(user.id, membership.userId))
      .where(and(eq(membership.orgId, orgId), eq(membership.role, "owner"))),
  );
  return rows[0]?.email ?? null;
}
