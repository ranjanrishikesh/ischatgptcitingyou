/**
 * Session + authorization helpers. The org a request acts on is ALWAYS resolved
 * server-side from a live membership row (via the user_memberships SECURITY
 * DEFINER function) — the client never asserts its own org. A non-member org id
 * yields NotFoundError (404), not 403, so membership is not confirmable.
 */
import { headers } from "next/headers";
import { sql } from "drizzle-orm";
import { auth } from "./auth";
import { withSystem } from "../db/client";
import { NotFoundError } from "../services/errors";

export interface SessionUser {
  id: string;
  email: string;
}

export async function getSessionUser(): Promise<SessionUser | null> {
  const session = await auth.api.getSession({ headers: await headers() });
  if (!session?.user) return null;
  return { id: session.user.id, email: session.user.email };
}

export async function requireUser(): Promise<SessionUser> {
  const u = await getSessionUser();
  if (!u) throw new NotFoundError("unauthorized");
  return u;
}

export interface OrgMembership {
  orgId: string;
  role: string;
}

/** All orgs the user belongs to (resolved server-side, RLS-bootstrap safe). */
export async function getUserOrgs(userId: string): Promise<OrgMembership[]> {
  const rows = await withSystem((db) =>
    db.execute(sql`select org_id, role from user_memberships(${userId})`),
  );
  return (rows as unknown as Array<Record<string, unknown>>).map((r) => ({
    orgId: String(r.org_id),
    role: String(r.role),
  }));
}

/** Assert the user is a member of orgId; return their role. 404 if not. */
export async function requireOrgMember(userId: string, orgId: string): Promise<string> {
  const m = (await getUserOrgs(userId)).find((o) => o.orgId === orgId);
  if (!m) throw new NotFoundError("org not found");
  return m.role;
}

/** The user's default (first) org, or null. */
export async function defaultOrg(userId: string): Promise<string | null> {
  const orgs = await getUserOrgs(userId);
  return orgs[0]?.orgId ?? null;
}
