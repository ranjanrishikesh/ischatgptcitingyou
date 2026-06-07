/**
 * Source management. A source mints a PUBLIC ingest id (in the drain URL) and a
 * per-source bearer secret. The bearer is returned ONCE at creation and stored
 * only as an HMAC — it can never be retrieved again, only rotated.
 */
import { randomUUID } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { withOrg } from "../db/client";
import { source, project } from "../db/schema";
import { newIngestId, newBearer, hashBearer } from "../ingest/ingestId";
import { invalidateSourceCache } from "../ingest/resolveSource";
import { Secret } from "../crypto/secret";
import { NotFoundError } from "./errors";

export interface CreatedSource {
  sourceId: string;
  ingestId: string;
  /** Shown ONCE. Never stored in plaintext. */
  bearer: Secret<string>;
}

export async function createSource(
  orgId: string,
  projectId: string,
  name?: string,
): Promise<CreatedSource> {
  const ingestId = newIngestId();
  const bearer = newBearer();
  const bearerHash = hashBearer(bearer);
  const id = randomUUID();

  await withOrg(orgId, async (db) => {
    const p = await db
      .select({ id: project.id })
      .from(project)
      .where(and(eq(project.id, projectId), eq(project.orgId, orgId)));
    if (!p.length) throw new NotFoundError("project not found");
    await db.insert(source).values({
      id,
      orgId,
      projectId,
      kind: "vercel",
      ingestIdPublic: ingestId,
      bearerHash,
      status: "active",
    });
  });

  return { sourceId: id, ingestId, bearer: new Secret(bearer) };
}

export async function listSources(orgId: string) {
  return withOrg(orgId, (db) =>
    db
      .select({
        id: source.id,
        projectId: source.projectId,
        ingestIdPublic: source.ingestIdPublic,
        status: source.status,
        createdAt: source.createdAt,
      })
      .from(source)
      .where(eq(source.orgId, orgId)),
  );
}

/** Rotate a source's bearer. Returns the new bearer ONCE. */
export async function rotateSourceBearer(orgId: string, sourceId: string): Promise<Secret<string>> {
  const bearer = newBearer();
  const bearerHash = hashBearer(bearer);
  const ingestId = await withOrg(orgId, async (db) => {
    const rows = await db
      .update(source)
      .set({ bearerHash })
      .where(and(eq(source.id, sourceId), eq(source.orgId, orgId)))
      .returning({ ingestId: source.ingestIdPublic });
    if (!rows.length) throw new NotFoundError("source not found");
    return rows[0]!.ingestId;
  });
  // Bust the resolve cache so the old bearer stops working promptly (per-process;
  // the short cache TTL bounds other instances).
  invalidateSourceCache(ingestId);
  return new Secret(bearer);
}

/** Disable a source (stops ingest). */
export async function setSourceStatus(orgId: string, sourceId: string, status: "active" | "disabled") {
  await withOrg(orgId, async (db) => {
    const rows = await db
      .update(source)
      .set({ status })
      .where(and(eq(source.id, sourceId), eq(source.orgId, orgId)))
      .returning({ ingestId: source.ingestIdPublic });
    if (!rows.length) throw new NotFoundError("source not found");
    invalidateSourceCache(rows[0]!.ingestId);
  });
}
