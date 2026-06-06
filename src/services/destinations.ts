/**
 * Destination management. Credentials are encrypted under the org DEK before
 * storage; the API never returns a stored secret (only status/last4). Rotation
 * re-encrypts and busts the dispatch caches.
 */
import { randomUUID } from "node:crypto";
import { and, eq } from "drizzle-orm";
import { withOrg } from "../db/client";
import { destination } from "../db/schema";
import { Secret } from "../crypto/secret";
import { encryptForOrg } from "./orgCrypto";
import { invalidateDestinationCaches } from "../destinations/dispatch";
import { NotFoundError } from "./errors";

export async function createPostHogDestination(
  orgId: string,
  args: { label: string; projectKey: string; host?: string; siteUrl?: string },
): Promise<{ destId: string }> {
  const destId = randomUUID();
  const ct = await encryptForOrg(orgId, destId, "posthog_project_key", new Secret(args.projectKey));
  await withOrg(orgId, (db) =>
    db.insert(destination).values({
      id: destId,
      orgId,
      kind: "posthog",
      label: args.label,
      secretCiphertext: ct,
      secretType: "posthog_project_key",
      config: { host: args.host, siteUrl: args.siteUrl },
      last4: args.projectKey.slice(-4),
      status: "active",
    }),
  );
  return { destId };
}

/** Created by the Google OAuth callback after a sheet has been provisioned. */
export async function createGoogleSheetsDestination(
  orgId: string,
  args: { label: string; refreshToken: Secret<string>; spreadsheetId: string; sheetName?: string },
): Promise<{ destId: string }> {
  const destId = randomUUID();
  const ct = await encryptForOrg(orgId, destId, "google_refresh_token", args.refreshToken);
  await withOrg(orgId, (db) =>
    db.insert(destination).values({
      id: destId,
      orgId,
      kind: "google_sheets",
      label: args.label,
      secretCiphertext: ct,
      secretType: "google_refresh_token",
      config: { spreadsheetId: args.spreadsheetId, sheetName: args.sheetName ?? "Logs" },
      status: "active",
    }),
  );
  return { destId };
}

export async function listDestinations(orgId: string) {
  return withOrg(orgId, (db) =>
    db
      .select({
        id: destination.id,
        kind: destination.kind,
        label: destination.label,
        last4: destination.last4,
        status: destination.status,
        lastRotatedAt: destination.lastRotatedAt,
        createdAt: destination.createdAt,
      })
      .from(destination)
      .where(eq(destination.orgId, orgId)),
  );
}

/** Rotate a destination credential (re-encrypt) and bust caches. */
export async function rotateDestinationSecret(
  orgId: string,
  destId: string,
  secretType: string,
  newSecret: Secret<string>,
  last4?: string,
): Promise<void> {
  const ct = await encryptForOrg(orgId, destId, secretType, newSecret);
  await withOrg(orgId, async (db) => {
    const rows = await db
      .update(destination)
      .set({ secretCiphertext: ct, secretType, last4: last4 ?? null, lastRotatedAt: new Date() })
      .where(and(eq(destination.id, destId), eq(destination.orgId, orgId)))
      .returning({ id: destination.id });
    if (!rows.length) throw new NotFoundError("destination not found");
  });
  invalidateDestinationCaches(orgId);
}
