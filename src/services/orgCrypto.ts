/**
 * Helpers for encrypting/decrypting a destination credential under an org's
 * per-tenant DEK. The org's wrapped DEK is read under RLS; the KEK unwraps it
 * just-in-time inside the crypto layer.
 */
import { eq } from "drizzle-orm";
import { withOrg } from "../db/client";
import { organization } from "../db/schema";
import { getKekProvider } from "../crypto/kek";
import { encryptTenantSecret } from "../crypto/tenantSecrets";
import type { Secret } from "../crypto/secret";

export interface OrgDek {
  wrappedDek: Buffer;
  kekKeyId: string;
}

export async function getOrgDek(orgId: string): Promise<OrgDek> {
  const rows = await withOrg(orgId, (db) =>
    db
      .select({ wrappedDek: organization.wrappedDek, kekKeyId: organization.kekKeyId })
      .from(organization)
      .where(eq(organization.id, orgId)),
  );
  const r = rows[0];
  if (!r) throw new Error("org not found");
  return { wrappedDek: r.wrappedDek, kekKeyId: r.kekKeyId };
}

/** Encrypt a secret for an org/destination, returning the ciphertext to store. */
export async function encryptForOrg(
  orgId: string,
  recordId: string,
  secretType: string,
  plaintext: Secret<string>,
): Promise<Buffer> {
  const dek = await getOrgDek(orgId);
  return encryptTenantSecret(
    getKekProvider(),
    { keyId: dek.kekKeyId, ciphertext: dek.wrappedDek },
    { tenantId: orgId, secretType, recordId },
    plaintext,
  );
}
