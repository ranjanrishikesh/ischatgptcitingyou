/**
 * Tenant secret encryption — the facade the rest of the app uses to protect
 * destination credentials (PostHog write keys, Google refresh tokens, …).
 *
 * Layering: KEK wraps a per-tenant DEK; the DEK encrypts each field. The DEK is
 * unwrapped just-in-time, used, and zeroized immediately. It is never cached as
 * a string and never logged.
 *
 * Two independent AAD bindings, on purpose:
 *   - the DEK wrap is bound to { tenantId, purpose: "tenant-dek" }
 *   - each field ciphertext is bound to { tenantId, secretType, recordId }
 * To decrypt, the caller must supply the SAME tenantId the row was stored under.
 * A single confused `org_id` variable is therefore not enough to cross tenants —
 * the attacker would have to corrupt two independently-sourced values.
 */
import { Secret } from "./secret";
import {
  aeadEncrypt,
  aeadDecrypt,
  generateDek,
  zeroize,
  type EncryptionContext,
} from "./envelope";
import type { KekProvider, WrappedDek } from "./kek";

const DEK_PURPOSE = "tenant-dek";

function dekContext(tenantId: string): EncryptionContext {
  return { tenantId, purpose: DEK_PURPOSE };
}

export interface FieldRef {
  tenantId: string;
  secretType: string; // e.g. "posthog_project_key", "google_refresh_token"
  recordId: string; // the destination row id
}

function fieldContext(ref: FieldRef): EncryptionContext {
  return { tenantId: ref.tenantId, secretType: ref.secretType, recordId: ref.recordId };
}

/**
 * Provision a fresh per-tenant DEK, wrapped by the KEK. Call once per org at
 * creation; store the returned WrappedDek + keyId on the organization row.
 */
export async function provisionTenantDek(
  kek: KekProvider,
  tenantId: string,
): Promise<WrappedDek> {
  const dek = generateDek();
  try {
    return await kek.wrapDek(dek, dekContext(tenantId));
  } finally {
    zeroize(dek);
  }
}

/** Encrypt a plaintext secret for storage. Returns the ciphertext blob. */
export async function encryptTenantSecret(
  kek: KekProvider,
  wrappedDek: WrappedDek,
  ref: FieldRef,
  plaintext: Secret<string>,
): Promise<Buffer> {
  const dek = await kek.unwrapDek(wrappedDek, dekContext(ref.tenantId));
  const pt = Buffer.from(plaintext.expose(), "utf8");
  try {
    return aeadEncrypt(pt, dek, fieldContext(ref));
  } finally {
    // Scrub both the plaintext copy and the DEK. (The original JS string from
    // .expose() is immutable and can't be wiped; this removes the Buffer copy.)
    zeroize(pt);
    zeroize(dek);
  }
}

/**
 * Decrypt a stored secret. `authenticatedTenantId` is the org id from the
 * verified session/request; it MUST equal `ref.tenantId` (the row's stored
 * org id) or we refuse before touching the KEK. Defence-in-depth on top of RLS.
 */
export async function decryptTenantSecret(
  kek: KekProvider,
  wrappedDek: WrappedDek,
  ref: FieldRef,
  ciphertext: Buffer,
  authenticatedTenantId: string,
): Promise<Secret<string>> {
  if (ref.tenantId !== authenticatedTenantId) {
    throw new Error("tenant mismatch: refusing to decrypt across tenants");
  }
  const dek = await kek.unwrapDek(wrappedDek, dekContext(ref.tenantId));
  try {
    const pt = aeadDecrypt(ciphertext, dek, fieldContext(ref));
    const value = pt.toString("utf8");
    zeroize(pt);
    return new Secret(value);
  } finally {
    zeroize(dek);
  }
}
