/**
 * Envelope encryption primitives. AES-256-GCM with authenticated additional
 * data (AAD). Used to encrypt per-field secrets under a per-tenant Data
 * Encryption Key (DEK); the DEK itself is wrapped by a KEK (see kek.ts).
 *
 * AAD binds a ciphertext to the identity of the thing it protects
 * ({tenantId, secretType, recordId}). Decryption with mismatched AAD FAILS —
 * so a ciphertext copied from one tenant/row cannot be decrypted in the context
 * of another, even if an attacker confuses a single id variable.
 */
import {
  randomBytes,
  createCipheriv,
  createDecipheriv,
  timingSafeEqual,
} from "node:crypto";

const ALGO = "aes-256-gcm";
const IV_LEN = 12; // 96-bit nonce, GCM standard
const TAG_LEN = 16;
const KEY_LEN = 32; // 256-bit

export type EncryptionContext = Record<string, string>;

/** 32 random bytes. Caller must zeroize after use. */
export function generateDek(): Buffer {
  return randomBytes(KEY_LEN);
}

/** Overwrite key material in place. Call as soon as a DEK is no longer needed. */
export function zeroize(buf: Buffer): void {
  buf.fill(0);
}

/**
 * Canonical AAD bytes: keys sorted so {a,b} and {b,a} produce identical AAD.
 * Anything non-deterministic here would make ciphertexts undecryptable.
 */
export function canonicalAad(context: EncryptionContext): Buffer {
  const sorted = Object.keys(context)
    .sort()
    .map((k) => [k, context[k]] as const);
  return Buffer.from(JSON.stringify(sorted), "utf8");
}

/** Encrypt -> [iv(12) | tag(16) | ciphertext]. key MUST be 32 bytes. */
export function aeadEncrypt(plaintext: Buffer, key: Buffer, context: EncryptionContext): Buffer {
  if (key.length !== KEY_LEN) throw new RangeError("aeadEncrypt: key must be 32 bytes");
  const iv = randomBytes(IV_LEN);
  const cipher = createCipheriv(ALGO, key, iv, { authTagLength: TAG_LEN });
  cipher.setAAD(canonicalAad(context));
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, tag, ct]);
}

/** Decrypt a [iv|tag|ct] blob. Throws if AAD/tag don't authenticate. */
export function aeadDecrypt(blob: Buffer, key: Buffer, context: EncryptionContext): Buffer {
  if (key.length !== KEY_LEN) throw new RangeError("aeadDecrypt: key must be 32 bytes");
  if (blob.length < IV_LEN + TAG_LEN) throw new RangeError("aeadDecrypt: blob too short");
  const iv = blob.subarray(0, IV_LEN);
  const tag = blob.subarray(IV_LEN, IV_LEN + TAG_LEN);
  const ct = blob.subarray(IV_LEN + TAG_LEN);
  const decipher = createDecipheriv(ALGO, key, iv, { authTagLength: TAG_LEN });
  decipher.setAAD(canonicalAad(context));
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(ct), decipher.final()]); // throws on auth failure
}

/** Constant-time buffer compare (for MAC/secret verification paths). */
export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) {
    // Still do a compare to keep timing uniform, then return false.
    timingSafeEqual(a, a);
    return false;
  }
  return timingSafeEqual(a, b);
}
