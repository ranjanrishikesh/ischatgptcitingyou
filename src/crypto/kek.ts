/**
 * Key Encryption Key (KEK) providers. A KEK wraps (encrypts) the per-tenant DEK.
 * The wrapped DEK is stored in the DB; the KEK itself never is.
 *
 *  - KmsKekProvider  (HOSTED): wrapping/unwrapping is a KMS API call. The raw KEK
 *    never exists in app memory, and KMS EncryptionContext is the cryptographic
 *    AAD binding the DEK to the tenant. A DB dump alone is undecryptable.
 *  - FileKekProvider (SELF-HOST fallback): KEK is a 32-byte key on disk. WEAKER:
 *    a DB dump PLUS this file = full recovery. Documented as such; self-host is
 *    encouraged to use its own KMS/Vault instead.
 *
 * The provider is chosen at boot from KEK_PROVIDER. Hosted mode rejects "file".
 */
import { readFileSync } from "node:fs";
import { aeadEncrypt, aeadDecrypt, type EncryptionContext } from "./envelope";

export interface WrappedDek {
  /** Identifies which KEK wrapped this DEK (for rotation + audit). */
  keyId: string;
  /** The encrypted DEK bytes. */
  ciphertext: Buffer;
}

export interface KekProvider {
  readonly kind: "file" | "kms";
  wrapDek(dek: Buffer, context: EncryptionContext): Promise<WrappedDek>;
  unwrapDek(wrapped: WrappedDek, context: EncryptionContext): Promise<Buffer>;
}

// --- File provider (self-host fallback) ------------------------------------

export class FileKekProvider implements KekProvider {
  readonly kind = "file" as const;
  readonly #key: Buffer;
  readonly #keyId: string;

  constructor(key: Buffer, keyId = "file:v1") {
    if (key.length !== 32) throw new RangeError("FileKekProvider: master key must be 32 bytes");
    this.#key = key;
    this.#keyId = keyId;
  }

  static fromFile(path: string): FileKekProvider {
    const raw = readFileSync(path, "utf8").trim();
    if (!raw) throw new Error("KEK_FILE_PATH: file is empty");
    const key = Buffer.from(raw, "base64");
    // base64 decoding is lenient (silently drops invalid chars), so a corrupted
    // file can still decode to 32 bytes of the WRONG key and only fail later as
    // an opaque AEAD error. Reject non-canonical base64 up front.
    if (key.toString("base64") !== raw) {
      throw new Error("KEK_FILE_PATH: not valid canonical base64");
    }
    return new FileKekProvider(key);
  }

  async wrapDek(dek: Buffer, context: EncryptionContext): Promise<WrappedDek> {
    return { keyId: this.#keyId, ciphertext: aeadEncrypt(dek, this.#key, context) };
  }

  async unwrapDek(wrapped: WrappedDek, context: EncryptionContext): Promise<Buffer> {
    return aeadDecrypt(wrapped.ciphertext, this.#key, context);
  }
}

// --- KMS provider (hosted) -------------------------------------------------
// AWS KMS Encrypt/Decrypt with EncryptionContext == our AAD. The SDK is imported
// lazily so self-host builds that never use KMS don't pay for it at startup.

export class KmsKekProvider implements KekProvider {
  readonly kind = "kms" as const;
  readonly #keyId: string;
  readonly #region: string;

  constructor(keyId: string, region: string) {
    if (!keyId) throw new Error("KmsKekProvider: KMS_KEY_ID required");
    this.#keyId = keyId;
    this.#region = region;
  }

  async #client() {
    const { KMSClient } = await import("@aws-sdk/client-kms");
    return new KMSClient({ region: this.#region });
  }

  async wrapDek(dek: Buffer, context: EncryptionContext): Promise<WrappedDek> {
    const { EncryptCommand } = await import("@aws-sdk/client-kms");
    const client = await this.#client();
    const res = await client.send(
      new EncryptCommand({
        KeyId: this.#keyId,
        Plaintext: dek,
        EncryptionContext: context,
      }),
    );
    if (!res.CiphertextBlob) throw new Error("KMS Encrypt returned no ciphertext");
    return { keyId: res.KeyId ?? this.#keyId, ciphertext: Buffer.from(res.CiphertextBlob) };
  }

  async unwrapDek(wrapped: WrappedDek, context: EncryptionContext): Promise<Buffer> {
    const { DecryptCommand } = await import("@aws-sdk/client-kms");
    const client = await this.#client();
    const res = await client.send(
      new DecryptCommand({
        CiphertextBlob: wrapped.ciphertext,
        EncryptionContext: context, // MUST match wrap; KMS fails closed otherwise
        KeyId: this.#keyId,
      }),
    );
    if (!res.Plaintext) throw new Error("KMS Decrypt returned no plaintext");
    return Buffer.from(res.Plaintext);
  }
}

// --- Selection -------------------------------------------------------------

let cached: KekProvider | null = null;

/** Resolve the KEK provider from env. Caches for process lifetime. */
export function getKekProvider(): KekProvider {
  if (cached) return cached;
  const kind = process.env.KEK_PROVIDER ?? "file";
  if (kind === "kms") {
    cached = new KmsKekProvider(process.env.KMS_KEY_ID ?? "", process.env.AWS_REGION ?? "us-east-1");
  } else if (kind === "file") {
    const path = process.env.KEK_FILE_PATH;
    if (!path) throw new Error("KEK_PROVIDER=file requires KEK_FILE_PATH");
    cached = FileKekProvider.fromFile(path);
  } else {
    throw new Error(`Unknown KEK_PROVIDER: ${kind}`);
  }
  return cached;
}

/** Test seam. */
export function __setKekProviderForTest(p: KekProvider | null): void {
  cached = p;
}
