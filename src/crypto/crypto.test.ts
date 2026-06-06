import { describe, it, expect } from "vitest";
import { randomBytes } from "node:crypto";
import { aeadEncrypt, aeadDecrypt, generateDek, constantTimeEqual } from "./envelope";
import { FileKekProvider } from "./kek";
import {
  provisionTenantDek,
  encryptTenantSecret,
  decryptTenantSecret,
} from "./tenantSecrets";
import { Secret } from "./secret";

describe("envelope AEAD", () => {
  it("round-trips with matching AAD", () => {
    const key = generateDek();
    const ctx = { tenantId: "t1", secretType: "posthog", recordId: "r1" };
    const blob = aeadEncrypt(Buffer.from("phc_secret"), key, ctx);
    expect(aeadDecrypt(blob, key, ctx).toString()).toBe("phc_secret");
  });

  it("fails on mismatched AAD (cannot reuse ciphertext across context)", () => {
    const key = generateDek();
    const blob = aeadEncrypt(Buffer.from("x"), key, { tenantId: "A", secretType: "s", recordId: "r" });
    expect(() =>
      aeadDecrypt(blob, key, { tenantId: "B", secretType: "s", recordId: "r" }),
    ).toThrow();
  });

  it("fails on tampered ciphertext", () => {
    const key = generateDek();
    const ctx = { tenantId: "t", secretType: "s", recordId: "r" };
    const blob = aeadEncrypt(Buffer.from("x"), key, ctx);
    const last = blob.length - 1;
    blob[last] = (blob[last] ?? 0) ^ 0xff;
    expect(() => aeadDecrypt(blob, key, ctx)).toThrow();
  });

  it("constantTimeEqual", () => {
    expect(constantTimeEqual(Buffer.from("abc"), Buffer.from("abc"))).toBe(true);
    expect(constantTimeEqual(Buffer.from("abc"), Buffer.from("abd"))).toBe(false);
    expect(constantTimeEqual(Buffer.from("abc"), Buffer.from("ab"))).toBe(false);
  });
});

describe("tenant secrets (KEK + per-tenant DEK)", () => {
  const kek = new FileKekProvider(randomBytes(32));

  it("encrypts and decrypts a tenant secret end to end", async () => {
    const tenantId = "11111111-1111-1111-1111-111111111111";
    const wrapped = await provisionTenantDek(kek, tenantId);
    const ref = { tenantId, secretType: "posthog_project_key", recordId: "dest-1" };

    const ct = await encryptTenantSecret(kek, wrapped, ref, new Secret("phc_abc123"));
    const out = await decryptTenantSecret(kek, wrapped, ref, ct, tenantId);
    expect(out.expose()).toBe("phc_abc123");
  });

  it("refuses to decrypt when the authenticated tenant differs", async () => {
    const tenantId = "11111111-1111-1111-1111-111111111111";
    const wrapped = await provisionTenantDek(kek, tenantId);
    const ref = { tenantId, secretType: "posthog_project_key", recordId: "dest-1" };
    const ct = await encryptTenantSecret(kek, wrapped, ref, new Secret("phc_abc123"));

    await expect(
      decryptTenantSecret(kek, wrapped, ref, ct, "22222222-2222-2222-2222-222222222222"),
    ).rejects.toThrow(/tenant mismatch/);
  });

  it("a DEK wrapped for tenant A cannot be unwrapped in tenant B's context", async () => {
    const wrappedA = await provisionTenantDek(kek, "A");
    // unwrap with a different tenant context must fail (AAD mismatch).
    await expect(kek.unwrapDek(wrappedA, { tenantId: "B", purpose: "tenant-dek" })).rejects.toThrow();
  });
});
