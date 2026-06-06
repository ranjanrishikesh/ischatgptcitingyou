/**
 * Ingest identity + per-source bearer.
 *
 * The ingest id (`ind_live_<rand>.<mac>`) is a PUBLIC routing token — it appears
 * in the drain URL and is a username, not a secret. It is SELF-VALIDATING: the
 * suffix is HMAC(pepper, rand). A forged / never-issued id is rejected in O(1)
 * with a constant-time compare and ZERO database hits — killing the pre-auth DB
 * amplification primitive (an attacker can't make us do work by spraying ids).
 *
 * The bearer (`ist_live_<rand>`) IS the secret. It is shown once at creation and
 * never stored; we store only HMAC(pepper, bearer). Verification is constant-time.
 *
 * The pepper (INGEST_ID_PEPPER) is server-side and rotatable.
 */
import { randomBytes, createHmac } from "node:crypto";
import { constantTimeEqual } from "../crypto/envelope";

const ID_PREFIX = "ind_live_";
const BEARER_PREFIX = "ist_live_";
const MAC_LEN_HEX = 32; // 16 bytes of HMAC-SHA256, truncated — plenty for a tag

function pepper(): Buffer {
  const p = process.env.INGEST_ID_PEPPER;
  if (!p) throw new Error("INGEST_ID_PEPPER is not set");
  return Buffer.from(p, "utf8");
}

function b64url(buf: Buffer): string {
  return buf.toString("base64url");
}

function macFor(rand: string): string {
  return createHmac("sha256", pepper()).update(rand).digest("hex").slice(0, MAC_LEN_HEX);
}

/** Mint a new public ingest id. */
export function newIngestId(): string {
  const rand = b64url(randomBytes(16));
  return `${ID_PREFIX}${rand}.${macFor(rand)}`;
}

/**
 * Validate an ingest id WITHOUT a DB lookup. Checks the prefix and the HMAC tag
 * in constant time. Returns true only for ids this server actually minted.
 */
export function verifyIngestId(id: string): boolean {
  try {
    if (typeof id !== "string" || !id.startsWith(ID_PREFIX)) return false;
    const body = id.slice(ID_PREFIX.length);
    const dot = body.lastIndexOf(".");
    if (dot <= 0) return false;
    const rand = body.slice(0, dot);
    const mac = body.slice(dot + 1);
    if (mac.length !== MAC_LEN_HEX) return false;
    return constantTimeEqual(Buffer.from(mac), Buffer.from(macFor(rand)));
  } catch {
    // A misconfiguration (e.g. INGEST_ID_PEPPER unset) must FAIL CLOSED to a 401,
    // never throw a 500 that leaks config state. The boot posture gate
    // (instrumentation.ts) is what actually refuses to start in that case.
    return false;
  }
}

/** Mint a new per-source bearer secret (returned ONCE; never stored raw). */
export function newBearer(): string {
  return `${BEARER_PREFIX}${b64url(randomBytes(32))}`;
}

/** Hash a bearer for storage. HMAC(pepper, bearer) — not reversible. */
export function hashBearer(bearer: string): string {
  return createHmac("sha256", pepper()).update(bearer).digest("hex");
}

/** Constant-time verify a presented bearer against a stored hash. */
export function verifyBearer(presented: string, storedHash: string): boolean {
  try {
    if (typeof presented !== "string" || typeof storedHash !== "string") return false;
    return constantTimeEqual(Buffer.from(hashBearer(presented)), Buffer.from(storedHash));
  } catch {
    return false; // fail closed (e.g. pepper unset) — never 500
  }
}

/** Extract the bearer from an Authorization header value, or null. */
export function bearerFromHeader(header: string | null): string | null {
  if (!header) return null;
  const m = /^Bearer\s+(.+)$/i.exec(header);
  return m ? m[1]!.trim() : null;
}
