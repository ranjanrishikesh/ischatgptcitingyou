/**
 * PKCE (RFC 7636) for the Google OAuth authorization-code flow. The code
 * verifier is a high-entropy secret generated per authorization attempt; only
 * its S256 challenge travels in the auth URL, so an intercepted authorization
 * code is useless without the verifier.
 */
import { randomBytes, createHash } from "node:crypto";

/** 32 random bytes -> 43-char base64url verifier (within RFC 43–128 range). */
export function generateCodeVerifier(): string {
  return randomBytes(32).toString("base64url");
}

/** S256 challenge = base64url(sha256(verifier)). */
export function codeChallengeS256(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

/** Opaque CSRF/state token binding the auth request to the callback. */
export function generateState(): string {
  return randomBytes(24).toString("base64url");
}
