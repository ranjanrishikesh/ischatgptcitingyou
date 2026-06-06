/**
 * Signed, tamper-evident OAuth state cookie. Carries the PKCE verifier + the
 * target orgId between the start and callback legs. HMAC-signed with the server
 * secret so a client cannot swap the orgId or forge the state.
 */
import { createHmac, timingSafeEqual } from "node:crypto";

export interface OAuthState {
  state: string;
  verifier: string;
  orgId: string;
  label: string;
  sheetName: string;
  iat?: number; // issued-at (ms); set on sign, checked on verify
}

const STATE_TTL_MS = 600_000; // 10 min — server-checked, independent of cookie maxAge

function secret(): Buffer {
  const s = process.env.BETTER_AUTH_SECRET;
  if (!s) throw new Error("BETTER_AUTH_SECRET not set");
  return Buffer.from(s, "utf8");
}

export function signOAuthState(payload: OAuthState): string {
  const stamped: OAuthState = { ...payload, iat: payload.iat ?? Date.now() };
  const body = Buffer.from(JSON.stringify(stamped), "utf8").toString("base64url");
  const mac = createHmac("sha256", secret()).update(body).digest("base64url");
  return `${body}.${mac}`;
}

export function verifyOAuthState(cookie: string | undefined): OAuthState | null {
  if (!cookie) return null;
  const dot = cookie.lastIndexOf(".");
  if (dot <= 0) return null;
  const body = cookie.slice(0, dot);
  const mac = cookie.slice(dot + 1);
  const expected = createHmac("sha256", secret()).update(body).digest("base64url");
  const a = Buffer.from(mac);
  const b = Buffer.from(expected);
  if (a.length !== b.length || !timingSafeEqual(a, b)) return null;
  let parsed: OAuthState;
  try {
    parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8")) as OAuthState;
  } catch {
    return null;
  }
  // Server-side expiry, independent of the browser cookie maxAge.
  if (typeof parsed.iat !== "number" || Date.now() - parsed.iat > STATE_TTL_MS) return null;
  return parsed;
}

export const OAUTH_COOKIE = "g_oauth";
