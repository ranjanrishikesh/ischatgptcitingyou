/**
 * Google OAuth 2.0 (authorization-code + PKCE). Least-privilege scope
 * `drive.file` — the app can only touch files IT creates/opens, never the user's
 * whole Drive. We store ONLY the refresh token (encrypted, as a destination
 * credential); access tokens are short-lived and never persisted.
 *
 * The Google `client_secret` is a platform-level secret (env), protected like
 * the other top-tier secrets — NOT a per-tenant credential.
 */
import { codeChallengeS256 } from "./pkce";
import { safeFetch } from "../../egress/safeFetch";
import { Secret } from "../../crypto/secret";

const AUTH_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
// Least privilege: drive.file grants access ONLY to files the app itself creates
// or opens — never the user's whole Drive/Sheets. The Sheets API authorizes
// create + values.append on a drive.file-granted (app-created) spreadsheet, so we
// do NOT request the broad `spreadsheets` scope (which would expose every sheet
// the user can edit). A leaked token can at most touch our own Logs sheet.
export const GOOGLE_SCOPES = "https://www.googleapis.com/auth/drive.file";

export interface AuthUrlParams {
  clientId: string;
  redirectUri: string;
  state: string;
  codeVerifier: string;
}

/** Build the consent-screen URL. offline + consent => we receive a refresh token. */
export function buildAuthUrl(p: AuthUrlParams): string {
  const q = new URLSearchParams({
    client_id: p.clientId,
    redirect_uri: p.redirectUri,
    response_type: "code",
    scope: GOOGLE_SCOPES,
    access_type: "offline",
    prompt: "consent",
    include_granted_scopes: "true",
    state: p.state,
    code_challenge: codeChallengeS256(p.codeVerifier),
    code_challenge_method: "S256",
  });
  return `${AUTH_ENDPOINT}?${q.toString()}`;
}

function clientCreds(): { id: string; secret: string } {
  const id = process.env.GOOGLE_CLIENT_ID;
  const secret = process.env.GOOGLE_CLIENT_SECRET;
  if (!id || !secret) throw new Error("GOOGLE_CLIENT_ID / GOOGLE_CLIENT_SECRET not set");
  return { id, secret };
}

export interface TokenResult {
  // Non-null on first consent AND whenever Google ROTATES it on a refresh grant.
  // Callers MUST persist a rotated token or the destination will eventually break.
  refreshToken: Secret<string> | null;
  accessToken: Secret<string>;
  expiresInSec: number;
}

async function tokenRequest(form: Record<string, string>): Promise<TokenResult> {
  const res = await safeFetch(TOKEN_ENDPOINT, {
    method: "POST",
    headers: { "content-type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams(form).toString(),
  });
  if (!res.ok) throw new Error(`google token endpoint status ${res.status}`);
  let json: { access_token?: string; refresh_token?: string; expires_in?: number };
  try {
    json = JSON.parse(res.body);
  } catch {
    throw new Error("google token response: malformed JSON"); // no body fragment in message
  }
  if (!json.access_token) throw new Error("google token response missing access_token");
  return {
    accessToken: new Secret(json.access_token),
    refreshToken: json.refresh_token ? new Secret(json.refresh_token) : null,
    expiresInSec: json.expires_in ?? 3600,
  };
}

/** Exchange an authorization code (with the PKCE verifier) for tokens. */
export async function exchangeCode(args: {
  code: string;
  codeVerifier: string;
  redirectUri: string;
}): Promise<TokenResult> {
  const { id, secret } = clientCreds();
  return tokenRequest({
    grant_type: "authorization_code",
    code: args.code,
    code_verifier: args.codeVerifier,
    redirect_uri: args.redirectUri,
    client_id: id,
    client_secret: secret,
  });
}

/** Mint a fresh access token from a stored refresh token. */
export async function refreshAccessToken(refreshToken: Secret<string>): Promise<TokenResult> {
  const { id, secret } = clientCreds();
  return tokenRequest({
    grant_type: "refresh_token",
    refresh_token: refreshToken.expose(),
    client_id: id,
    client_secret: secret,
  });
}
