/**
 * Google OAuth callback. Verifies the signed state cookie (CSRF + orgId binding),
 * exchanges the code (with the PKCE verifier) for tokens, creates an app-owned
 * spreadsheet, and stores the destination with the refresh token encrypted.
 */
import { cookies } from "next/headers";
import { requireUser, requireOrgMember } from "@/auth/session";
import { verifyOAuthState, OAUTH_COOKIE } from "@/auth/oauthState";
import { exchangeCode } from "@/destinations/google/oauth";
import { createSpreadsheet } from "@/destinations/google/sheets";
import { createGoogleSheetsDestination } from "@/services/destinations";

export const runtime = "nodejs";

function redirectUri(): string {
  const base = process.env.BETTER_AUTH_URL ?? "";
  return `${base}/api/oauth/google/callback`;
}

function back(path: string): Response {
  const base = process.env.BETTER_AUTH_URL ?? "";
  return Response.redirect(`${base}${path}`, 302);
}

export async function GET(req: Request): Promise<Response> {
  const url = new URL(req.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");

  const jar = await cookies();
  const saved = verifyOAuthState(jar.get(OAUTH_COOKIE)?.value);
  jar.delete({ name: OAUTH_COOKIE, path: "/api/oauth/google" }); // path must match the set

  if (!code || !state || !saved || saved.state !== state) {
    return back("/dashboard?error=oauth_state");
  }

  // Auth + re-verify membership of the bound org (defence-in-depth). A missing
  // session / revoked membership redirects gracefully rather than 500ing.
  try {
    const user = await requireUser();
    await requireOrgMember(user.id, saved.orgId);
  } catch {
    return back("/dashboard?error=unauthorized");
  }

  try {
    const tokens = await exchangeCode({ code, codeVerifier: saved.verifier, redirectUri: redirectUri() });
    if (!tokens.refreshToken) return back("/dashboard?error=no_refresh_token");

    const spreadsheetId = await createSpreadsheet(
      tokens.accessToken,
      "ischatgptcitingyou — AI crawler logs",
    );
    await createGoogleSheetsDestination(saved.orgId, {
      label: saved.label,
      refreshToken: tokens.refreshToken,
      spreadsheetId,
      sheetName: saved.sheetName,
    });
    return back("/dashboard?connected=google_sheets");
  } catch {
    return back("/dashboard?error=oauth_exchange");
  }
}
