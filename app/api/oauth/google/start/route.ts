/**
 * Begin the Google Sheets connect flow. Generates PKCE + state, stashes them in
 * a signed httpOnly cookie bound to the user's chosen org, and redirects to
 * Google's consent screen.
 */
import { cookies } from "next/headers";
import { requireUser, requireOrgMember, defaultOrg } from "@/auth/session";
import { generateCodeVerifier, generateState } from "@/destinations/google/pkce";
import { buildAuthUrl } from "@/destinations/google/oauth";
import { signOAuthState, OAUTH_COOKIE } from "@/auth/oauthState";
import { NotFoundError } from "@/services/errors";

export const runtime = "nodejs";

function redirectUri(): string {
  const base = process.env.BETTER_AUTH_URL ?? "";
  return `${base}/api/oauth/google/callback`;
}

export async function GET(req: Request): Promise<Response> {
  const url = new URL(req.url);
  let orgId: string;
  try {
    const user = await requireUser();
    const candidate = url.searchParams.get("orgId") ?? (await defaultOrg(user.id));
    if (!candidate) throw new NotFoundError("no org");
    await requireOrgMember(user.id, candidate); // 404 if not a member
    orgId = candidate;
  } catch {
    return new Response("not found", { status: 404 });
  }

  const clientId = process.env.GOOGLE_CLIENT_ID;
  if (!clientId) return new Response("google not configured", { status: 500 });

  const verifier = generateCodeVerifier();
  const state = generateState();
  const payload = {
    state,
    verifier,
    orgId,
    label: url.searchParams.get("label") ?? "Google Sheet",
    sheetName: url.searchParams.get("sheetName") ?? "Logs",
  };

  const jar = await cookies();
  jar.set(OAUTH_COOKIE, signOAuthState(payload), {
    httpOnly: true,
    secure: true,
    sameSite: "lax",
    path: "/api/oauth/google",
    maxAge: 600,
  });

  const authUrl = buildAuthUrl({ clientId, redirectUri: redirectUri(), state, codeVerifier: verifier });
  return Response.redirect(authUrl, 302);
}
