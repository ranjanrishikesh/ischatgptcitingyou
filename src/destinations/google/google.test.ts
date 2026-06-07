import { describe, it, expect } from "vitest";
import { generateCodeVerifier, codeChallengeS256, generateState } from "./pkce";
import { buildAuthUrl, GOOGLE_SCOPES } from "./oauth";
import { eventsToRows } from "./sheets";

describe("pkce", () => {
  it("verifier is base64url and within RFC length bounds", () => {
    const v = generateCodeVerifier();
    expect(v).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(v.length).toBeGreaterThanOrEqual(43);
    expect(v.length).toBeLessThanOrEqual(128);
  });

  it("S256 challenge is deterministic, base64url, and not the verifier", () => {
    const v = "test-verifier-fixed";
    const c = codeChallengeS256(v);
    expect(c).toBe(codeChallengeS256(v));
    expect(c).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(c).not.toBe(v);
  });

  it("state tokens are unique-ish and url-safe", () => {
    expect(generateState()).not.toBe(generateState());
    expect(generateState()).toMatch(/^[A-Za-z0-9_-]+$/);
  });
});

describe("buildAuthUrl", () => {
  it("requests least-privilege offline consent with PKCE S256", () => {
    const verifier = generateCodeVerifier();
    const url = new URL(
      buildAuthUrl({
        clientId: "cid.apps.googleusercontent.com",
        redirectUri: "https://app.example.com/oauth/google/callback",
        state: "st4te",
        codeVerifier: verifier,
      }),
    );
    const q = url.searchParams;
    expect(url.origin + url.pathname).toBe("https://accounts.google.com/o/oauth2/v2/auth");
    expect(q.get("client_id")).toBe("cid.apps.googleusercontent.com");
    expect(q.get("response_type")).toBe("code");
    expect(q.get("access_type")).toBe("offline");
    expect(q.get("prompt")).toBe("consent");
    expect(q.get("scope")).toBe(GOOGLE_SCOPES);
    expect(q.get("scope")).toContain("drive.file");
    expect(q.get("code_challenge_method")).toBe("S256");
    expect(q.get("code_challenge")).toBe(codeChallengeS256(verifier));
    expect(q.get("state")).toBe("st4te");
  });
});

describe("sheets eventsToRows", () => {
  it("maps AI events to [timestamp, path, ua, llm] rows", () => {
    const rows = eventsToRows([
      { pathname: "/p", userAgent: "GPTBot", llm: "ChatGPT", timestampMs: 1700000000000 },
    ]);
    expect(rows).toEqual([[new Date(1700000000000).toISOString(), "/p", "GPTBot", "ChatGPT"]]);
  });

  it("neutralizes CSV/formula injection in attacker-controlled cells", () => {
    const [row] = eventsToRows([
      {
        pathname: "=HYPERLINK(0)",
        userAgent: '=cmd|"/c calc"!A0',
        llm: "ChatGPT",
        timestampMs: 1700000000000,
      },
    ]);
    expect(row![1]).toBe("'=HYPERLINK(0)"); // path prefixed
    expect(row![2]).toBe("'=cmd|\"/c calc\"!A0"); // userAgent prefixed
    expect(row![3]).toBe("ChatGPT"); // safe value untouched
  });
});
