import { describe, it, expect, beforeAll } from "vitest";
import { signOAuthState, verifyOAuthState } from "./oauthState";

beforeAll(() => {
  process.env.BETTER_AUTH_SECRET = "test-secret-do-not-use";
});

const base = {
  state: "s",
  verifier: "v",
  orgId: "11111111-1111-1111-1111-111111111111",
  label: "L",
  sheetName: "Logs",
};

describe("oauthState", () => {
  it("round-trips a signed payload", () => {
    const out = verifyOAuthState(signOAuthState(base));
    expect(out?.orgId).toBe(base.orgId);
    expect(out?.verifier).toBe("v");
  });

  it("rejects a tampered payload (HMAC mismatch)", () => {
    const cookie = signOAuthState(base);
    const tampered = cookie.replace(/^[^.]+/, (b) => Buffer.from('{"orgId":"evil"}').toString("base64url"));
    expect(verifyOAuthState(tampered)).toBeNull();
  });

  it("rejects when no signature / malformed", () => {
    expect(verifyOAuthState(undefined)).toBeNull();
    expect(verifyOAuthState("nodot")).toBeNull();
  });

  it("rejects an expired state (server-side iat check, not just cookie maxAge)", () => {
    const stale = signOAuthState({ ...base, iat: Date.now() - 700_000 }); // >10 min
    expect(verifyOAuthState(stale)).toBeNull();
  });
});
