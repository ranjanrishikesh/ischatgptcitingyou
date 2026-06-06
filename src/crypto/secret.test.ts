import { describe, it, expect } from "vitest";
import { Secret, isSecret, redactForLog } from "./secret.js";

describe("Secret", () => {
  it("never leaks via toString / template / JSON / inspect", () => {
    const s = new Secret("phc_supersecret");
    expect(String(s)).toBe("[REDACTED]");
    expect(`${s}`).toBe("[REDACTED]");
    expect(s.toJSON()).toBe("[REDACTED]");
    expect(JSON.stringify({ key: s })).toBe('{"key":"[REDACTED]"}');
    expect(JSON.stringify(s)).toBe('"[REDACTED]"');
  });

  it("expose returns the underlying value", () => {
    expect(new Secret("v").expose()).toBe("v");
    expect(isSecret(new Secret("v"))).toBe(true);
    expect(isSecret("v")).toBe(false);
  });

  it("not enumerable via spread/entries", () => {
    const s = new Secret("v");
    expect(Object.entries(s)).toEqual([]);
    expect(JSON.stringify({ ...s })).toBe("{}");
  });

  it("redactForLog redacts Secrets and sensitive keys", () => {
    const out = redactForLog({
      apiKey: "raw-leak",
      authorization: "Bearer x",
      nested: { client_secret: "y", safe: "ok" },
      wrapped: new Secret("z"),
      keep: 42,
    }) as Record<string, unknown>;
    expect(out.apiKey).toBe("[REDACTED]");
    expect(out.authorization).toBe("[REDACTED]");
    expect((out.nested as Record<string, unknown>).client_secret).toBe("[REDACTED]");
    expect((out.nested as Record<string, unknown>).safe).toBe("ok");
    expect(out.wrapped).toBe("[REDACTED]");
    expect(out.keep).toBe(42);
  });
});
