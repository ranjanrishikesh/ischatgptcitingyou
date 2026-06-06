import { describe, it, expect, beforeAll } from "vitest";
import {
  newIngestId,
  verifyIngestId,
  newBearer,
  hashBearer,
  verifyBearer,
  bearerFromHeader,
} from "./ingestId";
import { classify, vendorFor } from "./classify";
import { parseNdjson, MAX_LINES } from "./parse";

beforeAll(() => {
  process.env.INGEST_ID_PEPPER = "test-pepper-do-not-use-in-prod";
});

describe("ingestId", () => {
  it("mints a self-validating id that verifies", () => {
    const id = newIngestId();
    expect(id.startsWith("ind_live_")).toBe(true);
    expect(verifyIngestId(id)).toBe(true);
  });

  it("rejects forged / tampered ids in O(1), no DB", () => {
    const id = newIngestId();
    expect(verifyIngestId("ind_live_forged.deadbeefdeadbeefdeadbeefdeadbeef")).toBe(false);
    expect(verifyIngestId(id.slice(0, -1) + "0")).toBe(false); // flipped mac char
    expect(verifyIngestId("nope")).toBe(false);
    expect(verifyIngestId("ind_live_nomachere")).toBe(false);
    expect(verifyIngestId("")).toBe(false);
  });

  it("bearer hashes are not reversible and verify constant-time", () => {
    const b = newBearer();
    expect(b.startsWith("ist_live_")).toBe(true);
    const h = hashBearer(b);
    expect(h).not.toContain(b);
    expect(verifyBearer(b, h)).toBe(true);
    expect(verifyBearer(b + "x", h)).toBe(false);
    expect(verifyBearer("wrong", h)).toBe(false);
  });

  it("parses bearer header", () => {
    expect(bearerFromHeader("Bearer abc")).toBe("abc");
    expect(bearerFromHeader("bearer  xyz ")).toBe("xyz");
    expect(bearerFromHeader(null)).toBe(null);
    expect(bearerFromHeader("Basic abc")).toBe(null);
  });
});

describe("classify", () => {
  const base = { method: "GET", statusCode: 200 };

  it("keeps AI crawlers tagged with vendor", () => {
    const r = classify({ ...base, pathname: "/pricing", userAgent: "Mozilla/5.0 ... ChatGPT-User/1.0 +https://openai.com/bot" });
    expect(r.keep && r.bucket === "ai" && r.client === "ai" && r.llm).toBeTruthy();
    if (r.keep) expect(r.llm).toBe("ChatGPT");
  });

  it("keeps Claude / Perplexity / Gemini with right vendor", () => {
    expect(vendorFor("ClaudeBot/1.0")).toBe("Claude");
    expect(vendorFor("PerplexityBot")).toBe("Perplexity");
    expect(vendorFor("Google-Extended")).toBe("Gemini");
  });

  it("drops real browsers", () => {
    const r = classify({ ...base, pathname: "/", userAgent: "Mozilla/5.0 (Macintosh) AppleWebKit/537.36 Chrome/120.0 Safari/537.36" });
    expect(r.keep).toBe(false);
  });

  it("keeps unknown non-browser UAs (possible new AI crawler)", () => {
    const r = classify({ ...base, pathname: "/", userAgent: "SomeBrandNewThing/2.0" });
    expect(r.keep && r.client === "unknown").toBeTruthy();
  });

  it("routes known non-AI bots to other/bot", () => {
    const r = classify({ ...base, pathname: "/", userAgent: "Googlebot/2.1 (+http://www.google.com/bot.html)" });
    expect(r.keep && r.bucket === "other" && r.client === "bot").toBeTruthy();
  });

  it("does not misclassify device brands containing 'bot' (CUBOT) as bots", () => {
    const r = classify({ ...base, pathname: "/", userAgent: "Mozilla/5.0 (Linux; Android 8.1.0; CUBOT MAX 3) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Mobile Safari/537.36" });
    expect(r.keep).toBe(false); // real browser, dropped — not kept as a bot
  });

  it("drops by method/status/asset/infra/ignored-bot", () => {
    expect(classify({ ...base, method: "POST", pathname: "/", userAgent: "ChatGPT-User" }).keep).toBe(false);
    expect(classify({ ...base, statusCode: 410, pathname: "/x", userAgent: "GPTBot" }).keep).toBe(false);
    expect(classify({ ...base, pathname: "/app.js", userAgent: "GPTBot" }).keep).toBe(false);
    expect(classify({ ...base, pathname: "/_next/static/x", userAgent: "GPTBot" }).keep).toBe(false);
    expect(classify({ ...base, pathname: "/", userAgent: "PetalBot" }).keep).toBe(false);
    expect(classify({ ...base, pathname: "/", userAgent: "https://evil.example/" }).keep).toBe(false);
  });
});

describe("parseNdjson", () => {
  it("parses proxy records and strips query", () => {
    const raw = [
      JSON.stringify({ timestamp: 1700000000000, proxy: { method: "GET", path: "/p?x=1", statusCode: 200, userAgent: "GPTBot" } }),
      "",
      JSON.stringify({ proxy: { method: "GET", path: "/q", statusCode: 200, userAgent: "ClaudeBot" } }),
    ].join("\n");
    const out = parseNdjson(raw);
    expect(out.records.length).toBe(2);
    expect(out.records[0]!.pathname).toBe("/p");
    expect(out.records[0]!.timestampMs).toBe(1700000000000);
  });

  it("counts bad lines, does not throw", () => {
    const out = parseNdjson("{not json\n" + JSON.stringify({ proxy: { method: "GET", path: "/", statusCode: 200, userAgent: "x" } }));
    expect(out.badLines).toBe(1);
    expect(out.records.length).toBe(1);
  });

  it("truncates past MAX_LINES", () => {
    const line = JSON.stringify({ proxy: { method: "GET", path: "/", statusCode: 200, userAgent: "x" } });
    const out = parseNdjson(Array(MAX_LINES + 50).fill(line).join("\n"));
    expect(out.truncated).toBe(true);
    expect(out.records.length).toBeLessThanOrEqual(MAX_LINES);
  });

  it("joins array user-agents", () => {
    const out = parseNdjson(JSON.stringify({ proxy: { method: "GET", path: "/", statusCode: 200, userAgent: ["Mozilla", "GPTBot"] } }));
    expect(out.records[0]!.userAgent).toBe("Mozilla GPTBot");
  });
});
