import { describe, it, expect } from "vitest";
import { buildLLMPageviewEvents } from "./posthog";

describe("buildLLMPageviewEvents", () => {
  const events = [
    { pathname: "/pricing", userAgent: "ChatGPT-User/1.0", llm: "ChatGPT", timestampMs: 1700000000000 },
  ];

  it("builds an LLM Pageview with $current_url = siteUrl + path", () => {
    const [e] = buildLLMPageviewEvents("src-1", events, "https://www.example.com/");
    expect(e!.event).toBe("LLM Pageview");
    const props = e!.properties as Record<string, unknown>;
    expect(props.$current_url).toBe("https://www.example.com/pricing"); // trailing slash trimmed
    expect(props.llm).toBe("ChatGPT");
    expect(props.userAgent).toBe("ChatGPT-User/1.0");
    expect(e!.distinct_id).toBe("ai-chatbot@ischatgptcitingyou");
    expect(e!.timestamp).toBe(new Date(1700000000000).toISOString());
  });

  it("uuid is deterministic per content (dedups redelivery)", () => {
    const a = buildLLMPageviewEvents("src-1", events)[0]!.uuid;
    const b = buildLLMPageviewEvents("src-1", events)[0]!.uuid;
    const c = buildLLMPageviewEvents("src-2", events)[0]!.uuid; // different source
    expect(a).toBe(b);
    expect(a).not.toBe(c);
    expect(String(a)).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
  });

  it("falls back to relative path when no siteUrl", () => {
    const [e] = buildLLMPageviewEvents("src-1", events);
    expect((e!.properties as Record<string, unknown>).$current_url).toBe("/pricing");
  });
});
