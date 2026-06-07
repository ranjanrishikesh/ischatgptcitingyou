/**
 * PostHog destination. AI-crawler page views are forwarded as "LLM Pageview"
 * events via PostHog's batch capture endpoint, using the customer's project
 * (write-only) key. Event shape carried over from the original vercel-log-drain.
 *
 * Idempotency: each event gets a deterministic `uuid` derived from its content,
 * so a redelivered batch dedups on PostHog's side too (defence-in-depth on top
 * of our own per-batch replay gate).
 */
import { createHash } from "node:crypto";
import { safeFetch, type SafeFetchResult } from "../egress/safeFetch";

export const POSTHOG_DEFAULT_HOST = "https://us.i.posthog.com";
// No person here — all AI traffic groups under one synthetic id.
const DISTINCT_ID = "ai-chatbot@ischatgptcitingyou";

export interface AiEvent {
  pathname: string;
  userAgent: string;
  llm: string;
  timestampMs: number;
}

/** Stable uuid from event content so PostHog dedups redelivered batches. */
function uuidFrom(s: string): string {
  const h = createHash("sha256").update(s).digest("hex");
  return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20, 32)}`;
}

export function buildLLMPageviewEvents(
  sourceId: string,
  events: AiEvent[],
  siteUrl?: string,
): Array<Record<string, unknown>> {
  const base = siteUrl ? siteUrl.replace(/\/+$/, "") : "";
  return events.map((e, i) => ({
    event: "LLM Pageview",
    distinct_id: DISTINCT_ID,
    // Include the per-batch index so distinct events that share path/UA/timestamp
    // (e.g. timestamp 0 from a missing/garbage source timestamp) are NOT collapsed
    // to one uuid; still deterministic across redeliveries of the same batch.
    uuid: uuidFrom(`${sourceId}|${i}|${e.pathname}|${e.userAgent}|${e.timestampMs}`),
    timestamp: new Date(e.timestampMs > 0 ? e.timestampMs : Date.now()).toISOString(),
    properties: {
      llm: e.llm,
      userAgent: e.userAgent,
      $current_url: base + e.pathname,
    },
  }));
}

/** Send a batch to PostHog. Host is validated by safeFetch (SSRF-safe). */
export async function sendToPostHog(
  host: string | undefined,
  apiKey: string,
  batch: Array<Record<string, unknown>>,
): Promise<SafeFetchResult> {
  const base = (host || POSTHOG_DEFAULT_HOST).replace(/\/+$/, "");
  return safeFetch(`${base}/batch/`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ api_key: apiKey, batch }),
  });
}
