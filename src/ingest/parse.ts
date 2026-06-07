/**
 * NDJSON parsing for Vercel Log Drain batches. Runs ONLY AFTER auth — never
 * parse attacker-controlled bytes before the bearer is verified.
 *
 * Vercel drains are NDJSON (one JSON object per line). Caps bound the work an
 * authenticated source can cause per batch. Each line is normalized to the
 * fields the classifier needs; unparseable lines are skipped, not fatal.
 */

export const MAX_BODY_BYTES = 5 * 1024 * 1024; // 5 MiB per batch
export const MAX_LINES = 20_000;

export interface NormalizedRecord {
  method: string;
  pathname: string; // path without query
  statusCode: number | string;
  userAgent: string;
  referer: string;
  timestampMs: number;
}

export interface ParseResult {
  records: NormalizedRecord[];
  totalLines: number;
  badLines: number;
  truncated: boolean;
}

/**
 * Read a request body with a HARD byte cap enforced WHILE streaming, so an
 * oversized (e.g. chunked, no/forged Content-Length) body can never be fully
 * buffered into memory first. Returns null if the cap is exceeded -> 413.
 * Content-Length is used only as a cheap fast-reject, never as the enforcement.
 */
export async function readBodyCapped(
  req: Request,
  maxBytes = MAX_BODY_BYTES,
): Promise<string | null> {
  const len = req.headers.get("content-length");
  if (len && Number(len) > maxBytes) return null;

  if (!req.body) {
    const t = await req.text();
    return Buffer.byteLength(t, "utf8") > maxBytes ? null : t;
  }

  const reader = req.body.getReader();
  const chunks: Buffer[] = [];
  let total = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    if (value) {
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        return null; // abort before retaining an oversized buffer
      }
      chunks.push(Buffer.from(value));
    }
  }
  return Buffer.concat(chunks).toString("utf8");
}

function uaToString(ua: unknown): string {
  if (Array.isArray(ua)) return ua.join(" ");
  return typeof ua === "string" ? ua : "";
}

/** Parse a raw NDJSON batch body into normalized records. */
export function parseNdjson(raw: string): ParseResult {
  const records: NormalizedRecord[] = [];
  let totalLines = 0;
  let badLines = 0;
  let truncated = false;

  const lines = raw.split("\n");
  for (const line of lines) {
    if (!line.trim()) continue;
    totalLines++;
    if (totalLines > MAX_LINES) {
      truncated = true;
      break;
    }
    let log: Record<string, unknown>;
    try {
      log = JSON.parse(line) as Record<string, unknown>;
    } catch {
      badLines++;
      continue;
    }
    if (!log || typeof log !== "object") {
      badLines++;
      continue;
    }
    const p = (log.proxy ?? {}) as Record<string, unknown>;
    const path = String(p.path ?? log.path ?? "");
    const pathname = path.split("?")[0] ?? "";
    const method = String(p.method ?? log.method ?? "");
    const statusCode = (p.statusCode ?? log.statusCode ?? "") as number | string;
    const ua = uaToString(p.userAgent ?? log.userAgent);
    const referer = String(p.referer ?? log.referer ?? "");
    const tsRaw = log.timestamp;
    const timestampMs =
      typeof tsRaw === "number" ? tsRaw : typeof tsRaw === "string" ? Date.parse(tsRaw) || 0 : 0;

    records.push({ method, pathname, statusCode, userAgent: ua, referer, timestampMs });
  }

  return { records, totalLines, badLines, truncated };
}
