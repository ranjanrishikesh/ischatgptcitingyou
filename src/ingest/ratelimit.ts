/**
 * Pre-auth rate limiter, keyed on client IP/ASN. Runs BEFORE any DB lookup or
 * body parse, so an unauthenticated flood can't make us do real work. Fixed
 * window via Redis INCR + EXPIRE (one round trip on the steady-state path).
 *
 * This is the IP limiter only — it MAY reject. The per-tenant spend/quota meter
 * (billing) is separate and is debited only AFTER the bearer verifies, so a
 * shared-IP attacker can never exhaust a victim tenant's quota.
 *
 * If Redis is not configured (self-host without Redis), limiting is a no-op —
 * self-host runs behind the operator's own infra.
 */
import { Redis } from "@upstash/redis";

let _redis: Redis | null = null;
let _checked = false;

function redis(): Redis | null {
  if (_checked) return _redis;
  _checked = true;
  const url = process.env.UPSTASH_REDIS_REST_URL;
  const token = process.env.UPSTASH_REDIS_REST_TOKEN;
  if (url && token) _redis = new Redis({ url, token });
  return _redis;
}

export interface RateLimitResult {
  allowed: boolean;
  remaining: number;
}

const WINDOW_SECONDS = 60;
const MAX_PER_WINDOW = 600; // batches/min/IP — generous for a real drain, caps floods

/** Returns allowed=false when the IP exceeded the window budget. */
export async function rateLimitIp(ip: string): Promise<RateLimitResult> {
  const r = redis();
  if (!r) return { allowed: true, remaining: MAX_PER_WINDOW };

  try {
    const bucket = Math.floor(Date.now() / 1000 / WINDOW_SECONDS);
    const key = `rl:ip:${ip}:${bucket}`;
    const count = await r.incr(key);
    if (count === 1) await r.expire(key, WINDOW_SECONDS * 2);
    return { allowed: count <= MAX_PER_WINDOW, remaining: Math.max(0, MAX_PER_WINDOW - count) };
  } catch {
    // A Redis blip must not 500 every legitimate drain. This is a pre-auth flood
    // guard only — the per-source bearer + per-tenant meter still gate real work
    // and money — so failing open here is acceptable and bounded.
    return { allowed: true, remaining: 0 };
  }
}

/**
 * Trusted client IP. The left-most X-Forwarded-For entry is CLIENT-SUPPLIED and
 * spoofable (an attacker rotates it to get a fresh bucket per request), so we
 * never key on it. On Vercel the platform sets `x-real-ip` to the true peer and
 * appends the real IP to the RIGHT of XFF; prefer those. Self-host operators
 * behind a different proxy must ensure the same (document the trusted-hop count).
 */
export function clientIp(headers: Headers): string {
  const real = headers.get("x-real-ip");
  if (real) return real.trim();
  const xff = headers.get("x-forwarded-for");
  if (xff) {
    const parts = xff.split(",").map((s) => s.trim()).filter(Boolean);
    if (parts.length) return parts[parts.length - 1]!; // right-most = trusted hop
  }
  return "unknown";
}
