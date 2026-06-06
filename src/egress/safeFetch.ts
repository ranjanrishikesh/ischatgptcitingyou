/**
 * SSRF-safe outbound fetch. The ONLY way this app talks to a destination.
 *
 * Defenses (resolve-and-pin at request time):
 *   - HTTPS only
 *   - resolve the hostname, reject if ANY resolved address is internal/private
 *   - PIN the connection to the validated IP (a custom dispatcher lookup returns
 *     only that address) so DNS rebinding between validation and connect can't
 *     swap in an internal IP
 *   - never follow redirects (a 3xx to an internal URL would re-open SSRF)
 *   - hard timeout
 *
 * Credentials are injected by the caller into headers right here at the edge;
 * on error we surface method+host+status only (never headers/body).
 */
import { promises as dns, type LookupAddress } from "node:dns";
import { isIP } from "node:net";
import { Agent, fetch as undiciFetch } from "undici";
import { isDisallowedIp } from "./ssrf";

export class SsrfError extends Error {}

const DEFAULT_TIMEOUT_MS = 10_000;

export interface SafeFetchInit {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
}

export interface SafeFetchResult {
  status: number;
  ok: boolean;
}

export async function safeFetch(rawUrl: string, init: SafeFetchInit = {}): Promise<SafeFetchResult> {
  let u: URL;
  try {
    u = new URL(rawUrl);
  } catch {
    throw new SsrfError("invalid url");
  }
  if (u.protocol !== "https:") throw new SsrfError("only https destinations allowed");
  // Constrain the port: legitimate destinations use 443. Blocks using our egress
  // as an arbitrary public host:port prober.
  if (u.port && u.port !== "443") throw new SsrfError(`port ${u.port} not allowed`);

  // Strip IPv6 brackets so both the validator and dns.lookup see a bare host.
  const host = u.hostname.replace(/^\[|\]$/g, "");

  let pinned: { address: string; family: number };
  if (isIP(host)) {
    // Literal IP destination — validate directly through the same validator and
    // pin to it (no DNS step, and the v6 validator actually runs on literals).
    if (isDisallowedIp(host)) throw new SsrfError(`disallowed address ${host}`);
    pinned = { address: host, family: isIP(host) };
  } else {
    // Resolve + validate ALL addresses now, then pin to the validated one.
    let addrs: { address: string; family: number }[];
    try {
      addrs = await dns.lookup(host, { all: true });
    } catch {
      throw new SsrfError("dns resolution failed");
    }
    if (!addrs.length) throw new SsrfError("no addresses resolved");
    for (const a of addrs) {
      if (isDisallowedIp(a.address)) throw new SsrfError(`disallowed address ${a.address}`);
    }
    pinned = addrs[0]!;
  }

  // Pin the connection to the validated IP. The lookup returns ONLY that
  // address, so undici connects there while TLS SNI / cert validation still
  // uses the hostname.
  const lookup = (
    _host: string,
    opts: { all?: boolean },
    cb: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void,
  ): void => {
    if (opts && opts.all) cb(null, [{ address: pinned.address, family: pinned.family }]);
    else cb(null, pinned.address, pinned.family);
  };
  const agent = new Agent({ connect: { lookup: lookup as never } });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), init.timeoutMs ?? DEFAULT_TIMEOUT_MS);
  try {
    const res = await undiciFetch(rawUrl, {
      method: init.method ?? "POST",
      headers: init.headers,
      body: init.body,
      redirect: "manual", // never follow — a 3xx could point internal
      dispatcher: agent,
      signal: controller.signal,
    });
    // We never read the body — cancel it so a slow/large response can't make the
    // socket (and agent.close) hang past the timeout.
    await res.body?.cancel().catch(() => {});
    if (res.status >= 300 && res.status < 400) {
      throw new SsrfError(`redirect not allowed (status ${res.status})`);
    }
    return { status: res.status, ok: res.status >= 200 && res.status < 300 };
  } finally {
    clearTimeout(timer);
    await agent.destroy().catch(() => {});
  }
}
